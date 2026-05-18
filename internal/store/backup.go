// SQLite backup helpers for #279 — `gbounce backup` + `gbounce restore`.
//
// Backup uses SQLite's `VACUUM INTO` statement: a one-shot atomic
// online-backup primitive that copies the live database into a new file
// at PATH while concurrent writers continue against the source. Two
// reasons for choosing VACUUM INTO over the lower-level backup API
// (sqlite3_backup_init / _step / _finish):
//
//  1. modernc.org/sqlite — gbounce's pure-Go SQLite driver — does not
//     expose the backup-API as a typed Go surface. The C-level entry
//     points exist inside the driver's libc shim but binding them
//     correctly from Go would require dropping to unsafe pointers +
//     reasoning about the driver's connection-handle lifetime. VACUUM
//     INTO is one SQL statement against the existing *sql.DB; it
//     composes cleanly with the existing pool + transaction model.
//
//  2. VACUUM INTO is atomic from the reader's perspective: the
//     destination file is created + populated inside a single
//     SQLite-side transaction. If the process dies mid-VACUUM, the
//     destination file is removed before any other connection sees it.
//     Critical for the [[creates-never-mutates]] read-only-backup
//     guarantee.
//
// Volume-table exclusion: gbounce's `decisions` table is the dominant
// volume (every forwarded request emits one row + one OCSF event).
// Default backups skip the decisions rows so the file stays small +
// DR-focused; operators who want the audit history in the backup pass
// `--include-audit`. VACUUM INTO can't be told to omit tables, so the
// flow is:
//
//   1. VACUUM INTO TMP                       — full copy
//   2. OPEN TMP                              — second handle
//   3. DELETE FROM <excluded> on TMP         — drop opt-out tables
//   4. VACUUM on TMP                         — reclaim freed pages so
//                                              the on-disk file is the
//                                              size of the kept data,
//                                              not source-size
//   5. INSERT INTO gbounce_backup_metadata   — provenance
//   6. mv TMP → PATH                         — atomic rename
//
// The gbounce_backup_metadata table is created on the destination
// (NOT the source) so the live database never grows a one-row admin
// table just because the operator ran a backup.
//
// Prompts subsystem: G-Slice 1 has no prompts table. `--include-prompts`
// is accepted as a documented no-op for cross-product CLI parity
// (kbounce + dbounce + ibounce ship the same flag); the metadata table
// records included_prompts=false unconditionally in G-Slice 1.
//
// Cross-product alignment per [[cross-product-agent-parity]]: kbounce
// (kbounce_backup_metadata) + dbounce (dbounce_backup_metadata) +
// ibounce (iam_jit_backup_metadata) ship the same metadata-table shape
// + the same VACUUM INTO + delete-excluded-tables flow.

package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// backupMetadataTable is the on-disk table embedded in every gbounce
// backup file carrying the provenance fields restore validates. Named
// `gbounce_backup_metadata` per the cross-product naming convention
// (kbounce ships `kbounce_backup_metadata`, dbounce ships
// `dbounce_backup_metadata`, ibounce ships `iam_jit_backup_metadata`).
const backupMetadataTable = "gbounce_backup_metadata"

// BackupOptions controls which optional tables ship in the backup file
// + carries the version string the CLI stamps into the metadata table.
// Defaults exclude the high-volume `decisions` table per the #279 spec.
type BackupOptions struct {
	// IncludeAudit ships the decisions table rows in the backup file.
	// Default false — gbounce's decisions table is the dominant volume
	// (every forwarded request emits one row), so a default-on inclusion
	// would silently produce multi-GB backup files on a busy proxy.
	// Operators who want the audit history in the backup opt in
	// explicitly; the JSONL audit-log + log-rotation pipeline is the
	// canonical long-term audit channel.
	IncludeAudit bool

	// IncludePrompts is accepted as a documented no-op in G-Slice 1.
	// gbounce has no prompts subsystem yet; the flag exists for
	// cross-product CLI parity (kbounce + dbounce + ibounce ship it).
	// The metadata table records included_prompts=false unconditionally
	// in G-Slice 1; later G-Slices that add a prompts table will wire
	// the flag through.
	IncludePrompts bool

	// GbounceVersion is the version string the CLI stamps into the
	// metadata table. Captured at the CLI layer (the `version`
	// package-level var in internal/cli) + passed through here so the
	// store package stays version-free.
	GbounceVersion string

	// Hostname is the source-host identifier the metadata table
	// records — captured as the sha256[:12] of the actual hostname so
	// the backup file is auditable ("this came from production-leader-
	// 02") without leaking the literal hostname into a file the
	// operator may share for support purposes.
	Hostname string

	// Now is the timestamp the metadata table records as created_at.
	// Pluggable for deterministic tests; defaults to time.Now() when
	// zero.
	Now time.Time
}

// BackupMetadata is the in-memory shape of the gbounce_backup_metadata
// row. The Backup function returns it for caller convenience (the CLI
// prints the included flags + created_at + hostname-hash to the
// operator); Restore reads its persisted form from the source file.
type BackupMetadata struct {
	GbounceVersion     string
	CreatedAt          time.Time
	SourceHostnameHash string
	SchemaVersion      int
	IncludedAudit      bool
	IncludedPrompts    bool
}

// excludedTablesFor returns the list of tables to DELETE from the
// VACUUM-INTO output when the operator did NOT opt them in. Centralized
// here so the backup + restore paths agree on the "high volume" set.
//
// G-Slice 1: decisions is the only opt-out table. include-prompts is a
// documented no-op (no prompts table exists yet); the flag is still
// honored at the metadata layer so a later G-Slice that adds a prompts
// table can extend this function with one branch.
func excludedTablesFor(opt BackupOptions) []string {
	var out []string
	if !opt.IncludeAudit {
		out = append(out, "decisions")
	}
	// Future: if !opt.IncludePrompts { out = append(out, "prompts") }
	return out
}

// Backup writes an online SQLite backup of the live store to dstPath +
// returns the metadata embedded in the new file. The destination file
// is created with 0o600 (mirrors the source database's privacy
// posture) + parent directories are created with 0o700.
//
// The flow tolerates a non-empty parent directory but REFUSES to
// overwrite an existing dstPath — the CLI is expected to pick a fresh
// timestamped filename per invocation, and silently clobbering an
// older backup would defeat the point of holding multiple snapshots.
func (s *Store) Backup(dstPath string, opt BackupOptions) (*BackupMetadata, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("gbounce: backup: store not open")
	}
	if dstPath == "" {
		return nil, errors.New("gbounce: backup: destination path required")
	}
	if _, err := os.Stat(dstPath); err == nil {
		return nil, fmt.Errorf("gbounce: backup: refusing to overwrite existing file %q", dstPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("gbounce: backup: stat %q: %w", dstPath, err)
	}
	if dir := filepath.Dir(dstPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("gbounce: backup: mkdir %q: %w", dir, err)
		}
	}

	// Resolve the metadata fields up-front so a Now-stamping change
	// during the VACUUM doesn't drift the persisted value.
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	meta := BackupMetadata{
		GbounceVersion:     opt.GbounceVersion,
		CreatedAt:          opt.Now.UTC(),
		SourceHostnameHash: hashHostname(opt.Hostname),
		SchemaVersion:      SchemaVersion,
		IncludedAudit:      opt.IncludeAudit,
		// G-Slice 1: IncludedPrompts is always false on disk because
		// there is no prompts table to ship. The CLI flag is accepted
		// for cross-product parity but does not affect the metadata
		// row; a later G-Slice will flip this to opt.IncludePrompts
		// once the prompts table exists.
		IncludedPrompts: false,
	}

	// Step 1: VACUUM INTO a temp path in the destination directory so
	// the atomic-rename at the end is on the same filesystem (cross-
	// filesystem rename would fall back to copy+unlink + lose the
	// atomicity).
	tmpPath := dstPath + ".tmp"
	// Defensive cleanup: a previous failed run may have left tmpPath.
	_ = os.Remove(tmpPath)

	// VACUUM INTO is a SQL statement bound to a connection. SQLite
	// serializes VACUUM internally; under a heavy concurrent writer
	// load on the source DB the operation can return SQLITE_BUSY
	// ("database is locked"). Retry with backoff so a concurrent
	// `gbounce run` workload doesn't break operator backups. Total
	// retry budget capped at ~2s so a genuinely-stuck VACUUM still
	// surfaces an actionable error.
	if err := vacuumIntoWithRetry(s.db, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("gbounce: backup: VACUUM INTO: %w", err)
	}

	// Step 2-5: open the freshly-vacuumed file as a second handle so we
	// can prune the opt-out tables + write the metadata table without
	// touching the source database.
	dst, err := sql.Open("sqlite",
		"file:"+tmpPath+
			"?_pragma=busy_timeout(5000)"+
			"&_pragma=synchronous(FULL)")
	if err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("gbounce: backup: open destination: %w", err)
	}
	defer dst.Close()
	dst.SetMaxOpenConns(1)

	excluded := excludedTablesFor(opt)
	for _, tbl := range excluded {
		// Use raw concatenation (tbl is from a fixed allowlist, not
		// user input) — modernc.org/sqlite does not parameterize
		// table-name positions.
		if _, err := dst.Exec("DELETE FROM " + tbl); err != nil {
			// Tolerate missing tables (a backup of an older schema
			// where the table didn't exist) — but surface any other
			// error so the operator sees the failure.
			if !isMissingTableErr(err) {
				_ = os.Remove(tmpPath)
				return nil, fmt.Errorf("gbounce: backup: prune %s: %w", tbl, err)
			}
		}
	}

	if err := writeBackupMetadata(dst, meta); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	// Step 4 (deferred to here so the metadata row gets the freed-page
	// reclamation benefit too): VACUUM to reclaim freed pages from the
	// pruned tables — without this the on-disk file is source-size
	// because SQLite marks pages free but doesn't shrink. VACUUM also
	// rebuilds the b-tree so the round-trip-byte-identical property
	// test holds.
	if _, err := dst.Exec(`VACUUM`); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("gbounce: backup: post-prune VACUUM: %w", err)
	}

	if err := dst.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("gbounce: backup: close destination: %w", err)
	}

	// Step 6: atomic rename to the final path + tighten perms.
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("gbounce: backup: rename to final: %w", err)
	}
	if err := os.Chmod(dstPath, 0o600); err != nil {
		return nil, fmt.Errorf("gbounce: backup: chmod %q: %w", dstPath, err)
	}
	return &meta, nil
}

// writeBackupMetadata creates the gbounce_backup_metadata table inside
// the destination database + inserts the single row. Schema is
// intentionally narrow so a future reader (a third-party tool or a
// sibling agent's restore code) can SELECT * without surprises.
func writeBackupMetadata(db *sql.DB, meta BackupMetadata) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + backupMetadataTable + ` (
		id INTEGER PRIMARY KEY,
		gbounce_version TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		source_hostname_hash TEXT NOT NULL DEFAULT '',
		schema_version INTEGER NOT NULL,
		included_audit INTEGER NOT NULL DEFAULT 0,
		included_prompts INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return fmt.Errorf("gbounce: backup: create metadata table: %w", err)
	}
	// Single-row design (id=1; UPSERT on conflict). Mirrors the
	// dbounce/kbounce metadata pattern.
	if _, err := db.Exec(
		`INSERT INTO `+backupMetadataTable+`(
			id, gbounce_version, created_at, source_hostname_hash,
			schema_version, included_audit, included_prompts
		) VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			gbounce_version=excluded.gbounce_version,
			created_at=excluded.created_at,
			source_hostname_hash=excluded.source_hostname_hash,
			schema_version=excluded.schema_version,
			included_audit=excluded.included_audit,
			included_prompts=excluded.included_prompts`,
		meta.GbounceVersion,
		meta.CreatedAt.Format(time.RFC3339),
		meta.SourceHostnameHash,
		meta.SchemaVersion,
		boolToInt(meta.IncludedAudit),
		boolToInt(meta.IncludedPrompts),
	); err != nil {
		return fmt.Errorf("gbounce: backup: write metadata row: %w", err)
	}
	return nil
}

// ReadBackupMetadata opens a backup file read-only + returns the
// embedded metadata row. Returns a friendly error when the file is a
// valid SQLite database but does NOT carry the metadata table — in
// which case the caller (Restore) refuses the file as "not a gbounce
// backup."
func ReadBackupMetadata(path string) (*BackupMetadata, error) {
	if path == "" {
		return nil, errors.New("gbounce: read backup metadata: path required")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("gbounce: read backup metadata: stat %q: %w", path, err)
	}
	db, err := sql.Open("sqlite",
		"file:"+path+
			"?mode=ro"+
			"&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("gbounce: read backup metadata: open %q: %w", path, err)
	}
	defer db.Close()

	// Existence check first so we can return a friendly "not a gbounce
	// backup file" error rather than a sqlite "no such table" error.
	var present int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
		backupMetadataTable,
	).Scan(&present); err != nil {
		return nil, fmt.Errorf("gbounce: read backup metadata: probe schema: %w", err)
	}
	if present == 0 {
		return nil, fmt.Errorf(
			"gbounce: read backup metadata: file %q is a SQLite database "+
				"but is missing the %s table — is this a gbounce backup file?",
			path, backupMetadataTable)
	}

	row := db.QueryRow(`SELECT
		gbounce_version, created_at, source_hostname_hash,
		schema_version, included_audit, included_prompts
		FROM ` + backupMetadataTable + ` WHERE id = 1`)
	var (
		meta        BackupMetadata
		createdStr  string
		includedAud int
		includedPrm int
	)
	if err := row.Scan(
		&meta.GbounceVersion, &createdStr, &meta.SourceHostnameHash,
		&meta.SchemaVersion, &includedAud, &includedPrm,
	); err != nil {
		return nil, fmt.Errorf("gbounce: read backup metadata: scan: %w", err)
	}
	if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
		meta.CreatedAt = t
	}
	meta.IncludedAudit = includedAud != 0
	meta.IncludedPrompts = includedPrm != 0
	return &meta, nil
}

// CountRowsByTable returns a map of table-name → row-count for every
// user-facing table the gbounce store ships. The gbounce_backup_metadata
// table is included so a reviewer can see "yes, the backup file has its
// provenance row." Hidden SQLite tables (sqlite_*) are skipped.
//
// Used by the CLI to print the post-restore row-count summary + by the
// tests to assert exclusion semantics. Pulls table names from
// sqlite_master so a future schema-version bump doesn't require
// updating a hand-maintained allowlist here.
func CountRowsByTable(path string) (map[string]int64, error) {
	db, err := sql.Open("sqlite",
		"file:"+path+
			"?mode=ro"+
			"&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("gbounce: count rows: open %q: %w", path, err)
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table'
		 AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("gbounce: count rows: list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("gbounce: count rows: scan table name: %w", err)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("gbounce: count rows: iterate tables: %w", err)
	}
	_ = rows.Close()

	out := make(map[string]int64, len(tables))
	for _, t := range tables {
		var n int64
		// Table name is from sqlite_master, not user input.
		if err := db.QueryRow("SELECT COUNT(*) FROM " + t).Scan(&n); err != nil {
			return nil, fmt.Errorf("gbounce: count rows: count %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// FileSHA256 returns the hex sha256 of the file at path. Used by the
// CLI to print a fingerprint of the restored database so the operator
// can pin "this is the file I want" in their change-management log.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("gbounce: sha256: open %q: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("gbounce: sha256: read %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashHostname returns the sha256[:12] hex digest of the input
// hostname. Per the #279 spec: source-host attribution without leaking
// the literal hostname into a file the operator may share.
func hashHostname(hostname string) string {
	if hostname == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(sum[:])[:12]
}

// boolToInt is the standard 0/1 SQLite-friendly bool encoding. Kept
// here (rather than in store.go) so the backup file is self-contained.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// vacuumIntoWithRetry runs VACUUM INTO against dstPath with a small
// SQLITE_BUSY retry budget. modernc.org/sqlite surfaces lock contention
// as the literal string "database is locked"; the loop retries on that
// substring for up to ~2s total before bubbling the error.
//
// Why a retry rather than just bumping busy_timeout: VACUUM INTO opens
// a fresh transaction that isn't covered by the pool's per-connection
// busy_timeout pragma. The kbounce port of this code uses the same
// pattern + the same retry budget for cross-product parity.
func vacuumIntoWithRetry(db *sql.DB, dstPath string) error {
	const (
		maxAttempts = 20
		baseDelay   = 25 * time.Millisecond
	)
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		_, err := db.Exec(`VACUUM INTO ?`, dstPath)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isBusyErr(err) {
			return err
		}
		// SQLITE_BUSY → backoff + retry. Linear backoff (not
		// exponential) keeps the worst-case wait bounded + matches the
		// kbounce reference. Total budget ≈ 20 * 25ms = 500ms baseline
		// before counting the busy-timeout pragma's own waits, which
		// adds up to the ~2s real-world ceiling.
		_ = os.Remove(dstPath) // VACUUM INTO leaves a zero-byte file on busy
		time.Sleep(baseDelay)
	}
	return fmt.Errorf("busy-retry exhausted after %d attempts: %w",
		maxAttempts, lastErr)
}

// isBusyErr returns true when err is the modernc.org/sqlite "database
// is locked" / SQLITE_BUSY error.
func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") ||
		strings.Contains(s, "SQLITE_BUSY")
}

// isMissingTableErr is true when err is the modernc.org/sqlite "no such
// table" error. Defensive: a backup of a pre-v1 database wouldn't have
// a given table; the prune step must tolerate that.
func isMissingTableErr(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite surfaces the error as a wrapped string;
	// substring match is the standard pattern in this codebase.
	return strings.Contains(err.Error(), "no such table")
}

// SortedTableNames returns the sorted user-table list a Backup file
// carries — useful for the CLI's verbose summary output. Pulled from
// sqlite_master so a future schema-bump table is included
// automatically.
func SortedTableNames(path string) ([]string, error) {
	counts, err := CountRowsByTable(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// MarshalMetadataJSON returns a deterministic JSON encoding of the
// BackupMetadata struct. Used by the CLI to project the metadata into
// the admin-action OCSF event details field so a SIEM rule can pivot
// on a single key.
func MarshalMetadataJSON(m *BackupMetadata) ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	return json.Marshal(map[string]any{
		"gbounce_version":      m.GbounceVersion,
		"created_at":           m.CreatedAt.UTC().Format(time.RFC3339),
		"source_hostname_hash": m.SourceHostnameHash,
		"schema_version":       m.SchemaVersion,
		"included_audit":       m.IncludedAudit,
		"included_prompts":     m.IncludedPrompts,
	})
}
