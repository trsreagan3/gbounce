// Tests for the #279 SQLite backup helper (gbounce-side).
//
// Coverage:
//   - row counts match source minus excluded tables (default + opt-in)
//   - metadata fields populated correctly
//   - excluded tables empty in the output
//   - --include-audit preserves the decisions table data
//   - --include-prompts accepted as a documented no-op (no error)
//   - destination file is 0o600
//   - refuses to overwrite an existing destination
//   - backup runs concurrently with a write-heavy goroutine (online
//     backup property test)
//   - round-trip: backup → restore → backup again produces backups
//     whose USER-table row counts are identical (byte-equality is too
//     strict for sqlite's b-tree representation across two VACUUM
//     passes; we assert the per-table counts + the metadata roundtrip)

package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// seedSourceForBackup populates a Store with a representative mix of
// decision rows so the backup + restore assertions have signal.
func seedSourceForBackup(t *testing.T, s *Store, decisionCount int) {
	t.Helper()
	now := time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)
	for i := 0; i < decisionCount; i++ {
		if _, err := s.RecordDecision(DecisionRow{
			At:             now.Add(time.Duration(i) * time.Second),
			Method:         "GET",
			Path:           "/seed",
			UpstreamHost:   "api.example",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			ClientHost:     "127.0.0.1",
			ClientPort:     50000 + i,
			HTTPStatus:     200,
			ResponseSize:   42,
			LatencyMS:      10,
		}); err != nil {
			t.Fatalf("seed RecordDecision[%d]: %v", i, err)
		}
	}
}

// openSeeded is a one-liner helper that opens a fresh store in a temp
// dir + seeds it. Returns the opened Store + its on-disk path. The
// caller is responsible for Close().
func openSeeded(t *testing.T, decisionCount int) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "state.db")
	s, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seedSourceForBackup(t, s, decisionCount)
	return s, p
}

func TestBackup_DefaultExcludesDecisionsTable(t *testing.T) {
	src, _ := openSeeded(t, 5)
	defer src.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup.db")
	meta, err := src.Backup(dst, BackupOptions{
		GbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if meta == nil {
		t.Fatal("Backup returned nil meta")
	}

	counts, err := CountRowsByTable(dst)
	if err != nil {
		t.Fatalf("CountRowsByTable: %v", err)
	}

	// Default opt-out: decisions is the high-volume table; gbounce
	// EXCLUDES it by default so a busy proxy's backup stays small.
	if got := counts["decisions"]; got != 0 {
		t.Errorf("default backup MUST exclude decisions rows; got %d", got)
	}
	// Metadata table is present + carries exactly one row.
	if got := counts[backupMetadataTable]; got != 1 {
		t.Errorf("backup file MUST embed the metadata row; got %d", got)
	}
	// schema_version table preserved.
	if got := counts["schema_version"]; got != 1 {
		t.Errorf("schema_version row MUST survive the backup; got %d", got)
	}

	if meta.IncludedAudit {
		t.Error("IncludedAudit MUST be false on default backup")
	}
	if meta.IncludedPrompts {
		t.Error("IncludedPrompts MUST be false in G-Slice 1")
	}
	if meta.GbounceVersion != "v1.0.0-test" {
		t.Errorf("GbounceVersion = %q", meta.GbounceVersion)
	}
	if meta.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", meta.SchemaVersion, SchemaVersion)
	}
	if len(meta.SourceHostnameHash) != 12 {
		t.Errorf("source_hostname_hash MUST be sha256[:12]; got len=%d",
			len(meta.SourceHostnameHash))
	}
	if d := time.Since(meta.CreatedAt); d < 0 || d > 5*time.Second {
		t.Errorf("CreatedAt drift = %v", d)
	}
}

func TestBackup_IncludeAuditFlagShipsTheDecisionsTable(t *testing.T) {
	src, _ := openSeeded(t, 7)
	defer src.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup-with-audit.db")
	meta, err := src.Backup(dst, BackupOptions{
		IncludeAudit:   true,
		GbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if !meta.IncludedAudit {
		t.Error("IncludedAudit MUST be true when flag passed")
	}

	counts, err := CountRowsByTable(dst)
	if err != nil {
		t.Fatalf("CountRowsByTable: %v", err)
	}
	if got := counts["decisions"]; got != 7 {
		t.Errorf("--include-audit MUST preserve decisions rows; got %d, want 7", got)
	}
}

func TestBackup_IncludePromptsAcceptedAsNoOp(t *testing.T) {
	// G-Slice 1: gbounce has no prompts table. The flag is accepted
	// for cross-product CLI parity; backup MUST NOT error + the
	// metadata field stays false (no table to record).
	src, _ := openSeeded(t, 3)
	defer src.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup-prompts.db")
	meta, err := src.Backup(dst, BackupOptions{
		IncludePrompts: true,
		GbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	if err != nil {
		t.Fatalf("Backup with --include-prompts: %v", err)
	}
	if meta.IncludedPrompts {
		t.Error("IncludedPrompts MUST stay false in G-Slice 1 (no prompts table)")
	}
	// Sanity: no prompts table appeared on disk.
	counts, err := CountRowsByTable(dst)
	if err != nil {
		t.Fatalf("CountRowsByTable: %v", err)
	}
	if _, ok := counts["prompts"]; ok {
		t.Error("prompts table MUST NOT exist on disk in G-Slice 1")
	}
}

func TestBackup_DestinationFilePermissions(t *testing.T) {
	src, _ := openSeeded(t, 1)
	defer src.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup.db")
	if _, err := src.Backup(dst, BackupOptions{
		GbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("backup file MUST be 0o600 (mirrors source DB privacy); got %o", perm)
	}
}

func TestBackup_RefusesToOverwriteExistingFile(t *testing.T) {
	src, _ := openSeeded(t, 1)
	defer src.Close()

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup.db")
	// First backup succeeds.
	if _, err := src.Backup(dst, BackupOptions{GbounceVersion: "v1"}); err != nil {
		t.Fatalf("first Backup: %v", err)
	}
	// Second backup to the same path must refuse.
	_, err := src.Backup(dst, BackupOptions{GbounceVersion: "v1"})
	if err == nil {
		t.Fatal("second Backup MUST refuse to overwrite")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("error message MUST mention overwrite refusal; got %q", err.Error())
	}
}

func TestBackup_ConcurrentWritesDuringBackup(t *testing.T) {
	// Online-backup property test: while a backup is running, a parallel
	// goroutine hammers the source DB with writes. The backup MUST
	// complete + the source MUST contain all written rows after the
	// backup returns. We use --include-audit so the dst file has signal
	// to compare against.
	src, _ := openSeeded(t, 5)
	defer src.Close()

	stop := make(chan struct{})
	var written int64
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := src.RecordDecision(DecisionRow{
				At:             time.Now().UTC(),
				Method:         "GET",
				Path:           "/concurrent",
				UpstreamHost:   "api.example",
				UpstreamPort:   443,
				UpstreamScheme: "https",
				ClientHost:     "127.0.0.1",
				ClientPort:     60000 + (i % 5000),
				HTTPStatus:     200,
				ResponseSize:   1,
				LatencyMS:      1,
			}); err == nil {
				atomic.AddInt64(&written, 1)
			}
		}
	}()
	// Give the writer a moment to ramp up so the backup overlaps real
	// concurrent activity.
	time.Sleep(50 * time.Millisecond)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup-concurrent.db")
	if _, err := src.Backup(dst, BackupOptions{
		IncludeAudit:   true,
		GbounceVersion: "v1",
	}); err != nil {
		t.Fatalf("Backup during concurrent writes: %v", err)
	}

	close(stop)
	wg.Wait()

	// Backup completed; source still has at least the seeded rows + the
	// concurrent writes.
	srcCount, err := src.CountDecisions()
	if err != nil {
		t.Fatalf("CountDecisions: %v", err)
	}
	w := atomic.LoadInt64(&written)
	if min := int64(5) + w; srcCount < min {
		t.Errorf("source DB MUST contain seeded+concurrent rows; got %d, min %d",
			srcCount, min)
	}

	// Backup file's decisions count is a snapshot AT some point during
	// the run — bounded between the pre-backup count (5) and the
	// post-backup source count.
	dstCounts, err := CountRowsByTable(dst)
	if err != nil {
		t.Fatalf("CountRowsByTable: %v", err)
	}
	if got := dstCounts["decisions"]; got < 5 {
		t.Errorf("backup file MUST contain at least the seeded rows; got %d", got)
	}
	if got := dstCounts["decisions"]; got > srcCount {
		t.Errorf("backup file MUST NOT contain more rows than source ends with; got %d > %d",
			got, srcCount)
	}
}

func TestBackup_RoundTripPreservesRowCounts(t *testing.T) {
	// Round-trip property: backup → restore-into-fresh-db → backup
	// again. The second backup's per-table row counts MUST match the
	// first backup's per-table row counts (we don't assert byte-identity
	// because SQLite's b-tree pagination + VACUUM rebuild may legitimately
	// reshape the file even with identical logical content).
	src, _ := openSeeded(t, 4)
	defer src.Close()

	dir := t.TempDir()
	backup1 := filepath.Join(dir, "backup1.db")
	if _, err := src.Backup(backup1, BackupOptions{
		IncludeAudit:   true,
		GbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	}); err != nil {
		t.Fatalf("first Backup: %v", err)
	}

	// Restore backup1 onto a fresh destination path. Use ProbePorts:[]
	// to skip the running-process probe (this test environment may have
	// real services bound on the default ports).
	fresh := filepath.Join(dir, "restored.db")
	if _, _, err := Restore(backup1, fresh, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{}, // skip probe
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Re-open the restored DB + back IT up.
	restored, err := Open(fresh)
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer restored.Close()
	backup2 := filepath.Join(dir, "backup2.db")
	if _, err := restored.Backup(backup2, BackupOptions{
		IncludeAudit:   true,
		GbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	}); err != nil {
		t.Fatalf("second Backup: %v", err)
	}

	counts1, err := CountRowsByTable(backup1)
	if err != nil {
		t.Fatalf("CountRowsByTable backup1: %v", err)
	}
	counts2, err := CountRowsByTable(backup2)
	if err != nil {
		t.Fatalf("CountRowsByTable backup2: %v", err)
	}

	for table, count := range counts1 {
		if counts2[table] != count {
			t.Errorf("round-trip MUST preserve row count for table %s: backup1=%d backup2=%d",
				table, count, counts2[table])
		}
	}
	for table := range counts2 {
		if _, ok := counts1[table]; !ok {
			t.Errorf("round-trip MUST NOT add new tables; saw %s only in backup2", table)
		}
	}
}

func TestBackup_IncludeAuditRoundTripPreservesRows(t *testing.T) {
	// Targeted assertion: "Backup with --include-audit captures
	// decision rows; round-trip preserves them."
	src, _ := openSeeded(t, 3)
	defer src.Close()

	dir := t.TempDir()
	backup := filepath.Join(dir, "backup-audit.db")
	if _, err := src.Backup(backup, BackupOptions{
		IncludeAudit:   true,
		GbounceVersion: "v1",
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	dst := filepath.Join(dir, "restored.db")
	if _, _, err := Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1",
		ProbePorts:     []HostPort{}, // skip probe
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restored, err := Open(dst)
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer restored.Close()

	n, err := restored.CountDecisions()
	if err != nil {
		t.Fatalf("CountDecisions on restored: %v", err)
	}
	if n != 3 {
		t.Errorf("--include-audit round-trip MUST preserve decisions rows; got %d, want 3", n)
	}
}

func TestReadBackupMetadata_OnNonBackupFile(t *testing.T) {
	// A SQLite database that is NOT a gbounce backup file (no
	// gbounce_backup_metadata table) MUST return a friendly error
	// pointing at the missing table.
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.db")
	db, err := sql.Open("sqlite",
		"file:"+plain+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE unrelated (x INTEGER)`); err != nil {
		t.Fatalf("create unrelated: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = ReadBackupMetadata(plain)
	if err == nil {
		t.Fatal("ReadBackupMetadata MUST refuse a non-backup file")
	}
	if !strings.Contains(err.Error(), backupMetadataTable) {
		t.Errorf("error MUST name the missing metadata table; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "gbounce backup file") {
		t.Errorf("error MUST be product-friendly; got %q", err.Error())
	}
}

func TestHashHostname_DeterministicAndBounded(t *testing.T) {
	a := hashHostname("my-prod-host-01")
	b := hashHostname("my-prod-host-01")
	c := hashHostname("my-prod-host-02")
	if a != b {
		t.Errorf("hashHostname MUST be deterministic; %q != %q", a, b)
	}
	if a == c {
		t.Errorf("hashHostname MUST differ across inputs; %q == %q", a, c)
	}
	if len(a) != 12 {
		t.Errorf("hashHostname MUST be 12 hex chars; got %d", len(a))
	}
	if h := hashHostname(""); h != "" {
		t.Errorf("empty hostname → empty hash; got %q", h)
	}
}

func TestFileSHA256_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("hello gbounce"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	sum, err := FileSHA256(path)
	if err != nil {
		t.Fatalf("FileSHA256: %v", err)
	}
	// Pin: known sha256 of "hello gbounce" so the helper's correctness
	// doesn't drift silently.
	const want = "fec05a191a52d920db870bb0c1de3a15dd74a610bb9d13ce846b92fbaeb93822"
	if sum != want {
		t.Errorf("FileSHA256 = %q; want %q", sum, want)
	}
}

func TestMarshalMetadataJSON_RoundTrip(t *testing.T) {
	meta := &BackupMetadata{
		GbounceVersion:     "v1.0.0-test",
		CreatedAt:          time.Date(2026, 5, 18, 14, 30, 0, 0, time.UTC),
		SourceHostnameHash: "abc123def456",
		SchemaVersion:      SchemaVersion,
		IncludedAudit:      true,
		IncludedPrompts:    false,
	}
	b, err := MarshalMetadataJSON(meta)
	if err != nil {
		t.Fatalf("MarshalMetadataJSON: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"gbounce_version":"v1.0.0-test"`,
		`"source_hostname_hash":"abc123def456"`,
		`"included_audit":true`,
		`"included_prompts":false`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("MarshalMetadataJSON missing %q in %s", want, s)
		}
	}

	// nil receiver returns "null" so a caller can use the bytes without
	// nil-checks.
	if b, err := MarshalMetadataJSON(nil); err != nil || string(b) != "null" {
		t.Errorf("nil → null; got %q err=%v", string(b), err)
	}
}
