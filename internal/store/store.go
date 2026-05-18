// Package store wraps a local SQLite database used by gbounce for
// decision audit logging.
//
// The schema is intentionally parallel to kbounce/dbounce so a future
// cross-product audit-log scraper can join across all four databases
// without translation.
//
// G-Slice 1 ships the minimum needed for the discovery-mode proxy:
//   - decisions table: one row per forwarded request
//   - schema_version table: monotonic migration tracker
//
// Profile / tap / pause / pending_prompts tables are deliberately not
// scaffolded yet — they arrive with their respective slices so the
// initial migration stays small. Schema is forward-additive.
//
// Driver: modernc.org/sqlite (pure Go; no CGO). A single binary builds
// cleanly for every platform.
//
// Path: defaults to ~/.gbounce/state.db. Override with the GBOUNCE_DB
// env var or by passing an explicit path to Open. Distinct from the
// kbounce/dbounce/ibounce DB paths so the products don't share file
// locks.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is bumped whenever the on-disk schema changes.
// Migrations are additive only (CREATE TABLE IF NOT EXISTS + ALTER
// TABLE ADD COLUMN); no destructive changes once we ship v1.
//
// Version log:
//
//	1 — initial: decisions table (G-Slice 1)
const SchemaVersion = 1

// DefaultDBPath returns the path the store opens when no explicit
// path is supplied. Honors GBOUNCE_DB for tests and CI sandboxes that
// want a scratch location.
func DefaultDBPath() (string, error) {
	if override := os.Getenv("GBOUNCE_DB"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("gbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".gbounce", "state.db"), nil
}

// Store wraps a sql.DB plus the migration state. Safe for concurrent
// use from multiple goroutines (sql.DB handles its own pooling).
type Store struct {
	db   *sql.DB
	path string
}

// Open initializes (creating if needed) the SQLite database at path.
// If path is "", DefaultDBPath() is consulted. Parent directories are
// created with 0o700 to keep the audit log private to the user.
func Open(path string) (*Store, error) {
	if path == "" {
		p, err := DefaultDBPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("gbounce: mkdir %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("gbounce: sql.Open: %w", err)
	}
	db.SetMaxOpenConns(4)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk path of the SQLite file.
func (s *Store) Path() string { return s.path }

// migrate runs the additive schema for the current SchemaVersion.
// Idempotent on re-open.
func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY
		)`,
		// decisions: one row per forwarded HTTP request. Columns chosen
		// to support both the audit-log shape (method/path/upstream/
		// http_status/response_size/latency_ms) and a future profile-
		// mode decision_verdict field (added in G-Slice 2 via ALTER TABLE
		// ADD COLUMN).
		`CREATE TABLE IF NOT EXISTS decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			upstream_host TEXT NOT NULL,
			upstream_port INTEGER NOT NULL DEFAULT 0,
			upstream_scheme TEXT NOT NULL DEFAULT '',
			client_host TEXT NOT NULL DEFAULT '',
			client_port INTEGER NOT NULL DEFAULT 0,
			http_status INTEGER NOT NULL DEFAULT 0,
			response_size INTEGER NOT NULL DEFAULT 0,
			latency_ms INTEGER NOT NULL DEFAULT 0,
			decision_verdict TEXT NOT NULL DEFAULT 'ALLOW',
			mode_at_decision TEXT NOT NULL DEFAULT 'discovery',
			enforced INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_at ON decisions(at)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_upstream_host ON decisions(upstream_host)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("gbounce: migrate: %w (stmt=%q)", err, q)
		}
	}

	// Stamp the schema version. INSERT-or-UPDATE pattern keeps it
	// idempotent on re-open.
	var ver int
	row := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`)
	switch err := row.Scan(&ver); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (?)`, SchemaVersion); err != nil {
			return fmt.Errorf("gbounce: stamp schema_version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("gbounce: read schema_version: %w", err)
	default:
		if ver < SchemaVersion {
			if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, SchemaVersion); err != nil {
				return fmt.Errorf("gbounce: bump schema_version: %w", err)
			}
		}
	}
	return nil
}

// DecisionRow is the input to RecordDecision. Plain struct (no proxy
// import) to keep the package boundary clean.
type DecisionRow struct {
	At             time.Time
	Method         string
	Path           string
	UpstreamHost   string
	UpstreamPort   int
	UpstreamScheme string
	ClientHost     string
	ClientPort     int
	HTTPStatus     int
	ResponseSize   int64
	LatencyMS      int64
	Verdict        string
	Mode           string
	Enforced       bool
}

// RecordDecision appends one row to the decisions audit log and
// returns the assigned row id. Failures bubble to the caller; the
// proxy logs them and keeps serving — audit-write failure must not
// crash the proxy.
func (s *Store) RecordDecision(d DecisionRow) (int64, error) {
	atStr := d.At.UTC().Format("2006-01-02T15:04:05Z")
	if d.At.IsZero() {
		atStr = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	verdict := d.Verdict
	if verdict == "" {
		verdict = "ALLOW"
	}
	mode := d.Mode
	if mode == "" {
		mode = "discovery"
	}
	enforced := 0
	if d.Enforced {
		enforced = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO decisions(
			at, method, path,
			upstream_host, upstream_port, upstream_scheme,
			client_host, client_port,
			http_status, response_size, latency_ms,
			decision_verdict, mode_at_decision, enforced
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		atStr, d.Method, d.Path,
		d.UpstreamHost, d.UpstreamPort, d.UpstreamScheme,
		d.ClientHost, d.ClientPort,
		d.HTTPStatus, d.ResponseSize, d.LatencyMS,
		verdict, mode, enforced,
	)
	if err != nil {
		return 0, fmt.Errorf("gbounce: record decision: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("gbounce: last insert id: %w", err)
	}
	return id, nil
}

// CountDecisions returns the total decision rows recorded so far.
func (s *Store) CountDecisions() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&n); err != nil {
		return 0, fmt.Errorf("gbounce: count decisions: %w", err)
	}
	return n, nil
}

// RecentDecisions returns the N most recently recorded decisions,
// newest first. Used by `gbounce audit tail`. Pass 0 or a negative
// limit for the implicit default of 50; capped at 1000.
func (s *Store) RecentDecisions(limit int) ([]DecisionRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT
		at, method, path,
		upstream_host, upstream_port, upstream_scheme,
		client_host, client_port,
		http_status, response_size, latency_ms,
		decision_verdict, mode_at_decision, enforced
		FROM decisions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("gbounce: recent decisions query: %w", err)
	}
	defer rows.Close()
	out := make([]DecisionRow, 0, limit)
	for rows.Next() {
		var (
			d        DecisionRow
			atStr    string
			enforced int
		)
		if err := rows.Scan(
			&atStr, &d.Method, &d.Path,
			&d.UpstreamHost, &d.UpstreamPort, &d.UpstreamScheme,
			&d.ClientHost, &d.ClientPort,
			&d.HTTPStatus, &d.ResponseSize, &d.LatencyMS,
			&d.Verdict, &d.Mode, &enforced,
		); err != nil {
			return nil, fmt.Errorf("gbounce: recent decisions scan: %w", err)
		}
		if t, perr := time.Parse("2006-01-02T15:04:05Z", atStr); perr == nil {
			d.At = t
		}
		d.Enforced = enforced != 0
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gbounce: recent decisions iterate: %w", err)
	}
	return out, nil
}
