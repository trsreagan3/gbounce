// Tests for the #279 SQLite restore helper (gbounce-side).
//
// Coverage:
//   - restore into empty DB succeeds + post-restore row counts match
//   - restore into non-empty DB without --force fails (ErrDestinationNotEmpty)
//   - restore with --force into non-empty DB succeeds + replaces content
//   - restore with mismatched schema_version fails (even with --force)
//   - restore with mismatched gbounce_version warns + succeeds with --force
//   - restore with running-process probe hitting an alive port refuses
//   - restore from a non-backup file refuses with a friendly error
//   - restore from a missing source file refuses with a clear error
//   - post-restore schema_version row stamped + migrate is idempotent

package store

import (
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// backupFromFresh writes a fresh seeded backup file + returns the
// path. Helper for the restore-side tests so they don't repeat the
// open + seed + Backup boilerplate.
func backupFromFresh(t *testing.T, opts BackupOptions) string {
	t.Helper()
	src, _ := openSeeded(t, 4)
	defer src.Close()

	dir := t.TempDir()
	backup := filepath.Join(dir, "snapshot.db")
	if opts.GbounceVersion == "" {
		opts.GbounceVersion = "v1.0.0-test"
	}
	// Backup with --include-audit so the round-trip has decision rows
	// to verify against (the default backup is empty of decisions).
	opts.IncludeAudit = true
	if _, err := src.Backup(backup, opts); err != nil {
		t.Fatalf("backupFromFresh.Backup: %v", err)
	}
	return backup
}

func TestRestore_IntoEmptyDestinationSucceeds(t *testing.T) {
	backup := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	result, warn, err := Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{}, // skip probe
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if warn != nil {
		t.Errorf("unexpected version warning: %s", warn.String())
	}
	if result == nil {
		t.Fatal("Restore returned nil result")
	}
	if result.SHA256 == "" {
		t.Error("result.SHA256 MUST be populated")
	}
	if got := result.RowCounts["decisions"]; got != 4 {
		t.Errorf("decisions count after restore = %d; want 4", got)
	}
}

func TestRestore_IntoPopulatedDestinationRefusesWithoutForce(t *testing.T) {
	backup := backupFromFresh(t, BackupOptions{})

	// Populate the destination by Opening a Store + closing it: the
	// schema_version row is config-bearing so its presence alone trips
	// the gate (the operator's "fresh install + 1 request" case stays
	// friction-free because decisions is NOT config-bearing — but
	// schema_version IS).
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	st, err := Open(dst)
	if err != nil {
		t.Fatalf("Open dst: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close dst: %v", err)
	}

	_, _, err = Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	if err == nil {
		t.Fatal("Restore MUST refuse a populated destination without --force")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("error MUST mention not-empty; got %q", err.Error())
	}
}

func TestRestore_IntoPopulatedDestinationWithForceReplacesContent(t *testing.T) {
	backup := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	// Pre-populate the destination with a decision row that should be
	// wiped by the restore.
	pre, err := Open(dst)
	if err != nil {
		t.Fatalf("Open pre: %v", err)
	}
	if _, err := pre.RecordDecision(DecisionRow{
		Method: "POST", Path: "/pre-restore", UpstreamHost: "pre.example",
	}); err != nil {
		t.Fatalf("RecordDecision pre: %v", err)
	}
	if err := pre.Close(); err != nil {
		t.Fatalf("Close pre: %v", err)
	}

	result, _, err := Restore(backup, dst, RestoreOptions{
		Force:          true,
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	if err != nil {
		t.Fatalf("Restore --force: %v", err)
	}
	if result == nil {
		t.Fatal("Restore returned nil result")
	}

	// After restore: the pre-restore decision row is gone; the backup's
	// seeded rows are present.
	restored, err := Open(dst)
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer restored.Close()
	rows, err := restored.RecentDecisions(50)
	if err != nil {
		t.Fatalf("RecentDecisions: %v", err)
	}
	for _, r := range rows {
		if r.Path == "/pre-restore" {
			t.Errorf("restore --force MUST replace pre-restore content; found %+v", r)
		}
	}
	foundSeed := false
	for _, r := range rows {
		if r.Path == "/seed" {
			foundSeed = true
			break
		}
	}
	if !foundSeed {
		t.Error("restore MUST install the backup's seeded decisions")
	}
}

func TestRestore_SchemaVersionMismatchRefused(t *testing.T) {
	// Build a "backup" with the metadata table claiming a schema_version
	// that does NOT match the running binary.
	backup := backupFromFresh(t, BackupOptions{})

	// Open the backup file directly + overwrite the schema_version row
	// to simulate a cross-schema backup.
	db, err := sql.Open("sqlite",
		"file:"+backup+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE `+backupMetadataTable+` SET schema_version = ?`,
		SchemaVersion+1); err != nil {
		t.Fatalf("UPDATE metadata: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err = Restore(backup, dst, RestoreOptions{
		Force:          true, // even with force
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	if err == nil {
		t.Fatal("schema_version mismatch MUST refuse even with --force")
	}
	if !strings.Contains(err.Error(), "schema_version mismatch") {
		t.Errorf("error MUST surface schema_version mismatch; got %q", err.Error())
	}
}

func TestRestore_GbounceVersionMismatchWarnsAndRequiresForce(t *testing.T) {
	backup := backupFromFresh(t, BackupOptions{
		GbounceVersion: "v1.0.0-test",
	})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")

	// First attempt WITHOUT --force: surfaces the warning + errors.
	_, warn, err := Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.1.0-test", // mismatch
		ProbePorts:     []HostPort{},
	})
	if err == nil {
		t.Fatal("version mismatch without --force MUST refuse")
	}
	if warn == nil {
		t.Fatal("warning MUST be populated on version mismatch")
	}
	if warn.BackupVersion != "v1.0.0-test" || warn.RunningVersion != "v1.1.0-test" {
		t.Errorf("warning fields = %+v", warn)
	}
	if !strings.Contains(err.Error(), "gbounce_version mismatch") {
		t.Errorf("error MUST mention gbounce_version mismatch; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error MUST mention --force as the override; got %q", err.Error())
	}

	// Second attempt WITH --force: warning surfaces + restore succeeds.
	dst2 := filepath.Join(dir, "dst2.db")
	result, warn2, err := Restore(backup, dst2, RestoreOptions{
		Force:          true,
		GbounceVersion: "v1.1.0-test",
		ProbePorts:     []HostPort{},
	})
	if err != nil {
		t.Fatalf("Restore --force version-mismatch: %v", err)
	}
	if result == nil {
		t.Fatal("Restore --force returned nil result")
	}
	if warn2 == nil {
		t.Fatal("warning MUST also surface on --force path")
	}
	if !strings.Contains(warn2.String(), "v1.0.0-test") ||
		!strings.Contains(warn2.String(), "v1.1.0-test") {
		t.Errorf("warning string MUST name both versions; got %q", warn2.String())
	}
}

func TestRestore_RunningProcessProbeRefuses(t *testing.T) {
	backup := backupFromFresh(t, BackupOptions{})

	// Start a real listener on a random port + tell Restore to probe it.
	// Simulates "gbounce run is already up" without depending on the
	// real default ports being available in the test env.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err = Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{{Host: "127.0.0.1", Port: port}},
		ProbeTimeout:   500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("running-process probe MUST refuse when port is alive")
	}
	if !strings.Contains(err.Error(), "running") {
		t.Errorf("error MUST mention running; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", port)) {
		t.Errorf("error MUST name the port the probe hit (%d); got %q", port, err.Error())
	}
	if !strings.Contains(err.Error(), "stop") && !strings.Contains(err.Error(), "Stop") {
		t.Errorf("error MUST tell the operator to stop gbounce first; got %q", err.Error())
	}
}

func TestRestore_RunningProcessProbeSkippedWhenPortListEmpty(t *testing.T) {
	// Empty (non-nil) ProbePorts skips the probe entirely. nil ProbePorts
	// triggers the default-loopback set; tests that need to skip pass
	// []HostPort{} explicitly.
	backup := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	if _, _, err := Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	}); err != nil {
		t.Fatalf("Restore with empty probe list: %v", err)
	}
}

func TestRestore_SourceNotABackupFileRefused(t *testing.T) {
	// A valid SQLite database that lacks the metadata table is refused
	// with a friendly "is this a gbounce backup file?" error.
	dir := t.TempDir()
	notABackup := filepath.Join(dir, "unrelated.db")
	db, err := sql.Open("sqlite",
		"file:"+notABackup+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE other (x INTEGER)`); err != nil {
		t.Fatalf("create other: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dst := filepath.Join(dir, "dst.db")
	_, _, err = Restore(notABackup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	if err == nil {
		t.Fatal("Restore MUST refuse a non-backup source file")
	}
	if !strings.Contains(err.Error(), backupMetadataTable) {
		t.Errorf("error MUST name the missing metadata table; got %q", err.Error())
	}
}

func TestRestore_SourceFileMissingRefused(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err := Restore(filepath.Join(dir, "nope.db"), dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	if err == nil {
		t.Fatal("Restore MUST refuse a missing source file")
	}
	if !strings.Contains(err.Error(), "source") {
		t.Errorf("error MUST mention source; got %q", err.Error())
	}
}

func TestRestore_PostRestoreSchemaVersionStamped(t *testing.T) {
	// After restore, opening the destination via Store.Open MUST
	// succeed + the schema_version row MUST be present (the migrate
	// path is idempotent + survives the restore's wholesale file
	// replacement).
	backup := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	if _, _, err := Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	st, err := Open(dst)
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer st.Close()

	var v int
	if err := st.db.QueryRow(
		`SELECT version FROM schema_version LIMIT 1`).Scan(&v); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if v != SchemaVersion {
		t.Errorf("post-restore schema_version = %d; want %d", v, SchemaVersion)
	}
}

func TestRestore_FreshInstallWithSingleDecisionStillCountsEmpty(t *testing.T) {
	// Gate-policy guard: a fresh install that has served exactly one
	// request has a decisions row but ZERO config-bearing rows other
	// than schema_version itself. The destination has the schema_version
	// row from migrate(); the empty-DB gate trips on that (correctly —
	// the operator should pass --force to overwrite). Verify the gate
	// message references --force so the operator's next move is clear.
	backup := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	st, err := Open(dst)
	if err != nil {
		t.Fatalf("Open dst: %v", err)
	}
	if _, err := st.RecordDecision(DecisionRow{
		Method: "GET", Path: "/", UpstreamHost: "x",
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, _, err = Restore(backup, dst, RestoreOptions{
		GbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	if err == nil {
		t.Fatal("Restore MUST trip the empty-DB gate when schema_version is stamped")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error MUST mention --force as the override; got %q", err.Error())
	}
}
