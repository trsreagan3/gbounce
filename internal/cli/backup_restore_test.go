// Tests for `gbounce backup` + `gbounce restore` CLI surfaces per #279.
//
// Coverage:
//   - root cobra command wires both subcommands
//   - backup writes a file at --out + prints summary lines
//   - backup default filename includes a UTC RFC3339-ish timestamp
//   - --include-prompts is accepted + surfaces the documented no-op note
//   - restore --in REQUIRED
//   - restore succeeds end-to-end from a backup of a populated DB
//   - restore refuses without --force when destination has rows
//   - restore refuses + names port on a running-process probe hit
//   - admin-action audit event is emitted on backup + restore (when
//     --audit-log-path is configured)

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trsreagan3/gbounce/internal/store"
)

func TestRootCmd_WiresBackupAndRestore(t *testing.T) {
	r := newRootCmd()
	subs := map[string]bool{}
	for _, c := range r.Commands() {
		subs[c.Name()] = true
	}
	if !subs["backup"] {
		t.Error("root cobra MUST wire `gbounce backup`")
	}
	if !subs["restore"] {
		t.Error("root cobra MUST wire `gbounce restore`")
	}
}

func seedCLIStore(t *testing.T, dbPath string, decisionCount int) {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open seed: %v", err)
	}
	defer st.Close()
	for i := 0; i < decisionCount; i++ {
		if _, err := st.RecordDecision(store.DecisionRow{
			Method:       "GET",
			Path:         fmt.Sprintf("/seed-%d", i),
			UpstreamHost: "api.example",
			HTTPStatus:   200,
		}); err != nil {
			t.Fatalf("RecordDecision[%d]: %v", i, err)
		}
	}
}

func TestBackupCmd_WritesFileAndPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	seedCLIStore(t, dbPath, 2)

	out := filepath.Join(dir, "backup.db")
	cmd := newBackupCmd()
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--out", out,
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute backup: %v", err)
	}

	if _, err := os.Stat(out); err != nil {
		t.Fatalf("backup file MUST exist on disk: %v", err)
	}

	s := stdout.String()
	for _, want := range []string{
		"wrote gbounce backup to",
		"schema_version=",
		"included_audit=false",
		"included_prompts=false",
		"tables:",
		"schema_version",
		"gbounce_backup_metadata",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout MUST contain %q; got:\n%s", want, s)
		}
	}
}

func TestBackupCmd_IncludeAuditShipsDecisionRows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	seedCLIStore(t, dbPath, 3)

	out := filepath.Join(dir, "with-audit.db")
	cmd := newBackupCmd()
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--out", out,
		"--include-audit",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute backup --include-audit: %v", err)
	}

	if !strings.Contains(stdout.String(), "included_audit=true") {
		t.Errorf("stdout MUST report included_audit=true; got %s", stdout.String())
	}
	counts, err := store.CountRowsByTable(out)
	if err != nil {
		t.Fatalf("CountRowsByTable: %v", err)
	}
	if got := counts["decisions"]; got != 3 {
		t.Errorf("backup MUST preserve decisions count under --include-audit; got %d, want 3", got)
	}
}

func TestBackupCmd_IncludePromptsAcceptedAsNoOp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	seedCLIStore(t, dbPath, 1)

	out := filepath.Join(dir, "with-prompts.db")
	cmd := newBackupCmd()
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--out", out,
		"--include-prompts",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute backup --include-prompts: %v", err)
	}
	// metadata still says included_prompts=false (no prompts table to ship)
	if !strings.Contains(stdout.String(), "included_prompts=false") {
		t.Errorf("stdout MUST report included_prompts=false in G-Slice 1; got %s", stdout.String())
	}
	// stderr carries the documented no-op note so an agent / operator
	// who passed the flag doesn't silently believe data shipped.
	if !strings.Contains(stderr.String(), "no-op") {
		t.Errorf("stderr MUST surface the no-op note; got %s", stderr.String())
	}
}

func TestBackupCmd_DefaultFilenameTimestamped(t *testing.T) {
	ts := defaultBackupFilename(false)
	if !strings.HasPrefix(ts, "gbounce-backup-") {
		t.Errorf("default filename MUST be gbounce-backup-<timestamp>.db; got %q", ts)
	}
	if !strings.HasSuffix(ts, ".db") {
		t.Errorf("default filename MUST end in .db; got %q", ts)
	}
	// Pin: no-timestamp shape stays stable for CI managers.
	if got := defaultBackupFilename(true); got != "gbounce-backup.db" {
		t.Errorf("no-timestamp filename = %q; want gbounce-backup.db", got)
	}
}

func TestRestoreCmd_RequiresInFlag(t *testing.T) {
	cmd := newRestoreCmd()
	cmd.SetArgs([]string{}) // no --in
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("restore MUST refuse without --in")
	}
	// Cobra's required-flag error pattern.
	if !strings.Contains(err.Error(), "in") {
		t.Errorf("error MUST mention --in; got %q", err.Error())
	}
}

func TestRestoreCmd_RoundTripFromBackup(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath, 5)

	// Backup via the CLI surface (exercises the same write path the
	// operator hits). Include audit so the round-trip has signal.
	backupOut := filepath.Join(dir, "backup.db")
	backup := newBackupCmd()
	backup.SetArgs([]string{
		"--db", srcPath,
		"--out", backupOut,
		"--include-audit",
	})
	var bOut, bErr bytes.Buffer
	backup.SetOut(&bOut)
	backup.SetErr(&bErr)
	if err := backup.Execute(); err != nil {
		t.Fatalf("Execute backup: %v", err)
	}

	// Restore into a fresh destination path.
	dst := filepath.Join(dir, "restored.db")
	restore := newRestoreCmd()
	restore.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-skip",
	})
	var rOut, rErr bytes.Buffer
	restore.SetOut(&rOut)
	restore.SetErr(&rErr)
	if err := restore.Execute(); err != nil {
		t.Fatalf("Execute restore: %v", err)
	}
	s := rOut.String()
	for _, want := range []string{
		"restored gbounce state.db from",
		"sha256:",
		"decisions",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("restore stdout MUST contain %q; got:\n%s", want, s)
		}
	}

	// Validate the restored DB carries the seeded decisions.
	st, err := store.Open(dst)
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer st.Close()
	n, err := st.CountDecisions()
	if err != nil {
		t.Fatalf("CountDecisions: %v", err)
	}
	if n != 5 {
		t.Errorf("restored decisions = %d; want 5", n)
	}
}

func TestRestoreCmd_RefusesPopulatedDestinationWithoutForce(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath, 1)

	backupOut := filepath.Join(dir, "backup.db")
	st, err := store.Open(srcPath)
	if err != nil {
		t.Fatalf("Open src: %v", err)
	}
	// Pin the backup's stamped version to whatever the test-binary's
	// package-level `version` is so the version-match gate doesn't
	// fire ahead of the gate we're actually exercising.
	if _, err := st.Backup(backupOut, store.BackupOptions{
		GbounceVersion: version,
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close src: %v", err)
	}

	// Populate the destination so the gate trips. Opening + closing a
	// Store stamps the schema_version row which is config-bearing.
	dst := filepath.Join(dir, "dst.db")
	dstSt, err := store.Open(dst)
	if err != nil {
		t.Fatalf("Open dst: %v", err)
	}
	if err := dstSt.Close(); err != nil {
		t.Fatalf("Close dst: %v", err)
	}

	cmd := newRestoreCmd()
	cmd.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-skip",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err = cmd.Execute()
	if err == nil {
		t.Fatal("restore MUST refuse a populated destination without --force")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("error MUST mention not-empty; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error MUST mention --force as the override; got %q", err.Error())
	}
}

func TestRestoreCmd_ProbePortRefusesWhenAlive(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath, 1)

	backupOut := filepath.Join(dir, "backup.db")
	st, err := store.Open(srcPath)
	if err != nil {
		t.Fatalf("Open src: %v", err)
	}
	if _, err := st.Backup(backupOut, store.BackupOptions{
		GbounceVersion: version,
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close src: %v", err)
	}

	// Open a random loopback port + point the probe at it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	dst := filepath.Join(dir, "dst.db")
	cmd := newRestoreCmd()
	cmd.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-port", fmt.Sprintf("%d", port),
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err = cmd.Execute()
	if err == nil {
		t.Fatal("restore MUST refuse when the probe finds a live port")
	}
	if !strings.Contains(err.Error(), "appears to be running") {
		t.Errorf("error MUST mention running; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", port)) {
		t.Errorf("error MUST name the port (%d) the probe hit; got %q", port, err.Error())
	}
	if !strings.Contains(err.Error(), "Stop") && !strings.Contains(err.Error(), "stop") {
		t.Errorf("error MUST tell the operator to stop gbounce first; got %q", err.Error())
	}
}

func TestBackupCmd_EmitsAdminActionEvent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	seedCLIStore(t, dbPath, 1)

	out := filepath.Join(dir, "backup.db")
	auditPath := filepath.Join(dir, "audit.jsonl")

	cmd := newBackupCmd()
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--out", out,
		"--audit-log-path", auditPath,
		"--actor", "alice",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute backup with audit-log-path: %v", err)
	}

	// Audit log file has at least one JSONL row carrying activity_name
	// = "backup.create".
	requireAdminActionEvent(t, auditPath, "backup.create", "alice")
}

func TestRestoreCmd_EmitsAdminActionEvent(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath, 1)

	backupOut := filepath.Join(dir, "backup.db")
	st, err := store.Open(srcPath)
	if err != nil {
		t.Fatalf("Open src: %v", err)
	}
	if _, err := st.Backup(backupOut, store.BackupOptions{
		GbounceVersion: version,
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close src: %v", err)
	}

	dst := filepath.Join(dir, "dst.db")
	auditPath := filepath.Join(dir, "audit.jsonl")
	cmd := newRestoreCmd()
	cmd.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-skip",
		"--audit-log-path", auditPath,
		"--actor", "bob",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute restore with audit-log-path: %v", err)
	}
	requireAdminActionEvent(t, auditPath, "backup.restore", "bob")
}

// requireAdminActionEvent scans the JSONL audit log + asserts at least
// one row carries activity_name=wantAction with the recorded actor
// matching wantActor (when non-empty).
func requireAdminActionEvent(t *testing.T, path, wantAction, wantActor string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log %q: %v", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	matched := false
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("invalid JSONL row: %v line=%s", err, scanner.Text())
			continue
		}
		if ev["activity_name"] != wantAction {
			continue
		}
		unmapped, _ := ev["unmapped"].(map[string]any)
		iam, _ := unmapped["iam_jit"].(map[string]any)
		ext, _ := iam["ext"].(map[string]any)
		cc, _ := ext["config_change"].(map[string]any)
		if wantActor != "" {
			if got, _ := cc["actor"].(string); got != wantActor {
				t.Errorf("activity_name=%q actor = %q; want %q",
					wantAction, got, wantActor)
				continue
			}
		}
		matched = true
		break
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	if !matched {
		t.Fatalf("no admin-action row with activity_name=%q found in %s",
			wantAction, path)
	}
}
