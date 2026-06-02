// Package cli — regression tests for the #319 / §A17 closures on the
// `gbounce logs` subcommands.
//
// F-311-1: `gbounce logs archive` produced empty tar.gz for non-`audit*`
//          filenames. Closed by surfacing a loud error when zero
//          audit-shaped files match in the target directory.
// F-311-2: `gbounce logs verify` reported OK when files_checked == 0.
//          Closed by flipping OK=false + returning a non-zero exit when
//          the directory has zero audit-shaped files.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trsreagan3/gbounce/internal/audit"
)

// stampChainToFile builds an N-event hash-chain via the audit package's
// StampJSON (the same code path the live writer uses) and writes the
// canonical rows to audit.jsonl in dir. Returns the file path.
func stampChainToFile(t *testing.T, dir string, n int) string {
	t.Helper()
	chain := audit.LoadChainState(dir, 0)
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		ev := map[string]any{
			"class_uid":     6003,
			"activity_name": "Read",
			"time":          1700000000000 + i,
			"unmapped":      map[string]any{"iam_jit": map[string]any{"i": i}},
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		stamped, err := chain.StampJSON(raw)
		if err != nil {
			t.Fatalf("stamp %d: %v", i, err)
		}
		buf.Write(stamped)
		buf.WriteByte('\n')
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLogsVerifyChain_Clean asserts the verify-chain command reports a
// clean chain (zero exit, "chain OK") for an untampered log.
func TestLogsVerifyChain_Clean(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 4)

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-chain on a clean log must succeed; got err=%v out=%q", err, buf.String())
	}
	if !strings.Contains(buf.String(), "chain OK:") {
		t.Errorf("expected 'chain OK:' summary; got: %q", buf.String())
	}
}

// TestLogsVerifyChain_TamperDetected is the load-bearing tamper test:
// edit one row's payload in place, then assert the command reports a
// hash-mismatch break AND exits non-zero — the property an
// incident-response runbook depends on per [[ibounce-honest-positioning]].
func TestLogsVerifyChain_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 4)

	// Tamper: flip a value inside the middle row's payload WITHOUT
	// recomputing its chain hash. The stored hash no longer matches the
	// recomputed hash over the edited payload.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected 4 rows, got %d", len(lines))
	}
	// Row index 2 (seq=2): change activity_name Read -> Delete.
	tampered := strings.Replace(lines[2], `"activity_name":"Read"`, `"activity_name":"Delete"`, 1)
	if tampered == lines[2] {
		t.Fatalf("tamper substitution did not change the row; row=%q", lines[2])
	}
	lines[2] = tampered
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	err = root.Execute()
	if err == nil {
		t.Fatalf("verify-chain MUST return a non-zero (error) result on a tampered log; got out=%q", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "TAMPER DETECTED") {
		t.Errorf("expected 'TAMPER DETECTED' in output; got: %q", out)
	}
	if !strings.Contains(out, "hash mismatch") {
		t.Errorf("expected the hash-mismatch reason naming the edited row; got: %q", out)
	}
	if !strings.Contains(out, "seq=2") {
		t.Errorf("expected the break to be reported at seq=2 (the edited row); got: %q", out)
	}
}

// TestLogsArchive_EmptyDir_ErrorsLoudly pins F-311-1: passing
// --audit-log to a directory that contains zero audit-shaped files
// MUST surface a clear error naming the offending dir + the filename
// pattern. Silent empty-tar.gz output is the bug.
func TestLogsArchive_EmptyDir_ErrorsLoudly(t *testing.T) {
	dir := t.TempDir()
	// Populate the dir with a non-conforming filename (the bug:
	// archiver silently skipped it + produced ~50-byte empty tar.gz).
	if err := os.WriteFile(filepath.Join(dir, "proxy.jsonl"), []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")

	root := newRootCmd()
	root.SetArgs([]string{"logs", "archive", "--audit-log", filepath.Join(dir, "proxy.jsonl"), "--out", out})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected error (F-311-1 regression: zero-audit-files must surface a clear error). got: out=%q", buf.String())
	}
	if !strings.Contains(err.Error(), "no audit-shaped files matched") {
		t.Errorf("error message must name the actual failure mode; got: %q", err.Error())
	}
}

// TestLogsVerify_EmptyDir_ReportsFailure pins F-311-2: a verify run
// against a dir with zero audit files MUST return non-zero + an
// error naming the dir, not silently report OK.
func TestLogsVerify_EmptyDir_ReportsFailure(t *testing.T) {
	dir := t.TempDir()
	// Empty dir: writer never started + the operator runs verify.
	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify", "--audit-log", filepath.Join(dir, "audit.jsonl")})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected error (F-311-2 regression: zero-files MUST report failure, not 'OK'). stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
	if !strings.Contains(err.Error(), "verify: 0 audit files") {
		t.Errorf("error message must name the underlying zero-files case; got: %q", err.Error())
	}
	// The stdout SHOULD also surface the explanation so the operator
	// sees the three likely root causes from the terminal.
	if !strings.Contains(stdout.String(), "writer never started") {
		t.Errorf("stdout must hint at root causes (writer never started / wrong dir / sibling path); got: %q", stdout.String())
	}
}

// TestDoctorHelp_ListsLogsSubcommand pins F-304-3: `gbounce doctor
// --help` MUST list both `caveats` AND `logs` subcommands so an
// operator scanning the help output sees the integrity-check entry
// point. The bug was Long help listing only caveats even though
// `doctor logs` was wired + functional.
func TestDoctorHelp_ListsLogsSubcommand(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"doctor", "--help"})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("doctor --help failed: %v", err)
	}
	output := buf.String()
	for _, want := range []string{"caveats", "logs"} {
		if !strings.Contains(output, want) {
			t.Errorf("doctor --help missing subcommand %q in output:\n%s", want, output)
		}
	}
}

// TestRunCmd_RegistersRotationFlags pins F-311-4: `gbounce run` MUST
// surface the cross-product rotation trio + the env-var override
// shape so the LOG-RETENTION.md contract holds.
func TestRunCmd_RegistersRotationFlags(t *testing.T) {
	cmd := newRunCmd()
	flags := cmd.Flags()
	for _, name := range []string{
		"audit-log-max-size-mb",
		"audit-log-max-age-days",
		"audit-db-retention-days",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("--%s flag must be registered on `gbounce run` (F-311-4 regression)", name)
		}
	}
}

// TestLogsVerifyChain_FileScoped_IgnoresSiblings is the load-bearing
// regression test for the dir-scoped sibling-glob bug: when
// --audit-log points at a specific .jsonl file, the verifier MUST
// inspect ONLY that file and ignore unrelated *.jsonl siblings in the
// same directory. Before the fix, siblings with missing chain blocks
// (e.g. a plain audit log that was never stamped, or an old rotated
// file from a different chain) caused a false TAMPER DETECTED exit 1.
func TestLogsVerifyChain_FileScoped_IgnoresSiblings(t *testing.T) {
	dir := t.TempDir()

	// Write a clean 4-event chain into the TARGET file.
	targetPath := stampChainToFile(t, dir, 4)

	// Write a sibling that looks like an audit log but has NO chain
	// blocks — exactly the shape that caused the false positive before
	// the fix. Naming it "passA-audit.jsonl" to mirror the live repro.
	sibling := filepath.Join(dir, "passA-audit.jsonl")
	unstamped := `{"class_uid":6003,"activity_name":"Read","time":1700001234000}` + "\n"
	if err := os.WriteFile(sibling, []byte(unstamped), 0o600); err != nil {
		t.Fatalf("WriteFile sibling: %v", err)
	}

	// Pointing at the target file must succeed (chain OK) even though
	// the sibling in the same dir would have caused TAMPER DETECTED.
	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", targetPath})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf(
			"verify-chain with a clean target MUST succeed even when unrelated "+
				"siblings exist in the same dir (sibling-glob regression). "+
				"got err=%v out=%q", err, buf.String())
	}
	if !strings.Contains(buf.String(), "chain OK:") {
		t.Errorf("expected 'chain OK:' in output; got: %q", buf.String())
	}
}

// TestLogsVerifyChain_FileScoped_TamperInTargetStillDetected ensures that
// file-scoped mode still catches a real tamper in the named file —
// ignoring siblings must NOT also ignore real evidence in the target.
func TestLogsVerifyChain_FileScoped_TamperInTargetStillDetected(t *testing.T) {
	dir := t.TempDir()
	targetPath := stampChainToFile(t, dir, 4)

	// A clean sibling that must be ignored.
	sibling := filepath.Join(dir, "clean-sibling.jsonl")
	if err := os.WriteFile(sibling, []byte(`{"class_uid":6003,"time":1700000000001}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile sibling: %v", err)
	}

	// Tamper the target: flip activity_name in row index 1 without
	// recomputing its chain hash — the canonical tamper pattern.
	raw, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected 4 rows, got %d", len(lines))
	}
	lines[1] = strings.Replace(lines[1], `"activity_name":"Read"`, `"activity_name":"Delete"`, 1)
	if err := os.WriteFile(targetPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", targetPath})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	err = root.Execute()
	if err == nil {
		t.Fatalf("verify-chain MUST detect tamper in the named file and exit non-zero; got out=%q", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "TAMPER DETECTED") {
		t.Errorf("expected 'TAMPER DETECTED' in output; got: %q", out)
	}
	if !strings.Contains(out, "hash mismatch") {
		t.Errorf("expected the hash-mismatch reason in output; got: %q", out)
	}
}
