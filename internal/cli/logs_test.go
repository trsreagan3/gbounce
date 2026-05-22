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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
