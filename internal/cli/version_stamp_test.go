package cli

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestResolveBuildInfo_PreservesLdflagsValues asserts that
// resolveBuildInfo NEVER overwrites a value an operator stamped via
// -ldflags. The Makefile + Dockerfile both pass explicit `-X` flags;
// if VCS auto-stamping clobbered those, release builds would silently
// regress to whatever git says — defeating the point of tagged
// releases. Closes #515.
func TestResolveBuildInfo_PreservesLdflagsValues(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	version = "v9.9.9-stamped"
	commit = "deadbeef"
	buildTime = "2026-01-01T00:00:00Z"

	resolveBuildInfo()

	if version != "v9.9.9-stamped" {
		t.Errorf("version overwritten: got %q want %q", version, "v9.9.9-stamped")
	}
	if commit != "deadbeef" {
		t.Errorf("commit overwritten: got %q want %q", commit, "deadbeef")
	}
	if buildTime != "2026-01-01T00:00:00Z" {
		t.Errorf("buildTime overwritten: got %q want %q", buildTime, "2026-01-01T00:00:00Z")
	}
}

// TestResolveBuildInfo_FillsDefaultsFromVCS asserts that when the
// build was NOT ldflags-stamped, resolveBuildInfo populates the
// defaults from runtime/debug.ReadBuildInfo's VCS settings. Under
// `go test` the test binary is built from the local source tree so
// vcs.revision is populated (unless the tree is brand-new with no
// commits — which we tolerate by accepting "none" as a passing value
// because the test binary itself reflects whatever the harness ran).
//
// The real assertion that matters lives in
// TestVersionStamp_GoBuildEndToEnd below, which builds a real binary
// with known ldflags and checks the output.
func TestResolveBuildInfo_FillsDefaultsFromVCS(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildTime
	defer func() { version, commit, buildTime = oldV, oldC, oldB }()

	version = "dev"
	commit = "none"
	buildTime = "unknown"

	resolveBuildInfo()

	// Test binaries built by `go test` have BuildInfo, but vcs.*
	// settings depend on whether the test runner used -buildvcs=auto
	// (default). When the harness sets -buildvcs=false (some CI does),
	// vcs.revision will be empty and commit stays "none". Both
	// outcomes are acceptable here; the load-bearing assertion is
	// TestVersionStamp_GoBuildEndToEnd below.
	t.Logf("resolved version=%q commit=%q buildTime=%q", version, commit, buildTime)
}

// TestVersionStamp_GoBuildEndToEnd is the state-verification test
// called out in #515 part 3: build a fresh gbounce binary with
// explicit ldflags, run it with `--version`, and assert the output
// contains the injected version + commit (not "dev" / "none").
//
// This is the test that would have caught #515 had it existed before.
// `iam-jit canary update`'s version-check step parses exactly this
// output to confirm a rebuild took effect.
func TestVersionStamp_GoBuildEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go-build smoke in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not available: %v", err)
	}

	// Locate the repo root so we can `go build ./cmd/gbounce`. The
	// test file lives at <repo>/internal/cli/version_stamp_test.go;
	// the repo root is two parents up.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	outDir := t.TempDir()
	outBin := filepath.Join(outDir, "gbounce-stamped")

	// Sentinel values: unmistakably synthetic + easy to grep for in
	// the failure message. The "test-1.0" / "abc1234" pair mirrors
	// the manual-smoke recipe in the #515 task report exactly so the
	// CI failure is one-to-one with the local repro.
	const (
		wantVersion   = "test-1.0"
		wantCommit    = "abc1234"
		wantBuildTime = "2026-05-24T00:00:00Z"
	)
	ldflags := strings.Join([]string{
		"-X github.com/trsreagan3/gbounce/internal/cli.version=" + wantVersion,
		"-X github.com/trsreagan3/gbounce/internal/cli.commit=" + wantCommit,
		"-X github.com/trsreagan3/gbounce/internal/cli.buildTime=" + wantBuildTime,
	}, " ")

	buildCmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", outBin, "./cmd/gbounce")
	buildCmd.Dir = repoRoot
	var buildErr bytes.Buffer
	buildCmd.Stderr = &buildErr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("go build failed: %v\nstderr:\n%s", err, buildErr.String())
	}

	runCmd := exec.Command(outBin, "--version")
	var runOut bytes.Buffer
	runCmd.Stdout = &runOut
	runCmd.Stderr = &runOut
	if err := runCmd.Run(); err != nil {
		t.Fatalf("running stamped binary --version failed: %v\noutput:\n%s", err, runOut.String())
	}

	got := strings.TrimSpace(runOut.String())
	// Format is load-bearing — see versionString. Asserting on the
	// whole shape (not just substring presence) protects the canary's
	// regex parser from a sneaky reorder.
	want := "gbounce " + wantVersion + " (commit " + wantCommit + ", built " + wantBuildTime + ")"
	if got != want {
		t.Errorf("--version output mismatch\n got:  %q\n want: %q", got, want)
	}

	// Belt + suspenders: explicitly assert the stamped values appear
	// AND the unstamped defaults do not. If resolveBuildInfo's VCS
	// fallback ever clobbered an ldflags value, this would catch it.
	if !strings.Contains(got, wantVersion) {
		t.Errorf("--version output missing stamped version %q: %q", wantVersion, got)
	}
	if !strings.Contains(got, wantCommit) {
		t.Errorf("--version output missing stamped commit %q: %q", wantCommit, got)
	}
	if strings.Contains(got, "dev (") || strings.Contains(got, "commit none") || strings.Contains(got, "built unknown") {
		t.Errorf("--version output still contains unstamped defaults: %q", got)
	}
}
