package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the whole cli test package from the developer's real
// ~/.gbounce/config.yaml. `gbounce run` now auto-loads that file (persistent
// operator config), so without this every run-invoking test would read the
// machine's config and behave non-hermetically — e.g. a local config with
// `allow_connect: true` made TestRunCmd_RequiresUpstreamOrConnect pass
// validation and then fail on a port bind. Point GBOUNCE_CONFIG at a path that
// does not exist so LoadRunConfig is a clean no-op; individual tests that want
// to exercise config loading set GBOUNCE_CONFIG / pass --config explicitly.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gbounce-cli-test-noconfig")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("GBOUNCE_CONFIG", filepath.Join(dir, "does-not-exist.yaml"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
