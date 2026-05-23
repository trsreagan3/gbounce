// profile_allow_test.go — #388 / §A25 Phase 2 MCP tool tests.

package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeMCPProfile(t *testing.T, dir, name, source string) string {
	t.Helper()
	body := "profiles:\n  " + name + ":\n    description: test\n"
	if source != "" {
		body += "    source: " + source + "\n"
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMcpTool_ProfileAllow_PendingByDefault(t *testing.T) {
	dir := t.TempDir()
	qp := filepath.Join(dir, "pending.jsonl")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", qp)
	path := writeMCPProfile(t, dir, "work", "")

	srv := NewServer(Config{
		Mode:              "discovery",
		ActiveProfileName: "work",
		ProfilesPath:      path,
	})

	out := callToolHelper(t, srv, "gbounce_profile_allow", map[string]any{
		"target": "api.staging.io",
		"action": []any{"GET:/v1/"},
		"reason": "agent reads staging",
	})
	require.Equal(t, true, out["ok"], "got %v", out)
	require.Equal(t, "pending_approval", out["status"])
	require.NotNil(t, out["pending_entry"])
}

func TestMcpTool_ProfileAllow_RefusesWildcardTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", filepath.Join(dir, "pending.jsonl"))
	path := writeMCPProfile(t, dir, "work", "")
	srv := NewServer(Config{
		Mode:              "discovery",
		ActiveProfileName: "work",
		ProfilesPath:      path,
	})
	out := callToolHelper(t, srv, "gbounce_profile_allow", map[string]any{
		"target": "*",
		"action": []any{"GET:/v1/"},
		"reason": "broad",
	})
	require.Equal(t, false, out["ok"])
	require.Equal(t, "target_too_broad", out["code"])
}

func TestMcpTool_DeniesRecent_NoStoreReturnsError(t *testing.T) {
	srv := NewServer(Config{Mode: "discovery"})
	// Explicitly pass empty DBPath; the helper would otherwise fall
	// through to DefaultDBPath() which depends on the test's HOME.
	srv.cfg.DBPath = ""
	t.Setenv("HOME", "/nonexistent-test-home-for-denies-recent")
	out := callToolHelper(t, srv, "gbounce_denies_recent", map[string]any{})
	// Either store_not_configured OR store_open_failed is acceptable —
	// both surface "no usable store" honestly.
	require.Equal(t, false, out["ok"])
	err, _ := out["error"].(string)
	if err != "store_not_configured" && err != "store_open_failed" {
		t.Fatalf("error: got %q; want store_not_configured or store_open_failed", err)
	}
}
