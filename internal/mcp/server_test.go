package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// callTool helper: sends a tools/call JSON-RPC request, returns the
// structuredContent map from the response.
func callToolHelper(t *testing.T, srv *Server, name string, args map[string]any) map[string]any {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
		},
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)
	in := bytes.NewReader(append(body, '\n'))
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(in, out))

	var resp map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp))
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "response did not contain a result envelope: %s", out.String())
	structured, ok := result["structuredContent"].(map[string]any)
	require.True(t, ok, "response result lacked structuredContent: %v", result)
	return structured
}

func TestMcpServer_Initialize(t *testing.T) {
	srv := NewServer(Config{Mode: "discovery"})
	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"1.0"}}}` + "\n"
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(strings.NewReader(req), out))
	assert.Contains(t, out.String(), "protocolVersion")
	assert.Contains(t, out.String(), "gbounce")
}

func TestMcpServer_ToolsList(t *testing.T) {
	srv := NewServer(Config{Mode: "discovery"})
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(strings.NewReader(req), out))
	body := out.String()
	for _, expected := range []string{
		"gbounce_active_mode",
		"gbounce_recommend_mode_for_task",
		"gbounce_dynamic_denies_list",
		"gbounce_deny_add",
		"gbounce_deny_remove",
	} {
		assert.Contains(t, body, expected, "tools/list must surface %s", expected)
	}
}

// TestMcpServer_GbounceActiveMode_Tool — task #363 / §A32 test.
func TestMcpServer_GbounceActiveMode_Tool(t *testing.T) {
	srv := NewServer(Config{
		Mode:              "discovery",
		ActiveProfileName: "",
		ProfilesPath:      "",
	})
	res := callToolHelper(t, srv, "gbounce_active_mode", map[string]any{})
	assert.Equal(t, "discovery", res["mode"])
	assert.Equal(t, "", res["active_profile"])
}

func TestMcpServer_GbounceActiveMode_WithProfile(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.yaml")
	yamlBody := `profiles:
  test-block-evil:
    description: "block evil.com"
    deny_hosts:
      - evil.com
      - "*.bad.com"
`
	require.NoError(t, os.WriteFile(profilesPath, []byte(yamlBody), 0o600))
	srv := NewServer(Config{
		Mode:              "discovery",
		ActiveProfileName: "test-block-evil",
		ProfilesPath:      profilesPath,
	})
	res := callToolHelper(t, srv, "gbounce_active_mode", map[string]any{})
	assert.Equal(t, "discovery", res["mode"])
	assert.Equal(t, "test-block-evil", res["active_profile"])
	// JSON-marshaled int becomes float64
	assert.EqualValues(t, 2, res["deny_hosts_count"])
}

// TestMcpServer_GbounceDynamicDeniesList_Tool — task #363 / §A32 test.
func TestMcpServer_GbounceDynamicDeniesList_Tool(t *testing.T) {
	dir := t.TempDir()
	denyPath := filepath.Join(dir, "dynamic-denies.yaml")

	yamlBody := `schema_version: "1.0"
product: iam-jit-dynamic-denies
denies:
  - id: dd_01H7MZQR5T8F9NPBKW3VYJSDXC
    targets:
      - evil.example.com
    reason: "MCP-list smoke test"
    duration: permanent
    added_by: tester
    added_at: 2026-05-23T00:00:00Z
    applied_to:
      - gbounce
    source: mcp
`
	require.NoError(t, os.WriteFile(denyPath, []byte(yamlBody), 0o600))

	srv := NewServer(Config{
		Mode:              "discovery",
		DynamicDeniesPath: denyPath,
	})
	res := callToolHelper(t, srv, "gbounce_dynamic_denies_list", map[string]any{})
	assert.EqualValues(t, 1, res["count"])
	assert.Equal(t, denyPath, res["path"])
	denies := res["denies"].([]any)
	require.Len(t, denies, 1)
	entry := denies[0].(map[string]any)
	assert.Equal(t, "dd_01H7MZQR5T8F9NPBKW3VYJSDXC", entry["id"])
	targets := entry["targets"].([]any)
	require.Len(t, targets, 1)
	assert.Equal(t, "evil.example.com", targets[0])
}

func TestMcpServer_DenyAdd_AppendsToFile(t *testing.T) {
	dir := t.TempDir()
	denyPath := filepath.Join(dir, "dynamic-denies.yaml")
	srv := NewServer(Config{
		Mode:              "discovery",
		DynamicDeniesPath: denyPath,
	})
	res := callToolHelper(t, srv, "gbounce_deny_add", map[string]any{
		"target":   "bad.example.com",
		"reason":   "smoke",
		"duration": "permanent",
	})
	id, ok := res["id"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(id, "dd_"))

	// Reload + verify the file has 1 rule.
	listRes := callToolHelper(t, srv, "gbounce_dynamic_denies_list", map[string]any{})
	assert.EqualValues(t, 1, listRes["count"])
}

func TestMcpServer_DenyRemove_DropsById(t *testing.T) {
	dir := t.TempDir()
	denyPath := filepath.Join(dir, "dynamic-denies.yaml")
	srv := NewServer(Config{
		Mode:              "discovery",
		DynamicDeniesPath: denyPath,
	})
	addRes := callToolHelper(t, srv, "gbounce_deny_add", map[string]any{
		"target": "bad.example.com",
		"reason": "smoke",
	})
	id := addRes["id"].(string)

	removeRes := callToolHelper(t, srv, "gbounce_deny_remove", map[string]any{
		"id": id,
	})
	assert.Equal(t, true, removeRes["removed"])

	listRes := callToolHelper(t, srv, "gbounce_dynamic_denies_list", map[string]any{})
	assert.EqualValues(t, 0, listRes["count"])
}

func TestMcpServer_RecommendMode_AuditOnly(t *testing.T) {
	srv := NewServer(Config{})
	res := callToolHelper(t, srv, "gbounce_recommend_mode_for_task", map[string]any{
		"wants_audit_only": true,
	})
	assert.Equal(t, "discovery", res["mode"])
}

func TestMcpServer_RecommendMode_NeedsURLPath(t *testing.T) {
	srv := NewServer(Config{})
	res := callToolHelper(t, srv, "gbounce_recommend_mode_for_task", map[string]any{
		"needs_url_path_enforcement": true,
	})
	assert.Equal(t, "mitm", res["mode"])
}

func TestMcpServer_RecommendMode_DescriptionKeyword(t *testing.T) {
	srv := NewServer(Config{})
	res := callToolHelper(t, srv, "gbounce_recommend_mode_for_task", map[string]any{
		"description": "audit all outbound calls",
	})
	assert.Equal(t, "discovery", res["mode"])
}

func TestComputeExpiresAt_Permanent(t *testing.T) {
	_, ok := computeExpiresAt(time.Now(), "permanent")
	assert.False(t, ok)
}

func TestComputeExpiresAt_30m(t *testing.T) {
	t0 := time.Now()
	expires, ok := computeExpiresAt(t0, "30m")
	require.True(t, ok)
	assert.Equal(t, t0.Add(30*time.Minute), expires)
}
