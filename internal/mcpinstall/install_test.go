package mcpinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Smoke tests for the package-level mcpinstall API. Mirrors
// dbounce/internal/mcpinstall/install_test.go shape per
// [[cross-product-agent-parity]].

func TestServerConfigDict_Shape(t *testing.T) {
	cfg := ServerConfigDict()
	servers := cfg["mcpServers"].(map[string]any)
	gbounceEntry := servers["gbounce"].(map[string]any)
	assert.Equal(t, "gbounce", gbounceEntry["command"])
	args := gbounceEntry["args"].([]string)
	assert.Equal(t, []string{"mcp", "serve"}, args)
}

func TestInstallClaudeCode_CreatesNew(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	res, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.True(t, res.Created)
	assert.False(t, res.Updated)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.NotNil(t, parsed["mcpServers"].(map[string]any)["gbounce"])
}

// TestMcpInstall_ClaudeCode_EmitsServerEntry — task #363 / §A32 test.
func TestMcpInstall_ClaudeCode_EmitsServerEntry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	entry, ok := servers["gbounce"].(map[string]any)
	require.True(t, ok, "mcpServers.gbounce must be an object")
	assert.Equal(t, "gbounce", entry["command"])
	args, ok := entry["args"].([]any)
	require.True(t, ok, "args must be a JSON array")
	assert.Equal(t, []any{"mcp", "serve"}, args)
}

// TestMcpInstall_Cursor_EmitsServerEntry — task #363 / §A32 test.
func TestMcpInstall_Cursor_EmitsServerEntry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cursor.json")
	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	entry, ok := servers["gbounce"].(map[string]any)
	require.True(t, ok, "mcpServers.gbounce must be an object")
	assert.Equal(t, "gbounce", entry["command"])
}

// TestMcpInstall_Codex_EmitsServerEntry — task #363 / §A32 test. Uses
// .json path so InstallCodex goes through installJSON instead of TOML
// snippet.
func TestMcpInstall_Codex_EmitsServerEntry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex.json")
	_, err := InstallCodex(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	entry, ok := servers["gbounce"].(map[string]any)
	require.True(t, ok, "mcpServers.gbounce must be an object")
	assert.Equal(t, "gbounce", entry["command"])
}

// TestMcpInstall_EnvBlockNotEmpty_AllClients — task #363 / §A32 test
// + the §A35 dbounce-regression pin: every install path MUST emit a
// populated env block (not {}), so the agent runtime stamps
// X-Agent-Name + X-Agent-Session-Id headers correctly.
func TestMcpInstall_EnvBlockNotEmpty_AllClients(t *testing.T) {
	cases := []struct {
		name      string
		install   func(opts Options) (*InstallResult, error)
		agentName string
	}{
		{"claude-code", InstallClaudeCode, "claude-code"},
		{"cursor", InstallCursor, "cursor"},
		{"codex", InstallCodex, "openai-codex"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, tc.name+".json")
			_, err := tc.install(Options{Path: target, Out: &bytes.Buffer{}})
			require.NoError(t, err)

			body, err := os.ReadFile(target)
			require.NoError(t, err)
			var parsed map[string]any
			require.NoError(t, json.Unmarshal(body, &parsed))
			servers := parsed["mcpServers"].(map[string]any)
			entry := servers["gbounce"].(map[string]any)
			env, ok := entry["env"].(map[string]any)
			require.True(t, ok, "mcpServers.gbounce.env must be an object (not %T)", entry["env"])
			assert.NotEmpty(t, env, "env block must NOT be {} — #363/§A32 launch-blocker")

			assert.Contains(t, env, AgentNameEnvVar)
			assert.Contains(t, env, AgentSessionIDEnvVar)
			assert.Equal(t, tc.agentName, env[AgentNameEnvVar])
			assert.Equal(t, "", env[AgentSessionIDEnvVar])

			// Suffix-shape parity assertions (mirror dbounce test).
			foundName, foundSession := false, false
			for k := range env {
				if strings.HasSuffix(k, "AGENT_NAME") {
					foundName = true
				}
				if strings.HasSuffix(k, "AGENT_SESSION_ID") {
					foundSession = true
				}
			}
			assert.True(t, foundName, "env must carry an *AGENT_NAME key")
			assert.True(t, foundSession, "env must carry an *AGENT_SESSION_ID key")
		})
	}
}

func TestInstallClaudeCode_UpdateExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	res, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.True(t, res.Updated)
	assert.False(t, res.Created)
}

func TestInstall_PreservesOtherServers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cfg.json")
	pre := `{"mcpServers": {"kbounce": {"command": "kbounce", "args": ["mcp", "serve"], "env": {}}}}`
	require.NoError(t, os.WriteFile(target, []byte(pre), 0o600))
	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	assert.NotNil(t, servers["gbounce"])
	assert.NotNil(t, servers["kbounce"], "OTHER MCP servers must survive")
}

func TestInstall_RefusesMalformedWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(target, []byte("not json"), 0o600))
	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
}

func TestInstall_ForceOverwritesMalformed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(target, []byte("not json"), 0o600))
	_, err := InstallCursor(Options{Path: target, Force: true, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.NotNil(t, parsed["mcpServers"].(map[string]any)["gbounce"])
}

func TestInstallCodex_TOMLPathPrintsSnippet(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")
	out := &bytes.Buffer{}
	res, err := InstallCodex(Options{Path: target, Out: out})
	require.NoError(t, err)
	assert.True(t, res.Manual)
	assert.Contains(t, out.String(), "[mcp_servers.gbounce]")
	_, err = os.Stat(target)
	assert.True(t, os.IsNotExist(err),
		"install-codex must NOT write to a .toml file")
}

func TestInstallCodex_TOMLSnippetIncludesAgentEnv(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")
	out := &bytes.Buffer{}
	res, err := InstallCodex(Options{Path: target, Out: out})
	require.NoError(t, err)
	require.True(t, res.Manual)
	snippet := res.Snippet
	assert.Contains(t, snippet, AgentNameEnvVar)
	assert.Contains(t, snippet, AgentSessionIDEnvVar)
	assert.Contains(t, snippet, "openai-codex")
}

func TestShowConfig_JSON(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeJSON))
	body := out.String()
	assert.Contains(t, body, `"command": "gbounce"`)
	assert.Contains(t, body, "install-claude-code")
}

func TestShowConfig_YAML(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeYAML))
	body := out.String()
	assert.Contains(t, body, "mcpServers:")
	assert.Contains(t, body, "gbounce:")
	assert.Contains(t, body, "- mcp")
}

func TestShowConfig_JSON_IncludesAgentEnv(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeJSON))
	body := out.String()
	assert.Contains(t, body, AgentNameEnvVar)
	assert.Contains(t, body, AgentSessionIDEnvVar)
	assert.Contains(t, body, DefaultAgentName)
}

func TestShowConfig_YAML_IncludesAgentEnv(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeYAML))
	body := out.String()
	assert.Contains(t, body, AgentNameEnvVar)
	assert.Contains(t, body, AgentSessionIDEnvVar)
	assert.NotContains(t, body, "env: {}",
		"YAML env block must be populated — #363/§A32 launch-blocker")
}

func TestFormatToolList_SortsByName(t *testing.T) {
	out := &bytes.Buffer{}
	entries := []ToolListEntry{
		{Name: "gbounce_zzz", Description: "z."},
		{Name: "gbounce_aaa", Description: "a."},
	}
	require.NoError(t, FormatToolList(out, entries))
	body := out.String()
	aIdx := strings.Index(body, "gbounce_aaa")
	zIdx := strings.Index(body, "gbounce_zzz")
	assert.True(t, aIdx >= 0 && zIdx > aIdx, "alphabetical order required")
}

func TestServerEntryForAgent_FallsBackToDefault(t *testing.T) {
	entry := ServerEntryForAgent("")
	env := entry["env"].(map[string]any)
	assert.Equal(t, DefaultAgentName, env[AgentNameEnvVar])
}

func TestAgentNameForClient_KnownClients(t *testing.T) {
	cases := map[string]string{
		"claude-code": "claude-code",
		"cursor":      "cursor",
		"codex":       "openai-codex",
		"unknown":     DefaultAgentName,
		"":            DefaultAgentName,
	}
	for client, want := range cases {
		client, want := client, want
		t.Run(client, func(t *testing.T) {
			assert.Equal(t, want, agentNameForClient(client))
		})
	}
}
