// Package mcpinstall implements the `gbounce mcp install-*` commands
// + the `show-config` / `list-tools` helpers.
//
// Cross-product parity: this package mirrors dbounce's + kbouncer's
// internal/mcpinstall + iam-jit's `ibounce mcp install-*` shape so an
// operator who learned one product gets the same shape on the other
// ([[cross-product-agent-parity]]). The MCP server entrypoint command
// differs (`gbounce` vs `dbounce` vs `kbounce` vs `ibounce`); the
// tool-name prefix differs (`gbounce_*` vs `dbounce_*` etc); everything
// else — flag names, path detection logic, atomic write pattern,
// `show-config` output structure, `list-tools` output format — is
// the same shape across all products.
//
// Audit-cadence notes (per [[audit-cadence-discipline]]):
//
//	(a) Merge-with-existing-config: every install path reads the
//	    existing config first, merges the gbounce entry into
//	    mcpServers, and writes the WHOLE document back. Other agents'
//	    MCP server entries are preserved.
//	(b) Atomic write: writeBytesAtomic writes to a sibling tempfile
//	    in the SAME directory as the target, then os.Rename. Partial
//	    overwrites of the operator's existing config are impossible.
//	(c) No elevation: every default path detection lands in the
//	    operator's $HOME (or %APPDATA% on Windows).
//
// #363 / §A32 — env-block parity. Every install-* writes a populated
// env block (GBOUNCE_AGENT_NAME + GBOUNCE_AGENT_SESSION_ID) so the
// agent runtime stamps X-Agent-Name + X-Agent-Session-Id headers on
// outbound HTTP traffic that gbounce proxies. Default-empty env blocks
// are forbidden — the §A35 dbounce regression that shipped {} env is
// pinned here by TestMcpInstall_EnvBlockNotEmpty_AllClients.
package mcpinstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ServerName is the key under mcpServers we install / merge.
const ServerName = "gbounce"

// ServerCommand is the binary the generated MCP config tells the agent
// to spawn.
const ServerCommand = "gbounce"

// ServerArgs are the argv passed to ServerCommand.
var ServerArgs = []string{"mcp", "serve"}

// DefaultAgentName is the agent-attribution name stamped into the
// generated MCP entry when the caller doesn't pass one explicitly.
// "claude-code" matches the install-claude-code default; the cursor +
// codex installers override per [[cross-product-agent-parity]] +
// #363 / §A32 (cross-bouncer agent-attribution env-var injection).
const DefaultAgentName = "claude-code"

// AgentNameEnvVar is the env-var key the agent runtime reads to stamp
// the X-Agent-Name HTTP header. The GBOUNCE_ prefix keeps the env-var
// namespace consistent across the Bounce suite (KBOUNCE_AGENT_NAME /
// IBOUNCE_AGENT_NAME / DBOUNCE_AGENT_NAME ship the same shape on the
// sibling products).
const AgentNameEnvVar = "GBOUNCE_AGENT_NAME"

// AgentSessionIDEnvVar is the env-var key the agent runtime reads to
// stamp the X-Agent-Session-Id HTTP header. Deliberately left EMPTY
// in the static snippet — the agent runtime mints a fresh UUID v7 per
// session. gbounce itself never reads this env var; it's a hint to
// the AGENT runtime, not configuration gbounce consumes.
const AgentSessionIDEnvVar = "GBOUNCE_AGENT_SESSION_ID"

// agentNameForClient returns the agent-name attribution value to
// stamp for the given install-* client. Names match dbounce + kbounce
// + ibounce per [[cross-product-agent-parity]]:
//
//	claude-code  → "claude-code"
//	cursor       → "cursor"
//	codex        → "openai-codex"
//	anything else → DefaultAgentName ("claude-code")
func agentNameForClient(clientName string) string {
	switch clientName {
	case "claude-code":
		return "claude-code"
	case "cursor":
		return "cursor"
	case "codex":
		return "openai-codex"
	default:
		return DefaultAgentName
	}
}

// ServerConfigDict is the canonical JSON snippet shape any MCP client
// ingests to use gbounce as an MCP server (stdio transport). Defaults
// agent-name attribution to DefaultAgentName; see
// ServerConfigDictForAgent for per-client overrides.
func ServerConfigDict() map[string]any {
	return ServerConfigDictForAgent(DefaultAgentName)
}

// ServerConfigDictForAgent is the per-agent variant of ServerConfigDict.
// The env block carries the agent-attribution hints (AgentNameEnvVar +
// AgentSessionIDEnvVar); the session id is deliberately empty because
// the agent runtime mints a fresh UUID v7 per session.
func ServerConfigDictForAgent(agentName string) map[string]any {
	if agentName == "" {
		agentName = DefaultAgentName
	}
	return map[string]any{
		"mcpServers": map[string]any{
			ServerName: ServerEntryForAgent(agentName),
		},
	}
}

// ServerEntry is the per-server portion of ServerConfigDict. Uses
// DefaultAgentName; see ServerEntryForAgent for per-client overrides.
func ServerEntry() map[string]any {
	return ServerEntryForAgent(DefaultAgentName)
}

// ServerEntryForAgent is the per-agent variant of ServerEntry.
func ServerEntryForAgent(agentName string) map[string]any {
	if agentName == "" {
		agentName = DefaultAgentName
	}
	return map[string]any{
		"command": ServerCommand,
		"args":    append([]string{}, ServerArgs...),
		"env": map[string]any{
			// #363 / §A32 — agent-attribution env-var injection. The
			// agent's MCP host inherits these into the child process;
			// the agent's HTTP client stamps them as X-Agent-Name +
			// X-Agent-Session-Id on every outbound call back through
			// the gbounce HTTP-shaped surface. The session id is
			// deliberately empty — the runtime mints a UUID v7 per
			// session.
			AgentNameEnvVar:      agentName,
			AgentSessionIDEnvVar: "",
		},
	}
}

// ---------------------------------------------------------------------
// Path detection — per supported client.
// ---------------------------------------------------------------------

// ClaudeCodeConfigCandidates returns the candidate config paths to
// try, in priority order.
func ClaudeCodeConfigCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	switch runtime.GOOS {
	case "darwin":
		out = []string{
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "claude-code", "mcp.json"),
			filepath.Join(home, ".claude.json"),
		}
	case "linux":
		out = []string{
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "claude-code", "mcp.json"),
			filepath.Join(home, ".claude.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		out = []string{
			filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".claude.json"),
		}
	default:
		out = []string{filepath.Join(home, ".claude.json")}
	}
	return out
}

// CursorConfigCandidates returns the candidate config paths for Cursor.
func CursorConfigCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".cursor", "mcp.json"),
	}
}

// CodexConfigCandidates returns the candidate config paths for Codex.
func CodexConfigCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".codex", "config.toml"),
	}
}

// ---------------------------------------------------------------------
// Install logic.
// ---------------------------------------------------------------------

// InstallResult describes what an install operation did.
type InstallResult struct {
	Path    string
	Created bool
	Updated bool
	Manual  bool
	Snippet string
	Reason  string
}

// Options are the shared install flags.
type Options struct {
	Path   string
	Force  bool
	Out    io.Writer
	Stderr io.Writer
}

func (o *Options) defaults() {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
}

// InstallClaudeCode adds the gbounce MCP server to the Claude Code /
// Claude Desktop config file.
func InstallClaudeCode(opts Options) (*InstallResult, error) {
	opts.defaults()
	target, err := resolveTarget(opts.Path, ClaudeCodeConfigCandidates())
	if err != nil {
		return nil, err
	}
	return installJSON(target, "claude-code", opts)
}

// InstallCursor adds the gbounce MCP server to Cursor's MCP config.
func InstallCursor(opts Options) (*InstallResult, error) {
	opts.defaults()
	target, err := resolveTarget(opts.Path, CursorConfigCandidates())
	if err != nil {
		return nil, err
	}
	return installJSON(target, "cursor", opts)
}

// InstallCodex installs into Codex.
func InstallCodex(opts Options) (*InstallResult, error) {
	opts.defaults()
	target := opts.Path
	if target == "" {
		cands := CodexConfigCandidates()
		if len(cands) == 0 {
			return nil, errors.New("gbounce mcp install-codex: cannot resolve home directory; pass --path")
		}
		target = cands[0]
	}

	if strings.HasSuffix(strings.ToLower(target), ".json") {
		return installJSON(target, "codex", opts)
	}

	snippet, err := snippetTOML()
	if err != nil {
		return nil, err
	}
	res := &InstallResult{
		Manual:  true,
		Path:    target,
		Snippet: snippet,
		Reason: "Codex stores MCP config in TOML (~/.codex/config.toml). " +
			"gbounce refuses to edit TOML in place (risks corrupting unrelated keys). " +
			"Paste the snippet below into your Codex config, or pass --path FILE.json " +
			"if you keep an alternative JSON-shaped MCP config.",
	}
	fmt.Fprintln(opts.Out, "gbounce mcp install-codex: manual install required")
	fmt.Fprintln(opts.Out, res.Reason)
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Target Codex config (for reference):")
	fmt.Fprintln(opts.Out, "  ", target)
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "TOML snippet to add:")
	fmt.Fprintln(opts.Out, snippet)
	return res, nil
}

// ---------------------------------------------------------------------
// Shared JSON-merge install.
// ---------------------------------------------------------------------

func resolveTarget(explicit string, candidates []string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if len(candidates) == 0 {
		return "", errors.New("cannot resolve home directory; pass --path")
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return candidates[0], nil
}

func installJSON(target, clientName string, opts Options) (*InstallResult, error) {
	res := &InstallResult{Path: target}

	existing := map[string]any{}
	existed := false
	if data, err := os.ReadFile(target); err == nil {
		existed = true
		if len(data) > 0 {
			if jerr := json.Unmarshal(data, &existing); jerr != nil {
				if !opts.Force {
					return nil, fmt.Errorf(
						"gbounce mcp install-%s: %s is not valid JSON (%v); "+
							"pass --force to overwrite or --path to write elsewhere",
						clientName, target, jerr)
				}
				existing = map[string]any{}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("gbounce mcp install-%s: read %s: %w", clientName, target, err)
	}

	serversRaw, ok := existing["mcpServers"]
	var servers map[string]any
	if ok {
		if cast, ok2 := serversRaw.(map[string]any); ok2 {
			servers = cast
		} else if !opts.Force {
			return nil, fmt.Errorf(
				"gbounce mcp install-%s: %s has a non-object mcpServers value; "+
					"refusing to overwrite (pass --force, or use `gbounce mcp show-config` "+
					"+ merge by hand)", clientName, target)
		} else {
			servers = map[string]any{}
		}
	}
	if servers == nil {
		servers = map[string]any{}
	}

	if _, hadGbounce := servers[ServerName]; hadGbounce {
		res.Updated = true
	}
	// #363 / §A32 — per-client agent-attribution. installJSON is the
	// single write-path for claude-code / cursor / codex JSON installs;
	// agentNameForClient varies the AgentNameEnvVar value per client
	// so the agent runtime stamps the correct X-Agent-Name on
	// outbound HTTP traffic.
	servers[ServerName] = ServerEntryForAgent(agentNameForClient(clientName))
	existing["mcpServers"] = servers

	res.Created = !existed

	if err := writeJSONAtomic(target, existing); err != nil {
		return nil, fmt.Errorf("gbounce mcp install-%s: write %s: %w", clientName, target, err)
	}

	verb := "added"
	if res.Updated {
		verb = "updated"
	}
	fmt.Fprintf(opts.Out, "gbounce mcp install-%s: %s `gbounce` MCP server in %s\n",
		clientName, verb, target)
	fmt.Fprintln(opts.Out, "")
	fmt.Fprintln(opts.Out, "Restart your MCP client so it re-reads the config.")
	fmt.Fprintln(opts.Out, "Verify with `gbounce mcp list-tools` (shows the same tools the agent will see).")

	return res, nil
}

func writeJSONAtomic(target string, payload any) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeBytesAtomic(target, data, 0o644)
}

func writeBytesAtomic(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".gbounce-mcp-install-*.tmp")
	if err != nil {
		return fmt.Errorf("create tempfile in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func snippetTOML() (string, error) {
	var b strings.Builder
	b.WriteString("[mcp_servers.")
	b.WriteString(ServerName)
	b.WriteString("]\n")
	b.WriteString("command = \"")
	b.WriteString(ServerCommand)
	b.WriteString("\"\n")
	b.WriteString("args = [")
	for i, a := range ServerArgs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("\"")
		b.WriteString(a)
		b.WriteString("\"")
	}
	b.WriteString("]\n")
	// #363 / §A32 — agent-attribution env vars. Codex install is the
	// "openai-codex" client; the TOML snippet matches the JSON shape
	// so an operator who hand-pastes gets the same agent attribution
	// as the auto-install paths.
	b.WriteString("\n[mcp_servers.")
	b.WriteString(ServerName)
	b.WriteString(".env]\n")
	b.WriteString(AgentNameEnvVar)
	b.WriteString(" = \"openai-codex\"\n")
	b.WriteString(AgentSessionIDEnvVar)
	b.WriteString(" = \"\"\n")
	return b.String(), nil
}

// ---------------------------------------------------------------------
// show-config + list-tools.
// ---------------------------------------------------------------------

// Shape is the output format selector for ShowConfig.
type Shape string

const (
	ShapeJSON Shape = "json"
	ShapeYAML Shape = "yaml"
)

// ShowConfig writes the canonical MCP server config snippet to w.
func ShowConfig(w io.Writer, shape Shape) error {
	cfg := ServerConfigDict()
	switch shape {
	case "", ShapeJSON:
		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		if _, err := w.Write(out); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	case ShapeYAML:
		yaml := "mcpServers:\n" +
			"  " + ServerName + ":\n" +
			"    command: " + ServerCommand + "\n" +
			"    args:\n"
		for _, a := range ServerArgs {
			yaml += "      - " + a + "\n"
		}
		yaml += "    env:\n" +
			"      " + AgentNameEnvVar + ": " + DefaultAgentName + "\n" +
			"      " + AgentSessionIDEnvVar + ": \"\"\n"
		if _, err := w.Write([]byte(yaml)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown shape %q (want json | yaml)", shape)
	}

	footer := "\n# Or for the common MCP clients:\n" +
		"#   gbounce mcp install-claude-code\n" +
		"#   gbounce mcp install-cursor\n" +
		"#   gbounce mcp install-codex\n" +
		"#\n" +
		"# Agent attribution (#363 / §A32): the " + AgentNameEnvVar + " +\n" +
		"# " + AgentSessionIDEnvVar + " env vars wire the agent's\n" +
		"# X-Agent-Name + X-Agent-Session-Id HTTP headers. See\n" +
		"# iam-roles/docs/AGENT-ATTRIBUTION.md for the per-runtime\n" +
		"# patterns (Claude Code / Cursor / Codex / custom).\n"
	if _, err := w.Write([]byte(footer)); err != nil {
		return err
	}
	return nil
}

// ToolListEntry is the simplified shape ListTools emits per row.
type ToolListEntry struct {
	Name        string
	Description string
}

// FormatToolList renders the entries as a 2-column table.
func FormatToolList(w io.Writer, entries []ToolListEntry) error {
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	nameWidth := 0
	for _, e := range entries {
		if l := len(e.Name); l > nameWidth {
			nameWidth = l
		}
	}
	if nameWidth > 36 {
		nameWidth = 36
	}
	if nameWidth < 12 {
		nameWidth = 12
	}

	fmt.Fprintf(w, "%-*s  %s\n", nameWidth, "NAME", "DESCRIPTION")
	for _, e := range entries {
		desc := firstSentence(e.Description)
		if len(desc) > 80 {
			desc = desc[:77] + "..."
		}
		fmt.Fprintf(w, "%-*s  %s\n", nameWidth, e.Name, desc)
	}
	return nil
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if i := strings.IndexAny(s, "\n"); i > 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i+1]
	}
	return strings.TrimSpace(s)
}
