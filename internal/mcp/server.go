// Package mcp implements gbounce's MCP (Model Context Protocol) server.
//
// #363 / §A32 — the MCP-over-stdio shape that Claude Code, Cursor,
// Codex, and Devin all consume. An agent client connects to
// `gbounce mcp serve`, discovers the tools via JSON-RPC 2.0
// `tools/list`, and invokes them with `tools/call`. Mirrors the Python
// iam-jit-bouncer MCP tool family (`bouncer_*`), kbouncer's
// (`kbounce_*`), and dbounce's (`dbounce_*`) so an operator who already
// learned one tool surface understands the other.
//
// Implementation notes:
//
//   - Hand-rolled JSON-RPC 2.0 loop over stdin/stdout. No external
//     MCP library dependency.
//   - Tools are dispatched via a string → handler map.
//   - Tools that READ state read it FRESH on every call (no caching).
//   - Mutating tools (gbounce_deny_add / gbounce_deny_remove) write to
//     the dynamic-denies YAML file; the running proxy picks up the
//     change on the next fsnotify event.
//
// Audit-cadence notes (per [[audit-cadence-discipline]]):
//
//   - MCP tools that MUTATE flow through the SAME on-disk write path
//     as a hand-edit. There is no MCP-specific bypass surface.
//   - gbounce_recommend_mode_for_task is DETERMINISTIC, per
//     [[bouncer-mode-selection-for-agents]]. No LLM call.
//   - Agent-impersonation surface: the MCP server runs as the
//     operator who started `gbounce mcp`. The agent that connects can
//     do EXACTLY what gbounce-the-process can do — no more.
package mcp

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/gbounce/internal/dynamicdeny"
	"github.com/trsreagan3/gbounce/internal/posture"
	"github.com/trsreagan3/gbounce/internal/profile"
)

// ProtocolVersion is the MCP protocol version we advertise. Tracks
// the 2024-11-05 spec; Python + kbouncer + dbounce advertise the same.
const ProtocolVersion = "2024-11-05"

// ServerName / ServerVersion identify the server to MCP clients.
const (
	ServerName    = "gbounce"
	ServerVersion = "1.0.0"
)

// maxToolCallParamsBytes caps the raw JSON-RPC `params` payload for
// `tools/call`. Bounded BEFORE per-tool dispatch so a runaway / hostile
// agent can't burn CPU on multi-MB payloads. 16 KiB matches dbounce.
const maxToolCallParamsBytes = 16 * 1024

// Config wires the MCP server to the live gbounce state on disk.
type Config struct {
	// Mode is the discovery/mitm mode the running proxy was started with.
	// Surfaced by gbounce_active_mode.
	Mode string

	// ActiveProfileName names the profile currently bound to the
	// running proxy. Empty when no profile is active.
	ActiveProfileName string

	// ProfilesPath is the path to the profiles.yaml currently in use.
	ProfilesPath string

	// DynamicDeniesPath is the path to the dynamic-denies YAML file
	// the gbounce_deny_add / gbounce_deny_remove / gbounce_dynamic_denies_list
	// tools consult. When empty the loader's default
	// (`~/.iam-jit/dynamic-denies.yaml`) is used.
	DynamicDeniesPath string

	// Actor is the value stamped into added_by when MCP-initiated
	// deny_add lands. Defaults to "gbounce-mcp" when empty.
	Actor string

	// DBPath is the on-disk SQLite store path. Used by
	// gbounce_denies_recent to read recent DENY decisions; empty →
	// the tool returns store_not_configured. #388 / §A25 Phase 2.
	DBPath string
}

// Server is the MCP-over-stdio server.
type Server struct {
	cfg Config
	mu  sync.Mutex
}

// NewServer constructs an MCP server from the given config.
func NewServer(cfg Config) *Server {
	if cfg.Actor == "" {
		cfg.Actor = "gbounce-mcp"
	}
	return &Server{cfg: cfg}
}

// Serve runs the JSON-RPC loop. One request per line on `in`; one
// response per line on `out`. Blocks until `in` returns io.EOF.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rawRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(errResponse(nil, -32700, fmt.Sprintf("parse error: %v", err)))
			continue
		}
		resp := s.dispatch(req)
		if resp == nil {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("mcp: encode response: %w", err)
		}
	}
	return scanner.Err()
}

type rawRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Server) dispatch(req rawRequest) any {
	switch req.Method {
	case "initialize":
		return okResponse(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name":    ServerName,
				"version": ServerVersion,
			},
		})
	case "tools/list":
		return okResponse(req.ID, map[string]any{"tools": ToolDescriptors()})
	case "tools/call":
		if len(req.Params) > maxToolCallParamsBytes {
			return errResponse(req.ID, -32602,
				fmt.Sprintf(
					"tools/call params exceed maximum size of %d bytes; submit smaller payload. Got %d bytes.",
					maxToolCallParamsBytes, len(req.Params)))
		}
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResponse(req.ID, -32602, fmt.Sprintf("invalid params: %v", err))
		}
		result, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			result = map[string]any{"error": err.Error()}
		}
		text, _ := json.MarshalIndent(result, "", "  ")
		return okResponse(req.ID, map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(text)}},
			"structuredContent": result,
		})
	case "notifications/initialized", "notifications/cancelled":
		return nil
	}
	return errResponse(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
}

func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "gbounce_active_mode":
		return s.toolActiveMode(args)
	case "gbounce_recommend_mode_for_task":
		return toolRecommendModeForTask(args)
	case "gbounce_dynamic_denies_list":
		return s.toolDynamicDeniesList(args)
	case "gbounce_deny_add":
		return s.toolDenyAdd(args)
	case "gbounce_deny_remove":
		return s.toolDenyRemove(args)
	case "gbounce_posture":
		return s.toolPosture(args)
	case "gbounce_profile_allow":
		return s.toolProfileAllow(args)
	case "gbounce_denies_recent":
		return s.toolDeniesRecent(args)
	}
	return nil, fmt.Errorf("unknown tool: %s", name)
}

// toolPosture surfaces gbounce's local posture (running / mode /
// profile / HTTP_PROXY wiring / MISCONFIG). Read-only; takes no
// arguments. Mirrors `gbounce posture --json` CLI shape. #383 / §A42.
func (s *Server) toolPosture(_ map[string]any) (map[string]any, error) {
	block := posture.Capture()
	bs, err := json.Marshal(block)
	if err != nil {
		return nil, fmt.Errorf("posture: marshal: %w", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(bs, &out); err != nil {
		return nil, fmt.Errorf("posture: unmarshal: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Read-only tools.
// ---------------------------------------------------------------------

func (s *Server) toolActiveMode(_ map[string]any) (map[string]any, error) {
	mode := s.cfg.Mode
	if mode == "" {
		mode = "discovery"
	}
	out := map[string]any{
		"mode":          mode,
		"active_profile": s.cfg.ActiveProfileName,
		"profiles_path": s.cfg.ProfilesPath,
	}
	// If a profile is active, surface its deny_hosts count so the agent
	// has a useful view without an extra round-trip.
	if s.cfg.ActiveProfileName != "" && s.cfg.ProfilesPath != "" {
		profiles, err := profile.LoadProfiles(s.cfg.ProfilesPath)
		if err == nil {
			if p, perr := profiles.Active(s.cfg.ActiveProfileName); perr == nil {
				out["deny_hosts_count"] = len(p.DenyHosts)
				out["deny_rules_count"] = len(p.DenyRules)
			}
		}
	}
	return out, nil
}

// toolRecommendModeForTask returns a deterministic mode recommendation
// per [[bouncer-mode-selection-for-agents]]. No LLM. The matrix:
//
//   - wants_audit_only=true                                  → discovery
//   - needs_url_path_enforcement=true                        → mitm
//   - description matches strong observation keywords (audit,
//     observe, watch, trace, log, monitor)                   → discovery
//   - description matches MITM-only keywords (path, body,
//     route, endpoint, query param, header)                  → mitm
//   - else default → discovery (safer; never breaks pinned SDKs)
func toolRecommendModeForTask(args map[string]any) (map[string]any, error) {
	wantsAuditOnly, _ := args["wants_audit_only"].(bool)
	needsPath, _ := args["needs_url_path_enforcement"].(bool)
	description, _ := args["description"].(string)

	var (
		mode   string
		reason string
	)
	switch {
	case wantsAuditOnly:
		mode = "discovery"
		reason = "wants_audit_only=true; observation-only mode does not need MITM."
	case needsPath:
		mode = "mitm"
		reason = "needs_url_path_enforcement=true; URL-path / method / body predicates require terminating TLS."
	default:
		lower := strings.ToLower(description)
		mitmKeywords := []string{"path", "body", "endpoint", "query param", "header", "route"}
		discoveryKeywords := []string{"audit", "observe", "watch", "trace", "log", "monitor", "discovery"}
		hasMITM, hasDisc := false, false
		for _, k := range mitmKeywords {
			if strings.Contains(lower, k) {
				hasMITM = true
				break
			}
		}
		for _, k := range discoveryKeywords {
			if strings.Contains(lower, k) {
				hasDisc = true
				break
			}
		}
		if hasMITM && !hasDisc {
			mode = "mitm"
			reason = "description references URL-path / body / endpoint predicates — MITM mode visibility required."
		} else {
			mode = "discovery"
			reason = "no MITM-only signal in inputs; defaulting to discovery (safer; pinned SDKs survive)."
		}
	}
	return map[string]any{
		"mode":   mode,
		"reason": reason,
	}, nil
}

func (s *Server) toolDynamicDeniesList(_ map[string]any) (map[string]any, error) {
	path := s.cfg.DynamicDeniesPath
	if path == "" {
		path = dynamicdeny.ResolveDefaultPath()
	}
	rs, err := dynamicdeny.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load dynamic denies: %w", err)
	}
	entries := make([]map[string]any, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		entry := map[string]any{
			"id":         r.ID,
			"targets":    r.Targets,
			"reason":     r.Reason,
			"duration":   r.Duration,
			"added_by":   r.AddedBy,
			"added_at":   r.AddedAt.Format(time.RFC3339),
			"applied_to": r.AppliedTo,
		}
		if r.ExpiresAt != nil {
			entry["expires_at"] = r.ExpiresAt.Format(time.RFC3339)
		}
		if r.Source != "" {
			entry["source"] = r.Source
		}
		entries = append(entries, entry)
	}
	return map[string]any{
		"count":  len(entries),
		"path":   path,
		"denies": entries,
	}, nil
}

// ---------------------------------------------------------------------
// Mutating tools.
// ---------------------------------------------------------------------

func (s *Server) toolDenyAdd(args map[string]any) (map[string]any, error) {
	target, _ := args["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("`target` is required + must be non-empty")
	}
	reason, _ := args["reason"].(string)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New("`reason` is required + must be non-empty")
	}
	duration, _ := args["duration"].(string)
	if duration == "" {
		duration = "permanent"
	}
	addedBy, _ := args["added_by"].(string)
	if addedBy == "" {
		addedBy = s.cfg.Actor
	}

	now := time.Now().UTC()
	rule := dynamicdeny.Rule{
		ID:        mintRuleID(),
		Targets:   []string{target},
		Reason:    reason,
		Duration:  duration,
		AddedBy:   addedBy,
		AddedAt:   now,
		AppliedTo: []string{"gbounce"},
		Source:    "mcp",
	}
	if expires, ok := computeExpiresAt(now, duration); ok {
		rule.ExpiresAt = &expires
	}

	path := s.cfg.DynamicDeniesPath
	if path == "" {
		path = dynamicdeny.ResolveDefaultPath()
	}
	if path == "" {
		return nil, errors.New("cannot resolve dynamic-denies path; pass --dynamic-denies-path or set IAM_JIT_DYNAMIC_DENIES_PATH")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := appendDenyRule(path, rule); err != nil {
		return nil, err
	}
	return map[string]any{
		"id":         rule.ID,
		"target":     target,
		"duration":   duration,
		"added_by":   addedBy,
		"path":       path,
		"applied_to": rule.AppliedTo,
	}, nil
}

func (s *Server) toolDenyRemove(args map[string]any) (map[string]any, error) {
	id, _ := args["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("`id` is required + must be non-empty")
	}
	path := s.cfg.DynamicDeniesPath
	if path == "" {
		path = dynamicdeny.ResolveDefaultPath()
	}
	if path == "" {
		return nil, errors.New("cannot resolve dynamic-denies path; pass --dynamic-denies-path or set IAM_JIT_DYNAMIC_DENIES_PATH")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	removed, err := removeDenyRule(path, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":      id,
		"removed": removed,
		"path":    path,
	}, nil
}

// ---------------------------------------------------------------------
// YAML write helpers (minimal, additive, no concurrency-safety beyond
// the per-server mutex; the dynamic-denies file is operator-edited so
// last-write-wins is acceptable. The fsnotify watcher in the proxy
// reloads on the resulting file change.)
// ---------------------------------------------------------------------

func appendDenyRule(path string, rule dynamicdeny.Rule) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir for dynamic-denies file: %w", err)
	}
	f := dynamicdeny.File{
		SchemaVersion: dynamicdeny.SchemaVersion,
		Product:       dynamicdeny.ProductMagic,
	}
	if raw, err := os.ReadFile(path); err == nil {
		if perr := yaml.Unmarshal(raw, &f); perr != nil {
			return fmt.Errorf("parse existing dynamic-denies %q: %w", path, perr)
		}
		if f.SchemaVersion == "" {
			f.SchemaVersion = dynamicdeny.SchemaVersion
		}
		if f.Product == "" {
			f.Product = dynamicdeny.ProductMagic
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read dynamic-denies %q: %w", path, err)
	}
	f.Denies = append(f.Denies, rule)
	return writeDynamicDeniesAtomic(path, &f)
}

func removeDenyRule(path, id string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read dynamic-denies %q: %w", path, err)
	}
	var f dynamicdeny.File
	if perr := yaml.Unmarshal(raw, &f); perr != nil {
		return false, fmt.Errorf("parse existing dynamic-denies %q: %w", path, perr)
	}
	kept := make([]dynamicdeny.Rule, 0, len(f.Denies))
	removed := false
	for _, r := range f.Denies {
		if r.ID == id {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	f.Denies = kept
	if !removed {
		return false, nil
	}
	if f.SchemaVersion == "" {
		f.SchemaVersion = dynamicdeny.SchemaVersion
	}
	if f.Product == "" {
		f.Product = dynamicdeny.ProductMagic
	}
	if err := writeDynamicDeniesAtomic(path, &f); err != nil {
		return false, err
	}
	return true, nil
}

func writeDynamicDeniesAtomic(path string, f *dynamicdeny.File) error {
	out, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal dynamic-denies: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gbounce-dynamic-denies-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// mintRuleID returns a `dd_<26-char-Crockford-base32>` rule id matching
// the loader's ruleIDPattern. Uses crypto/rand for entropy; the Crockford
// alphabet excludes I/L/O/U.
func mintRuleID() string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var buf [26]byte
	raw := make([]byte, 26)
	if _, err := rand.Read(raw); err != nil {
		// Fallback to time-only entropy if rand fails (extremely unusual).
		ts := time.Now().UnixNano()
		for i := range raw {
			raw[i] = byte(ts >> (uint(i*4) % 56))
		}
	}
	for i := 0; i < 26; i++ {
		buf[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return "dd_" + string(buf[:])
}

// computeExpiresAt parses `N{s,m,h,d,w}` against `now` + returns the
// resulting expiry. Returns (zero, false) for `permanent` so the
// caller leaves ExpiresAt nil.
func computeExpiresAt(now time.Time, duration string) (time.Time, bool) {
	d := strings.TrimSpace(duration)
	if d == "" || d == "permanent" {
		return time.Time{}, false
	}
	if len(d) < 2 {
		return time.Time{}, false
	}
	unit := d[len(d)-1]
	num := d[:len(d)-1]
	var n int
	for _, ch := range num {
		if ch < '0' || ch > '9' {
			return time.Time{}, false
		}
		n = n*10 + int(ch-'0')
	}
	var delta time.Duration
	switch unit {
	case 's':
		delta = time.Duration(n) * time.Second
	case 'm':
		delta = time.Duration(n) * time.Minute
	case 'h':
		delta = time.Duration(n) * time.Hour
	case 'd':
		delta = time.Duration(n) * 24 * time.Hour
	case 'w':
		delta = time.Duration(n) * 7 * 24 * time.Hour
	default:
		return time.Time{}, false
	}
	return now.Add(delta), true
}

// ---------------------------------------------------------------------
// JSON-RPC envelope helpers.
// ---------------------------------------------------------------------

func okResponse(id json.RawMessage, result any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
}

func errResponse(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	}
}
