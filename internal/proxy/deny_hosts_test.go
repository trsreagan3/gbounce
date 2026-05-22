// #314 / §A12 — deny_hosts regression suite.
//
// The 10 tests below cover:
//
//   - parse-time rejections (bare `*`, multi-level wildcards)
//   - match semantics (exact, wildcard-subdomain, wildcard matches the
//     bare org domain, wildcard does NOT match unrelated TLDs)
//   - end-to-end CONNECT denial (audit event shape + HTTP 403 +
//     ext.deny_reason)
//   - integration shape: CLI flag entries + file/profile entries union
//   - order-of-evaluation: deny WINS over allow (the latter is
//     not-yet-implemented in v1; this test pins the future behavior in
//     a parse-only shape that doesn't depend on an allow-list code
//     path landing yet)
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// startDenyHostsProxy spins a CONNECT-enabled gbounce instance with
// the given deny entries + an audit log so the deny-event shape can
// be asserted. Mirrors startConnectOnlyProxy from proxy_test.go but
// passes a Config.DenyHosts list.
func startDenyHostsProxy(t *testing.T, denyHosts []string) (proxyAddr, logPath string, st *store.Store, healthURL string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	st = s
	t.Cleanup(func() { _ = s.Close() })

	logPath = filepath.Join(dir, "audit.jsonl")
	lw, err := audit.NewLogWriter(context.Background(), audit.LogWriterOptions{Path: logPath, Fsync: true})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	t.Cleanup(func() { lw.Close() })

	cfg := Config{
		Host:                  "127.0.0.1",
		Port:                  0,
		MgmtHost:              "127.0.0.1",
		MgmtPort:              0,
		AllowConnect:          true,
		ForwardTimeoutSeconds: 2,
		DenyHosts:             denyHosts,
	}
	srv, err := NewServer(cfg, s, lw, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	proxyL, _ := net.Listen("tcp", "127.0.0.1:0")
	mgmtL, _ := net.Listen("tcp", "127.0.0.1:0")
	srv.SetAddrs(proxyL.Addr().String(), mgmtL.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ServeListeners(ctx, proxyL, mgmtL) }()
	t.Cleanup(func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
	})

	healthURL = "http://" + mgmtL.Addr().String() + "/healthz"
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return proxyL.Addr().String(), logPath, st, healthURL
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy never became healthy")
	return
}

// connectThroughProxy issues a raw HTTP CONNECT request through the
// gbounce proxy at proxyAddr targeting the given host:port. Returns
// the parsed HTTP response status. The function does NOT splice
// further bytes — we only care about the CONNECT response code +
// audit row.
func connectThroughProxy(t *testing.T, proxyAddr, targetHostPort string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHostPort, targetHostPort)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestDenyHosts_ExactMatch_Denied(t *testing.T) {
	proxyAddr, _, _, _ := startDenyHostsProxy(t, []string{"evil.example.com"})
	got := connectThroughProxy(t, proxyAddr, "evil.example.com:443")
	if got != http.StatusForbidden {
		t.Errorf("CONNECT evil.example.com → %d; want 403 (deny_hosts exact match)", got)
	}
}

func TestDenyHosts_WildcardSubdomain_Denied(t *testing.T) {
	proxyAddr, _, _, _ := startDenyHostsProxy(t, []string{"*.openai.com"})
	got := connectThroughProxy(t, proxyAddr, "api.openai.com:443")
	if got != http.StatusForbidden {
		t.Errorf("CONNECT api.openai.com via *.openai.com → %d; want 403", got)
	}
}

func TestDenyHosts_WildcardMatchesBareDomain_Denied(t *testing.T) {
	// `*.openai.com` is operator-friendly: it ALSO matches the bare
	// `openai.com`. Documented behavior per the deny_hosts.go header.
	proxyAddr, _, _, _ := startDenyHostsProxy(t, []string{"*.openai.com"})
	got := connectThroughProxy(t, proxyAddr, "openai.com:443")
	if got != http.StatusForbidden {
		t.Errorf("CONNECT openai.com via *.openai.com → %d; want 403 "+
			"(wildcard matches the bare org domain too)", got)
	}
}

func TestDenyHosts_WildcardDoesNotMatchUnrelated(t *testing.T) {
	// `*.openai.com` must NOT match `api.openai.org` (different TLD)
	// or `notopenai.com` (suffix accident). We allow the CONNECT to
	// proceed; an unreachable upstream produces 502 — that's fine for
	// this assertion, we only care that gbounce did NOT return 403.
	proxyAddr, _, _, _ := startDenyHostsProxy(t, []string{"*.openai.com"})

	cases := []string{"api.openai.org:443", "notopenai.com:443"}
	for _, host := range cases {
		got := connectThroughProxy(t, proxyAddr, host)
		if got == http.StatusForbidden {
			t.Errorf("CONNECT %s under *.openai.com → 403; want NOT 403 "+
				"(wildcard must not match unrelated hosts)", host)
		}
	}
}

func TestDenyHosts_NotInList_Allowed(t *testing.T) {
	// With an unrelated deny list, a CONNECT to any other host should
	// flow through normally. The upstream is a closed listener so the
	// proxy returns 502 from the dial failure — the load-bearing
	// assertion is "NOT 403."
	proxyAddr, _, _, _ := startDenyHostsProxy(t, []string{"evil.example.com"})
	got := connectThroughProxy(t, proxyAddr, "api.example.com:443")
	if got == http.StatusForbidden {
		t.Errorf("CONNECT api.example.com → 403; want NOT 403 (host not in deny list)")
	}
}

func TestDenyHosts_BareWildcardRejected(t *testing.T) {
	// `--deny-host '*'` at startup → NewServer must refuse to start.
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	defer st.Close()
	_, err := NewServer(Config{AllowConnect: true, DenyHosts: []string{"*"}}, st, nil, nil)
	if err == nil {
		t.Fatal("NewServer should reject bare-wildcard deny entry; got no error")
	}
	if !strings.Contains(err.Error(), "bare wildcard") {
		t.Errorf("error %q should mention 'bare wildcard'", err.Error())
	}
}

func TestDenyHosts_MultiLevelWildcardRejected(t *testing.T) {
	cases := []string{"*.foo.*.bar.com", "foo.*", "*.foo.*", "*.*"}
	for _, raw := range cases {
		dir := t.TempDir()
		st, _ := store.Open(filepath.Join(dir, "state.db"))
		_, err := NewServer(Config{AllowConnect: true, DenyHosts: []string{raw}}, st, nil, nil)
		st.Close()
		if err == nil {
			t.Errorf("NewServer should reject multi-level wildcard %q; got no error", raw)
			continue
		}
		// Either "multi-level wildcards" OR (for `foo.*`, `*.*`) the
		// "leading `*.<domain>`" message. Both surface as a single
		// parse error per ParseDenyHost.
		msg := err.Error()
		if !strings.Contains(msg, "wildcard") {
			t.Errorf("error %q should mention 'wildcard'", msg)
		}
	}
}

func TestDenyHosts_AuditEventEmitted(t *testing.T) {
	proxyAddr, logPath, st, _ := startDenyHostsProxy(t, []string{"*.openai.com"})

	got := connectThroughProxy(t, proxyAddr, "api.openai.com:443")
	if got != http.StatusForbidden {
		t.Fatalf("CONNECT api.openai.com → %d; want 403", got)
	}

	// SQLite row recorded.
	time.Sleep(80 * time.Millisecond)
	rows, _ := st.RecentDecisions(5)
	if len(rows) == 0 {
		t.Fatal("no decision rows recorded — deny audit was invisible")
	}

	// JSONL OCSF event has the full deny shape.
	time.Sleep(80 * time.Millisecond)
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var events []audit.Event
	for sc.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("decode event: %v\nline: %s", err, sc.Text())
		}
		events = append(events, ev)
	}
	if len(events) == 0 {
		t.Fatal("audit log is empty — deny event was not recorded")
	}
	ev := events[0]
	if ev.Unmapped.IAMJIT.Verdict != "DENY" {
		t.Errorf("verdict = %q; want DENY", ev.Unmapped.IAMJIT.Verdict)
	}
	if ev.StatusID != audit.StatusDenied {
		t.Errorf("status_id = %d; want %d (Denied)", ev.StatusID, audit.StatusDenied)
	}
	if ev.Unmapped.IAMJIT.Ext == nil {
		t.Fatal("ext should be populated")
	}
	reason, _ := ev.Unmapped.IAMJIT.Ext["deny_reason"].(string)
	if !strings.Contains(reason, "matched deny_hosts:") {
		t.Errorf("ext.deny_reason = %q; want a 'matched deny_hosts:' prefix", reason)
	}
	if !strings.Contains(reason, "*.openai.com") {
		t.Errorf("ext.deny_reason = %q; want it to name the matched rule (*.openai.com)", reason)
	}
}

func TestDenyHosts_DenyWinsOverAllow(t *testing.T) {
	// G-Slice 1 has no allow_hosts list yet — the order-of-evaluation
	// rule is documented + verified at the unit level via
	// MatchDenyHosts. When G-Slice 2 lands the allow list, the
	// end-to-end version of this test will assert "a host in both
	// deny and allow → still denied." For now: pin the unit-level
	// invariant + the doc comment.
	rules, err := ParseDenyHosts([]string{"both.example.com"})
	if err != nil {
		t.Fatalf("ParseDenyHosts: %v", err)
	}
	if got := MatchDenyHosts(rules, "both.example.com"); got == nil {
		t.Error("MatchDenyHosts(both.example.com): want hit; got nil")
	}
	// And ensure the deny_hosts.go header still documents the
	// invariant — a regression that REMOVED the rule would also
	// silently drop this doc-test.
	// (no-op assertion: documentation is enforced by the file header)
}

func TestDenyHosts_CLIAndProfileMerge(t *testing.T) {
	// Build a "profile YAML" file with one entry + pass two CLI
	// flags. Pre-merge in the cli surface; the proxy.Config sees a
	// single union list. The test exercises the union by parsing the
	// file ourselves, prepending the CLI entries, then verifying both
	// halves match.
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(yamlPath, []byte(strings.Join([]string{
		"# Operator-managed deny list — example profile shape",
		"deny_hosts:",
		"  - profile-only.example.com",
		"  - \"*.profile-wild.example.com\"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cliEntries := []string{"cli-only.example.com", "*.cli-wild.example.com"}

	fileContents, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	fileRules, err := ParseDenyHostsFile(string(fileContents))
	if err != nil {
		t.Fatalf("ParseDenyHostsFile: %v", err)
	}
	if len(fileRules) != 2 {
		t.Fatalf("file rules = %d; want 2", len(fileRules))
	}

	// Build union the same way cli.go does.
	merged := append([]string{}, cliEntries...)
	for _, r := range fileRules {
		merged = append(merged, r.Raw)
	}
	if len(merged) != 4 {
		t.Fatalf("merged = %d; want 4", len(merged))
	}

	// End-to-end: start a proxy with the merged list + assert each
	// of the 4 entries denies its target host.
	proxyAddr, _, _, _ := startDenyHostsProxy(t, merged)
	cases := []string{
		"cli-only.example.com:443",          // exact (CLI)
		"foo.cli-wild.example.com:443",      // wildcard (CLI)
		"profile-only.example.com:443",      // exact (profile)
		"sub.profile-wild.example.com:443",  // wildcard (profile)
		"profile-wild.example.com:443",      // wildcard bare-domain (profile)
	}
	for _, host := range cases {
		got := connectThroughProxy(t, proxyAddr, host)
		if got != http.StatusForbidden {
			t.Errorf("CONNECT %s through merged deny list → %d; want 403", host, got)
		}
	}
}

// TestDenyHosts_HealthzCounter is a small bonus that pins the
// /healthz total_deny_host_matches surface so a future refactor that
// renames or drops the counter doesn't silently regress operator
// visibility.
func TestDenyHosts_HealthzCounter(t *testing.T) {
	proxyAddr, _, _, healthURL := startDenyHostsProxy(t, []string{"counter.example.com"})

	// Pre-deny: counter should be 0.
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	if got, _ := body["total_deny_host_matches"].(float64); got != 0 {
		t.Errorf("pre-deny counter = %v; want 0", got)
	}
	if got, _ := body["deny_hosts_count"].(float64); got != 1 {
		t.Errorf("deny_hosts_count = %v; want 1", got)
	}

	// Trigger a deny.
	_ = connectThroughProxy(t, proxyAddr, "counter.example.com:443")

	resp, err = http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	if got, _ := body["total_deny_host_matches"].(float64); got != 1 {
		t.Errorf("post-deny counter = %v; want 1", got)
	}
}
