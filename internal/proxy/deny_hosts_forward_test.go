// #353 / §A28 — deny_hosts enforcement in reverse-proxy (handleForward)
// mode. Prior to this fix, `--deny-host` was silently ignored when
// gbounce ran with `--upstream <url>`; deny enforcement only ran in
// handleConnect (CONNECT-tunnel mode) and handleMITMConnect. The tests
// below lock in the fix:
//
//   - exact-match Host header → 403
//   - wildcard Host header   → 403
//   - allowed Host header    → proxied through to upstream (NOT 403)
//   - IP-literal upstream deny → 403 (the dogfood repro shape)
//   - audit event shape matches the CONNECT-mode deny event
//
// Mirrors deny_hosts_test.go's startDenyHostsProxy harness but plumbs
// in a real httptest.Server upstream so handleForward is exercised.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// startDenyHostsForwardProxy spins a reverse-proxy gbounce instance
// (UpstreamURL set, AllowConnect=false) with the given deny entries and
// an audit log so the deny-event shape can be asserted. The upstream is
// the caller's responsibility (typically an httptest.Server); pass its
// URL as upstreamURL.
func startDenyHostsForwardProxy(t *testing.T, upstreamURL string, denyHosts []string) (proxyAddr, logPath string, st *store.Store) {
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
		UpstreamURL:           upstreamURL,
		AllowConnect:          false,
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

	healthURL := "http://" + mgmtL.Addr().String() + "/healthz"
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return proxyL.Addr().String(), logPath, st
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy never became healthy")
	return
}

// forwardWithHost issues a GET to proxyAddr with an override Host
// header. Returns the status code. Uses a low-level Dial so the Host
// header lands on the wire as written (net/http normalizes Request.Host
// vs Header["Host"] inconsistently otherwise).
func forwardWithHost(t *testing.T, proxyAddr, hostHeader, path string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + path + " HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestHandleForward_DenyHostExactMatch(t *testing.T) {
	// Upstream is a real httptest server; if the deny-host check is
	// missing, the request flows through and we'd see 200 — the test
	// fails cleanly that way (the OPPOSITE of "upstream unreachable
	// masks the bug").
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, _, _ := startDenyHostsForwardProxy(t, upstream.URL, []string{"evil.example.com"})
	got := forwardWithHost(t, proxyAddr, "evil.example.com", "/anything")
	if got != http.StatusForbidden {
		t.Errorf("GET (Host: evil.example.com) → %d; want 403 (deny_hosts exact match)", got)
	}
}

func TestHandleForward_DenyHostWildcard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, _, _ := startDenyHostsForwardProxy(t, upstream.URL, []string{"*.evil.com"})
	got := forwardWithHost(t, proxyAddr, "api.evil.com", "/anything")
	if got != http.StatusForbidden {
		t.Errorf("GET (Host: api.evil.com) via *.evil.com → %d; want 403", got)
	}
}

func TestHandleForward_AllowedHost(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, _, _ := startDenyHostsForwardProxy(t, upstream.URL, []string{"evil.example.com"})
	got := forwardWithHost(t, proxyAddr, "good.example.com", "/anything")
	if got == http.StatusForbidden {
		t.Errorf("GET (Host: good.example.com) → 403; want NOT 403 (host not in deny list)")
	}
	if got != http.StatusOK {
		t.Errorf("GET (Host: good.example.com) → %d; want 200 (proxied through)", got)
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Errorf("upstream hit count = %d; want 1 (request must reach upstream)",
			atomic.LoadInt32(&upstreamHits))
	}
}

func TestHandleForward_DenyHostByIP(t *testing.T) {
	// The dogfood repro shape: --deny-host 127.0.0.1 + --upstream
	// http://127.0.0.1:<port>. The deny matches the upstream host (we
	// fall through to the second candidate in handleForward when the
	// inbound Host header is also 127.0.0.1 — but the load-bearing
	// assertion is "403, not 200 / 502").
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// upstream.URL is http://127.0.0.1:<port>.
	proxyAddr, _, _ := startDenyHostsForwardProxy(t, upstream.URL, []string{"127.0.0.1"})
	// Default Go HTTP client will set Host to the proxy host (also
	// 127.0.0.1) so either candidate fires the deny.
	got := forwardWithHost(t, proxyAddr, "127.0.0.1", "/anything")
	if got != http.StatusForbidden {
		t.Errorf("GET (deny 127.0.0.1 + upstream 127.0.0.1) → %d; want 403", got)
	}
}

func TestHandleForward_AuditEventEmitted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, logPath, st := startDenyHostsForwardProxy(t, upstream.URL, []string{"*.evil.com"})
	got := forwardWithHost(t, proxyAddr, "api.evil.com", "/anything")
	if got != http.StatusForbidden {
		t.Fatalf("GET (Host: api.evil.com) → %d; want 403", got)
	}

	// SQLite row recorded.
	time.Sleep(80 * time.Millisecond)
	rows, _ := st.RecentDecisions(5)
	if len(rows) == 0 {
		t.Fatal("no decision rows recorded — deny audit was invisible")
	}

	// JSONL OCSF event has the full deny shape (same fields as the
	// handleConnect-mode deny event so cross-mode SIEM queries don't
	// see schema drift).
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
	// Find the deny event (there may be multiple if the proxy emitted
	// a startup event etc — filter by verdict).
	var denyEv *audit.Event
	for i := range events {
		if events[i].Unmapped.IAMJIT.Verdict == "DENY" {
			denyEv = &events[i]
			break
		}
	}
	if denyEv == nil {
		t.Fatal("no DENY-verdict event found in audit log")
	}
	if denyEv.StatusID != audit.StatusDenied {
		t.Errorf("status_id = %d; want %d (Denied)", denyEv.StatusID, audit.StatusDenied)
	}
	if denyEv.Unmapped.IAMJIT.Ext == nil {
		t.Fatal("ext should be populated")
	}
	reason, _ := denyEv.Unmapped.IAMJIT.Ext["deny_reason"].(string)
	if !strings.Contains(reason, "matched deny_hosts:") {
		t.Errorf("ext.deny_reason = %q; want a 'matched deny_hosts:' prefix", reason)
	}
	if !strings.Contains(reason, "*.evil.com") {
		t.Errorf("ext.deny_reason = %q; want it to name the matched rule '*.evil.com'", reason)
	}
	// Source attribution — same shape as the CONNECT-mode deny event.
	src, _ := denyEv.Unmapped.IAMJIT.Ext["deny_source"].(string)
	if src != DenySourceStatic {
		t.Errorf("ext.deny_source = %q; want %q", src, DenySourceStatic)
	}
}
