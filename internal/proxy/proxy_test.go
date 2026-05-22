package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// startTestProxy spins a gbounce proxy in front of the given upstream
// httptest.Server and returns the proxy base URL + the mgmt /healthz
// URL + the store + the audit-log path. Cleanup is registered with t.
func startTestProxy(t *testing.T, upstream *httptest.Server, withAuditLog bool, allowConnect bool) (proxyURL, healthURL string, st *store.Store, logPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	st = s
	t.Cleanup(func() { _ = s.Close() })

	var lw *audit.LogWriter
	if withAuditLog {
		logPath = filepath.Join(dir, "audit.jsonl")
		lw, err = audit.NewLogWriter(context.Background(), audit.LogWriterOptions{Path: logPath, Fsync: true})
		if err != nil {
			t.Fatalf("NewLogWriter: %v", err)
		}
		t.Cleanup(func() { lw.Close() })
	}

	cfg := Config{
		Host:                  "127.0.0.1",
		Port:                  0,
		MgmtHost:              "127.0.0.1",
		MgmtPort:              0,
		UpstreamURL:           "",
		AllowConnect:          allowConnect,
		ForwardTimeoutSeconds: 5,
	}
	if upstream != nil {
		cfg.UpstreamURL = upstream.URL
	}

	srv, err := NewServer(cfg, s, lw, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mgmt: %v", err)
	}
	srv.SetAddrs(proxyL.Addr().String(), mgmtL.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.ServeListeners(ctx, proxyL, mgmtL)
	}()
	t.Cleanup(func() {
		cancel()
		time.Sleep(50 * time.Millisecond)
	})

	proxyURL = "http://" + proxyL.Addr().String()
	healthURL = "http://" + mgmtL.Addr().String() + "/healthz"

	// Wait for /healthz to respond.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy never became healthy")
	return
}

func TestProxy_HealthzReturnsJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	_, healthURL, _, _ := startTestProxy(t, upstream, false, false)
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" || body["product"] != "gbounce" {
		t.Errorf("body = %+v", body)
	}
	if body["mode"] != "discovery" {
		t.Errorf("mode = %v", body["mode"])
	}
}

func TestProxy_GETForwardedVerbatim(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/things" {
			t.Errorf("upstream got path %q", r.URL.Path)
		}
		if r.Header.Get("X-Test") != "yes" {
			t.Errorf("upstream missing header; got %q", r.Header.Get("X-Test"))
		}
		w.Header().Set("X-Echo", "hello")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	proxyURL, _, st, _ := startTestProxy(t, upstream, false, false)

	req, _ := http.NewRequest("GET", proxyURL+"/v1/things", nil)
	req.Header.Set("X-Test", "yes")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Echo") != "hello" {
		t.Errorf("response header not forwarded; got %q", resp.Header.Get("X-Echo"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Errorf("body = %q", string(body))
	}

	// Audit row recorded.
	time.Sleep(50 * time.Millisecond)
	n, err := st.CountDecisions()
	if err != nil {
		t.Fatalf("CountDecisions: %v", err)
	}
	if n < 1 {
		t.Errorf("decisions = %d; want >= 1", n)
	}
	rows, _ := st.RecentDecisions(5)
	if len(rows) == 0 || rows[0].Method != "GET" || rows[0].Path != "/v1/things" {
		t.Errorf("row[0] = %+v", rows[0])
	}
	if rows[0].HTTPStatus != 200 {
		t.Errorf("row.HTTPStatus = %d", rows[0].HTTPStatus)
	}
	if rows[0].Verdict != "ALLOW" {
		t.Errorf("row.Verdict = %q; want ALLOW", rows[0].Verdict)
	}
}

func TestProxy_POSTBodyForwarded(t *testing.T) {
	got := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.WriteHeader(201)
	}))
	defer upstream.Close()

	proxyURL, _, _, _ := startTestProxy(t, upstream, false, false)
	resp, err := http.Post(proxyURL+"/v1/things", "application/json", strings.NewReader(`{"x":1}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	select {
	case body := <-got:
		if body != `{"x":1}` {
			t.Errorf("upstream body = %q", body)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("upstream never received body")
	}
}

func TestProxy_AuditLogEmitsOCSFEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	proxyURL, _, _, logPath := startTestProxy(t, upstream, true, false)
	resp, err := http.Get(proxyURL + "/v1/test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	// Give the audit-log worker time to flush.
	time.Sleep(150 * time.Millisecond)

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !sc.Scan() {
		t.Fatal("audit log is empty")
	}
	var ev audit.Event
	if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if ev.Metadata.Product.Name != "gbounce" {
		t.Errorf("product = %q", ev.Metadata.Product.Name)
	}
	if ev.ClassUID != 6003 {
		t.Errorf("class_uid = %d", ev.ClassUID)
	}
	if ev.ActivityID != audit.ActivityRead {
		t.Errorf("activity_id = %d", ev.ActivityID)
	}
	if !strings.HasPrefix(ev.API.Operation, "GET ") {
		t.Errorf("api.operation = %q", ev.API.Operation)
	}
	if ev.API.Operation != "GET /v1/test" {
		t.Errorf("api.operation = %q", ev.API.Operation)
	}
	if ev.Unmapped.IAMJIT.Verdict != "ALLOW" {
		t.Errorf("verdict = %q", ev.Unmapped.IAMJIT.Verdict)
	}
	if ev.Unmapped.IAMJIT.Enforced {
		t.Errorf("enforced should be false")
	}
}

func TestProxy_HopByHopHeadersStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") != "" {
			t.Errorf("Connection header should have been stripped; got %q", r.Header.Get("Connection"))
		}
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("Proxy-Authorization should have been stripped; got %q", r.Header.Get("Proxy-Authorization"))
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	proxyURL, _, _, _ := startTestProxy(t, upstream, false, false)
	req, _ := http.NewRequest("GET", proxyURL+"/", nil)
	req.Header.Set("Connection", "close")
	req.Header.Set("Proxy-Authorization", "Basic xxx")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
}

func TestProxy_RejectsBadUpstream(t *testing.T) {
	dir := t.TempDir()
	s, _ := store.Open(filepath.Join(dir, "state.db"))
	defer s.Close()
	_, err := NewServer(Config{UpstreamURL: "ftp://nope.example"}, s, nil, nil)
	if err == nil {
		t.Fatal("expected error for non-http upstream scheme")
	}
}

func TestProxy_RequiresUpstreamOrConnect(t *testing.T) {
	dir := t.TempDir()
	s, _ := store.Open(filepath.Join(dir, "state.db"))
	defer s.Close()
	_, err := NewServer(Config{}, s, nil, nil)
	if err == nil {
		t.Fatal("expected error when neither --upstream nor --allow-connect")
	}
}

func TestProxy_CONNECTRefusedWhenDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()

	proxyURL, _, _, _ := startTestProxy(t, upstream, false, false /* allowConnect=false */)
	u, _ := url.Parse(proxyURL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("CONNECT status = %d; want 405", resp.StatusCode)
	}
}

func TestProxy_CONNECTSplicesWhenEnabled(t *testing.T) {
	// Set up a "fake upstream" — a plain TCP server that echoes a
	// fixed banner so we can prove the CONNECT splice flowed bytes.
	upstreamL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamL.Close()
	const banner = "ECHO BANNER\n"
	go func() {
		for {
			c, err := upstreamL.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				// Drain whatever client writes to keep them happy.
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	proxyURL, _, st, _ := startTestProxy(t, nil, false, true /* allowConnect=true */)
	u, _ := url.Parse(proxyURL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamL.Addr(), upstreamL.Addr())
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d; want 200", resp.StatusCode)
	}
	// Bytes from the upstream should now flow through the splice.
	got := make([]byte, len(banner))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != banner {
		t.Errorf("splice got %q; want %q", string(got), banner)
	}

	// Audit row recorded with method=CONNECT.
	time.Sleep(50 * time.Millisecond)
	rows, _ := st.RecentDecisions(5)
	found := false
	for _, r := range rows {
		if r.Method == "CONNECT" {
			found = true
			if r.HTTPStatus != 200 {
				t.Errorf("CONNECT row HTTPStatus = %d; want 200", r.HTTPStatus)
			}
			break
		}
	}
	if !found {
		t.Errorf("no CONNECT row in audit: %+v", rows)
	}
}

func TestProxy_RecordsOnUpstreamError(t *testing.T) {
	// Upstream that closes the connection without responding so the
	// proxy gets an error from client.Do.
	upstreamL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := upstreamL.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	defer upstreamL.Close()

	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	defer st.Close()
	cfg := Config{
		UpstreamURL:           "http://" + upstreamL.Addr().String(),
		ForwardTimeoutSeconds: 2,
	}
	srv, err := NewServer(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	pL, _ := net.Listen("tcp", "127.0.0.1:0")
	mL, _ := net.Listen("tcp", "127.0.0.1:0")
	srv.SetAddrs(pL.Addr().String(), mL.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ServeListeners(ctx, pL, mL)
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get("http://" + pL.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d; want 502", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	rows, _ := st.RecentDecisions(5)
	if len(rows) == 0 || rows[0].HTTPStatus != http.StatusBadGateway {
		t.Errorf("expected 502 audit row, got %+v", rows)
	}
}

func TestProxy_MisconfiguredCONNECTOnlyRejectsForward(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "state.db"))
	defer st.Close()
	cfg := Config{AllowConnect: true}
	srv, err := NewServer(cfg, st, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	pL, _ := net.Listen("tcp", "127.0.0.1:0")
	mL, _ := net.Listen("tcp", "127.0.0.1:0")
	srv.SetAddrs(pL.Addr().String(), mL.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ServeListeners(ctx, pL, mL)
	time.Sleep(50 * time.Millisecond)
	resp, err := http.Get("http://" + pL.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status = %d; want 421", resp.StatusCode)
	}
}

func TestLicensedForGbounce(t *testing.T) {
	if err := LicensedForGbounce(ModeDiscovery); err != nil {
		t.Errorf("discovery should be free; got %v", err)
	}
	if err := LicensedForGbounce(Mode("profile")); err == nil {
		t.Error("non-discovery modes should require a license")
	}
}

// startConnectOnlyProxy spins a gbounce instance with no --upstream (so
// non-CONNECT requests get the 421 path that #305 audits) + CONNECT
// enabled (so #303's failed-dial path is exercisable). Returns proxy
// address + audit-log path + store handle for assertions.
//
// Shared helper between the three #303/#305 regression tests; matches
// the existing startTestProxy signature shape so the test file stays
// uniform.
func startConnectOnlyProxy(t *testing.T) (proxyAddr, logPath string, st *store.Store) {
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
		AllowConnect:          true, // #303 needs the CONNECT path live
		ForwardTimeoutSeconds: 2,
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

// readAuditEvents drains a JSONL audit-log file into a slice of
// audit.Event for assertion. Sleeps a beat first to let the
// async-writer goroutine flush. Shared between the #303/#305 tests.
func readAuditEvents(t *testing.T, logPath string) []audit.Event {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []audit.Event
	for sc.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("decode event: %v\nline: %s", err, sc.Text())
		}
		out = append(out, ev)
	}
	return out
}

// TestProxy_UnreachableHostCONNECTLogged is the #303 regression: a
// CONNECT to a host that refuses TCP (we listen on a port then close
// the listener so the next dial is "connection refused") must land in
// the audit log with verdict=ALLOW + activity_id=Connect +
// status_id=Failure + ext.connect_refused=true.
//
// Picks an unreachable host by binding a TCP listener, capturing its
// address, then closing it — guaranteed-refused on every OS without
// touching 169.254/16 (which some CI environments route weirdly).
func TestProxy_UnreachableHostCONNECTLogged(t *testing.T) {
	// Reserve a port then close — the next dial to it is refused.
	tmpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tmp: %v", err)
	}
	refusedAddr := tmpL.Addr().String()
	_ = tmpL.Close()

	proxyAddr, logPath, st := startConnectOnlyProxy(t)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", refusedAddr, refusedAddr)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d; want 502", resp.StatusCode)
	}

	// SQLite row recorded with the connect-failure HTTPStatus.
	time.Sleep(80 * time.Millisecond)
	rows, _ := st.RecentDecisions(10)
	if len(rows) == 0 {
		t.Fatal("no decision rows recorded — #303 regression")
	}

	// OCSF event landed with #303's full extension shape.
	events := readAuditEvents(t, logPath)
	if len(events) == 0 {
		t.Fatal("audit log is empty — #303 regression: failed CONNECT was invisible")
	}
	ev := events[0]
	if ev.ActivityID != audit.ActivityConnect {
		t.Errorf("activity_id = %d; want %d (Connect)", ev.ActivityID, audit.ActivityConnect)
	}
	if ev.StatusID != audit.StatusFailure {
		t.Errorf("status_id = %d; want %d (Failure)", ev.StatusID, audit.StatusFailure)
	}
	if ev.Unmapped.IAMJIT.Verdict != "ALLOW" {
		t.Errorf("verdict = %q; want ALLOW (intent was to allow, upstream unreachable)", ev.Unmapped.IAMJIT.Verdict)
	}
	if ev.Unmapped.IAMJIT.Ext == nil {
		t.Fatal("ext should be populated")
	}
	if ev.Unmapped.IAMJIT.Ext["connect_refused"] != true {
		t.Errorf("ext.connect_refused = %v; want true", ev.Unmapped.IAMJIT.Ext["connect_refused"])
	}
	if s, ok := ev.Unmapped.IAMJIT.Ext["connect_error"].(string); !ok || s == "" {
		t.Errorf("ext.connect_error = %v; want a non-empty string", ev.Unmapped.IAMJIT.Ext["connect_error"])
	}
	// Same host:port extraction as the successful CONNECT path — the
	// SIEM filter `dst_endpoint.hostname=...` works for both success +
	// failure.
	if ev.DstEndpoint == nil || ev.DstEndpoint.Hostname == "" {
		t.Errorf("dst_endpoint = %+v; want host:port populated", ev.DstEndpoint)
	}
}

// TestProxy_NonCONNECTRequestLogged is the #305 regression: a plain
// GET sent through the proxy port on a CONNECT-only listener must
// return 421 AND land in the audit log with verdict=DENY +
// status_id=Denied + ext.deny_reason. IMDS attacks (which ride plain
// HTTP, not HTTPS) become visible.
func TestProxy_NonCONNECTRequestLogged(t *testing.T) {
	proxyAddr, logPath, st := startConnectOnlyProxy(t)

	// Send a proxy-style GET request: the client's proxy code puts the
	// full URL on the request-target line + the destination in Host.
	// `169.254.169.254` is the canonical IMDS endpoint; useful to
	// confirm the host shows up in the audit row (the attack visibility
	// is the whole point of #305).
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status = %d; want 421", resp.StatusCode)
	}

	// SQLite row recorded with verdict=DENY.
	time.Sleep(80 * time.Millisecond)
	rows, _ := st.RecentDecisions(10)
	if len(rows) == 0 {
		t.Fatal("no decision rows recorded — #305 regression")
	}
	if rows[0].Verdict != "DENY" {
		t.Errorf("row.Verdict = %q; want DENY", rows[0].Verdict)
	}
	if rows[0].UpstreamHost != "169.254.169.254" {
		t.Errorf("row.UpstreamHost = %q; want 169.254.169.254 (IMDS visibility)", rows[0].UpstreamHost)
	}

	// OCSF event landed with #305's full extension shape.
	events := readAuditEvents(t, logPath)
	if len(events) == 0 {
		t.Fatal("audit log is empty — #305 regression: rejected non-CONNECT was invisible")
	}
	ev := events[0]
	if ev.StatusID != audit.StatusDenied {
		t.Errorf("status_id = %d; want %d (Denied)", ev.StatusID, audit.StatusDenied)
	}
	if ev.Unmapped.IAMJIT.Verdict != "DENY" {
		t.Errorf("verdict = %q; want DENY", ev.Unmapped.IAMJIT.Verdict)
	}
	if ev.Unmapped.IAMJIT.Ext == nil {
		t.Fatal("ext should be populated")
	}
	reason, _ := ev.Unmapped.IAMJIT.Ext["deny_reason"].(string)
	if reason != "non-CONNECT method on CONNECT-only listener" {
		t.Errorf("ext.deny_reason = %q; want non-CONNECT-on-CONNECT-only message", reason)
	}
	// Method + path captured pre-TLS — agent operator can see what was
	// probed even though the response was rejected.
	if !strings.HasPrefix(ev.API.Operation, "GET ") {
		t.Errorf("api.operation = %q; want GET …", ev.API.Operation)
	}
	if !strings.Contains(ev.API.Operation, "/latest/meta-data") {
		t.Errorf("api.operation = %q; want path captured", ev.API.Operation)
	}
}

// TestProxy_DNSFailureCONNECTLogged is the #303 regression on the DNS-
// failure leg: a CONNECT to a non-resolvable hostname must still land
// in the audit log with verdict=ALLOW + status_id=Failure +
// ext.connect_refused=true. SSRF probes that use opaque hostnames
// (vs. raw IPs) take this leg.
func TestProxy_DNSFailureCONNECTLogged(t *testing.T) {
	proxyAddr, logPath, _ := startConnectOnlyProxy(t)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	// `.invalid` is the RFC 6761 reserved TLD that DNS resolvers MUST
	// fail to resolve — guaranteed DNS-error path without depending on
	// network state.
	const badHost = "definitely-does-not-exist-x9q7.invalid:443"
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", badHost, badHost)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d; want 502", resp.StatusCode)
	}

	events := readAuditEvents(t, logPath)
	if len(events) == 0 {
		t.Fatal("audit log is empty — #303 DNS-failure regression: failed CONNECT was invisible")
	}
	ev := events[0]
	if ev.ActivityID != audit.ActivityConnect {
		t.Errorf("activity_id = %d; want %d (Connect)", ev.ActivityID, audit.ActivityConnect)
	}
	if ev.StatusID != audit.StatusFailure {
		t.Errorf("status_id = %d; want %d (Failure)", ev.StatusID, audit.StatusFailure)
	}
	if ev.Unmapped.IAMJIT.Ext == nil || ev.Unmapped.IAMJIT.Ext["connect_refused"] != true {
		t.Errorf("ext.connect_refused = %v; want true", ev.Unmapped.IAMJIT.Ext)
	}
	if ev.DstEndpoint == nil || ev.DstEndpoint.Hostname != "definitely-does-not-exist-x9q7.invalid" {
		t.Errorf("dst_endpoint = %+v; want bad hostname captured", ev.DstEndpoint)
	}
}
