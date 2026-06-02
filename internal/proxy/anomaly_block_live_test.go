// anomaly_block_live_test.go proves Phase H block-mode ENFORCEMENT
// through the REAL gbounce decision path (iam-jit#59) — not d.Run /
// d.Decide in isolation, but an actual HTTP request flowing through
// handleForward against a live httptest upstream.
//
// Coverage:
//   - TestBlockModeEnforcesViaPreDecisionLivePath: a volume-spike burst
//     in mode=block is eventually DENIED (403) by the live proxy + the
//     upstream stops receiving the burst. This is the load-bearing proof
//     that block now enforces pre-decision.
//   - TestBlockModeCannotLoosenFloorDenyLivePath: a deny_hosts floor-deny
//     stays 403 even with an anomalous burst — the anomaly path is only
//     consulted on a non-deny floor and is tighten-only.
//   - TestAlertModeNeverDeniesLivePath: the same burst in the default
//     alert mode is NEVER denied (every request 200) — default behavior
//     preserved.
package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/anomaly"
	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// startAnomalyProxy spins a reverse-proxy gbounce instance with a wired
// anomaly Detector (the given config) + the given deny hosts, returning
// the proxy listen address and a hit counter for the upstream.
func startAnomalyProxy(t *testing.T, upstreamURL string, denyHosts []string, cfg anomaly.Config) (proxyAddr string, srv *Server) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	lw, err := audit.NewLogWriter(context.Background(), audit.LogWriterOptions{
		Path: filepath.Join(dir, "audit.jsonl"), Fsync: false,
	})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	t.Cleanup(func() { lw.Close() })

	srv, err = NewServer(Config{
		Host: "127.0.0.1", Port: 0, MgmtHost: "127.0.0.1", MgmtPort: 0,
		UpstreamURL: upstreamURL, AllowConnect: false, ForwardTimeoutSeconds: 2,
		DenyHosts: denyHosts,
	}, s, lw, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Wire the anomaly detector BEFORE serving so the live decision path
	// consults it.
	srv.SetAnomalyDetector(srv.NewAnomalyDetector(cfg))

	proxyL, _ := net.Listen("tcp", "127.0.0.1:0")
	mgmtL, _ := net.Listen("tcp", "127.0.0.1:0")
	srv.SetAddrs(proxyL.Addr().String(), mgmtL.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ServeListeners(ctx, proxyL, mgmtL) }()
	t.Cleanup(func() { cancel(); time.Sleep(30 * time.Millisecond) })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + mgmtL.Addr().String() + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return proxyL.Addr().String(), srv
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("proxy never became healthy")
	return
}

// getStatus drives a single GET through the proxy and returns the HTTP
// status. Host carries the agent identity-bearing target.
func getStatus(t *testing.T, proxyAddr, host, path, agent string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
	if agent != "" {
		req += "X-Agent-Name: " + agent + "\r\n"
	}
	req += "Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func blockCfg(mode string) anomaly.Config {
	c := anomaly.DefaultConfig()
	c.Enabled = true
	c.Mode = mode
	c.Sensitivity = "medium"
	c.MinActionsForBaseline = 5
	return c
}

// TestBlockModeEnforcesViaPreDecisionLivePath: a sharp burst through the
// LIVE proxy in mode=block must eventually be DENIED (403). This fails if
// block does not enforce pre-decision (every request would 200).
func TestBlockModeEnforcesViaPreDecisionLivePath(t *testing.T) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, _ := startAnomalyProxy(t, upstream.URL, nil, blockCfg("block"))

	// Drive a volume-spike burst for one (agent, action, resource). The
	// recent-window rate climbs above the learned per-hour baseline mean,
	// so the action_frequency dimension trips and Decide tightens
	// allow->deny BEFORE the upstream is dialed.
	denied := false
	for i := 0; i < 400; i++ {
		if getStatus(t, proxyAddr, "good.example.com", "/v1/data", "agent-burst") == http.StatusForbidden {
			denied = true
			break
		}
	}
	if !denied {
		t.Fatalf("block mode never DENIED an anomalous burst through the live path; "+
			"block is not enforcing pre-decision (upstream hits=%d)", atomic.LoadInt32(&hits))
	}
}

// TestBlockModeCannotLoosenFloorDenyLivePath: a deny_hosts floor-deny
// must stay 403 even while an anomalous burst is running. The anomaly
// path is consulted only AFTER deny_hosts passes (non-deny floor), so it
// can never turn a deterministic deny into an allow.
func TestBlockModeCannotLoosenFloorDenyLivePath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// deny_hosts denies the target outright (the deterministic floor).
	proxyAddr, _ := startAnomalyProxy(t, upstream.URL, []string{"locked.example.com"}, blockCfg("block"))

	// Every request to the denied host must be 403 — never loosened to a
	// 200 by the anomaly machinery, regardless of how many we send.
	for i := 0; i < 50; i++ {
		got := getStatus(t, proxyAddr, "locked.example.com", "/v1/data", "agent-x")
		if got != http.StatusForbidden {
			t.Fatalf("floor-deny request #%d → %d; want 403 (anomaly must NEVER loosen a deny)", i, got)
		}
	}
}

// TestAlertModeNeverDeniesLivePath: the same burst in the default alert
// mode must NEVER be denied through the live path. Default behavior
// preserved: alert only flags.
func TestAlertModeNeverDeniesLivePath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, srv := startAnomalyProxy(t, upstream.URL, nil, blockCfg("alert"))
	for i := 0; i < 400; i++ {
		if got := getStatus(t, proxyAddr, "good.example.com", "/v1/data", "agent-alert"); got == http.StatusForbidden {
			t.Fatalf("alert mode DENIED request #%d (403); alert must never block", i)
		}
	}
	// The detector should still have flagged the spike (alert surfaces it)
	// even though it never denied.
	if flagged := srv.anomalyDetector.Status()["anomalies_flagged"].(int64); flagged < 1 {
		t.Fatalf("alert mode should still FLAG the spike for review; anomalies_flagged=%d", flagged)
	}
}

// TestDisabledDetectorNeverDeniesLivePath: default-off — an unconfigured
// detector must let everything through (no 403 from the anomaly path).
func TestDisabledDetectorNeverDeniesLivePath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, _ := startAnomalyProxy(t, upstream.URL, nil, anomaly.DefaultConfig()) // disabled
	for i := 0; i < 200; i++ {
		if got := getStatus(t, proxyAddr, "good.example.com", "/v1/data", "agent-off"); got == http.StatusForbidden {
			t.Fatalf("disabled detector DENIED request #%d (403); default-off must never block", i)
		}
	}
}
