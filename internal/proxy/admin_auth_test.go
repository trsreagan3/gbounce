// admin_auth_test.go — #524 BB-3 + BB-4 state-verification tests for
// the mgmt-port admin-endpoint auth middleware (requireMgmtAuth) and
// the /healthz field-scoping helper (requestAuthenticatedOrLoopback).
//
// Test corpus mirrors the shape filed against kbouncer + dbounce so
// the cross-product agent parity per [[cross-product-agent-parity]]
// stays auditable: every Bounce gets the same fail-closed admin gate
// and the same well-formed loopback recognition.

package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/store"
)

// fakeAdminHandler is the no-op handler the middleware wraps in the
// tests below. Returns 200 "ok" so a test that exercises the auth
// gate can distinguish "request reached the handler" from "auth
// middleware rejected the request".
func fakeAdminHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// TestRequireMgmtAuth_LoopbackNoTokenAllows — BB-3 §1: loopback bind
// + no token configured → request passes through (preserves existing
// UX for default-deploy operators on loopback).
func TestRequireMgmtAuth_LoopbackNoTokenAllows(t *testing.T) {
	h := requireMgmtAuth(fakeAdminHandler, "", "127.0.0.1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("loopback + no token: status = %d body = %q; want 200", rec.Code, rec.Body.String())
	}
}

// TestRequireMgmtAuth_ExternalNoTokenRefuses — BB-3 §2: external bind
// + no token configured → 503 with operator-actionable hint. This is
// the defense-in-depth case: the CLI startup gate already refuses
// this shape, so reaching this branch means a test harness, config-
// file loader, or programmatic embed bypassed the CLI gate. Fail
// closed.
func TestRequireMgmtAuth_ExternalNoTokenRefuses(t *testing.T) {
	h := requireMgmtAuth(fakeAdminHandler, "", "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("external + no token: status = %d; want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "--audit-events-token") {
		t.Errorf("external + no token: body lacks operator hint pointing at --audit-events-token: %q", rec.Body.String())
	}
}

// TestRequireMgmtAuth_ExternalCorrectTokenAllows — BB-3 §3: external
// bind + token set + correct Bearer → request passes through.
func TestRequireMgmtAuth_ExternalCorrectTokenAllows(t *testing.T) {
	const token = "s3cret-token-#524-BB3"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("external + correct token: status = %d body = %q; want 200", rec.Code, rec.Body.String())
	}
}

// TestRequireMgmtAuth_ExternalWrongTokenRefuses — BB-3 §4: external
// bind + token set + wrong Bearer → 401.
func TestRequireMgmtAuth_ExternalWrongTokenRefuses(t *testing.T) {
	const token = "s3cret-token-#524-BB3"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("external + wrong token: status = %d; want 401", rec.Code)
	}
}

// TestRequireMgmtAuth_ExternalMissingHeaderRefuses — BB-3 §4 variant:
// external bind + token set + NO Authorization header → 401 with
// explicit "Authorization: Bearer <token> required" message.
func TestRequireMgmtAuth_ExternalMissingHeaderRefuses(t *testing.T) {
	const token = "s3cret-token-#524-BB3"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("external + missing header: status = %d; want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bearer") {
		t.Errorf("external + missing header: body lacks Bearer hint: %q", rec.Body.String())
	}
}

// TestRequireMgmtAuth_LoopbackTokenSetEnforced — BB-3 belt-and-
// suspenders: even on loopback, if a token is configured the gate
// enforces it. Matches the handler-internal bearer check the
// reload-handlers already do, which means the middleware is a strict
// SUPERSET — never weaker than the handler-internal check.
func TestRequireMgmtAuth_LoopbackTokenSetEnforced(t *testing.T) {
	const token = "loopback-still-needs-token"
	h := requireMgmtAuth(fakeAdminHandler, token, "127.0.0.1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/profile/reload", nil)
	// No Authorization header → 401 even though we're on loopback.
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("loopback + token set + no header: status = %d; want 401", rec.Code)
	}
}

// TestRequireMgmtAuth_ConstantTimeCompareUsed — BB-3 §5: per
// [[scorer-is-ground-truth]] + §A99 the bearer compare MUST be
// constant-time. We can't trivially observe timing in a unit test
// without flakes; the assertion is structural — admin_auth.go must
// import crypto/subtle. The existing TestBearerComparisonUsesConstant
// TimeCompare (constant_time_compare_test.go) walks every .go file
// in the package; this comment serves as the breadcrumb that this
// file also relies on that invariant.
//
// Smoke check: a near-match string (one byte off at the end) MUST be
// rejected even though a wall-clock compare would short-circuit at
// the differing byte. The behavior is identical to a constant-time
// compare on rejection, so this isn't a timing PROOF — just a
// behavioral baseline against accidental regressions where someone
// swapped subtle.ConstantTimeCompare for == .
func TestRequireMgmtAuth_ConstantTimeCompareUsed(t *testing.T) {
	const token = "match-prefix-then-diverge-at-the-very-end-1"
	const near = "match-prefix-then-diverge-at-the-very-end-2"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	req.Header.Set("Authorization", "Bearer "+near)
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("near-match token: status = %d; want 401", rec.Code)
	}
}

// startScopedHealthzProxy is a #524-BB-4 helper: starts a gbounce
// proxy with an EXPLICIT MgmtHost + AuditEventsToken so the BB-4
// /healthz field-scoping branches are exercised. Different shape
// from startTestProxy (which always binds 127.0.0.1 + leaves the
// token empty), so we use it ONLY for the field-scoping tests below
// to keep the parity_544 corpus untouched.
//
// The underlying TCP listener is ALWAYS on 127.0.0.1 (we never bind
// 0.0.0.0 in a unit test — that would expose the test server on CI
// hosts). The auth decision keys on cfg.MgmtHost, which we set to
// whatever value the test needs. This is safe because the healthz
// handler reads s.cfg.MgmtHost at request time, not at construction.
//
// Returns the healthz URL + the configured token (for the auth'd
// probes).
func startScopedHealthzProxy(t *testing.T, mgmtHost, token string) (healthURL, configuredToken string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	upstream := newQuietUpstream(t)

	cfg := Config{
		Host:                  "127.0.0.1",
		Port:                  0,
		MgmtHost:              mgmtHost,
		MgmtPort:              0,
		UpstreamURL:           upstream.URL,
		AllowConnect:          false,
		ForwardTimeoutSeconds: 5,
		AuditEventsToken:      token,
	}

	srv, err := NewServer(cfg, s, nil, nil)
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
	go func() { _ = srv.ServeListeners(ctx, proxyL, mgmtL) }()
	t.Cleanup(func() { cancel(); time.Sleep(50 * time.Millisecond) })

	healthURL = "http://" + mgmtL.Addr().String() + "/healthz"

	// Wait for /healthz to respond. Use the configured token so the
	// readiness probe works under any auth shape.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, healthURL, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return healthURL, token
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("scoped proxy never became healthy")
	return healthURL, token
}

// invokeHealthzDirect builds a Server with the given cfg, then calls
// s.healthz(rec, req) directly. This sidesteps the real net.Listen
// loop so we can craft a synthetic RemoteAddr to drive the BB-4
// field-scoping branches (binding 0.0.0.0 in a unit test would expose
// the test server on CI). Returns the decoded JSON body + status.
func invokeHealthzDirect(t *testing.T, mgmtHost, token, remoteAddr, authHeader string) (map[string]any, int) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	upstream := newQuietUpstream(t)
	cfg := Config{
		Host:                  "127.0.0.1",
		Port:                  0,
		MgmtHost:              mgmtHost,
		MgmtPort:              0,
		UpstreamURL:           upstream.URL,
		AllowConnect:          false,
		ForwardTimeoutSeconds: 5,
		AuditEventsToken:      token,
	}
	srv, err := NewServer(cfg, s, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = remoteAddr
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	srv.healthz(rec, req)

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		raw, _ := io.ReadAll(rec.Body)
		t.Fatalf("decode: %v (raw=%s)", err, raw)
	}
	return body, rec.Code
}

// TestHealthz_LoopbackReturnsFullPayload — BB-4 §6: loopback mgmt
// host + loopback RemoteAddr → FULL payload including upstream +
// operational counters (preserves existing behavior + cross-bouncer
// parity). Uses the live-server path so this also exercises the real
// HTTP serving stack — different from the invokeHealthzDirect path
// below which is needed only to fake a non-loopback RemoteAddr.
func TestHealthz_LoopbackReturnsFullPayload(t *testing.T) {
	healthURL, _ := startScopedHealthzProxy(t, "127.0.0.1", "")
	body := fetchHealthzAsMap(t, healthURL, "")
	for _, key := range []string{"upstream", "total_requests", "deny_hosts_count"} {
		if _, ok := body[key]; !ok {
			t.Errorf("loopback /healthz: missing %q from body: %#v", key, body)
		}
	}
}

// TestHealthz_ExternalUnauthScopesPayload — BB-4 §7: external mgmt
// host + non-loopback RemoteAddr + no Authorization header → response
// excludes upstream + operational counters. Direct-invocation path so
// we can fake a non-loopback RemoteAddr without binding 0.0.0.0 in a
// unit test.
func TestHealthz_ExternalUnauthScopesPayload(t *testing.T) {
	body, status := invokeHealthzDirect(t,
		"0.0.0.0",
		"test-token-#524-BB4",
		"10.0.0.5:54321", // non-loopback RemoteAddr
		"",               // no Authorization header
	)
	if status != http.StatusOK {
		t.Errorf("unauth external /healthz status = %d; want 200", status)
	}

	// Sensitive fields MUST be absent on unauth + external.
	for _, key := range []string{
		"upstream",
		"total_requests",
		"total_errors",
		"deny_hosts_count",
		"dynamic_denies_path",
		"mitm_enabled",
		"audit_log_path",
	} {
		if _, ok := body[key]; ok {
			t.Errorf("unauth external /healthz: leaked %q in body: %#v", key, body)
		}
	}

	// Parity-floor fields MUST be present so the composite monitor
	// per [[cross-product-agent-parity]] decodes successfully.
	for _, key := range []string{"status", "product", "chain_initialized", "llm_budget"} {
		if _, ok := body[key]; !ok {
			t.Errorf("unauth external /healthz: missing parity-floor key %q: %#v", key, body)
		}
	}
	if body["status"] != "ok" {
		t.Errorf("unauth /healthz status = %v; want ok", body["status"])
	}
	if body["product"] != "gbounce" {
		t.Errorf("unauth /healthz product = %v; want gbounce", body["product"])
	}
}

// TestHealthz_ExternalAuthReturnsFullPayload — BB-4 §8: external
// mgmt host + non-loopback RemoteAddr + correct Bearer → full payload
// returns (parity with loopback path).
func TestHealthz_ExternalAuthReturnsFullPayload(t *testing.T) {
	const token = "test-token-#524-BB4-auth"
	body, status := invokeHealthzDirect(t,
		"0.0.0.0",
		token,
		"10.0.0.5:54321",
		"Bearer "+token,
	)
	if status != http.StatusOK {
		t.Errorf("auth'd external /healthz status = %d; want 200", status)
	}
	for _, key := range []string{
		"upstream",
		"total_requests",
		"deny_hosts_count",
		"dynamic_denies_enabled",
		"mitm_enabled",
	} {
		if _, ok := body[key]; !ok {
			t.Errorf("auth'd external /healthz: missing %q: %#v", key, body)
		}
	}
}

// TestHealthz_ExternalLoopbackRemoteAddrAllowsFull — BB-4 §6b:
// MgmtHost is "0.0.0.0" but the request ARRIVED via loopback
// (e.g. operator port-forwarded an SSH tunnel). The RemoteAddr-based
// fallback in requestAuthenticatedOrLoopback should still grant the
// full payload — the trust anchor here is "the request actually came
// from loopback" regardless of the configured bind host.
func TestHealthz_ExternalLoopbackRemoteAddrAllowsFull(t *testing.T) {
	body, status := invokeHealthzDirect(t,
		"0.0.0.0",
		"any-token",
		"127.0.0.1:54321",
		"", // no auth — loopback RemoteAddr is the trust anchor
	)
	if status != http.StatusOK {
		t.Errorf("loopback-RemoteAddr /healthz status = %d; want 200", status)
	}
	if _, ok := body["upstream"]; !ok {
		t.Errorf("loopback-RemoteAddr /healthz: missing upstream: %#v", body)
	}
}

// TestHealthz_ExternalWrongTokenScopesPayload — BB-4 §7b: external
// mgmt host + wrong Bearer → still scoped (auth FAILED, not just
// missing). Closes the "operator typo on the monitor's token →
// suddenly leaking upstream URL" path.
func TestHealthz_ExternalWrongTokenScopesPayload(t *testing.T) {
	body, status := invokeHealthzDirect(t,
		"0.0.0.0",
		"correct-token",
		"10.0.0.5:54321",
		"Bearer wrong-token",
	)
	if status != http.StatusOK {
		t.Errorf("wrong-token /healthz status = %d; want 200 (scoped, not 401)", status)
	}
	if _, ok := body["upstream"]; ok {
		t.Errorf("wrong-token /healthz: leaked upstream: %#v", body)
	}
}

// fetchHealthzAsMap helper: GET healthURL with optional Bearer token,
// decode to map[string]any. Used only by the loopback live-server
// test (the external-bound BB-4 tests use invokeHealthzDirect to
// avoid binding 0.0.0.0 in a unit test).
func fetchHealthzAsMap(t *testing.T, healthURL, token string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, healthURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", healthURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; want 200 or 503 (degraded); body = %s", resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

// TestRemoteAddrIsLoopback exercises the IP-string parser the BB-4
// helper falls back on when the configured MgmtHost is non-loopback
// (or when a future deployment shape lands a localhost request on an
// off-loopback listener). Defense-in-depth: even if MgmtHost is
// somehow "0.0.0.0" the request that ACTUALLY arrived over loopback
// gets the full payload.
func TestRemoteAddrIsLoopback(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.1:0", true},
		{"[::1]:8080", true},
		{"[::ffff:127.0.0.1]:8080", true},
		{"10.0.0.5:8080", false},
		{"192.168.1.5:9999", false},
		{"[2001:db8::1]:8080", false},
		{"", false},
		{"malformed", false},
	}
	for _, c := range cases {
		got := remoteAddrIsLoopback(c.in)
		if got != c.want {
			t.Errorf("remoteAddrIsLoopback(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}
