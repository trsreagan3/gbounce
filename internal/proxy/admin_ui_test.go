// admin_ui_test.go covers the purpose-driven monitoring console
// shipped in iam-jit #682. Sibling of events_ui_test.go (which covers
// the legacy live-tail at GET /). The page itself is bundled into the
// gbounce binary; tests assert structural invariants the founder
// direction in [[gbounce-ui-purpose-driven]] requires:
//
//   - all 5 panels (Q1..Q5) render
//   - feature panel is wired to /admin/features
//   - stuck signals panel is wired to /admin/stuck-signals
//   - SSE consumed from /admin/stream
//   - no external CDNs / fonts / analytics
//   - no surveillance-flavoured copy
//   - no embedded bearer token
//
// Plus the JSON endpoint round-trips for /admin/features +
// /admin/stuck-signals so a future schema drift fails loud.
package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/store"
)

// adminUIBody fetches the rendered HTML for the admin console.
func adminUIBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q; want text/html", ct)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestAdminUI_RendersHTMLAtAdminUI(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	body := adminUIBody(t, srv.URL+"/")
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(body)), "<!doctype html>") {
		t.Errorf("body does not start with <!doctype html>")
	}
}

// TestAdminUI_AnswersFiveOperatorQuestions — the founder direction
// in [[gbounce-ui-purpose-driven]] is explicit: the UI must answer
// 5 specific questions. We probe for the Q1..Q5 / Q4 + Q5 labels +
// the panel headings.
func TestAdminUI_AnswersFiveOperatorQuestions(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	body := adminUIBody(t, srv.URL+"/")
	checks := []string{
		// Q1 live decision stream
		"What is my agent doing right now",
		// Q2 stuck detection
		"Is the agent stuck",
		// Q3 deny stream
		"What is gbounce blocking",
		// Q4 + Q5 features
		"Features",
		"on, off, and actually firing",
		// Question labels themselves
		`<span class="q">Q1</span>`,
		`<span class="q">Q2</span>`,
		`<span class="q">Q3</span>`,
		`<span class="q">Q4 + Q5</span>`,
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("admin UI missing required phrase: %q", want)
		}
	}
}

func TestAdminUI_ConsumesSSEStream(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	body := adminUIBody(t, srv.URL+"/")
	if !strings.Contains(body, "EventSource") {
		t.Errorf("admin UI missing EventSource wiring")
	}
	if !strings.Contains(body, "/admin/stream") {
		t.Errorf("admin UI missing /admin/stream reference")
	}
	for _, evType := range []string{"decision", "features", "stuck-signals"} {
		if !strings.Contains(body, `"`+evType+`"`) {
			t.Errorf("admin UI missing SSE event handler: %q", evType)
		}
	}
}

func TestAdminUI_NoExternalDependencies(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	body := strings.ToLower(adminUIBody(t, srv.URL+"/"))
	for _, needle := range []string{
		"googleapis.com", "gstatic.com", "cloudflare", "cdn.",
		"googletagmanager", "google-analytics", "fonts.google",
		"//unpkg.com", "//cdnjs.", "//jsdelivr.",
	} {
		if strings.Contains(body, needle) {
			t.Errorf("external dependency leaked: %s", needle)
		}
	}
}

func TestAdminUI_NoEmbeddedToken(t *testing.T) {
	const secret = "ADMIN-UI-TOKEN-NEVER-LEAK-AAA1234"
	srv := httptest.NewServer(adminUIHandler(secret))
	defer srv.Close()
	body := adminUIBody(t, srv.URL+"/")
	if strings.Contains(body, secret) {
		t.Errorf("bearer token leaked into admin UI body")
	}
}

func TestAdminUI_SafetyNotSurveillanceLanguage(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	body := strings.ToLower(adminUIBody(t, srv.URL+"/"))
	for _, term := range []string{"violation", "infraction", "unauthorized"} {
		// allow as substring inside long words, only flag whole-word
		idx := strings.Index(body, term)
		if idx == -1 {
			continue
		}
		// crude word-boundary check
		before := byte(0)
		after := byte(0)
		if idx > 0 {
			before = body[idx-1]
		}
		if idx+len(term) < len(body) {
			after = body[idx+len(term)]
		}
		alnum := func(c byte) bool {
			return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		}
		if !alnum(before) && !alnum(after) {
			t.Errorf("forbidden surveillance term in admin UI: %s", term)
		}
	}
}

func TestAdminUI_EmptyStateGivesTestCommand(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	body := adminUIBody(t, srv.URL+"/")
	// Empty state must include an actionable HTTPS_PROXY example —
	// per [[gbounce-ui-purpose-driven]] the UI tells the operator
	// HOW to test when nothing has flowed yet.
	if !strings.Contains(body, "HTTPS_PROXY") {
		t.Errorf("empty-state copy missing HTTPS_PROXY test command")
	}
}

func TestAdminUI_StrictCSPHeader(t *testing.T) {
	srv := httptest.NewServer(adminUIHandler(""))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing CSP")
	}
	for _, expect := range []string{"default-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, expect) {
			t.Errorf("CSP missing %q (have %q)", expect, csp)
		}
	}
}

// ---------- /admin/features endpoint ----------

func TestAdminFeatures_ReturnsFeatureSnapshot(t *testing.T) {
	upstream := newQuietUpstream(t)
	_, healthURL, _, _ := startTestProxy(t, upstream, false, false)
	base := strings.TrimSuffix(healthURL, "/healthz")
	resp, err := http.Get(base + "/admin/features")
	if err != nil {
		t.Fatalf("GET /admin/features: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	var body featureStatusSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ProcessStartedUnixMs == 0 {
		t.Errorf("ProcessStartedUnixMs is zero")
	}
	if body.NowUnixMs == 0 {
		t.Errorf("NowUnixMs is zero")
	}
	// Confirm the canonical feature names per [[gbounce-ui-purpose-driven]]
	// question 4 — operator wants the explicit list of features.
	wantNames := []string{
		"mitm", "deny_hosts", "dynamic_deny", "injection_scan",
		"profile_enforcement", "audit_log", "session_recorder",
		"object_storage", "disk_pressure_circuit_breaker",
	}
	got := make(map[string]bool, len(body.Features))
	for _, f := range body.Features {
		got[f.Name] = true
	}
	for _, n := range wantNames {
		if !got[n] {
			t.Errorf("missing feature: %s", n)
		}
	}
}

// TestAdminFeatures_AuditLogConfiguredButNeverFiredHonestSurface —
// the honesty bar per [[ibounce-honest-positioning]]: if the audit
// log is configured but no traffic has flowed, we must surface
// ConfiguredButNeverFired=true — NOT a green "OK".
func TestAdminFeatures_AuditLogConfiguredButNeverFiredHonestSurface(t *testing.T) {
	upstream := newQuietUpstream(t)
	_, healthURL, _, _ := startTestProxy(t, upstream, true /* withAuditLog */, false)
	base := strings.TrimSuffix(healthURL, "/healthz")
	resp, err := http.Get(base + "/admin/features")
	if err != nil {
		t.Fatalf("GET /admin/features: %v", err)
	}
	defer resp.Body.Close()
	var body featureStatusSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var auditLog *FeatureStatus
	for i := range body.Features {
		if body.Features[i].Name == "audit_log" {
			auditLog = &body.Features[i]
			break
		}
	}
	if auditLog == nil {
		t.Fatalf("audit_log feature missing")
	}
	if !auditLog.Enabled {
		t.Errorf("audit_log should be enabled when --audit-log is set")
	}
	if !auditLog.ConfiguredButNeverFired {
		t.Errorf("audit_log should be ConfiguredButNeverFired=true when no traffic has flowed (got fire_count_total=%d, last_fired_unix_ms=%d)",
			auditLog.FireCountTotal, auditLog.LastFiredUnixMs)
	}
}

// TestAdminFeatures_DisabledFeaturesNotConfiguredButNeverFired —
// inverse of the above: a feature that is OFF must not be flagged
// as ConfiguredButNeverFired (it's not configured at all).
func TestAdminFeatures_DisabledFeaturesNotConfiguredButNeverFired(t *testing.T) {
	upstream := newQuietUpstream(t)
	_, healthURL, _, _ := startTestProxy(t, upstream, false, false)
	base := strings.TrimSuffix(healthURL, "/healthz")
	resp, err := http.Get(base + "/admin/features")
	if err != nil {
		t.Fatalf("GET /admin/features: %v", err)
	}
	defer resp.Body.Close()
	var body featureStatusSnapshot
	_ = json.NewDecoder(resp.Body).Decode(&body)
	for _, f := range body.Features {
		if !f.Enabled && f.ConfiguredButNeverFired {
			t.Errorf("feature %s is disabled but reports ConfiguredButNeverFired=true", f.Name)
		}
	}
}

// ---------- /admin/stuck-signals endpoint ----------

func TestAdminStuckSignals_EmptyStateHonest(t *testing.T) {
	upstream := newQuietUpstream(t)
	_, healthURL, _, _ := startTestProxy(t, upstream, false, false)
	base := strings.TrimSuffix(healthURL, "/healthz")
	resp, err := http.Get(base + "/admin/stuck-signals")
	if err != nil {
		t.Fatalf("GET /admin/stuck-signals: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	signals, ok := body["signals"].([]any)
	if !ok {
		t.Fatalf("signals key missing or wrong type: %T", body["signals"])
	}
	if len(signals) != 0 {
		t.Errorf("empty bouncer should have zero stuck signals; got %d", len(signals))
	}
}

// TestAdminStuckSignals_DetectsUpstreamRetryStorm — quantified
// threshold check: insert >= stuckRetryThreshold rows to the same
// (method, host, path) within stuckWindowSeconds + the endpoint must
// surface a signal with the exact threshold string.
func TestAdminStuckSignals_DetectsUpstreamRetryStorm(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	now := time.Now()
	for i := 0; i < stuckRetryThreshold+1; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			At:           now.Add(-time.Duration(i) * time.Second),
			Method:       "GET",
			Path:         "/v1/messages",
			UpstreamHost: "api.example.com",
			UpstreamPort: 443,
			HTTPStatus:   200,
			Verdict:      "ALLOW",
		})
		if err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	signals := computeStuckSignals(st, now)
	found := false
	for _, s := range signals {
		if s["kind"] == "upstream_retry_storm" {
			found = true
			thresh, _ := s["threshold"].(string)
			if !strings.Contains(thresh, "5 in 30s") {
				t.Errorf("threshold string does not name the quantified bound: %q", thresh)
			}
			if _, ok := s["count"]; !ok {
				t.Errorf("signal missing count field")
			}
		}
	}
	if !found {
		t.Errorf("expected upstream_retry_storm signal not found in %+v", signals)
	}
}

// TestAdminStuckSignals_DetectsDenyStorm — same shape as the retry
// storm but for the DENY verdict pattern. Per
// [[gbounce-ui-purpose-driven]] question 2 — "agent is stuck
// bouncing off a deny rule" is the canonical example.
func TestAdminStuckSignals_DetectsDenyStorm(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	now := time.Now()
	for i := 0; i < stuckDenyThreshold+1; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			At:           now.Add(-time.Duration(i) * time.Second),
			Method:       "CONNECT",
			Path:         "/",
			UpstreamHost: "bad.example.com",
			HTTPStatus:   403,
			Verdict:      "DENY",
		})
		if err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	signals := computeStuckSignals(st, now)
	found := false
	for _, s := range signals {
		if s["kind"] == "deny_storm" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected deny_storm signal not found in %+v", signals)
	}
}

// ---------- /admin/stream SSE ----------

// TestAdminStream_EmitsInitialFrames — the SSE handler MUST push an
// initial features + stuck-signals frame on connect so the UI shows
// state immediately (no 5-second blank window).
func TestAdminStream_EmitsInitialFrames(t *testing.T) {
	upstream := newQuietUpstream(t)
	_, healthURL, _, _ := startTestProxy(t, upstream, false, false)
	base := strings.TrimSuffix(healthURL, "/healthz")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/admin/stream", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("content-type = %q (want text/event-stream)", ct)
	}
	// Read everything until ctx times out and we get EOF from the
	// canceled connection. The initial frames are written + flushed
	// synchronously inside the handler before it enters the select
	// loop, so they MUST land within the first read window.
	done := make(chan struct {
		s   string
		err error
	}, 1)
	go func() {
		b, e := io.ReadAll(resp.Body)
		done <- struct {
			s   string
			err error
		}{string(b), e}
	}()
	var read string
	select {
	case r := <-done:
		read = r.s
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("timeout waiting for SSE body")
	}
	if !strings.Contains(read, "event: features") {
		t.Errorf("SSE stream missing initial 'event: features' frame; got %q", read)
	}
	if !strings.Contains(read, "event: stuck-signals") {
		t.Errorf("SSE stream missing initial 'event: stuck-signals' frame; got %q", read)
	}
}

// TestAdminMonitoring_ExternalBindRequiresBearer — the loopback case
// is open + tested above; off-loopback requires a token via the
// bind-time gate (mirrors /audit/events).
func TestAdminFeatures_RequireBearerWhenSet(t *testing.T) {
	h := (&Server{}).adminFeaturesHandler("expected-token")
	// No header should reject.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/features", nil)
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d (want 403)", rec.Code)
	}
	// Wrong token should reject.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/features", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d (want 403) for wrong token", rec.Code)
	}
	// _token query param fallback rejected with wrong value.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/features?_token=wrong", nil)
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d (want 403) for wrong _token=", rec.Code)
	}
}
