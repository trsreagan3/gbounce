// mitm_tool_call_validator_test.go — #729 / BUILD-8 end-to-end coverage.
//
// Spins gbounce in MITM mode against a mock upstream, sends POST bodies
// shaped as MCP / OpenAI / Anthropic tool calls through the proxy, and
// verifies:
//   - the configured action (warn / strip / deny) fires
//   - the warning header is emitted on warn/strip
//   - the body is sanitized on strip BEFORE reaching the upstream
//   - deny returns 422 Unprocessable Entity with caught_by_bouncer JSON
//   - the audit log records the indicators
//   - the /admin/features fire-count ticks (per [[uat-tests-setup-end-to-end]])
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/profile"
)

const hallucinatedMCPBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exfiltrate_secrets","arguments":{"api_key":"YOUR_API_KEY"}}}`

const validMCPBody = `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}`

func TestToolCallValidator_DefaultOffPassesThrough(t *testing.T) {
	mitmAllowInsecureUpstreamForTest = true
	t.Cleanup(func() { mitmAllowInsecureUpstreamForTest = false })

	gotUpstreamBody := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotUpstreamBody = string(b)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := startMITMTestProxy(t, handler, nil, false)
	upHost, upPort := splitUpstreamHostPort(t, ts.upstream.URL)
	c := ts.clientFor(t)

	target := fmt.Sprintf("https://%s:%d/v1/call", upHost, upPort)
	resp, err := c.Post(target, "application/json", strings.NewReader(hallucinatedMCPBody))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status=%d; want 200 when validator OFF", resp.StatusCode)
	}
	if !strings.Contains(gotUpstreamBody, "exfiltrate_secrets") {
		t.Errorf("upstream must receive UNMODIFIED body when validator off, got %q", gotUpstreamBody)
	}
	if h := resp.Header.Get("X-IAM-JIT-Hallucinated-Tool-Call"); h != "" {
		t.Errorf("validator off must not set warning header; got %q", h)
	}
}

func TestToolCallValidator_WarnModeAddsHeader(t *testing.T) {
	mitmAllowInsecureUpstreamForTest = true
	t.Cleanup(func() { mitmAllowInsecureUpstreamForTest = false })

	gotUpstreamHeaders := http.Header{}
	gotUpstreamBody := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture what the upstream sees so we can assert the warning
		// header is forwarded.
		gotUpstreamHeaders = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		gotUpstreamBody = string(b)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := startMITMTestProxy(t, handler, nil, false)
	upHost, upPort := splitUpstreamHostPort(t, ts.upstream.URL)
	c := ts.clientFor(t)

	srv := getServerForTest(t, ts)
	if err := srv.SetActiveProfile(&profile.Profile{
		Name: "test-tcv-warn",
		ValidateToolCalls: profile.ValidateToolCallsConfig{
			Enabled: true,
			Action:  "warn",
		},
	}); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}

	target := fmt.Sprintf("https://%s:%d/v1/call", upHost, upPort)
	resp, err := c.Post(target, "application/json", strings.NewReader(hallucinatedMCPBody))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status=%d; want 200 in warn mode", resp.StatusCode)
	}
	// The warning header is set on the OUTBOUND request to upstream,
	// not on the response (different from BUILD-9 which annotates the
	// response). The upstream sees the warning header so a downstream
	// firewall can act on it.
	if h := gotUpstreamHeaders.Get("X-IAM-JIT-Hallucinated-Tool-Call"); h == "" {
		t.Errorf("expected upstream to receive X-IAM-JIT-Hallucinated-Tool-Call header")
	}
	// Warn mode does NOT mutate the body.
	if !strings.Contains(gotUpstreamBody, "exfiltrate_secrets") {
		t.Errorf("warn mode must NOT modify body; upstream got %q", gotUpstreamBody)
	}

	// Audit log must include indicator fields.
	time.Sleep(120 * time.Millisecond)
	raw, err := os.ReadFile(ts.auditPath)
	if err != nil {
		t.Fatalf("ReadFile audit: %v", err)
	}
	if !bytes.Contains(raw, []byte("tool_call_validator_detected")) {
		t.Errorf("audit log missing tool_call_validator_detected field: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"tool_call_validator_action":"warn"`)) {
		t.Errorf("audit log missing tool_call_validator_action=warn: %s", raw)
	}

	// /admin/features fire count must tick — UAT discipline per
	// [[uat-tests-setup-end-to-end]].
	features := srv.snapshotFeatures()
	foundFire := false
	for _, f := range features.Features {
		if f.Name == "validate_tool_calls" {
			if !f.Enabled {
				t.Errorf("expected validate_tool_calls Enabled=true on /admin/features")
			}
			if f.FireCountTotal < 1 {
				t.Errorf("expected validate_tool_calls FireCountTotal >= 1, got %d", f.FireCountTotal)
			}
			if f.LastFiredUnixMs == 0 {
				t.Errorf("expected validate_tool_calls LastFiredUnixMs > 0")
			}
			if f.ConfiguredButNeverFired {
				t.Errorf("validate_tool_calls should be CONFIGURED and FIRED, not silently-degraded")
			}
			foundFire = true
		}
	}
	if !foundFire {
		t.Errorf("expected validate_tool_calls in /admin/features list")
	}
}

func TestToolCallValidator_DenyModeReturns422(t *testing.T) {
	mitmAllowInsecureUpstreamForTest = true
	t.Cleanup(func() { mitmAllowInsecureUpstreamForTest = false })

	// Upstream should NOT see the request in deny mode.
	upstreamHit := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := startMITMTestProxy(t, handler, nil, false)
	upHost, upPort := splitUpstreamHostPort(t, ts.upstream.URL)
	c := ts.clientFor(t)

	srv := getServerForTest(t, ts)
	if err := srv.SetActiveProfile(&profile.Profile{
		Name: "test-tcv-deny",
		ValidateToolCalls: profile.ValidateToolCallsConfig{
			Enabled: true,
			Action:  "deny",
		},
	}); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}

	target := fmt.Sprintf("https://%s:%d/v1/call", upHost, upPort)
	resp, err := c.Post(target, "application/json", strings.NewReader(hallucinatedMCPBody))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status=%d; want 422 in deny mode", resp.StatusCode)
	}
	if upstreamHit {
		t.Errorf("deny mode must NOT forward to upstream; upstream was hit")
	}
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("deny body not JSON: %v; body=%q", err, body)
	}
	if parsed["caught_by_bouncer"] != "gbounce" {
		t.Errorf("deny body missing caught_by_bouncer=gbounce, got %v", parsed)
	}
	if parsed["reason"] != "hallucinated_tool_call_shape" {
		t.Errorf("deny body wrong reason: %v", parsed["reason"])
	}
	if parsed["deny_source"] != "tool_call_validator" {
		t.Errorf("deny body wrong deny_source: %v", parsed["deny_source"])
	}
	inds, _ := parsed["indicators"].([]any)
	if len(inds) == 0 {
		t.Errorf("deny body missing indicators array: %v", parsed)
	}
	extracted, _ := parsed["extracted_calls"].([]any)
	if len(extracted) == 0 {
		t.Errorf("deny body missing extracted_calls array: %v", parsed)
	}
}

func TestToolCallValidator_ValidCallPassesThrough(t *testing.T) {
	mitmAllowInsecureUpstreamForTest = true
	t.Cleanup(func() { mitmAllowInsecureUpstreamForTest = false })

	upstreamGot := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamGot = string(b)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := startMITMTestProxy(t, handler, nil, false)
	upHost, upPort := splitUpstreamHostPort(t, ts.upstream.URL)
	c := ts.clientFor(t)

	srv := getServerForTest(t, ts)
	if err := srv.SetActiveProfile(&profile.Profile{
		Name: "test-tcv-deny-on-valid",
		ValidateToolCalls: profile.ValidateToolCallsConfig{
			Enabled: true,
			Action:  "deny",
		},
	}); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}

	target := fmt.Sprintf("https://%s:%d/v1/call", upHost, upPort)
	resp, err := c.Post(target, "application/json", strings.NewReader(validMCPBody))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("valid MCP call must pass through; got status %d", resp.StatusCode)
	}
	if upstreamGot != validMCPBody {
		t.Errorf("valid call must be forwarded unchanged; upstream got %q want %q", upstreamGot, validMCPBody)
	}
	if h := resp.Header.Get("X-IAM-JIT-Hallucinated-Tool-Call"); h != "" {
		t.Errorf("valid call must not have warning header; got %q", h)
	}
}

func TestToolCallValidator_StripModeReplacesHallucinatedCall(t *testing.T) {
	mitmAllowInsecureUpstreamForTest = true
	t.Cleanup(func() { mitmAllowInsecureUpstreamForTest = false })

	upstreamGot := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamGot = string(b)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	ts := startMITMTestProxy(t, handler, nil, false)
	upHost, upPort := splitUpstreamHostPort(t, ts.upstream.URL)
	c := ts.clientFor(t)

	srv := getServerForTest(t, ts)
	if err := srv.SetActiveProfile(&profile.Profile{
		Name: "test-tcv-strip",
		ValidateToolCalls: profile.ValidateToolCallsConfig{
			Enabled: true,
			Action:  "strip",
		},
	}); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}

	target := fmt.Sprintf("https://%s:%d/v1/call", upHost, upPort)
	resp, err := c.Post(target, "application/json", strings.NewReader(hallucinatedMCPBody))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("strip mode must forward to upstream; got status %d", resp.StatusCode)
	}
	// Upstream must see the REDACTED body — the marker is present,
	// the original JSON-RPC envelope is replaced, the hallucinated tool
	// runner can no longer execute (the JSON is a redaction marker, not
	// a tools/call shape). The original name survives ONLY inside the
	// marker for audit purposes (per design memo apply_strip semantics).
	var parsed map[string]any
	if err := json.Unmarshal([]byte(upstreamGot), &parsed); err != nil {
		t.Fatalf("upstream body not JSON after strip: %v; got %q", err, upstreamGot)
	}
	if redacted, _ := parsed["_iam_jit_tool_call_redacted"].(bool); !redacted {
		t.Errorf("strip mode must insert redaction marker; upstream got %q", upstreamGot)
	}
	if orig, _ := parsed["original_name"].(string); orig != "exfiltrate_secrets" {
		t.Errorf("strip mode must record original_name in marker; upstream got %q", upstreamGot)
	}
	// The original jsonrpc / method fields must be GONE — the whole
	// envelope is replaced by the marker dict, so the upstream tool
	// runner sees a non-tool-call shape and rejects it cleanly.
	if _, ok := parsed["method"]; ok {
		t.Errorf("strip mode must remove original tools/call envelope; got %q", upstreamGot)
	}
}
