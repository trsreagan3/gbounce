package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newQuietUpstream is the no-op upstream every parity test below shares:
// returns 200 with no body. We never hit it via the proxy (the tests
// only probe /healthz on the mgmt port), but startTestProxy refuses to
// build a Server without either --upstream or --allow-connect.
func newQuietUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// healthz_parity_544_test.go — #544 / MRR-5 M2 + M3 cross-bouncer
// parity tests for the gbounce /healthz endpoint. Asserts the wire-
// shape OBSERVABLE through the HTTP probe (never inspects internal
// struct fields) so the field set stays aligned with ibounce's
// /healthz per [[cross-product-agent-parity]].
//
// The 6-test corpus mirrors the same shape filed against kbouncer +
// dbounce; the cross-bouncer composite monitor in MRR-5 §2 relies on
// the key set being identical across all four bouncers.

// fetchHealthzBody is a small helper that wraps the GET + JSON
// decode + non-200 check used by every parity test below.
func fetchHealthzBody(t *testing.T, healthURL string) map[string]any {
	t.Helper()
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("GET %s: %v", healthURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

// TestHealthz_HasChainInitialized — #544 — bare /healthz must include
// the chain_initialized key per [[cross-product-agent-parity]]. The
// absence of the key would break any composite monitor that asserts a
// uniform key set across all four bouncers.
func TestHealthz_HasChainInitialized(t *testing.T) {
	_, healthURL, _, _ := startTestProxy(t, newQuietUpstream(t), false, false)
	body := fetchHealthzBody(t, healthURL)
	if _, ok := body["chain_initialized"]; !ok {
		t.Fatalf("/healthz missing chain_initialized field: %#v", body)
	}
}

// TestHealthz_ChainInitializedTrueWhenConfigured — #544 — when the
// audit log writer is wired (withAuditLog=true), chain_initialized
// must be true. Verifies the field tracks the underlying writer state
// rather than being hard-coded.
func TestHealthz_ChainInitializedTrueWhenConfigured(t *testing.T) {
	_, healthURL, _, _ := startTestProxy(t, newQuietUpstream(t), true, false)
	body := fetchHealthzBody(t, healthURL)
	got, ok := body["chain_initialized"].(bool)
	if !ok {
		t.Fatalf("chain_initialized not a bool: %#v (type %T)",
			body["chain_initialized"], body["chain_initialized"])
	}
	if !got {
		t.Errorf("chain_initialized = false; want true when audit log writer is configured")
	}
}

// TestHealthz_ChainInitializedFalseWhenNoChain — #544 — when no audit
// log writer is wired (withAuditLog=false), chain_initialized must be
// false. Closes the cold-start gap noted in MRR-5-MONITORING-RUNBOOK
// §6 M2: a non-configured audit chain MUST surface immediately on
// /healthz, not on the first decision attempt.
func TestHealthz_ChainInitializedFalseWhenNoChain(t *testing.T) {
	_, healthURL, _, _ := startTestProxy(t, newQuietUpstream(t), false, false)
	body := fetchHealthzBody(t, healthURL)
	got, ok := body["chain_initialized"].(bool)
	if !ok {
		t.Fatalf("chain_initialized not a bool: %#v (type %T)",
			body["chain_initialized"], body["chain_initialized"])
	}
	if got {
		t.Errorf("chain_initialized = true; want false when no audit log writer is configured")
	}
}

// TestHealthz_HasLlmBudget — #544 — /healthz must include the
// llm_budget key per [[cross-product-agent-parity]]. Symmetric to
// TestHealthz_HasChainInitialized.
func TestHealthz_HasLlmBudget(t *testing.T) {
	_, healthURL, _, _ := startTestProxy(t, newQuietUpstream(t), false, false)
	body := fetchHealthzBody(t, healthURL)
	if _, ok := body["llm_budget"]; !ok {
		t.Fatalf("/healthz missing llm_budget field: %#v", body)
	}
}

// TestHealthz_LlmBudgetEnabledFalse — #544 — Go bouncers don't run
// LLM per [[bouncer-zero-llm-when-agent-in-loop]] so the llm_budget
// block must report enabled=false unconditionally. This is honest per
// [[ibounce-honest-positioning]] (not a stub) — if a Go bouncer ever
// adds LLM features, this test should fail loudly so the parity shape
// gets re-evaluated against ibounce's full disabled→enabled shape.
func TestHealthz_LlmBudgetEnabledFalse(t *testing.T) {
	_, healthURL, _, _ := startTestProxy(t, newQuietUpstream(t), false, false)
	body := fetchHealthzBody(t, healthURL)
	llmBudget, ok := body["llm_budget"].(map[string]any)
	if !ok {
		t.Fatalf("llm_budget not an object: %#v (type %T)",
			body["llm_budget"], body["llm_budget"])
	}
	enabled, ok := llmBudget["enabled"].(bool)
	if !ok {
		t.Fatalf("llm_budget.enabled not a bool: %#v (type %T)",
			llmBudget["enabled"], llmBudget["enabled"])
	}
	if enabled {
		t.Errorf("llm_budget.enabled = true; Go bouncers don't run LLM per [[bouncer-zero-llm-when-agent-in-loop]]")
	}
}

// TestHealthz_LlmBudgetShapeMatchesIbounceWhenDisabled — #544 — when
// the side-LLM is OFF, ibounce reports exactly `{"enabled": false}`
// (single key, no other fields). Go bouncers' disabled-shape MUST
// match byte-for-byte so a cross-bouncer SRE monitor that parses
// llm_budget.enabled doesn't trip on unexpected extra fields. Per
// MRR-5 §2 the composite monitor reads this block uniformly.
func TestHealthz_LlmBudgetShapeMatchesIbounceWhenDisabled(t *testing.T) {
	_, healthURL, _, _ := startTestProxy(t, newQuietUpstream(t), false, false)
	body := fetchHealthzBody(t, healthURL)
	llmBudget, ok := body["llm_budget"].(map[string]any)
	if !ok {
		t.Fatalf("llm_budget not an object: %#v", body["llm_budget"])
	}
	if len(llmBudget) != 1 {
		t.Errorf("llm_budget has %d keys; want exactly 1 (enabled) to match ibounce's disabled-shape: %#v",
			len(llmBudget), llmBudget)
	}
	if _, ok := llmBudget["enabled"]; !ok {
		t.Errorf("llm_budget missing required 'enabled' key: %#v", llmBudget)
	}
}
