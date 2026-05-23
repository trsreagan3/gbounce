// Tests for the gbounce structured-deny 403 wire body (#459 / §A57b).
// Asserts the canonical Python ibounce shape rides on gbounce 403s per
// [[cross-product-agent-parity]]: caught_by_bouncer leads,
// classifier_hook marks "go-heuristic-only", suggested_allow_command
// is shell-friendly, recommended_action is one of the canonical three,
// destructive-verb heuristic fires, legacy keys preserved.
package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trsreagan3/gbounce/internal/structureddeny"
)

// TestStructuredDeny403_IncludesCaughtByBouncer asserts the
// caught_by_bouncer field rides on the 403 body per
// [[ambient-value-prop-and-friction-framing]].
func TestStructuredDeny403_IncludesCaughtByBouncer(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "DELETE", "/api/v1/users/42", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	if got, ok := body["caught_by_bouncer"].(string); !ok || got != "gbounce" {
		t.Fatalf("caught_by_bouncer = %v; want \"gbounce\"", body["caught_by_bouncer"])
	}
}

// TestStructuredDeny403_IncludesClassifierField asserts the
// go-heuristic-only marker rides on the wire per
// [[ibounce-honest-positioning]].
func TestStructuredDeny403_IncludesClassifierField(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "DELETE", "/api/v1/users/42", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	if got, ok := body["classifier_hook"].(string); !ok || got != structureddeny.ClassifierHookGoHeuristic {
		t.Fatalf("classifier_hook = %v; want %q",
			body["classifier_hook"], structureddeny.ClassifierHookGoHeuristic)
	}
}

// TestStructuredDeny403_IncludesSuggestedAllowCommand asserts the
// gbounce profile allow command rides on the wire body when the deny
// is allow-able (not a dynamic-deny rule).
func TestStructuredDeny403_IncludesSuggestedAllowCommand(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "GET", "/api/v1/foo", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	got, ok := body["suggested_allow_command"].(string)
	if !ok || got == "" {
		t.Fatalf("suggested_allow_command missing or empty: %v", body["suggested_allow_command"])
	}
	for _, want := range []string{"gbounce profile allow", "--target evil.example.com", "--action GET:/api/v1/foo"} {
		if !strings.Contains(got, want) {
			t.Errorf("suggested_allow_command = %q; missing %q", got, want)
		}
	}
}

// TestStructuredDeny403_IncludesRecommendedAction asserts the enum is
// one of the canonical three.
func TestStructuredDeny403_IncludesRecommendedAction(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "GET", "/api/v1/foo", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	got, ok := body["recommended_action"].(string)
	if !ok {
		t.Fatalf("recommended_action missing: %v", body["recommended_action"])
	}
	switch got {
	case structureddeny.RecommendedActionEasyAllow,
		structureddeny.RecommendedActionHaltEscalate,
		structureddeny.RecommendedActionRephraseRetry:
	default:
		t.Fatalf("recommended_action = %q; want one of the canonical three", got)
	}
}

// TestStructuredDeny403_PreservesLegacyKeys asserts the legacy
// `error` field (used by old grep-on-error clients) is preserved per
// [[creates-never-mutates]].
func TestStructuredDeny403_PreservesLegacyKeys(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "GET", "/api/v1/foo", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	for _, k := range []string{"error", "decision_verdict", "decision_reason"} {
		if _, ok := body[k]; !ok {
			t.Errorf("legacy key %q missing from 403 body", k)
		}
	}
	if got, _ := body["decision_verdict"].(string); got != "deny" {
		t.Errorf("decision_verdict = %v; want \"deny\"", body["decision_verdict"])
	}
}

// TestStructuredDeny403_HeuristicClassifierAdversarialBackstop asserts
// the Go-local heuristic mirrors KNOWN_ADVERSARIAL_PATTERNS for the
// gbounce action shape METHOD:/path-prefix. The HTTP DELETE method
// itself contains "delete" so the heuristic fires.
func TestStructuredDeny403_HeuristicClassifierAdversarialBackstop(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "DELETE", "/api/v1/users/42", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	if got, _ := body["is_likely_injection_classification"].(string); got != structureddeny.InjectionAppearsAdversarial {
		t.Errorf("classification for DELETE = %v; want %q",
			got, structureddeny.InjectionAppearsAdversarial)
	}
	// Non-destructive GET → ambiguous.
	body2 := gbounceWrite403AndDecode(t, "GET", "/api/v1/users/42", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	if got, _ := body2["is_likely_injection_classification"].(string); got != structureddeny.InjectionAmbiguous {
		t.Errorf("classification for GET = %v; want %q",
			got, structureddeny.InjectionAmbiguous)
	}
}

// TestStructuredDeny403_SchemaVersionFieldPresent asserts the wire
// schema version is emitted so consumers can detect future bumps.
func TestStructuredDeny403_SchemaVersionFieldPresent(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "GET", "/api/v1/foo", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	if got, _ := body["structured_deny_schema_version"].(string); got != structureddeny.SchemaVersion {
		t.Fatalf("structured_deny_schema_version = %v; want %q",
			body["structured_deny_schema_version"], structureddeny.SchemaVersion)
	}
}

// TestStructuredDeny403_DenyEventIDFieldPresent asserts the stable
// event id is on the wire so an agent can pass it to a future MCP
// iam_jit_handle_deny call.
func TestStructuredDeny403_DenyEventIDFieldPresent(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "GET", "/api/v1/foo", "evil.example.com", &DenyHostRule{Raw: "evil.example.com", Source: DenySourceStatic})
	got, _ := body["deny_event_id"].(string)
	if !strings.HasPrefix(got, "evt_gbounce_") {
		t.Fatalf("deny_event_id = %q; want evt_gbounce_ prefix", got)
	}
}

// TestStructuredDeny403_DynamicDenyRoutesToRephraseRetry asserts a
// dynamic-deny rule deny routes the agent to rephrase+retry (operator
// must edit the YAML — not allow-able from the CLI).
func TestStructuredDeny403_DynamicDenyRoutesToRephraseRetry(t *testing.T) {
	body := gbounceWrite403AndDecode(t, "GET", "/api/v1/foo", "evil.example.com", &DenyHostRule{
		Raw: "evil.example.com", Source: DenySourceDynamic, DynamicDenyRuleID: "dd_01ABC",
	})
	if got, _ := body["recommended_action"].(string); got != structureddeny.RecommendedActionRephraseRetry {
		t.Fatalf("dynamic_deny recommended_action = %v; want %q",
			body["recommended_action"], structureddeny.RecommendedActionRephraseRetry)
	}
	if got, _ := body["suggested_allow_command"].(string); !strings.HasPrefix(got, "#") {
		t.Fatalf("dynamic_deny suggested_allow_command = %q; want leading `#`", got)
	}
}

// gbounceWrite403AndDecode invokes writeStructuredDeny403 against an
// httptest recorder and decodes the JSON body.
func gbounceWrite403AndDecode(t *testing.T, method, path, host string, rule *DenyHostRule) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	w := httptest.NewRecorder()
	legacyMsg := "gbounce: request denied by deny_hosts rule: " + rule.Raw
	writeStructuredDeny403(w, req, rule, legacyMsg, classifyGbounceDenySource(rule))
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", w.Result().StatusCode)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v\nbody=%s", err, w.Body.String())
	}
	return body
}
