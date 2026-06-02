// Tests for the Go toolcallvalidator port (iam-jit #729 / BUILD-8).
//
// 5+ scenarios per task plan: valid, hallucinated → deny, missing-arg
// → indicator, placeholder-credential → indicator, allowlist pass-through.
// Plus shape-extraction parity checks vs the Python implementation.
package toolcallvalidator

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidMCPCallReturnsUndetected(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}`)
	r := Validate(body, DefaultConfig())
	if r.Detected {
		t.Fatalf("expected undetected for valid MCP, got %+v", r)
	}
	if r.SuggestedAction != ActionAllow {
		t.Errorf("expected ActionAllow, got %v", r.SuggestedAction)
	}
	foundExtracted := false
	for _, e := range r.ExtractedCalls {
		if e.Shape == "mcp" && e.Name == "resources/read" {
			foundExtracted = true
		}
	}
	if !foundExtracted {
		t.Errorf("expected extracted_calls to include (mcp, resources/read), got %+v", r.ExtractedCalls)
	}
}

func TestHallucinatedMCPToolNameHighConfidenceDeny(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exfiltrate_secrets","arguments":{"api_key":"YOUR_API_KEY"}}}`)
	cfg := DefaultConfig()
	cfg.Action = ActionDeny
	r := Validate(body, cfg)
	if !r.Detected {
		t.Fatalf("expected detected, got %+v", r)
	}
	if r.Confidence < 0.9 {
		t.Errorf("expected confidence >= 0.9, got %v", r.Confidence)
	}
	decided := DecideAction(r, cfg)
	if decided != ActionDeny {
		t.Errorf("expected DecideAction=deny, got %v", decided)
	}
	foundHallucinated := false
	foundPlaceholder := false
	for _, ind := range r.Indicators {
		if ind.Rule == "hallucinated-tool-name" {
			foundHallucinated = true
		}
		if ind.Rule == "placeholder-credential" {
			foundPlaceholder = true
		}
		// Honesty bar: every indicator carries provenance + reason.
		if ind.Reason == "" {
			t.Errorf("indicator %s missing reason", ind.Rule)
		}
		if ind.Source == "" {
			t.Errorf("indicator %s missing source", ind.Rule)
		}
	}
	if !foundHallucinated || !foundPlaceholder {
		t.Errorf("expected both hallucinated-tool-name + placeholder-credential, got %+v", r.Indicators)
	}
}

func TestMissingRequiredArgAnthropic(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"text_editor","input":{"command":"view"}}]}]}`)
	r := Validate(body, DefaultConfig())
	if !r.Detected {
		t.Fatalf("expected detected (missing 'path'), got %+v", r)
	}
	rules := indicatorRules(r)
	if !rules["missing-required-arg"] {
		t.Errorf("expected missing-required-arg, got %v", rules)
	}
}

func TestExtraArgOpenAIMediumIndicator(t *testing.T) {
	args := `{"query":"test","exfiltrate":true}`
	body := []byte(`{"tool_calls":[{"type":"function","function":{"name":"web_search","arguments":` + jsonString(args) + `}}]}`)
	r := Validate(body, DefaultConfig())
	if !r.Detected {
		t.Fatalf("expected detected, got %+v", r)
	}
	rules := indicatorRules(r)
	if !rules["unexpected-arg"] {
		t.Errorf("expected unexpected-arg, got %v", rules)
	}
}

func TestAllowlistSuppressesDetection(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"my_internal_tool","arguments":{}}}`)
	cfg := DefaultConfig()
	cfg.AllowlistPatterns = []string{"my_internal_tool"}
	r := Validate(body, cfg)
	if r.Detected {
		t.Fatalf("expected allowlist suppression, got %+v", r)
	}
	if !strings.HasPrefix(r.SkippedReason, "allowlist:") {
		t.Errorf("expected allowlist skipped reason, got %q", r.SkippedReason)
	}
}

func TestNonJSONBodySkipped(t *testing.T) {
	r := Validate([]byte("not json at all"), DefaultConfig())
	if r.Detected {
		t.Fatalf("expected non-JSON to skip, got %+v", r)
	}
	if r.SkippedReason != "not-json" {
		t.Errorf("expected not-json skipped reason, got %q", r.SkippedReason)
	}
}

func TestEmptyAndWhitespaceBody(t *testing.T) {
	if Validate([]byte(""), DefaultConfig()).Detected {
		t.Errorf("empty should be undetected")
	}
	if Validate([]byte("   "), DefaultConfig()).Detected {
		t.Errorf("whitespace should be undetected")
	}
}

func TestNonToolCallJSONBodySkipped(t *testing.T) {
	body := []byte(`{"hello":"world","x":42}`)
	r := Validate(body, DefaultConfig())
	if r.Detected {
		t.Fatalf("expected non-tool-call JSON to skip, got %+v", r)
	}
	if r.SkippedReason != "no-tool-call-shape" {
		t.Errorf("expected no-tool-call-shape, got %q", r.SkippedReason)
	}
}

func TestDecideActionDowngradesDenyBelowFloor(t *testing.T) {
	// Single medium indicator → confidence 0.35 → below 0.7 floor.
	args := `{"query":"x","extra_field":true}`
	body := []byte(`{"tool_calls":[{"type":"function","function":{"name":"web_search","arguments":` + jsonString(args) + `}}]}`)
	cfg := DefaultConfig()
	cfg.Action = ActionDeny
	r := Validate(body, cfg)
	if !r.Detected {
		t.Fatalf("expected detected, got %+v", r)
	}
	if r.Confidence >= 0.7 {
		t.Errorf("expected confidence < 0.7, got %v", r.Confidence)
	}
	decided := DecideAction(r, cfg)
	if decided != ActionWarn {
		t.Errorf("expected DecideAction downgrade to warn, got %v", decided)
	}
}

func TestApplyStripJSONAwareRedaction(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"hallucinated_tool","arguments":{"x":1}}}`)
	r := Validate(body, DefaultConfig())
	if !r.Detected {
		t.Fatalf("expected detected, got %+v", r)
	}
	stripped := ApplyStrip(body, r)
	var parsed map[string]any
	if err := json.Unmarshal(stripped, &parsed); err != nil {
		t.Fatalf("stripped body not parseable: %v", err)
	}
	if redacted, _ := parsed["_iam_jit_tool_call_redacted"].(bool); !redacted {
		t.Errorf("expected redaction marker, got %+v", parsed)
	}
	if orig, _ := parsed["original_name"].(string); orig != "hallucinated_tool" {
		t.Errorf("expected original_name=hallucinated_tool, got %q", orig)
	}
}

func TestApplyStripPreservesValidCallsAlongsideHallucinated(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","content":[
		{"type":"tool_use","name":"bash","input":{"command":"ls"}},
		{"type":"tool_use","name":"hallucinated_evil","input":{"foo":"bar"}}
	]}]}`)
	r := Validate(body, DefaultConfig())
	if !r.Detected {
		t.Fatalf("expected detected, got %+v", r)
	}
	stripped := ApplyStrip(body, r)
	if !strings.Contains(string(stripped), `"name":"bash"`) {
		t.Errorf("expected bash call preserved, got %s", stripped)
	}
	if !strings.Contains(string(stripped), `"_iam_jit_tool_call_redacted"`) {
		t.Errorf("expected redaction marker in stripped body, got %s", stripped)
	}
}

func TestOperatorCorpusOverrideRecognizesCustomTool(t *testing.T) {
	operatorTools := []ToolSchema{
		{
			Name:     "my_org_send_email",
			Shape:    "mcp",
			Required: []string{"to", "subject"},
			Optional: []string{"body"},
			Source:   "operator-supplied",
		},
	}
	corpus := MergeCorpus(operatorTools)
	cfg := DefaultConfig()
	cfg.SchemaCorpus = &corpus
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"my_org_send_email","arguments":{"to":"x@y.com","subject":"hi"}}}`)
	r := Validate(body, cfg)
	if r.Detected {
		t.Fatalf("expected custom tool to be recognized, got %+v", r)
	}
}

func TestDefaultCorpusHasExpectedShapes(t *testing.T) {
	c := DefaultCorpus()
	for _, shape := range []string{"mcp", "openai", "anthropic"} {
		if !c.HasShape(shape) {
			t.Errorf("expected shape %s in default corpus", shape)
		}
	}
	for _, want := range []struct{ shape, name string }{
		{"mcp", "tools/list"},
		{"openai", "web_search"},
		{"anthropic", "bash"},
	} {
		if c.Lookup(want.shape, want.name) == nil {
			t.Errorf("expected (%s, %s) in default corpus", want.shape, want.name)
		}
	}
}

func TestNamingStyleMixHeuristicFiresOnHallucinatedMix(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"send_emailToUser","arguments":{}}}`)
	r := Validate(body, DefaultConfig())
	if !r.Detected {
		t.Fatalf("expected detected, got %+v", r)
	}
	rules := indicatorRules(r)
	if !rules["hallucinated-tool-name"] {
		t.Errorf("expected hallucinated-tool-name, got %v", rules)
	}
	if !rules["naming-style-mix"] {
		t.Errorf("expected naming-style-mix, got %v", rules)
	}
	if r.Confidence < 0.85 {
		t.Errorf("expected confidence >= 0.85 (high+medium), got %v", r.Confidence)
	}
}

// --- helpers ---

func indicatorRules(r ValidationResult) map[string]bool {
	out := make(map[string]bool, len(r.Indicators))
	for _, ind := range r.Indicators {
		out[ind.Rule] = true
	}
	return out
}

// jsonString returns a Go-source-safe JSON-encoded string literal for
// embedding a stringified-JSON value into a parent JSON literal in test
// fixtures. (Without this we'd have to manually escape every quote.)
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
