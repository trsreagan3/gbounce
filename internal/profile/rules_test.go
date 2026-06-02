package profile

import (
	"testing"
)

// TestMITM_ProfileRuleMatchesByPath (spec test): a rule with a path
// predicate matches when the URL path matches.
func TestMITM_ProfileRuleMatchesByPath(t *testing.T) {
	rule, err := ParseRule(RuleSpec{
		Host: "api.openai.com",
		Path: "/v1/chat/completions",
	})
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if !rule.Match("api.openai.com", 443, "POST", "/v1/chat/completions", "") {
		t.Errorf("expected match for exact path")
	}
	if rule.Match("api.openai.com", 443, "POST", "/v1/models", "") {
		t.Errorf("unexpected match for different path")
	}
	if rule.Match("api.example.com", 443, "POST", "/v1/chat/completions", "") {
		t.Errorf("unexpected match for different host")
	}
}

// TestMITM_ProfileRuleMatchesByMethod (spec test): a method-only rule
// matches across hosts when the method matches.
func TestMITM_ProfileRuleMatchesByMethod(t *testing.T) {
	rule, err := ParseRule(RuleSpec{Method: []string{"POST", "PUT"}})
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if !rule.Match("any.host", 443, "POST", "/", "") {
		t.Errorf("expected POST match")
	}
	if !rule.Match("any.host", 443, "put", "/", "") { // case-insensitive
		t.Errorf("expected PUT match (case-insensitive)")
	}
	if rule.Match("any.host", 443, "GET", "/", "") {
		t.Errorf("unexpected GET match")
	}
}

// TestProfileRule_HostWildcard mirrors the documented `*.openai.com`
// semantics from #314: matches the bare suffix + any subdomain.
func TestProfileRule_HostWildcard(t *testing.T) {
	rule, err := ParseRule(RuleSpec{Host: "*.openai.com"})
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	for _, host := range []string{"openai.com", "api.openai.com", "foo.bar.openai.com"} {
		if !rule.Match(host, 443, "GET", "/", "") {
			t.Errorf("expected match for host %q", host)
		}
	}
	if rule.Match("openaicompetitor.com", 443, "GET", "/", "") {
		t.Errorf("unexpected match for non-subdomain")
	}
}

// TestProfileRule_QueryParamMatch covers the per-param value predicate.
func TestProfileRule_QueryParamMatch(t *testing.T) {
	rule, err := ParseRule(RuleSpec{
		QueryParams: map[string]string{"action": "delete"},
	})
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if !rule.Match("h", 443, "GET", "/", "action=delete&id=1") {
		t.Errorf("expected match")
	}
	if rule.Match("h", 443, "GET", "/", "action=read&id=1") {
		t.Errorf("unexpected match")
	}
}

// TestProfileRule_PathPrefixAndRegex covers the prefix + regex shapes.
func TestProfileRule_PathPrefixAndRegex(t *testing.T) {
	prefixRule, err := ParseRule(RuleSpec{PathPrefix: "/admin/"})
	if err != nil {
		t.Fatalf("ParseRule prefix: %v", err)
	}
	if !prefixRule.Match("h", 443, "GET", "/admin/users", "") {
		t.Errorf("expected prefix match")
	}
	if prefixRule.Match("h", 443, "GET", "/public/users", "") {
		t.Errorf("unexpected prefix match")
	}

	regexRule, err := ParseRule(RuleSpec{PathRegex: `^/v1/(chat|completions)/`})
	if err != nil {
		t.Fatalf("ParseRule regex: %v", err)
	}
	if !regexRule.Match("h", 443, "POST", "/v1/chat/foo", "") {
		t.Errorf("expected regex match")
	}
	if regexRule.Match("h", 443, "POST", "/v2/chat/foo", "") {
		t.Errorf("unexpected regex match")
	}
}

// TestProfileRule_RequiresMITM_DetectsPredicates: rules with method,
// path, or query-param predicates must report RequiresMITM=true.
func TestProfileRule_RequiresMITM_DetectsPredicates(t *testing.T) {
	cases := []struct {
		name string
		spec RuleSpec
		want bool
	}{
		{"host only", RuleSpec{Host: "x"}, false},
		{"port only", RuleSpec{Port: 443}, false},
		{"method", RuleSpec{Method: "POST"}, true},
		{"path", RuleSpec{Path: "/x"}, true},
		{"path_prefix", RuleSpec{PathPrefix: "/x"}, true},
		{"path_regex", RuleSpec{PathRegex: `/x`}, true},
		{"query", RuleSpec{QueryParams: map[string]string{"a": "b"}}, true},
	}
	for _, c := range cases {
		r, err := ParseRule(c.spec)
		if err != nil {
			t.Fatalf("%s: ParseRule: %v", c.name, err)
		}
		if got := r.RequiresMITM(); got != c.want {
			t.Errorf("%s: RequiresMITM=%v want %v", c.name, got, c.want)
		}
	}
}

// TestProfileRule_RejectsMultiLevelWildcard: only single leading
// wildcards are allowed.
func TestProfileRule_RejectsMultiLevelWildcard(t *testing.T) {
	_, err := ParseRule(RuleSpec{Host: "*.foo.*.bar.com"})
	if err == nil {
		t.Fatalf("expected error for multi-level wildcard")
	}
}

// TestFirstMatch_SkipsMITMOnlyRulesInDiscoveryMode confirms a rule
// requiring MITM is skipped when the caller passes mitmActive=false.
func TestFirstMatch_SkipsMITMOnlyRulesInDiscoveryMode(t *testing.T) {
	rules, err := ParseRules([]RuleSpec{
		{Host: "evil.example.com"},                // host-only, no MITM needed
		{Host: "api.openai.com", Path: "/v1/foo"}, // MITM-required
	})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	// In CONNECT-only mode, only the host-only rule can fire.
	if got := FirstMatch(rules, false, "api.openai.com", 443, "GET", "/v1/foo", ""); got != nil {
		t.Errorf("expected MITM-required rule to be skipped in CONNECT mode; got %+v", got)
	}
	if got := FirstMatch(rules, false, "evil.example.com", 443, "GET", "/", ""); got == nil {
		t.Errorf("host-only rule should still match in CONNECT mode")
	}
	// In MITM mode both rules can fire.
	if got := FirstMatch(rules, true, "api.openai.com", 443, "GET", "/v1/foo", ""); got == nil {
		t.Errorf("MITM-required rule should match when mitmActive=true")
	}
}

// TestFirstAllowMatch_MatchesSamePredicatesAsFirstMatch (iam-jit
// #377) confirms the allow-rule matcher uses the identical predicate
// engine + mitmActive skip semantics as FirstMatch — the allow layer
// is just the deny matcher pointed at the allow_rules slice.
func TestFirstAllowMatch_MatchesSamePredicatesAsFirstMatch(t *testing.T) {
	allow, err := ParseRules([]RuleSpec{
		{Host: "api.openai.com", Path: "/v1/chat/completions", Method: "POST"},
	})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	// MITM mode: the predicate set matches → allow fires.
	if got := FirstAllowMatch(allow, true, "api.openai.com", 443, "POST", "/v1/chat/completions", ""); got == nil {
		t.Errorf("allow_rule should match the exact request shape in MITM mode")
	}
	// Wrong method → no match.
	if got := FirstAllowMatch(allow, true, "api.openai.com", 443, "GET", "/v1/chat/completions", ""); got != nil {
		t.Errorf("allow_rule must not match a different method; got %+v", got)
	}
	// CONNECT-only mode: a MITM-required allow_rule is skipped (same as
	// the deny matcher) so a discovery-mode run can't accidentally
	// "allow" on an unmatchable predicate.
	if got := FirstAllowMatch(allow, false, "api.openai.com", 443, "POST", "/v1/chat/completions", ""); got != nil {
		t.Errorf("MITM-required allow_rule must be skipped in CONNECT mode; got %+v", got)
	}
}

// TestFirstAllowMatch_EmptyListIsNoOp confirms a nil/empty allow list
// never matches (the pre-#377 deny-only shape).
func TestFirstAllowMatch_EmptyListIsNoOp(t *testing.T) {
	if got := FirstAllowMatch(nil, true, "api.openai.com", 443, "POST", "/x", ""); got != nil {
		t.Errorf("empty allow list must never match; got %+v", got)
	}
}
