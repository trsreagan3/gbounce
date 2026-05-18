package audit

import (
	"strings"
	"testing"
	"time"
)

func TestParseFilter_EqExpr(t *testing.T) {
	f, err := ParseFilter("upstream_host=api.example.com")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	if f.Field != "upstream_host" || f.Op != FilterOpEq || f.Value != "api.example.com" {
		t.Errorf("parsed = %+v", f)
	}
}

func TestParseFilter_RegexExpr(t *testing.T) {
	f, err := ParseFilter("api.operation~^GET ")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	if f.Field != "api.operation" || f.Op != FilterOpRe {
		t.Errorf("parsed = %+v", f)
	}
	if f.Re == nil || !f.Re.MatchString("GET /v1/x") {
		t.Errorf("regex didn't compile/match")
	}
}

func TestParseFilter_NumericExprs(t *testing.T) {
	f, err := ParseFilter("http_status>=400")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	if f.Op != FilterOpGTE || f.Num != 400 {
		t.Errorf("parsed = %+v", f)
	}
	f2, err := ParseFilter("http_status<=499")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	if f2.Op != FilterOpLTE || f2.Num != 499 {
		t.Errorf("parsed = %+v", f2)
	}
}

func TestParseFilter_BadInputs(t *testing.T) {
	cases := []string{
		"no_op_here",
		"=value_only",
		"http_status>=notanumber",
		"path~[invalid(regex",
	}
	for _, c := range cases {
		if _, err := ParseFilter(c); err == nil {
			t.Errorf("ParseFilter(%q) should have errored", c)
		}
	}
}

func TestParseFilters_AggregatesAndPropagatesError(t *testing.T) {
	good, err := ParseFilters([]string{"method=GET", "http_status>=200"})
	if err != nil {
		t.Fatalf("ParseFilters: %v", err)
	}
	if len(good) != 2 {
		t.Errorf("len = %d", len(good))
	}
	if _, err := ParseFilters([]string{"method=GET", "broken"}); err == nil {
		t.Error("expected error on broken expr")
	}
}

// helper: build a minimal RequestInput-shaped event for filter tests.
func mkEvent(method, path, host string, status int) Event {
	return FromRequest(RequestInput{
		At:             time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
		DecisionID:     1,
		Mode:           "discovery",
		Method:         method,
		Path:           path,
		UpstreamHost:   host,
		UpstreamPort:   443,
		UpstreamScheme: "https",
		ClientHost:     "127.0.0.1",
		ClientPort:     56000,
		HTTPStatus:     status,
	})
}

func TestMatch_GbounceSpecificFields(t *testing.T) {
	ev := mkEvent("GET", "/v1/x", "api.example.com", 200)
	cases := []struct {
		expr string
		want bool
	}{
		{"upstream_host=api.example.com", true},
		{"upstream_host=other.example", false},
		{"method=GET", true},
		{"method=POST", false},
		{"path=/v1/x", true},
		{"path=/v1/y", false},
		{"http_status>=200", true},
		{"http_status<=199", false},
		{"http_status>=400", false},
		{"http_status<=200", true},
	}
	for _, c := range cases {
		f, err := ParseFilter(c.expr)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", c.expr, err)
		}
		if got := match(ev, f); got != c.want {
			t.Errorf("match(%q) = %v; want %v", c.expr, got, c.want)
		}
	}
}

func TestMatchAll_ANDsemantics(t *testing.T) {
	ev := mkEvent("GET", "/v1/x", "api.example.com", 200)
	filters, err := ParseFilters([]string{
		"upstream_host=api.example.com",
		"method=GET",
		"http_status>=200",
	})
	if err != nil {
		t.Fatalf("ParseFilters: %v", err)
	}
	if !MatchAll(ev, filters) {
		t.Error("all three filters should match")
	}
	// Adding one non-matching filter rejects the event.
	filters = append(filters, mustParseFilter(t, "method=POST"))
	if MatchAll(ev, filters) {
		t.Error("AND should reject when one filter fails")
	}
}

func TestMatch_RegexOnNestedPath(t *testing.T) {
	ev := mkEvent("GET", "/v1/users/42", "api.example.com", 200)
	f := mustParseFilter(t, "api.operation~^GET /v1/users/")
	if !match(ev, f) {
		t.Errorf("regex on api.operation should match")
	}
}

func TestMatch_OCSFNumericFields(t *testing.T) {
	ev := mkEvent("GET", "/x", "h", 200)
	if !match(ev, mustParseFilter(t, "severity_id=1")) {
		t.Error("severity_id=1 should match Informational")
	}
	if !match(ev, mustParseFilter(t, "activity_id=2")) {
		t.Error("GET → activity_id=2")
	}
	if !match(ev, mustParseFilter(t, "status_id=1")) {
		t.Error("200 → status_id=1")
	}
}

func TestMatch_AgentExtensionFields(t *testing.T) {
	ev := mkEvent("GET", "/x", "h", 200)
	// Inject agent block under the iam-jit ext (the proxy + future
	// MCP-driven events stash agent identity here).
	if ev.Unmapped.IAMJIT.Ext == nil {
		ev.Unmapped.IAMJIT.Ext = map[string]any{}
	}
	ev.Unmapped.IAMJIT.Ext["agent"] = map[string]any{
		"name":       "claude-code",
		"session_id": "sess-abc-123",
	}
	ev.Unmapped.IAMJIT.Ext["event_type"] = "api.request"

	if !match(ev, mustParseFilter(t, "unmapped.iam_jit.agent.name=claude-code")) {
		t.Error("agent.name should match")
	}
	if !match(ev, mustParseFilter(t, "unmapped.iam_jit.agent.session_id=sess-abc-123")) {
		t.Error("agent.session_id should match")
	}
	if !match(ev, mustParseFilter(t, "unmapped.iam_jit.event_type=api.request")) {
		t.Error("event_type should match")
	}
}

func TestMatch_UnknownFieldReturnsFalse(t *testing.T) {
	ev := mkEvent("GET", "/x", "h", 200)
	if match(ev, mustParseFilter(t, "no.such.field=anything")) {
		t.Error("unknown field should not match")
	}
}

func TestSupportedFilterFields_StableOrdering(t *testing.T) {
	got := SupportedFilterFields()
	if len(got) < 8 {
		t.Errorf("supported field list shrank: %d", len(got))
	}
	// Spot-check that gbounce-specific fields are listed.
	joined := strings.Join(got, ",")
	for _, f := range []string{"upstream_host", "path", "method", "http_status"} {
		if !strings.Contains(joined, f) {
			t.Errorf("missing gbounce-specific field %q", f)
		}
	}
}

func mustParseFilter(t *testing.T, expr string) Filter {
	t.Helper()
	f, err := ParseFilter(expr)
	if err != nil {
		t.Fatalf("ParseFilter(%q): %v", expr, err)
	}
	return f
}
