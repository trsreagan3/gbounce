package proxy

import (
	"testing"

	"github.com/trsreagan3/gbounce/internal/audit"
)

func evWithHost(host string) audit.Event {
	return audit.Event{DstEndpoint: &audit.OCSFEndpoint{Hostname: host}}
}

func TestHostExcludedFromUI(t *testing.T) {
	globs := []string{"*.datadoghq.com", "exact.example.com"}
	cases := []struct {
		host string
		want bool
	}{
		{"http-intake.logs.us5.datadoghq.com", true},     // glob match
		{"http-intake.logs.us5.datadoghq.com:443", true}, // host:port stripped
		{"HTTP-INTAKE.LOGS.US5.DATADOGHQ.COM", true},     // case-insensitive
		{"exact.example.com", true},                      // exact match
		{"exact.example.com:8443", true},                 // exact + port
		{"api.github.com", false},                        // real traffic untouched
		{"notdatadoghq.com", false},                      // suffix-only, not subdomain
		{"", false},                                      // no host
	}
	for _, c := range cases {
		got := hostExcludedFromUI(evWithHost(c.host), globs)
		if got != c.want {
			t.Errorf("hostExcludedFromUI(%q) = %v; want %v", c.host, got, c.want)
		}
	}
	// Nil dst endpoint must never panic / never exclude.
	if hostExcludedFromUI(audit.Event{}, globs) {
		t.Errorf("event with nil DstEndpoint must not be excluded")
	}
}

func TestApplyUIExcludeHosts_DropsNoiseKeepsUsage(t *testing.T) {
	events := []audit.Event{
		evWithHost("http-intake.logs.us5.datadoghq.com:443"),
		evWithHost("api.github.com"),
		evWithHost("agent.datadoghq.com"),
		evWithHost("slack.com"),
	}
	out := applyUIExcludeHosts(events, []string{"*.datadoghq.com"})
	if len(out) != 2 {
		t.Fatalf("expected 2 events kept (github, slack); got %d", len(out))
	}
	for _, ev := range out {
		if ev.DstEndpoint.Hostname == "" {
			continue
		}
		if h := ev.DstEndpoint.Hostname; h == "http-intake.logs.us5.datadoghq.com:443" || h == "agent.datadoghq.com" {
			t.Errorf("datadog event leaked through UI filter: %q", h)
		}
	}

	// Empty exclude list is a no-op (all events retained).
	if got := applyUIExcludeHosts(events, nil); len(got) != len(events) {
		t.Errorf("empty exclude list must be a no-op; got %d want %d", len(got), len(events))
	}

	// A malformed glob must not swallow unrelated traffic (exact-match
	// backstop only). "[" is an invalid path.Match pattern.
	if got := applyUIExcludeHosts(events, []string{"["}); len(got) != len(events) {
		t.Errorf("malformed glob must not drop events; got %d want %d", len(got), len(events))
	}
}
