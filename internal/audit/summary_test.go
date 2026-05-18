package audit

import (
	"strings"
	"testing"
)

func TestSummarize_EmptyInputZeroCounts(t *testing.T) {
	s := Summarize(nil)
	if s.Total != 0 {
		t.Errorf("Total = %d; want 0", s.Total)
	}
	// Groups map is initialized but every bucket is empty.
	for _, g := range s.Ordering {
		if buckets, ok := s.Groups[g]; !ok || len(buckets) != 0 {
			t.Errorf("group %q has %d buckets; want 0", g, len(buckets))
		}
	}
	out := RenderSummary(s)
	if !strings.Contains(out, "Total events: 0") {
		t.Errorf("RenderSummary missing total: %q", out)
	}
	if !strings.Contains(out, "(no events matched)") {
		t.Errorf("RenderSummary missing empty marker: %q", out)
	}
}

func TestSummarize_CorrectCountsAcrossGroupings(t *testing.T) {
	events := []Event{
		mkEvent("GET", "/x", "api.example.com", 200),
		mkEvent("GET", "/x", "api.example.com", 200),
		mkEvent("POST", "/y", "api.example.com", 201),
		mkEvent("GET", "/x", "other.example", 500),
	}
	s := Summarize(events)
	if s.Total != 4 {
		t.Errorf("Total = %d; want 4", s.Total)
	}

	// upstream_host: 3 to api.example.com, 1 to other.example.
	hostBuckets := s.Groups["upstream_host"]
	if hostBuckets["api.example.com"] != 3 {
		t.Errorf("api.example.com count = %d; want 3", hostBuckets["api.example.com"])
	}
	if hostBuckets["other.example"] != 1 {
		t.Errorf("other.example count = %d; want 1", hostBuckets["other.example"])
	}

	// method: 3 GET, 1 POST.
	methodBuckets := s.Groups["method"]
	if methodBuckets["GET"] != 3 || methodBuckets["POST"] != 1 {
		t.Errorf("method buckets = %+v", methodBuckets)
	}

	// http_status: 2x200, 1x201, 1x500.
	statusBuckets := s.Groups["http_status"]
	if statusBuckets["200"] != 2 || statusBuckets["201"] != 1 || statusBuckets["500"] != 1 {
		t.Errorf("http_status buckets = %+v", statusBuckets)
	}

	// Composite grouping: "api.example.com GET 200" should have 2.
	composite := s.Groups["upstream_host+method+http_status"]
	if composite["api.example.com GET 200"] != 2 {
		t.Errorf("composite api.example.com GET 200 = %d; want 2", composite["api.example.com GET 200"])
	}
	if composite["other.example GET 500"] != 1 {
		t.Errorf("composite other.example GET 500 = %d; want 1", composite["other.example GET 500"])
	}
}

func TestRenderSummary_DeterministicOrdering(t *testing.T) {
	events := []Event{
		mkEvent("GET", "/a", "a.example", 200),
		mkEvent("GET", "/b", "b.example", 200),
	}
	out1 := RenderSummary(Summarize(events))
	out2 := RenderSummary(Summarize(events))
	if out1 != out2 {
		t.Error("RenderSummary should be deterministic across calls")
	}
}

func TestSummarize_GbounceSpecificGroupingsPresent(t *testing.T) {
	s := Summarize([]Event{mkEvent("GET", "/x", "h", 200)})
	for _, g := range []string{
		"upstream_host",
		"method",
		"http_status",
		"upstream_host+method+http_status",
	} {
		if _, ok := s.Groups[g]; !ok {
			t.Errorf("missing gbounce-specific grouping %q", g)
		}
	}
}
