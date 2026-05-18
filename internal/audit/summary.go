// summary.go ships the `--summary` count-summary view.
//
// Groupings (cross-product per [[cross-product-agent-parity]]):
//
//	event_type
//	severity_id
//	actor.user.name
//	api.operation
//
// Plus gbounce-specific groupings:
//
//	upstream_host
//	method
//	http_status
//	upstream_host + method + http_status (composite, the "request
//	  shape" key — answers "how did calls to api.example.com / GET
//	  break down by HTTP status?")
//
// Output shape is a stable map-of-grouping → map-of-bucket → count.
// The CLI renderer walks the maps in alphabetical key order so the
// printed output is deterministic across runs.
package audit

import (
	"fmt"
	"sort"
	"strings"
)

// Summary is the count-summary result. Keyed by grouping name (e.g.
// "event_type") → bucket value → count.
type Summary struct {
	Total    int
	Groups   map[string]map[string]int
	Ordering []string
}

// summaryGroupings is the stable ordering of groupings in the printed
// output. Order is the human-readable narrative order: the broad
// "what kind of event was this" first, then the more specific shapes.
var summaryGroupings = []string{
	"event_type",
	"severity_id",
	"actor.user.name",
	"api.operation",
	"upstream_host",
	"method",
	"http_status",
	"upstream_host+method+http_status",
}

// Summarize builds a Summary from a slice of (already filtered) events.
// Empty input is honored — every grouping returns an empty map with
// zero counts, which the renderer prints as "(no events matched)".
func Summarize(events []Event) Summary {
	s := Summary{
		Total:    len(events),
		Groups:   make(map[string]map[string]int, len(summaryGroupings)),
		Ordering: append([]string{}, summaryGroupings...),
	}
	for _, g := range summaryGroupings {
		s.Groups[g] = make(map[string]int)
	}
	for _, ev := range events {
		for _, g := range summaryGroupings {
			key := groupKey(ev, g)
			s.Groups[g][key]++
		}
	}
	return s
}

// groupKey resolves the bucket-value of one event for one grouping.
// Mirrors the field-resolution logic in filter.go's resolveField so a
// `--filter X=Y` matches exactly the events that summarize as bucket Y
// under grouping X.
func groupKey(ev Event, grouping string) string {
	switch grouping {
	case "event_type":
		if ev.Unmapped.IAMJIT.Ext != nil {
			if v, ok := ev.Unmapped.IAMJIT.Ext["event_type"].(string); ok && v != "" {
				return v
			}
			if v, ok := ev.Unmapped.IAMJIT.Ext["admin_action"].(string); ok && v != "" {
				return v
			}
		}
		if ev.ActivityName != "" {
			return ev.ActivityName
		}
		return "(unknown)"
	case "severity_id":
		return fmt.Sprintf("%d", ev.SeverityID)
	case "actor.user.name":
		if ev.Unmapped.IAMJIT.Ext != nil {
			if cc, ok := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any); ok {
				if a, ok := cc["actor"].(string); ok && a != "" {
					return a
				}
			}
		}
		return "(unset)"
	case "api.operation":
		if ev.API.Operation != "" {
			return ev.API.Operation
		}
		return "(unset)"
	case "upstream_host":
		if ev.API.Service.Name != "" {
			return ev.API.Service.Name
		}
		return "(unset)"
	case "method":
		op := ev.API.Operation
		if i := strings.Index(op, " "); i > 0 {
			return op[:i]
		}
		if op != "" {
			return op
		}
		return "(unset)"
	case "http_status":
		if ev.Unmapped.IAMJIT.Ext != nil {
			if v, ok := ev.Unmapped.IAMJIT.Ext["http_status"]; ok {
				if n, ok := toFloat(v); ok {
					return fmt.Sprintf("%d", int(n))
				}
			}
		}
		return "(unset)"
	case "upstream_host+method+http_status":
		host := groupKey(ev, "upstream_host")
		method := groupKey(ev, "method")
		status := groupKey(ev, "http_status")
		return host + " " + method + " " + status
	}
	return "(unknown)"
}

// RenderSummary prints a Summary to a string in stable order. The
// rendered shape is humane (alpha-sorted bucket keys within each
// grouping; grouping order matches summaryGroupings).
func RenderSummary(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Total events: %d\n", s.Total)
	if s.Total == 0 {
		fmt.Fprintln(&b, "(no events matched)")
		return b.String()
	}
	for _, g := range s.Ordering {
		buckets := s.Groups[g]
		fmt.Fprintf(&b, "\nBy %s:\n", g)
		if len(buckets) == 0 {
			fmt.Fprintln(&b, "  (no buckets)")
			continue
		}
		keys := make([]string, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-40s  %d\n", k, buckets[k])
		}
	}
	return b.String()
}
