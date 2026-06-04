package crossbouncer

import (
	"strconv"
	"strings"
	"time"
)

// Event wraps a single OCSF (class 6003) audit event decoded from a bouncer's
// /audit/events NDJSON stream. It is backed by the raw decoded map so it stays
// resilient to per-bouncer field variation — accessors read defined field
// paths with documented fallbacks, exactly like the Python reader.
type Event struct {
	Raw map[string]any
}

// String-path getters -------------------------------------------------------

// get walks a dotted path through nested maps and returns the leaf value.
func (e Event) get(path string) (any, bool) {
	cur := any(e.Raw)
	for _, key := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[key]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// getString returns the leaf at path as a trimmed string if it is a non-empty
// string. Numbers/bools are NOT coerced here (use the typed accessors).
func (e Event) getString(path string) string {
	v, ok := e.get(path)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// firstString returns the first non-empty getString across the given paths.
func (e Event) firstString(paths ...string) string {
	for _, p := range paths {
		if s := e.getString(p); s != "" {
			return s
		}
	}
	return ""
}

// Semantic accessors --------------------------------------------------------

// Bouncer is the synthetic _bouncer field stamped by the fan-out client.
func (e Event) Bouncer() string { return e.getString("_bouncer") }

// SessionID is the cross-bouncer correlation key.
func (e Event) SessionID() string {
	return e.getString("unmapped.iam_jit.agent.session_id")
}

// TimeMS normalizes the `time` field (epoch-ms int/float OR ISO-8601 string)
// to int64 epoch-milliseconds. ok=false when there is no parseable timestamp.
func (e Event) TimeMS() (int64, bool) {
	v, ok := e.get("time")
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case string:
		return parseTimeMS(t)
	}
	return 0, false
}

// parseTimeMS parses either a numeric epoch-ms string or an ISO-8601 timestamp.
func parseTimeMS(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	// RFC3339 / ISO-8601 (Go handles the trailing Z natively).
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

// TimeISO returns the event time as an ISO-8601Z string, or "" if none.
func (e Event) TimeISO() string {
	ms, ok := e.TimeMS()
	if !ok {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// Verdict returns the normalized lowercase decision: "allow", "deny", or
// "unknown". Heartbeat/admin events report "unknown" here — use EventType for
// those. Canonical field is unmapped.iam_jit.verdict, with a top-level
// `verdict` fallback (matching the TUI).
func (e Event) Verdict() string {
	raw := e.firstString("unmapped.iam_jit.verdict", "verdict")
	switch strings.ToUpper(raw) {
	case "ALLOW", "ALLOWED":
		return "allow"
	case "DENY", "DENIED":
		return "deny"
	}
	return "unknown"
}

// EventType returns the iam-jit event type, falling back to the OCSF class name.
func (e Event) EventType() string {
	return e.firstString("unmapped.iam_jit.event_type", "event_type", "class_name")
}

// IsHeartbeat reports whether this is a heartbeat event (excluded from
// compliance + verdict tallies).
func (e Event) IsHeartbeat() bool {
	return strings.Contains(strings.ToUpper(e.EventType()), "HEARTBEAT")
}

// Action returns the service:Action / operation string with fallbacks.
func (e Event) Action() string {
	return e.firstString(
		"api.operation",
		"unmapped.iam_jit.operation",
		"activity_name",
	)
}

// Principal returns the acting identity with the documented fallback chain.
func (e Event) Principal() string {
	return e.firstString(
		"actor.user.uid",
		"actor.user.name",
		"unmapped.iam_jit.agent.name",
		"unmapped.iam_jit.principal",
		"unmapped.iam_jit.actor",
	)
}

// Reason returns the deny/decision reason with fallbacks.
func (e Event) Reason() string {
	return e.firstString(
		"unmapped.iam_jit.deny_reason",
		"unmapped.iam_jit.reason",
		"reason",
		"finding_info.title",
	)
}

// IAMContext returns the role/identity context with fallbacks.
func (e Event) IAMContext() string {
	return e.firstString(
		"unmapped.iam_jit.role",
		"unmapped.iam_jit.role_arn",
		"actor.user.uid",
		"actor.session.issuer",
	)
}

// Severity returns the severity label, deriving it from severity_id if the
// string form is absent.
func (e Event) Severity() string {
	if s := e.getString("severity"); s != "" {
		return s
	}
	if v, ok := e.get("severity_id"); ok {
		switch toInt(v) {
		case 1:
			return "Informational"
		case 2:
			return "Low"
		case 3:
			return "Medium"
		case 4:
			return "High"
		case 5:
			return "Critical"
		}
	}
	return ""
}

// Status returns the OCSF status, deriving from status_id if absent.
func (e Event) Status() string {
	if s := e.getString("status"); s != "" {
		return s
	}
	if v, ok := e.get("status_id"); ok {
		switch toInt(v) {
		case 0:
			return "Unknown"
		case 1:
			return "Success"
		case 2:
			return "Failure"
		}
	}
	return ""
}

// AnomalyVerdict returns the anomaly verdict, e.g. "anomalous".
func (e Event) AnomalyVerdict() string {
	return e.getString("unmapped.iam_jit.anomaly_verdict")
}

// MFAGated reports whether MFA was present on the request (any of the
// documented MFA fields is truthy).
func (e Event) MFAGated() bool {
	for _, p := range []string{
		"unmapped.iam_jit.mfa_present",
		"unmapped.iam_jit.mfa",
		"unmapped.aws.MultiFactorAuthPresent",
	} {
		if v, ok := e.get(p); ok && truthy(v) {
			return true
		}
	}
	return false
}

// Resources returns the resource identifiers with the documented fallback
// across resources[], api.resources[], and dst_endpoint host/ip.
func (e Event) Resources() []string {
	if rs := collectUIDNames(e.Raw["resources"]); len(rs) > 0 {
		return rs
	}
	if v, ok := e.get("api.resources"); ok {
		if rs := collectUIDNames(v); len(rs) > 0 {
			return rs
		}
	}
	if h := e.getString("dst_endpoint.hostname"); h != "" {
		return []string{h}
	}
	if ip := e.getString("dst_endpoint.ip"); ip != "" {
		return []string{ip}
	}
	return nil
}

// collectUIDNames pulls uid (preferred) or name from a []resource list.
func collectUIDNames(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if uid, ok := m["uid"].(string); ok && strings.TrimSpace(uid) != "" {
			out = append(out, strings.TrimSpace(uid))
			continue
		}
		if name, ok := m["name"].(string); ok && strings.TrimSpace(name) != "" {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}

// helpers -------------------------------------------------------------------

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return -1
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "1", "yes":
			return true
		}
	case float64:
		return t != 0
	}
	return false
}
