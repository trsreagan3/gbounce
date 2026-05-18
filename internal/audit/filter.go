// filter.go ships the audit-tail filter expression parser + matcher.
//
// `gbounce audit tail --filter EXPR` lets an operator (or an MCP-driven
// agent) narrow the JSONL stream against the OCSF v1.1.0 class 6003
// (API Activity) event shape. Repeatable; AND semantics.
//
// Grammar (per the [[cross-product-agent-parity]] memo — ibounce +
// kbounce + dbounce ship the identical grammar):
//
//	field=value        string equality (case-sensitive)
//	field~regex        Go RE2 regex match
//	field>=N           numeric greater-or-equal
//	field<=N           numeric less-or-equal
//
// Supported fields (cross-product OCSF):
//
//	severity_id
//	activity_id
//	status_id
//	actor.user.name
//	api.operation
//	unmapped.iam_jit.agent.name
//	unmapped.iam_jit.agent.session_id
//	unmapped.iam_jit.event_type
//
// gbounce-specific fields (documented as such; they live under the
// unmapped.iam_jit.ext block in the OCSF event but resolve directly
// from the Decision row for ergonomics):
//
//	upstream_host
//	path
//	method
//	http_status
//
// The matcher walks the OCSF Event struct (NOT a re-marshaled map) so
// nested-path lookups are zero-allocation in the hot path of `--follow`.
package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FilterOp is one of the four supported comparison ops.
type FilterOp int

const (
	FilterOpEq  FilterOp = iota // field=value
	FilterOpRe                  // field~regex
	FilterOpGTE                 // field>=N
	FilterOpLTE                 // field<=N
)

// Filter is one parsed expression. Re is non-nil only for FilterOpRe.
type Filter struct {
	Field string
	Op    FilterOp
	Value string
	Num   float64
	Re    *regexp.Regexp
}

// ParseFilter parses one expression into a Filter. Errors include the
// raw input so an operator can pinpoint which --filter flag was wrong.
func ParseFilter(expr string) (Filter, error) {
	// Order matters: ">=" and "<=" are two chars, must be checked
	// before single-char "=". "~" is single-char and unambiguous.
	switch {
	case strings.Contains(expr, ">="):
		return parseNumeric(expr, ">=", FilterOpGTE)
	case strings.Contains(expr, "<="):
		return parseNumeric(expr, "<=", FilterOpLTE)
	case strings.Contains(expr, "~"):
		field, value, ok := splitOnce(expr, "~")
		if !ok || field == "" {
			return Filter{}, fmt.Errorf("filter %q: expected field~regex", expr)
		}
		re, err := regexp.Compile(value)
		if err != nil {
			return Filter{}, fmt.Errorf("filter %q: invalid regex: %w", expr, err)
		}
		return Filter{Field: field, Op: FilterOpRe, Value: value, Re: re}, nil
	case strings.Contains(expr, "="):
		field, value, ok := splitOnce(expr, "=")
		if !ok || field == "" {
			return Filter{}, fmt.Errorf("filter %q: expected field=value", expr)
		}
		return Filter{Field: field, Op: FilterOpEq, Value: value}, nil
	default:
		return Filter{}, fmt.Errorf("filter %q: no operator (=, ~, >=, <=)", expr)
	}
}

// parseNumeric pulls the numeric value + records both Value (string
// form, for error messages) and Num (parsed float).
func parseNumeric(expr, sep string, op FilterOp) (Filter, error) {
	field, value, ok := splitOnce(expr, sep)
	if !ok || field == "" {
		return Filter{}, fmt.Errorf("filter %q: expected field%sN", expr, sep)
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return Filter{}, fmt.Errorf("filter %q: numeric op %s needs a number, got %q", expr, sep, value)
	}
	return Filter{Field: field, Op: op, Value: value, Num: n}, nil
}

// splitOnce splits on the FIRST occurrence of sep. Returns "", "", false
// when sep is not present.
func splitOnce(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

// ParseFilters is a small convenience: parses a slice of expressions,
// returning the first error. AND semantics — every filter must match.
func ParseFilters(exprs []string) ([]Filter, error) {
	out := make([]Filter, 0, len(exprs))
	for _, e := range exprs {
		f, err := ParseFilter(e)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// MatchAll returns true when every filter matches the event.
func MatchAll(ev Event, filters []Filter) bool {
	for _, f := range filters {
		if !match(ev, f) {
			return false
		}
	}
	return true
}

// match resolves the field, then applies the op.
func match(ev Event, f Filter) bool {
	str, num, hasStr, hasNum := resolveField(ev, f.Field)
	switch f.Op {
	case FilterOpEq:
		if hasStr {
			return str == f.Value
		}
		if hasNum {
			// Allow `severity_id=1` to match a numeric field by string
			// comparison too — operators don't care which type the
			// field is internally.
			return strconv.FormatFloat(num, 'f', -1, 64) == f.Value
		}
		return false
	case FilterOpRe:
		if hasStr {
			return f.Re.MatchString(str)
		}
		if hasNum {
			return f.Re.MatchString(strconv.FormatFloat(num, 'f', -1, 64))
		}
		return false
	case FilterOpGTE:
		if hasNum {
			return num >= f.Num
		}
		if hasStr {
			n, err := strconv.ParseFloat(str, 64)
			if err == nil {
				return n >= f.Num
			}
		}
		return false
	case FilterOpLTE:
		if hasNum {
			return num <= f.Num
		}
		if hasStr {
			n, err := strconv.ParseFloat(str, 64)
			if err == nil {
				return n <= f.Num
			}
		}
		return false
	}
	return false
}

// resolveField returns the value for a dotted-path field name. Returns
// (str, num, hasStr, hasNum) — exactly one of hasStr / hasNum is true
// when the field exists; both false when the field is absent.
//
// The supported set is a deliberate allowlist (NOT generic reflection)
// so cross-product agents writing filter expressions don't accidentally
// reach into private struct fields.
func resolveField(ev Event, field string) (string, float64, bool, bool) {
	switch field {
	// OCSF cross-product fields.
	case "severity_id":
		return "", float64(ev.SeverityID), false, true
	case "activity_id":
		return "", float64(ev.ActivityID), false, true
	case "status_id":
		return "", float64(ev.StatusID), false, true
	case "api.operation":
		return ev.API.Operation, 0, true, false
	case "actor.user.name":
		// gbounce doesn't populate actor today; an admin-action event
		// stashes the actor under unmapped.iam_jit.config_change.actor.
		// We surface it here for filter parity with sibling products.
		if cc, ok := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any); ok {
			if a, ok := cc["actor"].(string); ok {
				return a, 0, true, false
			}
		}
		return "", 0, false, false
	case "unmapped.iam_jit.agent.name":
		if agent, ok := ev.Unmapped.IAMJIT.Ext["agent"].(map[string]any); ok {
			if v, ok := agent["name"].(string); ok {
				return v, 0, true, false
			}
		}
		return "", 0, false, false
	case "unmapped.iam_jit.agent.session_id":
		if agent, ok := ev.Unmapped.IAMJIT.Ext["agent"].(map[string]any); ok {
			if v, ok := agent["session_id"].(string); ok {
				return v, 0, true, false
			}
		}
		return "", 0, false, false
	case "unmapped.iam_jit.event_type":
		if v, ok := ev.Unmapped.IAMJIT.Ext["event_type"].(string); ok {
			return v, 0, true, false
		}
		// Fall back: admin-action events label themselves via
		// activity_name + a top-level admin_action field.
		if v, ok := ev.Unmapped.IAMJIT.Ext["admin_action"].(string); ok {
			return v, 0, true, false
		}
		return "", 0, false, false

	// gbounce-specific fields.
	case "upstream_host":
		return ev.API.Service.Name, 0, true, false
	case "path":
		if len(ev.Resources) > 0 {
			return ev.Resources[0].Name, 0, true, false
		}
		return "", 0, false, false
	case "method":
		// api.operation is "<METHOD> <path>"; pull the verb.
		op := ev.API.Operation
		if i := strings.Index(op, " "); i > 0 {
			return op[:i], 0, true, false
		}
		return op, 0, true, false
	case "http_status":
		if ev.Unmapped.IAMJIT.Ext != nil {
			if v, ok := ev.Unmapped.IAMJIT.Ext["http_status"]; ok {
				if n, ok := toFloat(v); ok {
					return "", n, false, true
				}
			}
		}
		return "", 0, false, false
	}

	return "", 0, false, false
}

// toFloat coerces the common numeric-shape `any` values that land in
// the OCSF Ext map. JSON-decoded numbers arrive as float64; in-process
// values arrive as int / int64.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

// SupportedFilterFields returns the allowlist of filter field names for
// help/error messages. Order is stable so the CLI help reads the same
// across builds.
func SupportedFilterFields() []string {
	return []string{
		// Cross-product OCSF.
		"severity_id",
		"activity_id",
		"status_id",
		"actor.user.name",
		"api.operation",
		"unmapped.iam_jit.agent.name",
		"unmapped.iam_jit.agent.session_id",
		"unmapped.iam_jit.event_type",
		// gbounce-specific.
		"upstream_host",
		"path",
		"method",
		"http_status",
	}
}
