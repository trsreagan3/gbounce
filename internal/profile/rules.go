// Package profile implements MITM-mode profile-rule matching for
// gbounce (#315 / §A13). A rule matches an outbound request when ALL
// configured predicates match: host (exact + wildcard), port (exact),
// method (exact or list), path (exact, prefix, or regex), and
// query_param.NAME (exact value match).
//
// Profile rules complement the simpler #314 `--deny-host` shape:
//
//   - `--deny-host evil.example.com` denies the entire HOST.
//   - A profile rule with `host: api.openai.com, method: POST,
//     path: /v1/chat/completions` denies ONLY the chat-completions
//     endpoint while leaving other api.openai.com calls allowed.
//
// MITM mode is what makes path/method matching possible — in
// CONNECT-only mode gbounce only sees `host:port`. The proxy
// enforces this invariant: profile rules with a `path` or `method`
// predicate are SKIPPED in non-MITM mode (the predicate is
// unmatchable). That keeps the existing CONNECT-mode shape exactly
// as it was before #315.
package profile

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Rule is one compiled profile-deny entry. The Source field preserves
// the operator-written rule shape so the audit `ext.deny_reason`
// surfaces something an operator can pivot on.
type Rule struct {
	// Host is the destination hostname predicate. Supports a single
	// leading wildcard (`*.openai.com`) using the same semantics as
	// #314: `*.openai.com` matches `api.openai.com`, `foo.openai.com`,
	// AND the bare `openai.com`. Empty = any host.
	Host string
	// hostWildcard is set when Host starts with "*." (compiled-up
	// form so the hot path skips the strings.HasPrefix check).
	hostWildcard bool
	// hostSuffix is the portion after "*." when Host is a wildcard.
	hostSuffix string

	// Port is the destination port predicate. Zero = any port.
	Port int

	// Methods is the list of HTTP methods the rule matches. Empty =
	// any method. Comparison is case-insensitive against the upper-
	// cased inbound method.
	Methods []string

	// Path is the URL-path predicate. Mutually exclusive shapes:
	// PathExact / PathPrefix / PathRegex — exactly one is populated
	// when this field set is non-empty. Empty = any path.
	PathExact  string
	PathPrefix string
	PathRegex  *regexp.Regexp

	// QueryParams maps a query-param name to the exact value it must
	// hold. Empty = no query-param predicate. Match is on the FIRST
	// occurrence of the named param when the URL contains duplicates.
	QueryParams map[string]string

	// Reason is the operator-supplied explanation surfaced in the
	// audit `ext.deny_reason` field + the 403 response body. Optional.
	Reason string

	// Source is the original rule index + a short summary used in the
	// `ext.deny_reason` audit-field when the operator didn't supply
	// a Reason.
	Source string
}

// RuleSpec is the operator-written form a profile YAML / CLI flag
// produces. Validated into a Rule by ParseRule.
type RuleSpec struct {
	Host        string            `yaml:"host" json:"host"`
	Port        int               `yaml:"port" json:"port"`
	Method      any               `yaml:"method" json:"method"`              // string or []string
	Path        string            `yaml:"path" json:"path"`                  // exact path
	PathPrefix  string            `yaml:"path_prefix" json:"path_prefix"`    // prefix shape
	PathRegex   string            `yaml:"path_regex" json:"path_regex"`      // RE2 regex
	QueryParams map[string]string `yaml:"query_params" json:"query_params"`
	Reason      string            `yaml:"reason" json:"reason"`
}

// ParseRule compiles a RuleSpec into a Rule. Returns a clear error
// message naming the offending field on any validation failure.
func ParseRule(spec RuleSpec) (Rule, error) {
	r := Rule{
		Host:        strings.ToLower(strings.TrimSpace(spec.Host)),
		Port:        spec.Port,
		Reason:      spec.Reason,
		QueryParams: map[string]string{},
	}

	if strings.HasPrefix(r.Host, "*.") {
		r.hostWildcard = true
		r.hostSuffix = strings.TrimPrefix(r.Host, "*.")
		if r.hostSuffix == "" {
			return Rule{}, fmt.Errorf("profile rule: host wildcard %q has no suffix", spec.Host)
		}
		if strings.Contains(r.hostSuffix, "*") {
			return Rule{}, fmt.Errorf("profile rule: host %q has multi-level wildcard (not supported)", spec.Host)
		}
	} else if strings.Contains(r.Host, "*") {
		return Rule{}, fmt.Errorf("profile rule: host %q has a non-leading wildcard (only `*.domain` is supported)", spec.Host)
	}

	switch m := spec.Method.(type) {
	case nil:
		// no method predicate
	case string:
		if m != "" {
			r.Methods = []string{strings.ToUpper(m)}
		}
	case []string:
		for _, mm := range m {
			mm = strings.ToUpper(strings.TrimSpace(mm))
			if mm != "" {
				r.Methods = append(r.Methods, mm)
			}
		}
	case []any:
		for _, mm := range m {
			s, ok := mm.(string)
			if !ok {
				return Rule{}, fmt.Errorf("profile rule: method entry %v is not a string", mm)
			}
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "" {
				r.Methods = append(r.Methods, s)
			}
		}
	default:
		return Rule{}, fmt.Errorf("profile rule: method must be a string or list of strings (got %T)", spec.Method)
	}

	pathSet := 0
	if spec.Path != "" {
		r.PathExact = spec.Path
		pathSet++
	}
	if spec.PathPrefix != "" {
		r.PathPrefix = spec.PathPrefix
		pathSet++
	}
	if spec.PathRegex != "" {
		re, err := regexp.Compile(spec.PathRegex)
		if err != nil {
			return Rule{}, fmt.Errorf("profile rule: path_regex %q does not compile: %w", spec.PathRegex, err)
		}
		r.PathRegex = re
		pathSet++
	}
	if pathSet > 1 {
		return Rule{}, fmt.Errorf("profile rule: only one of path / path_prefix / path_regex may be set")
	}

	for k, v := range spec.QueryParams {
		k = strings.TrimSpace(k)
		if k == "" {
			return Rule{}, fmt.Errorf("profile rule: query_params has an empty key")
		}
		r.QueryParams[k] = v
	}

	r.Source = describeRule(r)
	return r, nil
}

// Match returns true when the rule's predicates ALL match the given
// request shape. Empty predicates always match (the operator omitted
// them).
func (r Rule) Match(host string, port int, method, path, query string) bool {
	if !r.matchHost(host) {
		return false
	}
	if r.Port != 0 && r.Port != port {
		return false
	}
	if len(r.Methods) > 0 {
		upper := strings.ToUpper(method)
		hit := false
		for _, m := range r.Methods {
			if m == upper {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	switch {
	case r.PathExact != "":
		if path != r.PathExact {
			return false
		}
	case r.PathPrefix != "":
		if !strings.HasPrefix(path, r.PathPrefix) {
			return false
		}
	case r.PathRegex != nil:
		if !r.PathRegex.MatchString(path) {
			return false
		}
	}
	if len(r.QueryParams) > 0 {
		values, err := url.ParseQuery(query)
		if err != nil {
			return false
		}
		for k, want := range r.QueryParams {
			got := values.Get(k)
			if got != want {
				return false
			}
		}
	}
	return true
}

// matchHost reports whether host matches the rule's Host predicate.
// Empty rule.Host = match everything (no host predicate).
func (r Rule) matchHost(host string) bool {
	if r.Host == "" {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if !r.hostWildcard {
		return host == r.Host
	}
	if host == r.hostSuffix {
		return true
	}
	return strings.HasSuffix(host, "."+r.hostSuffix)
}

// RequiresMITM reports whether the rule has predicates only MITM mode
// can evaluate. CONNECT-mode callers SKIP rules where this is true
// since the path / method / query info isn't available pre-MITM.
func (r Rule) RequiresMITM() bool {
	if len(r.Methods) > 0 {
		return true
	}
	if r.PathExact != "" || r.PathPrefix != "" || r.PathRegex != nil {
		return true
	}
	if len(r.QueryParams) > 0 {
		return true
	}
	return false
}

// describeRule builds a short pivotable string for the audit
// `ext.deny_reason` when the operator didn't pass an explicit reason.
func describeRule(r Rule) string {
	parts := []string{}
	if r.Host != "" {
		parts = append(parts, "host="+r.Host)
	}
	if r.Port != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", r.Port))
	}
	if len(r.Methods) > 0 {
		parts = append(parts, "method="+strings.Join(r.Methods, "|"))
	}
	if r.PathExact != "" {
		parts = append(parts, "path="+r.PathExact)
	} else if r.PathPrefix != "" {
		parts = append(parts, "path_prefix="+r.PathPrefix)
	} else if r.PathRegex != nil {
		parts = append(parts, "path_regex="+r.PathRegex.String())
	}
	if len(r.QueryParams) > 0 {
		kvs := make([]string, 0, len(r.QueryParams))
		for k, v := range r.QueryParams {
			kvs = append(kvs, k+"="+v)
		}
		parts = append(parts, "query_params="+strings.Join(kvs, "&"))
	}
	if len(parts) == 0 {
		return "(empty rule)"
	}
	return strings.Join(parts, " ")
}

// ParseRules compiles a slice of RuleSpecs. Stops at the first parse
// error so the operator's offending entry surfaces cleanly.
func ParseRules(specs []RuleSpec) ([]Rule, error) {
	out := make([]Rule, 0, len(specs))
	for i, s := range specs {
		r, err := ParseRule(s)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// FirstMatch walks the rule list + returns the first rule that
// matches the given request shape. Returns nil when nothing matches.
// `mitmActive` indicates whether the proxy is running in MITM mode;
// when false, rules that RequiresMITM() are skipped (the predicate
// is unmatchable so a CONNECT-only run can't fire them).
func FirstMatch(rules []Rule, mitmActive bool, host string, port int, method, path, query string) *Rule {
	for i := range rules {
		if !mitmActive && rules[i].RequiresMITM() {
			continue
		}
		if rules[i].Match(host, port, method, path, query) {
			return &rules[i]
		}
	}
	return nil
}
