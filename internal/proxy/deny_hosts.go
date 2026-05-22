// Package proxy — deny_hosts support (#314 / §A12).
//
// Operators need to BLOCK specific destinations through gbounce
// WITHOUT MITM. Before #314 gbounce could audit-log every CONNECT but
// couldn't refuse one based on host. This file adds:
//
//   - Profile + CLI surface for `deny_hosts: [...]` entries (exact +
//     wildcard host strings).
//   - Compiled, deterministic match-time evaluation against the
//     CONNECT target. Match → recordDeny + 403 to the client +
//     audit-event verdict=DENY / status_id=4 (Denied) / ext.deny_reason.
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// verdict word is DENY (operator-initiated rule) — never "violation."
//
// Per [[creates-never-mutates]] this is an additive feature; absent a
// deny_hosts list the proxy behaves exactly as it did before #314.
//
// Per [[don't-tailor-to-lighthouse]] the wildcard semantics are
// generic; no specific provider blocklist is hardcoded. Operators feed
// their own deny entries (the README documents 169.254.169.254 +
// *.openai.com only as concrete EXAMPLES, not defaults).
//
// Wildcard semantics
// ------------------
//
// Exact (`evil.example.com`):
//   - matches exactly the literal host string (case-insensitive).
//
// Leading-`*` wildcard (`*.example.com`):
//   - matches `api.example.com`, `foo.bar.example.com`, AND the bare
//     `example.com`. Operator-friendly: when somebody writes
//     `*.example.com` they usually mean "this org and all its
//     subdomains." We document the choice; otherwise we'd be the only
//     deny-list semantics where `*.example.com` doesn't block the
//     org itself — surprising in the wrong direction.
//   - case-insensitive.
//
// Bare `*`:
//   - REJECTED at parse time. A whole-Internet block is `--default-
//     policy deny` (queued for G-Slice 2); using `*` here would surprise
//     operators who type it expecting to scope to a domain and instead
//     deny everything.
//
// Multi-level wildcards (`*.foo.*.bar.com`, `foo.*`, etc):
//   - REJECTED at parse time. The match semantics get ambiguous fast
//     (what does `foo.*` match? what about `*.*`?). Single-leading-`*`
//     is the only supported wildcard shape.
//
// Order of evaluation
// -------------------
//
// deny_hosts WINS over any future allow_hosts list. If both are present
// and contain the same host, deny is the verdict — the safer-by-default
// shape per [[safety-mode-lean-permissive]] (block rarely; when an
// operator wrote a deny rule, they meant it).
package proxy

import (
	"fmt"
	"strings"
)

// DenyHostRule is one compiled deny-list entry. The Raw field is the
// operator-written form (kept so the deny_reason audit event reports
// what the operator actually wrote, not a normalized internal shape).
//
// #324d — Source + DynamicDenyRuleID distinguish static
// (`--deny-host` / `--deny-hosts-file`) entries from dynamic entries
// pulled from `~/.iam-jit/dynamic-denies.yaml`. The match-time audit
// event surfaces both fields so a SIEM analyst can answer "which
// dynamic-deny rule fired?" + "did the static deny do its job today?"
// without grepping the config file.
type DenyHostRule struct {
	// Raw is the operator-written entry (preserved for the audit
	// `deny_reason` field so SIEM rules can pivot on the EXACT string
	// the operator deployed).
	Raw string
	// suffix is the host-suffix portion for wildcard rules. For
	// `*.example.com` the suffix is `example.com`. Empty for exact
	// rules.
	suffix string
	// exact is the lowercase host for exact-match rules. Empty for
	// wildcard rules.
	exact string
	// isWildcard is true for wildcard rules (`*.example.com`), false
	// for exact rules.
	isWildcard bool
	// Source is "static" for `--deny-host` + `--deny-hosts-file`
	// entries, "dynamic" for entries loaded from the dynamic-denies
	// YAML file. Empty defaults to "static" so the pre-#324d call
	// sites stay legal.
	Source string
	// DynamicDenyRuleID is the originating rule id (`dd_<ULID>`) for
	// dynamic entries. Empty for static entries. Surfaces in the deny
	// audit event under `ext.dynamic_deny_rule_id`.
	DynamicDenyRuleID string
}

// DenySourceStatic + DenySourceDynamic are the canonical Source enum
// values surfaced on the deny audit event under
// `ext.deny_source`. Operators query SIEMs for these strings.
const (
	DenySourceStatic  = "static"
	DenySourceDynamic = "dynamic"
)

// String returns the operator-written entry. Implements fmt.Stringer
// so a deny rule renders cleanly in error messages + the deny_reason
// audit field.
func (r DenyHostRule) String() string { return r.Raw }

// ParseDenyHost compiles one operator-written deny entry into a
// DenyHostRule, or returns a clear error explaining why the entry is
// invalid. The error message names the offending entry so an operator
// debugging a startup failure sees exactly which line of their config
// the parser rejected.
func ParseDenyHost(raw string) (DenyHostRule, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return DenyHostRule{}, fmt.Errorf("deny_hosts: empty entry")
	}

	// Bare `*` is rejected — operators want `--default-policy deny`
	// for that shape; `*` here would surprise.
	if trimmed == "*" {
		return DenyHostRule{}, fmt.Errorf(
			"deny_hosts: bare wildcard %q is not allowed "+
				"(use --default-policy deny for a deny-everything posture)",
			trimmed)
	}

	// Reject multi-level wildcards. The only supported wildcard shape
	// is a single leading `*.` followed by a domain that contains no
	// further `*`.
	starCount := strings.Count(trimmed, "*")
	switch {
	case starCount == 0:
		// Exact-match rule. Normalize to lowercase + validate the host
		// is at least minimally well-formed (no spaces, no scheme).
		if err := validateHostLiteral(trimmed); err != nil {
			return DenyHostRule{}, fmt.Errorf("deny_hosts %q: %w", raw, err)
		}
		return DenyHostRule{
			Raw:   trimmed,
			exact: strings.ToLower(trimmed),
		}, nil
	case starCount == 1:
		// Single wildcard — must be in the leading `*.` position.
		if !strings.HasPrefix(trimmed, "*.") {
			return DenyHostRule{}, fmt.Errorf(
				"deny_hosts %q: the only supported wildcard shape is a "+
					"leading `*.<domain>` (e.g. `*.example.com`); other "+
					"wildcard positions are ambiguous and not allowed",
				raw)
		}
		suffix := strings.TrimPrefix(trimmed, "*.")
		if suffix == "" {
			return DenyHostRule{}, fmt.Errorf(
				"deny_hosts %q: wildcard `*.` requires a domain suffix "+
					"(e.g. `*.example.com`)", raw)
		}
		if err := validateHostLiteral(suffix); err != nil {
			return DenyHostRule{}, fmt.Errorf("deny_hosts %q: %w", raw, err)
		}
		return DenyHostRule{
			Raw:        trimmed,
			suffix:     strings.ToLower(suffix),
			isWildcard: true,
		}, nil
	default:
		return DenyHostRule{}, fmt.Errorf(
			"deny_hosts %q: multi-level wildcards (`*.foo.*.bar.com`, "+
				"`foo.*`, etc) are not allowed; use a single leading "+
				"`*.<domain>`", raw)
	}
}

// validateHostLiteral does a permissive structural check so obvious
// junk (scheme prefixes, spaces, ports) is caught at parse time. We
// deliberately don't enforce strict RFC 1035 — IPv4 literals,
// link-local IPv6 (`169.254.169.254`), and IDN-encoded names all need
// to flow through.
func validateHostLiteral(s string) error {
	if s == "" {
		return fmt.Errorf("empty host")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("host contains whitespace: %q", s)
	}
	if strings.Contains(s, "://") {
		return fmt.Errorf("host must not include a scheme (got %q)", s)
	}
	if strings.Contains(s, "/") {
		return fmt.Errorf("host must not include a path (got %q)", s)
	}
	// Reject embedded port; the deny check matches host only (matching
	// on `host:443` would be confusing — most operators write
	// `evil.example.com` and expect every port to be denied).
	if strings.Contains(s, ":") && !strings.HasPrefix(s, "[") {
		// Bracketed IPv6 literals (`[::1]`) ride through; bare
		// `host:port` does not.
		return fmt.Errorf(
			"host must not include a port (got %q); deny applies to all ports", s)
	}
	return nil
}

// ParseDenyHosts compiles a list of operator-written entries into a
// list of DenyHostRule, returning the FIRST parse error. Returning on
// the first error keeps startup behavior deterministic (the operator
// fixes one entry at a time rather than guessing which of many
// reported errors they need to fix first).
//
// All produced rules carry Source="static" — the #314 static-deny
// shape. Callers that build dynamic rules (#324d) use
// ParseDynamicDenyHost to set Source + DynamicDenyRuleID.
func ParseDenyHosts(raws []string) ([]DenyHostRule, error) {
	if len(raws) == 0 {
		return nil, nil
	}
	out := make([]DenyHostRule, 0, len(raws))
	for _, raw := range raws {
		// Skip blank lines / comments in pre-trim — callers may pass
		// raw file contents directly.
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		rule, err := ParseDenyHost(raw)
		if err != nil {
			return nil, err
		}
		rule.Source = DenySourceStatic
		out = append(out, rule)
	}
	return out, nil
}

// ParseDynamicDenyHost compiles a single operator-written entry whose
// source is the dynamic-denies YAML (#324d). Mirrors ParseDenyHost
// shape; the produced rule carries Source="dynamic" + the originating
// rule id so the deny audit event can surface both. A parse error is
// returned with the same shape as ParseDenyHost — callers in #324d
// drop the offending rule + emit a `dynamic_deny.parse_error`
// admin-action event.
func ParseDynamicDenyHost(raw, ruleID string) (DenyHostRule, error) {
	r, err := ParseDenyHost(raw)
	if err != nil {
		return DenyHostRule{}, err
	}
	r.Source = DenySourceDynamic
	r.DynamicDenyRuleID = ruleID
	return r, nil
}

// Match returns the matching DenyHostRule for the given host (case-
// insensitive), or nil when no rule matches. The host argument is the
// bare hostname (no port); callers pass it after splitting off `:port`.
func MatchDenyHosts(rules []DenyHostRule, host string) *DenyHostRule {
	if len(rules) == 0 || host == "" {
		return nil
	}
	h := strings.ToLower(strings.TrimSpace(host))
	// Strip IPv6 brackets if present so `[::1]` matches an exact entry
	// of `::1`. Operators writing the deny entry don't have to wrap
	// their IPv6 literal in brackets.
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	for i := range rules {
		r := &rules[i]
		if r.isWildcard {
			// `*.example.com` matches `api.example.com` (suffix match
			// preceded by `.`) AND bare `example.com` (the suffix
			// itself). The bare-domain branch is the operator-
			// friendly choice documented above.
			if h == r.suffix {
				return r
			}
			if strings.HasSuffix(h, "."+r.suffix) {
				return r
			}
			continue
		}
		if h == r.exact {
			return r
		}
	}
	return nil
}

// ParseDenyHostsFile parses a deny-hosts file written in any of three
// equivalent shapes:
//
//   - newline-delimited entries:
//
//       evil.example.com
//       *.openai.com
//       169.254.169.254
//
//   - YAML-list-style (`- entry` per line):
//
//       - evil.example.com
//       - *.openai.com
//
//   - YAML-document with a top-level `deny_hosts:` key:
//
//       deny_hosts:
//         - evil.example.com
//         - *.openai.com
//
// This is the forward-compatibility hinge for the future profile-YAML
// surface (G-Slice 2): a profile YAML file containing only
// `deny_hosts: [...]` parses through this function unchanged, so the
// G-2 profile-mode work doesn't have to re-parse this shape. We avoid
// pulling in yaml.v3 as a runtime dependency for one feature.
//
// Comment lines (`#` prefix after trim) and blank lines are ignored.
func ParseDenyHostsFile(contents string) ([]DenyHostRule, error) {
	var entries []string
	for _, line := range strings.Split(contents, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// Skip the `deny_hosts:` key line if the operator wrote a
		// YAML-style document — its presence is informational; we
		// already KNOW the entries are deny-host entries because
		// they're being read from a --deny-hosts-file.
		if strings.HasPrefix(t, "deny_hosts:") {
			rest := strings.TrimSpace(strings.TrimPrefix(t, "deny_hosts:"))
			// Support inline `deny_hosts: [a, b, c]` as well.
			if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
				inner := strings.Trim(rest, "[]")
				for _, item := range strings.Split(inner, ",") {
					item = strings.TrimSpace(strings.Trim(item, "\"'"))
					if item != "" {
						entries = append(entries, item)
					}
				}
			}
			continue
		}
		// Strip a leading `- ` so YAML-list entries flow through.
		if strings.HasPrefix(t, "- ") {
			t = strings.TrimSpace(strings.TrimPrefix(t, "- "))
		} else if strings.HasPrefix(t, "-") && len(t) > 1 && t[1] == ' ' {
			t = strings.TrimSpace(t[2:])
		}
		// Strip surrounding quotes so quoted YAML scalars work.
		t = strings.Trim(t, "\"'")
		if t == "" {
			continue
		}
		entries = append(entries, t)
	}
	return ParseDenyHosts(entries)
}
