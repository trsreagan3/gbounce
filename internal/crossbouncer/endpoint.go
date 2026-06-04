// Package crossbouncer is gbounce's read-only aggregator over the whole Bounce
// suite. It queries each bouncer's mgmt-port /audit/events endpoint over HTTP,
// stitches the OCSF events into a unified view, and powers the cross-bouncer
// dashboard + the flight-recorder / audit-stream / compliance-map commands.
//
// Architecture (founder decision 2026-06-04): gbounce is a READ-ONLY
// aggregator. It only READS what each bouncer chooses to expose over its
// mgmt HTTP endpoint; it never controls another bouncer at runtime. An
// attacker who compromises gbounce sees logs, controls nothing — the
// "independence as a security property" positioning is preserved. The one
// write path (the `deny` command) writes a SHARED rules file that each
// bouncer INDEPENDENTLY chooses to honor; gbounce does not push rules into
// another process's memory.
//
// This mirrors the Python implementation in iam-jit (cli_audit_query.py +
// agent_diff/fanout.py): same default ports, same /audit/events wire shape,
// same session-id correlation key.
package crossbouncer

import (
	"os"
	"sort"
	"strings"
)

// Endpoint is one bouncer's management HTTP surface.
type Endpoint struct {
	Name    string // canonical bouncer name (ibounce/kbounce/dbounce/gbounce/iam-jit-serve)
	MgmtURL string // base URL, no trailing slash, e.g. "http://127.0.0.1:8769"
}

// Default mgmt ports — must match iam-jit's DEFAULT_BOUNCERS
// (src/iam_jit/cli_audit_query.py) and gbounce's own mgmt port.
const (
	defaultKbounceURL = "http://127.0.0.1:8766"
	defaultIbounceURL = "http://127.0.0.1:8767"
	defaultDbounceURL = "http://127.0.0.1:8768"
	defaultGbounceURL = "http://127.0.0.1:8769"
	defaultServeURL   = "http://127.0.0.1:8000"
)

// defaultBouncers is the canonical fan-out set, excluding iam-jit-serve (which
// is added on demand — it's a query-only surface, not a bouncer). Order is the
// stable display order.
func defaultBouncers() []Endpoint {
	return []Endpoint{
		{Name: "ibounce", MgmtURL: defaultIbounceURL},
		{Name: "kbounce", MgmtURL: defaultKbounceURL},
		{Name: "dbounce", MgmtURL: defaultDbounceURL},
		{Name: "gbounce", MgmtURL: defaultGbounceURL},
	}
}

// DefaultEndpoints returns the standard fan-out set. The iam-jit-serve surface
// is included only when includeServe is true (it's not a bouncer; some
// commands — audit query — fan out to it, others — flight-recorder — don't).
// The serve URL honors the IAM_JIT_URL env override, matching iam-jit.
func DefaultEndpoints(includeServe bool) []Endpoint {
	eps := defaultBouncers()
	if includeServe {
		serve := strings.TrimRight(strings.TrimSpace(os.Getenv("IAM_JIT_URL")), "/")
		if serve == "" {
			serve = defaultServeURL
		}
		eps = append(eps, Endpoint{Name: "iam-jit-serve", MgmtURL: serve})
	}
	return eps
}

// defaultURLFor returns the canonical mgmt URL for a known bouncer name, or ""
// if the name is unknown. "kbouncer" is accepted as an alias for "kbounce".
func defaultURLFor(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ibounce":
		return defaultIbounceURL
	case "kbounce", "kbouncer":
		return defaultKbounceURL
	case "dbounce":
		return defaultDbounceURL
	case "gbounce":
		return defaultGbounceURL
	case "iam-jit-serve", "iam-jit", "serve":
		serve := strings.TrimRight(strings.TrimSpace(os.Getenv("IAM_JIT_URL")), "/")
		if serve == "" {
			serve = defaultServeURL
		}
		return serve
	}
	return ""
}

// canonicalName normalizes a bouncer name; "kbouncer" collapses to "kbounce"
// so the two spellings deduplicate (matching iam-jit's fan-out behavior).
func canonicalName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "kbouncer" {
		return "kbounce"
	}
	return n
}

// ResolveEndpoints turns the repeatable --bouncer flag into the fan-out set.
//
// Each raw entry is either:
//   - "" / empty slice          -> all default bouncers
//   - "name"                    -> look up the default URL for that name
//   - "name=URL"                -> explicit override
//   - "a,b,c" or "a=URL,b"      -> comma-split, each handled as above
//
// Unknown bare names (no "=" and not in the default registry) are skipped and
// reported in the returned `skipped` slice so the caller can warn. Duplicate
// canonical names keep the first occurrence (so an explicit override wins only
// if it appears first).
func ResolveEndpoints(raw []string, includeServe bool) (eps []Endpoint, skipped []string) {
	// Flatten comma-separated values.
	var parts []string
	for _, r := range raw {
		for _, p := range strings.Split(r, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
	}
	if len(parts) == 0 {
		return DefaultEndpoints(includeServe), nil
	}

	seen := map[string]bool{}
	for _, p := range parts {
		var name, url string
		if i := strings.IndexByte(p, '='); i >= 0 {
			name = canonicalName(p[:i])
			url = strings.TrimRight(strings.TrimSpace(p[i+1:]), "/")
		} else {
			name = canonicalName(p)
			url = defaultURLFor(name)
		}
		if name == "" {
			continue
		}
		if url == "" {
			skipped = append(skipped, p)
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		eps = append(eps, Endpoint{Name: name, MgmtURL: url})
	}
	return eps, skipped
}

// SortEndpoints orders endpoints by name for stable output.
func SortEndpoints(eps []Endpoint) {
	sort.Slice(eps, func(i, j int) bool { return eps[i].Name < eps[j].Name })
}

// ProtocolFor maps a bouncer name to its protocol label, matching iam-jit's
// _BOUNCER_PROTOCOL map. Unknown names map to the name itself.
func ProtocolFor(bouncer string) string {
	switch canonicalName(bouncer) {
	case "ibounce":
		return "AWS"
	case "kbounce":
		return "K8s"
	case "dbounce":
		return "SQL"
	case "gbounce":
		return "HTTP"
	case "iam-jit-serve":
		return "iam-jit"
	}
	return bouncer
}
