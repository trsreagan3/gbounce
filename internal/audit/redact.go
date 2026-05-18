// redact.go strips sensitive query-string parameters from a URL path
// before the path lands in an export artifact.
//
// gbounce records the raw inbound URL path (with query string) so the
// live audit-tail bare display can show exactly what an agent called.
// Exports (CSV, OCSF Detection Finding bundle, future webhook payload)
// land in SIEMs, support tickets, and Claude analysis threads — the
// raw query-string is the most likely place a token leaks.
//
// Denylist (case-insensitive query-param names):
//
//	token, api_key, password, secret, bearer, key, authorization
//
// The denylist matches what kbounce + dbounce + ibounce strip in their
// equivalent exports per [[cross-product-agent-parity]].
//
// Behavior:
//
//   - The query string is split on "&" / ";" (both RFC-3986-legal
//     separators). Each k=v pair is checked against the denylist
//     by lowercased key name. Matching values are replaced with the
//     literal "REDACTED"; the key + "=" + "REDACTED" stays so a SIEM
//     analyst can still see which sensitive params WERE present
//     without seeing their values.
//
//   - Path-of-URL (the segment before "?") is preserved verbatim. We
//     do NOT redact path segments — operators rely on the path to
//     pivot on which API was called.
//
//   - When the input has no "?" the input is returned unchanged.
//
// Test discipline: the sentinel test (a `?token=sentinel-XYZ` row +
// `assert sentinel-XYZ not in exported CSV`) is load-bearing for the
// share-export-with-Claude story per [[investigate-with-claude]] —
// don't loosen the denylist without updating that test.
package audit

import (
	"strings"
)

// sensitiveQueryParams is the lowercased denylist. A query-param key
// whose lowercased form equals one of these is redacted on export.
var sensitiveQueryParams = map[string]struct{}{
	"token":         {},
	"api_key":       {},
	"apikey":        {},
	"password":      {},
	"passwd":        {},
	"secret":        {},
	"bearer":        {},
	"key":           {},
	"authorization": {},
	"auth":          {},
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"client_secret": {},
	"sig":           {},
	"signature":     {},
}

// redactedValue is the placeholder a sensitive param's value gets
// replaced with. Kept short + obvious so an analyst skimming a CSV
// sees the redaction immediately.
const redactedValue = "REDACTED"

// RedactURLPath strips sensitive query-string params from a URL path.
// Returns the input unchanged when there's no query string.
//
// Inputs are typically the `path` field of a Decision row — a relative
// URL like "/v1/dashboards?token=abc&user=bob". Absolute URLs work
// too: the function splits on the first "?" regardless of scheme.
func RedactURLPath(path string) string {
	if path == "" {
		return path
	}
	q := strings.IndexByte(path, '?')
	if q < 0 {
		return path
	}
	head := path[:q]
	query := path[q+1:]
	// A fragment may follow the query string. Preserve it verbatim
	// (fragments aren't sent over the wire by browsers, but gbounce
	// will faithfully record whatever the client sent).
	var fragment string
	if hashIdx := strings.IndexByte(query, '#'); hashIdx >= 0 {
		fragment = query[hashIdx:]
		query = query[:hashIdx]
	}
	redacted := redactQueryString(query)
	if redacted == query && fragment == "" {
		return path
	}
	if redacted == "" && fragment == "" {
		return head + "?"
	}
	return head + "?" + redacted + fragment
}

// redactQueryString walks each "&"-or-";"-separated pair and rewrites
// sensitive values to "REDACTED". Order is preserved.
func redactQueryString(query string) string {
	if query == "" {
		return query
	}
	// Find separators (both "&" and ";" are legal per RFC 3986). Walk
	// manually instead of strings.Split so we can preserve the original
	// separator (most clients use "&"; some legacy SDKs use ";").
	out := make([]byte, 0, len(query))
	start := 0
	for i := 0; i <= len(query); i++ {
		if i == len(query) || query[i] == '&' || query[i] == ';' {
			pair := query[start:i]
			out = append(out, []byte(redactPair(pair))...)
			if i < len(query) {
				out = append(out, query[i])
			}
			start = i + 1
		}
	}
	return string(out)
}

// redactPair rewrites a single "k=v" pair when k matches the denylist.
// A bare "k" (no "=") is preserved verbatim — denylist match is on the
// key, but with no "=" there's no value to strip.
func redactPair(pair string) string {
	if pair == "" {
		return pair
	}
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return pair
	}
	key := pair[:eq]
	lower := strings.ToLower(key)
	if _, hit := sensitiveQueryParams[lower]; hit {
		return key + "=" + redactedValue
	}
	return pair
}

// RedactedExt clones the OCSF unmapped.iam_jit.ext map with sensitive
// fields rewritten in-place. Currently a thin wrapper around
// RedactURLPath for any "path"-like field; reserved as a hook for
// future per-field redaction (e.g., header bag).
func RedactedExt(ext map[string]any) map[string]any {
	if ext == nil {
		return nil
	}
	out := make(map[string]any, len(ext))
	for k, v := range ext {
		out[k] = v
	}
	return out
}

// RedactEvent returns a copy of ev with the query-string-bearing
// fields stripped. Used on the export path (CSV + OCSF bundle); the
// live tail leaves the raw value in place so an operator can see what
// an agent actually called in-context.
func RedactEvent(ev Event) Event {
	out := ev
	// Path lives in Resources[0].Name (relative path) and
	// Resources[0].UID (full URL). Both must be redacted; both come
	// from the same source string so the redaction is idempotent.
	if len(out.Resources) > 0 {
		out.Resources = append([]OCSFResource(nil), ev.Resources...)
		for i := range out.Resources {
			out.Resources[i].Name = RedactURLPath(out.Resources[i].Name)
			out.Resources[i].UID = RedactURLPath(out.Resources[i].UID)
		}
	}
	// api.operation is "<METHOD> <path>" — redact the path portion.
	if i := strings.Index(out.API.Operation, " "); i > 0 {
		out.API.Operation = out.API.Operation[:i+1] + RedactURLPath(out.API.Operation[i+1:])
	}
	return out
}
