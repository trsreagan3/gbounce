// redact.go — credential-shape redaction for MITM-mode body capture.
//
// MITM mode intercepts request/response bodies. Before any body
// touches the audit pipeline we walk it for credential shapes +
// replace matches with `***REDACTED-CREDENTIAL***` so a JSONL audit
// log doesn't accidentally become a credential leak.
//
// Per the spec, redaction is DEFAULT-ON. An operator can pass
// `--audit-log-include-bodies` to opt in to raw body capture for a
// specific deployment (e.g. an isolated SOC sandbox), but the
// default is the safe shape.
//
// Two redaction paths:
//
//   - RedactHeaders(http.Header) — case-insensitive header name match
//     against a hardcoded list of credential-bearing headers.
//   - RedactJSONBody([]byte) — best-effort JSON walk. Field names
//     matching common credential shapes (suffix `_token`, `_secret`,
//     `_key`, or exact name `password`, `api_key`, `apikey`,
//     `secret`, `password`, `token`) have their VALUE replaced with
//     the sentinel string. Non-JSON or malformed JSON is returned
//     unchanged + the audit event marks `request_body_redacted=false`
//     so the SIEM-side filter can still find the row.
//
// Test discipline: the sentinel test (Bearer token / x-api-key /
// JSON {"api_key":"..."}) is load-bearing for the spec's "no actual
// secret in any audit field" verification — don't loosen the regexes
// without updating the redact_test.go suite.
package mitm

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
)

// RedactedValue is the literal string credential matches are rewritten
// to. Verbose on purpose so an analyst skimming the audit log
// recognizes it immediately. Matches the cross-product convention.
const RedactedValue = "***REDACTED-CREDENTIAL***"

// redactedHeaders is the case-insensitive set of header names whose
// values get rewritten. Includes both standard names + common vendor-
// specific ones an agent might surface (OpenAI, Anthropic, AWS,
// Vercel, GitHub).
var redactedHeaders = map[string]struct{}{
	"authorization":             {},
	"cookie":                    {},
	"set-cookie":                {},
	"proxy-authorization":       {},
	"x-api-key":                 {},
	"x-anthropic-api-key":       {},
	"x-openai-api-key":          {},
	"x-aws-access-key-id":       {},
	"x-aws-security-token":      {},
	"x-amz-security-token":      {},
	"x-vercel-protection-bypass": {},
	"x-github-token":            {},
	"x-auth-token":              {},
	"x-access-token":            {},
}

// RedactHeaders returns a copy of h with the credential-bearing
// values rewritten to the redaction sentinel. The original header is
// not mutated.
func RedactHeaders(h http.Header) http.Header {
	if len(h) == 0 {
		return http.Header{}
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		lower := strings.ToLower(k)
		if _, hit := redactedHeaders[lower]; hit {
			out[k] = []string{RedactedValue}
			continue
		}
		out[k] = append([]string(nil), vv...)
	}
	return out
}

// IsRedactedHeader reports whether the given header name (any case)
// is in the redaction set. Helper for tests + the future per-header
// audit metadata.
func IsRedactedHeader(name string) bool {
	_, hit := redactedHeaders[strings.ToLower(name)]
	return hit
}

// RedactJSONBody walks a JSON document + rewrites the VALUES of
// credential-shape fields. Returns the redacted body + a boolean
// reporting whether ANY field was rewritten. Non-JSON or malformed
// JSON returns the input unchanged + false (audit log marks
// body_redacted=false so the SIEM-side filter can still find the row).
//
// The walk handles nested objects + arrays. Numbers / booleans /
// nulls are skipped (a credential is a string).
func RedactJSONBody(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}
	// Quick reject: bodies that don't start with { or [ aren't JSON.
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return body, false
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return body, false
	}
	changed := walkAndRedact(&v)
	if !changed {
		return body, false
	}
	out, err := json.Marshal(v)
	if err != nil {
		// Re-marshal failure is unexpected; fall back to the original
		// body + report "no redaction" so the audit event is honest.
		return body, false
	}
	return out, true
}

// walkAndRedact mutates v in place when v points at a value
// containing credential-shape fields. Returns true when any
// rewrite happened.
func walkAndRedact(v *any) bool {
	if v == nil {
		return false
	}
	switch typed := (*v).(type) {
	case map[string]any:
		changed := false
		for k, sub := range typed {
			if isCredentialFieldName(k) {
				if _, isStr := sub.(string); isStr {
					typed[k] = RedactedValue
					changed = true
					continue
				}
			}
			if changedInner := walkValue(&sub); changedInner {
				typed[k] = sub
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for i := range typed {
			if changedInner := walkValue(&typed[i]); changedInner {
				changed = true
			}
		}
		return changed
	}
	return false
}

// walkValue is the recursive shape used by walkAndRedact. Returns
// true when redaction happened anywhere in v's subtree.
func walkValue(v *any) bool {
	switch typed := (*v).(type) {
	case map[string]any:
		changed := false
		for k, sub := range typed {
			if isCredentialFieldName(k) {
				if _, isStr := sub.(string); isStr {
					typed[k] = RedactedValue
					changed = true
					continue
				}
			}
			if changedInner := walkValue(&sub); changedInner {
				typed[k] = sub
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for i := range typed {
			if changedInner := walkValue(&typed[i]); changedInner {
				changed = true
			}
		}
		return changed
	}
	return false
}

// isCredentialFieldName matches the credential-shape regexes from
// the spec. Case-insensitive. Matches:
//
//   - exact: password, secret, token, api_key, apikey, auth,
//     authorization
//   - suffix: *_token, *_secret, *_key (e.g. access_token,
//     client_secret, refresh_token, signing_key)
func isCredentialFieldName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	switch lower {
	case "password", "passwd", "secret", "token", "api_key", "apikey",
		"auth", "authorization", "bearer", "access_token",
		"refresh_token", "id_token", "client_secret", "session_token",
		"private_key", "signing_key":
		return true
	}
	for _, suffix := range []string{"_token", "_secret", "_key", "_password", "_apikey"} {
		if strings.HasSuffix(lower, suffix) {
			// Avoid matching innocuous keys whose suffix collides
			// (e.g. "public_key" — public material isn't a credential,
			// but most fields named "<thing>_key" in a request body
			// ARE credentials; we err on the side of redacting).
			return true
		}
	}
	return false
}

// RedactBody redacts credential-shape fields from a captured body, choosing
// the strategy by Content-Type. JSON bodies match by field name;
// application/x-www-form-urlencoded bodies use the same k=v matching as query
// params. Previously ALL bodies went through RedactJSONBody, which returns
// non-JSON unchanged — so form-encoded credentials (e.g. `password=hunter2`)
// leaked verbatim into the audit snapshot. This dispatcher closes that gap.
func RedactBody(contentType string, body []byte) ([]byte, bool) {
	// Parse the media type (keeps params like the multipart boundary).
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(contentType))
		if i := strings.IndexByte(mt, ';'); i >= 0 {
			mt = strings.TrimSpace(mt[:i])
		}
	}
	switch strings.ToLower(mt) {
	case "application/x-www-form-urlencoded":
		redacted, changed := RedactQueryParams(string(body))
		return []byte(redacted), changed
	case "multipart/form-data":
		// multipart bodies (file uploads, legacy auth flows) can carry
		// credential-named fields; the JSON walk leaves them verbatim →
		// leak. Redact credential parts; never store file-part contents.
		return redactMultipartBody(body, params["boundary"])
	default:
		// Default: treat as JSON. RedactJSONBody returns the body unchanged
		// for non-JSON content, preserving prior behavior for other types.
		return RedactJSONBody(body)
	}
}

// _maxMultipartFieldSnapshot bounds how much of a single non-file part value
// we read into the audit snapshot (defense against a huge text field).
const _maxMultipartFieldSnapshot = 64 * 1024

// redactMultipartBody rewrites a multipart/form-data body into a compact,
// credential-safe audit representation (`name=value&name=value`): credential-
// shape fields are replaced with the sentinel, FILE parts are recorded by
// name only (their contents are NEVER snapshotted), and a body we cannot
// parse is SUPPRESSED with a marker so a raw secret can never reach the JSONL.
// Returns (snapshot, anyCredentialRedacted).
func redactMultipartBody(body []byte, boundary string) ([]byte, bool) {
	if boundary == "" {
		return []byte("***MULTIPART-BODY-SUPPRESSED (no boundary; credential-safe redaction unavailable)***"), true
	}
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	var parts []string
	redactedAny := false
	for {
		p, perr := r.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			// Malformed — never store the raw body; suppress.
			return []byte("***MULTIPART-BODY-SUPPRESSED (parse error; credential-safe redaction unavailable)***"), true
		}
		name := p.FormName()
		if name == "" {
			name = p.FileName()
		}
		if fn := p.FileName(); fn != "" {
			// File upload — record presence only, never the bytes.
			parts = append(parts, name+"=[file:"+fn+"]")
			_ = p.Close()
			continue
		}
		val, _ := io.ReadAll(io.LimitReader(p, _maxMultipartFieldSnapshot))
		_ = p.Close()
		if isCredentialFieldName(name) {
			parts = append(parts, name+"="+RedactedValue)
			redactedAny = true
		} else {
			parts = append(parts, name+"="+string(val))
		}
	}
	return []byte(strings.Join(parts, "&")), redactedAny
}

// RedactQueryParams rewrites credential-shape query-param VALUES in
// place. Returns the redacted string + a boolean reporting whether
// anything was rewritten. Input is the raw query string (no leading
// `?`). Matches the same suffix shapes as JSON field names so a
// `?secret=...` in the URL is treated identically to a JSON body
// `{"secret": "..."}`.
func RedactQueryParams(query string) (string, bool) {
	if query == "" {
		return query, false
	}
	out := make([]byte, 0, len(query))
	start := 0
	changed := false
	for i := 0; i <= len(query); i++ {
		if i == len(query) || query[i] == '&' || query[i] == ';' {
			pair := query[start:i]
			redacted, rewrote := redactPair(pair)
			if rewrote {
				changed = true
			}
			out = append(out, []byte(redacted)...)
			if i < len(query) {
				out = append(out, query[i])
			}
			start = i + 1
		}
	}
	return string(out), changed
}

// redactPair rewrites a single "k=v" pair when k matches a credential
// shape. A bare "k" (no "=") is preserved verbatim.
func redactPair(pair string) (string, bool) {
	if pair == "" {
		return pair, false
	}
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return pair, false
	}
	key := pair[:eq]
	if isCredentialFieldName(key) {
		return key + "=" + RedactedValue, true
	}
	return pair, false
}
