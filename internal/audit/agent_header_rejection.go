// agent_header_rejection.go ships the §A18 / #320 structured
// rejection breadcrumb that lands at
// `unmapped.iam_jit.ext.agent_header_rejection` whenever an inbound
// `X-Agent-Name` or `X-Agent-Session-Id` header fails validation.
//
// Before §A18 the rejection signal was a single counter on /healthz
// (`total_agent_headers_rejected`) plus the §A17 string
// `agent_rejected_reason`. UAT 2026-05-22 surfaced that SOC analysts
// querying the audit log directly couldn't tell which header was
// rejected or why — the counter was too coarse + the string lumped
// charset + length failures together. The structured breadcrumb
// fixes this by recording the field name + a bounded enum reason +
// the rejected value's length (NEVER the value itself — that lives
// only in the truncated stderr line emitted by the rejection logger,
// with control-char filtering, so a malicious header value can't
// pollute the audit log).
//
// Same shape ships across all four Bounce products per
// [[cross-product-agent-parity]] — a SIEM filter on
// `unmapped.iam_jit.ext.agent_header_rejection.reason=
// invalid_name_charset` resolves across ibounce + kbounce + dbounce
// + gbounce uniformly.
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// breadcrumb is "audit transparency" — operator visibility into a
// validation rejection that would otherwise be silent — not
// "violation" framing. A rejected header is most often a
// misconfigured agent SDK, not an attack.

package audit

// AgentHeaderRejectionReason names the enumerated reasons an inbound
// X-Agent-* header can fail validation. Bounded set so SIEM filters
// can rely on a closed vocabulary; new reasons land here when the
// validation regex evolves.
type AgentHeaderRejectionReason string

const (
	// AgentHeaderRejectionInvalidNameCharset names the case where the
	// X-Agent-Name header value contained a character outside the
	// canonical [A-Za-z0-9._-] shape (shell-injection payloads land
	// here).
	AgentHeaderRejectionInvalidNameCharset AgentHeaderRejectionReason = "invalid_name_charset"

	// AgentHeaderRejectionInvalidNameLength names the case where the
	// X-Agent-Name header value's character composition is valid but
	// it exceeded the 64-char cap.
	AgentHeaderRejectionInvalidNameLength AgentHeaderRejectionReason = "invalid_name_length"

	// AgentHeaderRejectionInvalidSessionIDFormat names the case where
	// the X-Agent-Session-Id header value contained a character
	// outside the canonical [A-Za-z0-9_-] shape (note: missing the
	// dot vs the name regex by design — UUIDs don't carry dots).
	AgentHeaderRejectionInvalidSessionIDFormat AgentHeaderRejectionReason = "invalid_session_id_format"

	// AgentHeaderRejectionInvalidSessionIDLength names the case where
	// the X-Agent-Session-Id header value's character composition is
	// valid but it exceeded the 128-char cap.
	AgentHeaderRejectionInvalidSessionIDLength AgentHeaderRejectionReason = "invalid_session_id_length"

	// AgentHeaderRejectionApplicationNameUnparseable is dbounce-only
	// (SQL agents declare attribution via the `application_name`
	// startup parameter rather than HTTP headers; the prefix matched
	// but the tag body failed to split into NAME:SESSIONID). Defined
	// here so the cross-product reason enum is one closed set even
	// though gbounce never emits it.
	AgentHeaderRejectionApplicationNameUnparseable AgentHeaderRejectionReason = "application_name_unparseable"
)

// AgentNameField + AgentSessionIDField name the canonical header
// fields that the rejection breadcrumb references. Centralized so
// the audit-log shape is one string across products + the cross-
// product test suite can assert exact-match equality.
const (
	AgentNameField      = "X-Agent-Name"
	AgentSessionIDField = "X-Agent-Session-Id"

	// AgentApplicationNameField is the dbounce-specific equivalent
	// for SQL connections (no HTTP headers; agents declare attribution
	// via the PostgreSQL `application_name` startup parameter or
	// MySQL `_program_name` connection-attribute). Used by dbounce
	// when a malformed `iam-jit-agent:NAME:SESSIONID` tag is detected.
	AgentApplicationNameField = "application_name"
)

// ClassifyAgentNameRejection returns the canonical
// AgentHeaderRejectionReason for a raw X-Agent-Name value that
// already failed IsValidAgentName. Splits charset vs length so the
// SIEM analyst can distinguish "the agent's SDK is sending shell-
// injection-shaped payloads" (charset) from "the agent picked an
// overly-verbose canonical name" (length).
//
// The 64-char cap is the cross-product covenant per
// [[cross-product-agent-parity]]; agents that need richer naming
// should use the optional version field instead of stuffing it into
// name.
func ClassifyAgentNameRejection(raw string) AgentHeaderRejectionReason {
	if len(raw) > 64 {
		return AgentHeaderRejectionInvalidNameLength
	}
	return AgentHeaderRejectionInvalidNameCharset
}

// ClassifyAgentSessionIDRejection returns the canonical
// AgentHeaderRejectionReason for a raw X-Agent-Session-Id value
// that already failed IsValidSessionID. Same split rationale as
// ClassifyAgentNameRejection: length tells the SIEM analyst the
// agent built a non-UUID id; charset tells them the SDK is sending
// something pathological.
func ClassifyAgentSessionIDRejection(raw string) AgentHeaderRejectionReason {
	if len(raw) > 128 {
		return AgentHeaderRejectionInvalidSessionIDLength
	}
	return AgentHeaderRejectionInvalidSessionIDFormat
}

// BuildAgentHeaderRejectionBreadcrumb produces the per-rejection
// entry shape that lands at
// `unmapped.iam_jit.ext.agent_header_rejection` (when single) or as
// one element of the list (when multiple headers were rejected on
// the same request). Cross-product invariant: callers MUST NOT
// include the raw value — only its length. The truncated stderr
// rejection line (with control-char filtering) is the only sink
// that ever sees the raw value, per
// [[security-team-positioning-safety-not-surveillance]].
//
// Returns a map[string]any (rather than a typed struct) so the
// caller can splice it into the OCSF Ext map without a separate
// JSON marshalling round-trip — the OCSF v1.1.0 wire shape encodes
// extensions as untyped key/value maps anyway.
func BuildAgentHeaderRejectionBreadcrumb(field string, reason AgentHeaderRejectionReason, rawValueLength int) map[string]any {
	return map[string]any{
		"field":                field,
		"reason":               string(reason),
		"value_redacted_length": rawValueLength,
	}
}
