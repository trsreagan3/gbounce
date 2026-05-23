// audit_events.go ships the GET /audit/events HTTP endpoint that lives
// alongside /healthz on the management server.
//
// This is the "headless" sibling of `gbounce audit tail --filter ...
// --export jsonl` (#268): same filter language, same supported field
// catalog, same OCSF wire shape. The cross-bouncer `iam-jit audit
// query` CLI (#271) calls this endpoint on each reachable bouncer
// in parallel + merges the results.
//
// Wire shape:
//
//	GET /audit/events?since=ISO8601&until=ISO8601
//	                 &filter=field=value&filter=...
//	                 &limit=N&format=jsonl|ocsf-bundle
//
// Defaults:
//   - limit: 100 (max 1000)
//   - format: jsonl (one OCSF event per line; same shape the JSONL
//     audit-log writer emits, with URL-token redaction applied)
//
// Auth model:
//   - Loopback bind (default): NO auth header required. The mgmt server
//     refuses to bind off-loopback without --i-know-this-binds-externally.
//   - External bind: requires Authorization: Bearer <AuditEventsToken>.
//     The bind-time gate refuses an external bind without a token set.
//
// Per [[cross-product-agent-parity]] the same endpoint ships on every
// bouncer in the suite (ibounce / kbounce / dbounce / gbounce). Per
// [[creates-never-mutates]] this is read-only; per
// [[self-host-zero-billing-dependency]] no phone-home — the endpoint
// only ever talks to the operator-controlled mgmt port.

package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// AuditEventsDefaultLimit is the response cap when ?limit= is unset.
// Picked at 100 so a default probe returns a useful window without
// flooding a slow link; cross-bouncer query callers (the iam-jit
// audit query CLI) can ask for up to AuditEventsMaxLimit when they
// actually need more.
const AuditEventsDefaultLimit = 100

// AuditEventsMaxLimit caps ?limit= so a runaway query can't return an
// unbounded payload. Matches the audit-tail SQLite cap.
const AuditEventsMaxLimit = 1000

// AuditEventsFormatJSONL is the default response format: one
// JSON-encoded OCSF v1.1.0 class 6003 (API Activity) event per line.
const AuditEventsFormatJSONL = "jsonl"

// AuditEventsFormatOCSFBundle wraps the response in a single OCSF v1.1.0
// class 2004 (Detection Finding) document. Useful when the caller wants
// ONE SIEM-ingestible artifact instead of a stream.
const AuditEventsFormatOCSFBundle = "ocsf-bundle"

// auditEventsHandler builds the http.HandlerFunc for /audit/events.
// Pass requireBearer = "" to allow unauthenticated requests (loopback
// mode); pass a non-empty token to require an Authorization header
// match (external-bind mode).
func auditEventsHandler(st *store.Store, requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAuditError(w, http.StatusMethodNotAllowed,
				"only GET is supported")
			return
		}
		// Auth gate (external-bind only). Missing or empty header =>
		// 401 (no credential offered); present but wrong => 403
		// (credential offered + rejected). Mirrors the OAuth / RFC 6750
		// convention every SDK already special-cases.
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeAuditError(w, http.StatusUnauthorized,
					"Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearer(ah)
			// §A99 — constant-time compare; a wall-clock-string
			// compare leaks the configured token byte-by-byte over
			// enough requests. Mirrors the pattern already used in
			// kbouncer/internal/mcp/bulk_answer.go.
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(requireBearer)) != 1 {
				writeAuditError(w, http.StatusForbidden,
					"bearer token rejected")
				return
			}
		}

		q := r.URL.Query()
		opts, err := parseAuditEventsQuery(q)
		if err != nil {
			writeAuditError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Read the most recent N decisions from the store, then apply
		// the (since, until, filter) trio in memory. The store already
		// caps + orders newest-first; the in-memory pass keeps the
		// filter language identical to the CLI's `audit tail --filter`.
		rows, err := st.RecentDecisions(opts.fetchLimit)
		if err != nil {
			writeAuditError(w, http.StatusInternalServerError,
				fmt.Sprintf("store read: %v", err))
			return
		}
		events := rowsToAuditEvents(rows)
		events = applyAuditEventsTimeBounds(events, opts.since, opts.until)
		if len(opts.filters) > 0 {
			kept := make([]audit.Event, 0, len(events))
			for _, ev := range events {
				if audit.MatchAll(ev, opts.filters) {
					kept = append(kept, ev)
				}
			}
			events = kept
		}
		// Apply the response-side limit AFTER filtering so a filtered
		// query returns up to `limit` matching events (not "the first
		// limit rows that happened to be filtered down to N").
		if len(events) > opts.limit {
			events = events[:opts.limit]
		}

		switch opts.format {
		case AuditEventsFormatJSONL:
			w.Header().Set("Content-Type", "application/x-ndjson")
			enc := json.NewEncoder(w)
			for _, ev := range events {
				if err := enc.Encode(audit.RedactEvent(ev)); err != nil {
					// Response already partially written; nothing useful
					// we can do here besides stop emitting.
					return
				}
			}
		case AuditEventsFormatOCSFBundle:
			w.Header().Set("Content-Type", "application/json")
			redacted := make([]audit.Event, 0, len(events))
			for _, ev := range events {
				redacted = append(redacted, audit.RedactEvent(ev))
			}
			bundle := buildAuditEventsBundle(redacted)
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(bundle)
		}
	}
}

// auditEventsOpts holds the parsed query-string state. Internal to
// this file; the handler does not surface it to callers.
type auditEventsOpts struct {
	limit      int
	fetchLimit int // = max(limit, AuditEventsMaxLimit) so filters can
	// trim a wider source set down to the response cap. Capped at
	// AuditEventsMaxLimit so an attacker can't ask for unbounded
	// reads even via filter funnels.
	format  string
	since   *time.Time
	until   *time.Time
	filters []audit.Filter
}

// parseAuditEventsQuery validates + parses the URL query into a typed
// option set. Surfaces filter / time-bound / limit / format errors as
// plain strings so the 400 response carries an actionable message.
func parseAuditEventsQuery(q url.Values) (auditEventsOpts, error) {
	opts := auditEventsOpts{
		limit:      AuditEventsDefaultLimit,
		fetchLimit: AuditEventsMaxLimit,
		format:     AuditEventsFormatJSONL,
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return opts, fmt.Errorf("limit=%q: must be a positive integer", v)
		}
		if n > AuditEventsMaxLimit {
			return opts, fmt.Errorf("limit=%d exceeds max %d", n, AuditEventsMaxLimit)
		}
		opts.limit = n
	}
	if v := q.Get("format"); v != "" {
		switch v {
		case AuditEventsFormatJSONL, AuditEventsFormatOCSFBundle:
			opts.format = v
		default:
			return opts, fmt.Errorf(
				"format=%q: want one of: %s, %s",
				v, AuditEventsFormatJSONL, AuditEventsFormatOCSFBundle)
		}
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return opts, fmt.Errorf("since=%q: want RFC3339 / ISO 8601", v)
		}
		opts.since = &t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return opts, fmt.Errorf("until=%q: want RFC3339 / ISO 8601", v)
		}
		opts.until = &t
	}
	if opts.since != nil && opts.until != nil && opts.since.After(*opts.until) {
		return opts, errors.New("since must be <= until")
	}
	for _, raw := range q["filter"] {
		f, err := audit.ParseFilter(raw)
		if err != nil {
			return opts, fmt.Errorf("filter %q: %v", raw, err)
		}
		opts.filters = append(opts.filters, f)
	}
	return opts, nil
}

// applyAuditEventsTimeBounds drops events outside [since, until] when
// either bound is set. Bounds are inclusive on both ends.
func applyAuditEventsTimeBounds(events []audit.Event, since, until *time.Time) []audit.Event {
	if since == nil && until == nil {
		return events
	}
	kept := make([]audit.Event, 0, len(events))
	for _, ev := range events {
		t := time.UnixMilli(ev.Time).UTC()
		if since != nil && t.Before(*since) {
			continue
		}
		if until != nil && t.After(*until) {
			continue
		}
		kept = append(kept, ev)
	}
	return kept
}

// rowsToAuditEvents is the gbounce-package mirror of cli.rowsToEvents.
// Lives in the proxy package so the handler doesn't import cli (which
// would create an import cycle). Builds the OCSF wire shape the CLI's
// filter / summary / export pipeline already operates against.
//
// #303 + #305 reconstruction: the SQLite store doesn't carry the
// per-event override fields (activity_id_override, status_id_override,
// ext.connect_refused, ext.deny_reason) — extending the schema would
// be a wider blast-radius change. Instead, the deterministic
// (method, http_status, verdict) triple is enough to recover the
// override intent for the two cases this audit slice covers:
//
//   - method=CONNECT + verdict=ALLOW + http_status=502 → #303 failed
//     CONNECT (the ONLY path in the proxy that sets BadGateway on the
//     CONNECT verb is the dial-failure leg; happy-path = 200, other
//     error legs = 400/405/500).
//   - verdict=DENY + http_status=421 → #305 non-CONNECT rejected.
//
// Both legs also lift the activity_id to ActivityConnect for CONNECT
// rows so a SIEM filter on activity_id=6 finds tunnel attempts whether
// they succeeded or failed.
func rowsToAuditEvents(rows []store.DecisionRow) []audit.Event {
	out := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		in := audit.RequestInput{
			At:             r.At,
			DecisionID:     r.ID,
			Mode:           r.Mode,
			Method:         r.Method,
			Path:           r.Path,
			UpstreamHost:   r.UpstreamHost,
			UpstreamPort:   r.UpstreamPort,
			UpstreamScheme: r.UpstreamScheme,
			ClientHost:     r.ClientHost,
			ClientPort:     r.ClientPort,
			HTTPStatus:     r.HTTPStatus,
			ResponseSize:   r.ResponseSize,
			LatencyMS:      r.LatencyMS,
			Verdict:        r.Verdict,
			// #318 / #320 / §A20 (R3-02) — agent identity threading.
			// The store persists agent_session_id + agent_name on
			// every decision row (per the #308 schema migration) and
			// RecentDecisions selects them, but earlier audit_events
			// builds dropped both on the floor here. Result: every
			// event from /audit/events showed agent.name=anonymous +
			// detected_from=unknown — even when the JSONL log + the
			// CLI tail had the correct agent block. That broke cross-
			// product `iam-jit audit query --filter agent.session_id=
			// <id>` against gbounce (the matching events looked
			// anonymous on the wire).
			//
			// audit.FromRequest below re-runs IsValidSessionID +
			// IsValidAgentName on these values + builds the OCSF
			// unmapped.iam_jit.agent block; per [[cross-product-
			// agent-parity]] this matches the dbounce + kbouncer
			// recipe.
			AgentSessionID: r.AgentSessionID,
			AgentName:      r.AgentName,
		}
		// #303 + #305 — recover the override fields from the persistent
		// (method, http_status, verdict) triple. Shared with the CLI
		// reconstruction site (cli.rowsToEvents) via the audit package
		// so the HTTP /audit/events stream + the local `gbounce audit
		// tail` output surface the same shape.
		audit.ReconstructOverridesFromRow(&in)
		out = append(out, audit.FromRequest(in))
	}
	return out
}

// auditEventsBundle is the on-wire shape for ?format=ocsf-bundle. OCSF
// v1.1.0 class 2004 (Detection Finding) carrying the API Activity
// events as an inline list. Same shape `gbounce audit tail --export
// ocsf-bundle` produces, just streamed back to the HTTP caller.
type auditEventsBundle struct {
	Metadata     map[string]any  `json:"metadata"`
	Time         int64           `json:"time"`
	ClassUID     int             `json:"class_uid"`
	ClassName    string          `json:"class_name"`
	CategoryUID  int             `json:"category_uid"`
	CategoryName string          `json:"category_name"`
	ActivityID   int             `json:"activity_id"`
	ActivityName string          `json:"activity_name"`
	TypeUID      int             `json:"type_uid"`
	TypeName     string          `json:"type_name"`
	SeverityID   int             `json:"severity_id"`
	Severity     string          `json:"severity"`
	StatusID     int             `json:"status_id"`
	Status       string          `json:"status"`
	FindingInfo  map[string]any  `json:"finding_info"`
	Events       []audit.Event   `json:"events"`
}

// buildAuditEventsBundle wraps a slice of events as one OCSF Detection
// Finding. Required fields match the OCSF v1.1.0 class 2004 spec so a
// SIEM that ingests Detection Findings accepts the document without
// product-specific mapping.
func buildAuditEventsBundle(events []audit.Event) auditEventsBundle {
	now := time.Now().UTC()
	return auditEventsBundle{
		Metadata: map[string]any{
			"version": audit.OCSFSchemaVersion,
			"product": map[string]any{
				"name":        audit.ProductName,
				"vendor_name": audit.VendorName,
			},
		},
		Time:         now.UnixMilli(),
		ClassUID:     2004,
		ClassName:    "Detection Finding",
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "Create",
		TypeUID:      2004*100 + 1,
		TypeName:     "Detection Finding: Create",
		SeverityID:   1,
		Severity:     "Informational",
		StatusID:     99,
		Status:       "Other",
		FindingInfo: map[string]any{
			"uid":          fmt.Sprintf("gbounce-audit-events-%d", now.UnixNano()),
			"title":        "gbounce audit-events query",
			"desc":         fmt.Sprintf("HTTP /audit/events query returned %d event(s).", len(events)),
			"created_time": now.UnixMilli(),
		},
		Events: events,
	}
}

// writeAuditError writes a JSON error body with the right status code.
// Centralized so every error path produces an identically-shaped
// payload — the cross-bouncer CLI can rely on a consistent shape.
func writeAuditError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// parseBearer pulls the bearer token out of an Authorization header.
// Returns (token, true) on a well-formed "Bearer <token>"; ("", false)
// otherwise. Case-insensitive on the scheme name per RFC 6750.
func parseBearer(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}
