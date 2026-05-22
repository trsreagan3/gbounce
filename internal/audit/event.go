// Package audit implements gbounce's OCSF event builder + JSONL log
// writer. Every decision in the proxy hot-path is funneled through
// FromRequest (the canonical event builder) into the LogWriter.
//
// Wire schema: OCSF v1.1.0 class 6003 (API Activity). Every event
// emitted by every product in the Bounce suite (ibounce / kbounce /
// dbounce / gbounce) conforms to the same OCSF base shape so a
// customer's SIEM ingest (AWS Security Lake, Splunk, Cloudflare,
// IBM, ...) auto-categorizes the events without product-specific
// glue. See the [[ocsf-audit-schema]] memo for the per-product
// activity_id mappings + the unmapped.iam_jit extension catalog.
//
// G-Slice 1 mappings (HTTP method → OCSF activity_id):
//
//	GET / HEAD / OPTIONS → 2 (Read)
//	POST                 → 1 (Create) — best-effort; HTTP semantics
//	                       are loose
//	PUT / PATCH          → 3 (Update)
//	DELETE               → 4 (Delete)
//	other                → 99 (Other)
//
// gbounce is observation-only in G-Slice 1 — every event carries
// verdict=ALLOW + enforced=false. Profile/tap modes (later slices)
// will introduce DENY verdicts; the wire shape is forward-compatible.
package audit

import (
	"strconv"
	"strings"
	"time"
)

// OCSFSchemaVersion is the OCSF schema version every event declares.
// Pinned to 1.1.0 per the [[ocsf-audit-schema]] decision; bumping
// requires a coordinated change across all Bounce products + a
// schema-validation test refresh.
const OCSFSchemaVersion = "1.1.0"

// ProductName identifies gbounce in shared multi-product audit
// streams. Matches the OCSF metadata.product.name enum.
const ProductName = "gbounce"

// VendorName is the OCSF metadata.product.vendor_name field. Same
// across the Bounce suite so a SIEM pivot on vendor groups our events.
const VendorName = "iam-jit"

// buildVersion is the gbounce binary's build version. Stamped at build
// time via the cli package's -ldflags variable; the audit package
// reads it via SetBuildVersion at startup so the import graph stays
// acyclic (cli imports audit, never the reverse).
//
// Unset → "dev" (matches cli.version's default).
var buildVersion = "dev"

// SetBuildVersion is called from cli.Main at startup to thread the
// linker-stamped binary version into the OCSF metadata.product.version
// field. Idempotent + safe to call before/after a NewLogWriter.
func SetBuildVersion(v string) {
	if v == "" {
		return
	}
	buildVersion = v
}

// OCSF activity_id enum (class 6003 / API Activity).
const (
	ActivityUnknown = 0
	ActivityCreate  = 1
	ActivityRead    = 2
	ActivityUpdate  = 3
	ActivityDelete  = 4
	// ActivityConnect is the gbounce-specific extension for the HTTP
	// CONNECT verb. OCSF v1.1.0's class 6003 enum stops at 4+99; CONNECT
	// is a transport-establishment action that doesn't map cleanly to
	// Create/Read/Update/Delete. We reserve activity_id=6 for it so the
	// SIEM-side pivot can isolate tunnel-establishment events from
	// payload calls. Used by #303 + the successful-CONNECT happy-path
	// audit so both the success and the failure carry the same
	// activity_id (a SIEM filter on `activity_id=6` finds all tunnel
	// attempts).
	ActivityConnect = 6
	ActivityOther   = 99
)

// OCSF status_id enum.
const (
	StatusUnknown = 0
	StatusSuccess = 1
	StatusFailure = 2
	// StatusDenied is the gbounce-specific extension for explicit
	// policy-deny outcomes. OCSF v1.1.0's status_id enum has
	// Unknown=0/Success=1/Failure=2/Other=99; "Denied" is a verdict-
	// shaped outcome that's distinct from a generic 4xx failure. Used
	// by #305 (non-CONNECT on CONNECT-only listener) + reserved for
	// future profile/tap-mode DENY events. SIEM filter on
	// `status_id=4` isolates policy denials.
	StatusDenied = 4
	StatusOther  = 99
)

// OCSF severity_id enum (only the values gbounce actually emits).
const (
	SeverityInformational = 1
	SeverityMedium        = 3
	SeverityHigh          = 4
)

// OCSF class / category constants for API Activity events.
const (
	ClassUID     = 6003
	ClassName    = "API Activity"
	CategoryUID  = 6
	CategoryName = "Application Activity"
)

// OCSFProduct is the metadata.product object.
type OCSFProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

// OCSFMetadata is the metadata top-level object every OCSF event
// carries.
type OCSFMetadata struct {
	Version string      `json:"version"`
	Product OCSFProduct `json:"product"`
}

// OCSFAPIService is the api.service sub-object. For gbounce this is
// the upstream hostname so a SIEM can pivot on "which upstream".
type OCSFAPIService struct {
	Name string `json:"name,omitempty"`
}

// OCSFAPIRequest is the api.request sub-object — gbounce stashes the
// decision_id here so a SIEM row joins back to the local SQLite row.
type OCSFAPIRequest struct {
	UID string `json:"uid,omitempty"`
}

// OCSFAPI is the api object — operation, service, request.
type OCSFAPI struct {
	Operation string         `json:"operation,omitempty"`
	Service   OCSFAPIService `json:"service"`
	Request   OCSFAPIRequest `json:"request"`
}

// OCSFResource is one entry in the resources[] array. gbounce maps an
// HTTP request to a single resource with name = URL path, uid = full
// URL, type = "http resource".
type OCSFResource struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

// OCSFEndpoint is the src_endpoint / dst_endpoint object.
type OCSFEndpoint struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// OCSFUnmapped is the unmapped top-level object — OCSF's
// vendor-extension hook. iam-jit-specific fields land under
// `unmapped.iam_jit`.
type OCSFUnmapped struct {
	IAMJIT IAMJITExt `json:"iam_jit"`
}

// OCSFAgent is the iam-jit-native agent-identity block populated per
// [[agent-identity-in-audit]] (#266). Always non-nil on events emitted
// by FromRequest so a SIEM query on `unmapped.iam_jit.agent.name=
// "anonymous"` surfaces unattributed traffic as a first-class signal
// (#308). The shape mirrors kbouncer's OCSFAgent — same field names +
// JSON tags so cross-bouncer queries port across products. gbounce
// detects agent identity ONLY from the inbound HTTP headers
// `X-Agent-Session-Id` + `X-Agent-Name`; it does NOT walk the process
// tree (kbouncer's domain) so ProcessExe/ParentExe stay omitted.
// DetectedFrom is "http_header" when either header was present (and
// passed validation); "unknown" otherwise.
type OCSFAgent struct {
	Name         string `json:"name"`
	SessionID    string `json:"session_id,omitempty"`
	DetectedFrom string `json:"detected_from"`
}

// IAMJITExt is the iam-jit vendor extension under unmapped.iam_jit.
// Common fields (mode/verdict/decision_id/enforced) match across the
// Bounce suite; gbounce-specific fields (http_status, response_size,
// latency_ms) live under Ext.
//
// Agent is the cross-bouncer agent-identity block (#266 / #308).
// Always non-nil on events emitted by FromRequest — when neither
// X-Agent-Session-Id nor X-Agent-Name was present the block surfaces
// as {name:"anonymous", detected_from:"unknown"} so a SIEM query on
// unmapped.iam_jit.agent.name="anonymous" finds unattributed traffic
// as a first-class signal. The flat keys
// `Ext[AgentSessionIDExtKey]` + `Ext[AgentNameExtKey]` are also
// populated when present so the existing SessionRecorder
// (`{dir}/{session_id}.ndjson`) routes events unchanged.
type IAMJITExt struct {
	Mode       string         `json:"mode,omitempty"`
	Verdict    string         `json:"verdict,omitempty"`
	DecisionID int64          `json:"decision_id,omitempty"`
	Enforced   bool           `json:"enforced,omitempty"`
	Agent      *OCSFAgent     `json:"agent,omitempty"`
	Ext        map[string]any `json:"ext,omitempty"`
}

// AgentNameAnonymous is the sentinel populated under
// unmapped.iam_jit.agent.name when no X-Agent-Name header was supplied.
// Honest-effort: gbounce DOES NOT fabricate a name from User-Agent or
// peer-PID (those are unreliable for HTTP traffic + would be
// surveillance-shaped per
// [[security-team-positioning-safety-not-surveillance]]). "anonymous"
// makes the absence visible to the SIEM operator.
const AgentNameAnonymous = "anonymous"

// DetectionSource enum values for unmapped.iam_jit.agent.detected_from.
// gbounce supports exactly two: http_header (the headers fired) and
// unknown (no agent identity was supplied).
const (
	DetectionSourceHTTPHeader = "http_header"
	DetectionSourceUnknown    = "unknown"
)

// Event is the OCSF v1.1.0 class 6003 (API Activity) wire shape. Every
// field name + nested object matches the OCSF spec verbatim —
// downstream SIEMs ingest this directly without product-specific
// mapping.
type Event struct {
	Metadata     OCSFMetadata   `json:"metadata"`
	Time         int64          `json:"time"`
	ClassUID     int            `json:"class_uid"`
	ClassName    string         `json:"class_name"`
	CategoryUID  int            `json:"category_uid"`
	CategoryName string         `json:"category_name"`
	ActivityID   int            `json:"activity_id"`
	ActivityName string         `json:"activity_name"`
	TypeUID      int            `json:"type_uid"`
	TypeName     string         `json:"type_name"`
	SeverityID   int            `json:"severity_id"`
	Severity     string         `json:"severity"`
	StatusID     int            `json:"status_id"`
	Status       string         `json:"status"`
	API          OCSFAPI        `json:"api"`
	Resources    []OCSFResource `json:"resources"`
	SrcEndpoint  *OCSFEndpoint  `json:"src_endpoint,omitempty"`
	DstEndpoint  *OCSFEndpoint  `json:"dst_endpoint,omitempty"`
	Unmapped     OCSFUnmapped   `json:"unmapped"`

	// DecisionID is the SQLite decision-row id for this event. Used
	// internally for error-message correlation; not serialized into the
	// wire shape (the OCSF home is unmapped.iam_jit.decision_id +
	// api.request.uid). The "-" json tag enforces that.
	DecisionID int64 `json:"-"`
}

// RequestInput is the minimal struct the proxy passes to FromRequest —
// keeps the audit package free of proxy-package dependencies (no
// import cycles) while still capturing every field the OCSF wire-shape
// requires.
//
// All fields are optional; missing-field defaults are sensible for
// observation-only test runs that don't go through the full proxy.
type RequestInput struct {
	At             time.Time
	DecisionID     int64
	Mode           string
	Method         string
	Path           string
	UpstreamHost   string
	UpstreamPort   int
	UpstreamScheme string // "http" or "https" — used to build the full URL
	ClientHost     string
	ClientPort     int
	HTTPStatus     int
	ResponseSize   int64
	LatencyMS      int64
	// AgentSessionID + AgentName carry the agent's per-session context.
	// The proxy populates these from the inbound `X-Agent-Session-Id`
	// + `X-Agent-Name` headers (when present); empty otherwise. They
	// land in `unmapped.iam_jit.ext[agent_session_id|agent_name]` so
	// the per-session NDJSON recorder (#285) can route events into the
	// right session file. Empty session_id → event is not routed to a
	// session file (raw curl from a script has no session identity).
	AgentSessionID string
	AgentName      string

	// Verdict overrides the default "ALLOW" verdict on the
	// unmapped.iam_jit extension. Empty → "ALLOW" (the discovery-mode
	// default). Used by #305 to emit verdict=DENY for explicit policy
	// rejections (non-CONNECT method on CONNECT-only listener) and by
	// #303 to emit verdict=ALLOW alongside a failed-CONNECT outcome
	// (we INTENDED to allow; upstream was unreachable).
	Verdict string

	// ActivityIDOverride lets the caller pin a specific OCSF activity_id
	// when method→activity mapping doesn't fit. Used for #303 (CONNECT
	// failure → ActivityConnect) and reserved for future events whose
	// activity is determined by context rather than HTTP verb. Zero =
	// fall back to method-derived activity. The matching activity_name
	// + type_uid + type_name are recomputed from the override.
	ActivityIDOverride int

	// StatusIDOverride lets the caller pin a specific OCSF status_id
	// independent of the HTTP status code mapping. Used for #303
	// (CONNECT dial failure → StatusFailure, even though we never sent
	// an HTTP status to the client) and #305 (explicit DENY →
	// StatusDenied). Zero = fall back to HTTPStatus mapping. The
	// matching status string is recomputed from the override.
	StatusIDOverride int

	// ExtraExt fields merge into the unmapped.iam_jit.ext map alongside
	// the standard http_status / response_size / latency_ms / agent
	// keys. Used by #303 to record `connect_refused: true` +
	// `connect_error: <error>`, and by #305 to record `deny_reason`.
	// Empty map = no extras.
	ExtraExt map[string]any
}

// FromRequest builds an OCSF class 6003 (API Activity) Event from a
// RequestInput. Single source of truth for the audit-export wire
// shape.
//
// G-Slice 1 always emits verdict=ALLOW + enforced=false (discovery
// mode is observation-only). Mappings:
//
//   - activity_id: HTTP method → Create / Read / Update / Delete / Other
//   - status_id:   HTTP status class → Success (1xx/2xx/3xx) /
//     Failure (4xx) / Other (5xx)
//   - severity_id: always Informational (Slice 1); profile/tap modes
//     will lift this when DENY verdicts arrive.
//   - api.operation: "<METHOD> <path>" (e.g. "GET /v1/dashboards")
//   - api.service.name: upstream hostname (so a SIEM can pivot)
//   - api.request.uid: decision_id stringified
//   - resources: one entry — name=path, uid=full URL, type="http resource"
//   - src_endpoint: the client connection address
//   - dst_endpoint: the upstream
//   - unmapped.iam_jit: mode + verdict + decision_id + enforced + ext
//     (http_status, response_size, latency_ms)
func FromRequest(in RequestInput) Event {
	ts := in.At
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	activityID := httpMethodToActivityID(in.Method)
	activityName := strings.ToLower(in.Method)
	if activityName == "" {
		activityName = "unknown"
	}
	// #303 — caller may pin a specific activity_id (e.g. ActivityConnect
	// for a failed CONNECT) when method-derived mapping doesn't fit.
	if in.ActivityIDOverride != 0 {
		activityID = in.ActivityIDOverride
		activityName = activityNameForID(activityID)
	}

	statusID, status := mapHTTPStatusToOCSF(in.HTTPStatus)
	// #303 + #305 — caller may pin a specific status_id (Failure on
	// CONNECT dial error, Denied on policy reject) independent of any
	// HTTP status code sent to the client.
	if in.StatusIDOverride != 0 {
		statusID = in.StatusIDOverride
		status = statusNameForID(statusID)
	}

	operation := strings.ToUpper(in.Method)
	if in.Path != "" {
		operation = strings.ToUpper(in.Method) + " " + in.Path
	}

	api := OCSFAPI{
		Operation: operation,
		Service:   OCSFAPIService{Name: in.UpstreamHost},
		Request:   OCSFAPIRequest{UID: strconv.FormatInt(in.DecisionID, 10)},
	}

	resources := buildResources(in)

	var src *OCSFEndpoint
	if in.ClientHost != "" || in.ClientPort != 0 {
		src = &OCSFEndpoint{}
		if looksLikeIP(in.ClientHost) {
			src.IP = in.ClientHost
		} else {
			src.Hostname = in.ClientHost
		}
		src.Port = in.ClientPort
	}
	var dst *OCSFEndpoint
	if in.UpstreamHost != "" || in.UpstreamPort != 0 {
		dst = &OCSFEndpoint{
			Hostname: in.UpstreamHost,
			Port:     in.UpstreamPort,
		}
	}

	ext := map[string]any{}
	if in.HTTPStatus != 0 {
		ext["http_status"] = in.HTTPStatus
	}
	if in.ResponseSize != 0 {
		ext["response_size"] = in.ResponseSize
	}
	if in.LatencyMS != 0 {
		ext["latency_ms"] = in.LatencyMS
	}
	// #285 — agent session context lands at the same fixed Ext keys
	// the SessionRecorder reads (AgentSessionIDExtKey + AgentNameExtKey).
	// Only valid session ids flow through; the recorder's IsValidSessionID
	// gate also rejects malformed input, so this is belt-and-suspenders.
	// #308 — agent block also lands under unmapped.iam_jit.agent (built
	// further below) so cross-bouncer queries on
	// `unmapped.iam_jit.agent.{name,session_id}` resolve.
	validSessionID := in.AgentSessionID != "" && IsValidSessionID(in.AgentSessionID)
	validAgentName := in.AgentName != "" && IsValidAgentName(in.AgentName)
	if validSessionID {
		ext[AgentSessionIDExtKey] = in.AgentSessionID
	}
	if validAgentName {
		ext[AgentNameExtKey] = in.AgentName
	}
	// #303 + #305 — merge caller-supplied extras (connect_refused,
	// connect_error, deny_reason, …) after the standard keys so the
	// caller's intent wins on collisions. Keys are documented per-call-
	// site rather than centralized — the ext map is the OCSF-extension
	// catch-all by design.
	for k, v := range in.ExtraExt {
		ext[k] = v
	}
	if len(ext) == 0 {
		ext = nil
	}

	mode := in.Mode
	if mode == "" {
		mode = "discovery"
	}
	// #303 + #305 — caller may override the default "ALLOW" verdict
	// (e.g. "DENY" for explicit policy reject in #305). Empty falls
	// back to "ALLOW" to preserve the G-Slice 1 discovery-mode default.
	verdict := in.Verdict
	if verdict == "" {
		verdict = "ALLOW"
	}

	// #308 — agent-identity block under unmapped.iam_jit.agent. Always
	// non-nil so a SIEM query on `unmapped.iam_jit.agent.name=
	// "anonymous"` finds every unattributed event as a first-class
	// signal. Detection source is "http_header" when either header
	// fired (and passed validation); "unknown" otherwise. Honest-effort
	// per [[ibounce-honest-positioning]] — gbounce never fabricates a
	// name from User-Agent or peer-PID.
	agent := buildAgentBlock(in.AgentSessionID, in.AgentName, validSessionID, validAgentName)

	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         ts.UTC().UnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   activityID,
		ActivityName: activityName,
		TypeUID:      ClassUID*100 + activityID,
		TypeName:     typeNameForActivity(activityID),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     statusID,
		Status:       status,
		API:          api,
		Resources:    resources,
		SrcEndpoint:  src,
		DstEndpoint:  dst,
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				Mode:       mode,
				Verdict:    verdict,
				DecisionID: in.DecisionID,
				Enforced:   false,
				Agent:      agent,
				Ext:        ext,
			},
		},
		DecisionID: in.DecisionID,
	}
}

// buildAgentBlock returns the OCSFAgent for one event. Both inputs are
// already-validated forms of the inbound X-Agent-Session-Id +
// X-Agent-Name headers. Empty inputs → anonymous block; either-or-both
// present → http_header detection source. Always returns a non-nil
// pointer so `unmapped.iam_jit.agent.name` is queryable as a
// first-class field on every gbounce event (#308).
func buildAgentBlock(rawSessionID, rawName string, validSessionID, validName bool) *OCSFAgent {
	name := AgentNameAnonymous
	if validName {
		name = rawName
	}
	sessionID := ""
	if validSessionID {
		sessionID = rawSessionID
	}
	detectedFrom := DetectionSourceUnknown
	if validSessionID || validName {
		detectedFrom = DetectionSourceHTTPHeader
	}
	return &OCSFAgent{
		Name:         name,
		SessionID:    sessionID,
		DetectedFrom: detectedFrom,
	}
}

// httpMethodToActivityID maps an HTTP method to the OCSF activity_id
// enum per the [[ocsf-audit-schema]] memo's gbounce table. HTTP
// semantics are inherently loose (a POST can read, a GET can have
// side effects) but the body of the spec recommends the
// safe/idempotent classification — we follow that.
func httpMethodToActivityID(method string) int {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return ActivityRead
	case "POST":
		return ActivityCreate
	case "PUT", "PATCH":
		return ActivityUpdate
	case "DELETE":
		return ActivityDelete
	case "":
		return ActivityUnknown
	default:
		return ActivityOther
	}
}

// mapHTTPStatusToOCSF translates an HTTP response status code into the
// OCSF status_id / status enum per the [[ocsf-audit-schema]] memo.
// 1xx/2xx/3xx → Success; 4xx → Failure; 5xx → Other. Zero (no
// response) → Unknown.
func mapHTTPStatusToOCSF(code int) (int, string) {
	switch {
	case code == 0:
		return StatusUnknown, "Unknown"
	case code >= 100 && code < 400:
		return StatusSuccess, "Success"
	case code >= 400 && code < 500:
		return StatusFailure, "Failure"
	case code >= 500 && code < 600:
		return StatusOther, "Other"
	default:
		return StatusUnknown, "Unknown"
	}
}

// typeNameForActivity returns the OCSF type_name string for the given
// activity_id. Tracks the OCSF spec's type_name enum verbatim — except
// for ActivityConnect (6) which is gbounce's CONNECT extension and uses
// the matching "API Activity: Connect" label so SIEM rendering stays
// human-readable.
func typeNameForActivity(activityID int) string {
	switch activityID {
	case ActivityCreate:
		return "API Activity: Create"
	case ActivityRead:
		return "API Activity: Read"
	case ActivityUpdate:
		return "API Activity: Update"
	case ActivityDelete:
		return "API Activity: Delete"
	case ActivityConnect:
		return "API Activity: Connect"
	case ActivityOther:
		return "API Activity: Other"
	default:
		return "API Activity: Unknown"
	}
}

// activityNameForID returns the lowercase activity_name string for an
// OCSF activity_id when the caller didn't supply a method (e.g. #303
// pins ActivityConnect on a failed CONNECT). Tracks the same enum the
// SIEM-side schema renders.
func activityNameForID(activityID int) string {
	switch activityID {
	case ActivityCreate:
		return "create"
	case ActivityRead:
		return "read"
	case ActivityUpdate:
		return "update"
	case ActivityDelete:
		return "delete"
	case ActivityConnect:
		return "connect"
	case ActivityOther:
		return "other"
	default:
		return "unknown"
	}
}

// ReconstructOverridesFromRow infers the #303 + #305 override fields
// from the persistent (method, http_status, verdict) signals that the
// store layer DOES carry. Called by the SQLite-backed reconstruction
// sites (proxy.rowsToAuditEvents, cli.rowsToEvents) so the
// /audit/events HTTP endpoint + the `gbounce audit tail` CLI surface
// the same activity_id / status_id / ext keys as the canonical JSONL
// audit log (which carries the override fields directly from the
// proxy hot path).
//
// The reconstruction is deterministic for the two cases this slice
// covers:
//
//   - method=CONNECT → activity_id=Connect (success + failure share
//     one activity pivot)
//   - method=CONNECT + verdict=ALLOW + http_status=502 → #303 dial
//     failure: status_id=Failure + ext.connect_refused=true (the full
//     connect_error string lives in the JSONL log only — the SIEM-side
//     filter `connect_refused=true` is enough to isolate the case)
//   - verdict=DENY → #305 explicit reject: status_id=Denied +
//     ext.deny_reason="non-CONNECT method on CONNECT-only listener"
//
// Idempotent: callers that already populated ActivityIDOverride /
// StatusIDOverride / ExtraExt have those values preserved (the
// reconstruction only fills zero values).
func ReconstructOverridesFromRow(in *RequestInput) {
	if in == nil {
		return
	}
	if strings.EqualFold(in.Method, "CONNECT") && in.ActivityIDOverride == 0 {
		in.ActivityIDOverride = ActivityConnect
	}
	if strings.EqualFold(in.Method, "CONNECT") && in.HTTPStatus == 502 && strings.EqualFold(in.Verdict, "ALLOW") {
		if in.StatusIDOverride == 0 {
			in.StatusIDOverride = StatusFailure
		}
		if in.ExtraExt == nil {
			in.ExtraExt = map[string]any{}
		}
		if _, ok := in.ExtraExt["connect_refused"]; !ok {
			in.ExtraExt["connect_refused"] = true
		}
	}
	if strings.EqualFold(in.Verdict, "DENY") {
		if in.StatusIDOverride == 0 {
			in.StatusIDOverride = StatusDenied
		}
		if in.ExtraExt == nil {
			in.ExtraExt = map[string]any{}
		}
		// #314 — distinguish the two known deny shapes by HTTPStatus.
		// The JSONL hot path carries the EXACT deny_reason via ExtraExt;
		// this reconstruction is the SQLite-rebuild fallback used by
		// `gbounce audit tail` + GET /audit/events to give a SIEM a
		// useful (if generic) reason when the JSONL log isn't available.
		//   - HTTP 403 + CONNECT → deny_hosts rule match (#314)
		//   - HTTP 421 (or anything else) → non-CONNECT on CONNECT-only
		//     listener (#305)
		if _, ok := in.ExtraExt["deny_reason"]; !ok {
			if in.HTTPStatus == 403 && strings.EqualFold(in.Method, "CONNECT") {
				in.ExtraExt["deny_reason"] = "matched deny_hosts rule"
			} else {
				in.ExtraExt["deny_reason"] = "non-CONNECT method on CONNECT-only listener"
			}
		}
	}
}

// statusNameForID returns the OCSF status enum name for a pinned
// status_id. Used by #303 + #305 callers that pass StatusIDOverride.
func statusNameForID(statusID int) string {
	switch statusID {
	case StatusSuccess:
		return "Success"
	case StatusFailure:
		return "Failure"
	case StatusDenied:
		return "Denied"
	case StatusOther:
		return "Other"
	default:
		return "Unknown"
	}
}

// buildResources derives the single resources[] entry from a parsed
// HTTP request. Returns an empty slice (not nil) when no path was
// captured — OCSF requires the field to be present as an array.
func buildResources(in RequestInput) []OCSFResource {
	if in.Path == "" && in.UpstreamHost == "" {
		return []OCSFResource{}
	}
	scheme := in.UpstreamScheme
	if scheme == "" {
		scheme = "https"
	}
	hostPort := in.UpstreamHost
	if in.UpstreamPort != 0 && in.UpstreamPort != 80 && in.UpstreamPort != 443 {
		hostPort = in.UpstreamHost + ":" + strconv.Itoa(in.UpstreamPort)
	}
	fullURL := scheme + "://" + hostPort + in.Path
	name := in.Path
	if name == "" {
		name = "/"
	}
	return []OCSFResource{{
		Name: name,
		UID:  fullURL,
		Type: "http resource",
	}}
}

// looksLikeIP is a cheap IPv4-shape check (dotted-quad of digits).
// Good enough for the src_endpoint split — full RFC parsing isn't
// worth the dependency surface, and downstream SIEMs re-validate.
func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
