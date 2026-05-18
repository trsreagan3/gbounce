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
	ActivityOther   = 99
)

// OCSF status_id enum.
const (
	StatusUnknown = 0
	StatusSuccess = 1
	StatusFailure = 2
	StatusOther   = 99
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

// IAMJITExt is the iam-jit vendor extension under unmapped.iam_jit.
// Common fields (mode/verdict/decision_id/enforced) match across the
// Bounce suite; gbounce-specific fields (http_status, response_size,
// latency_ms) live under Ext.
type IAMJITExt struct {
	Mode       string         `json:"mode,omitempty"`
	Verdict    string         `json:"verdict,omitempty"`
	DecisionID int64          `json:"decision_id,omitempty"`
	Enforced   bool           `json:"enforced,omitempty"`
	Ext        map[string]any `json:"ext,omitempty"`
}

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

	statusID, status := mapHTTPStatusToOCSF(in.HTTPStatus)

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
	if len(ext) == 0 {
		ext = nil
	}

	mode := in.Mode
	if mode == "" {
		mode = "discovery"
	}

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
				Verdict:    "ALLOW",
				DecisionID: in.DecisionID,
				Enforced:   false,
				Ext:        ext,
			},
		},
		DecisionID: in.DecisionID,
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
// activity_id. Tracks the OCSF spec's type_name enum verbatim.
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
	case ActivityOther:
		return "API Activity: Other"
	default:
		return "API Activity: Unknown"
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
