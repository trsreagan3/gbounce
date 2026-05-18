// export.go ships the three export formats gbounce's `audit tail
// --export` can emit.
//
// Formats:
//
//   - jsonl: one OCSF event per line. The same wire shape the JSONL
//     audit-log writer emits, just with redaction applied. Designed
//     for downstream `jq` + Vector / Fluent Bit pipelines.
//
//   - csv: tabular. Default columns: timestamp, severity, event_type,
//     actor, operation, verdict, agent.name, agent.session_id,
//     upstream_host, path, method, http_status. `--csv-columns`
//     overrides. RFC 4180 quoting via encoding/csv.
//
//   - ocsf-bundle: OCSF Detection Finding (class 2004) wrapping the
//     contained API Activity events. This is the share-with-SIEM
//     shape — a single top-level finding with a "findings" array of
//     the underlying API Activity events. Useful when a SOC analyst
//     wants ONE artifact (not a stream) summarizing a session.
//
// Every format applies the same URL-token redaction (see redact.go) so
// `gbounce audit tail --export csv --out share.csv` produces an
// artifact safe to paste into a support ticket OR a Claude analysis
// thread without further sanitization.
package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// DefaultCSVColumns is the column order `--export csv` uses when the
// operator doesn't pass --csv-columns. Stable across builds so
// downstream scripts can rely on the header.
var DefaultCSVColumns = []string{
	"timestamp",
	"severity",
	"event_type",
	"actor",
	"operation",
	"verdict",
	"agent.name",
	"agent.session_id",
	"upstream_host",
	"path",
	"method",
	"http_status",
}

// ExportFormat names the three supported export formats.
type ExportFormat string

const (
	ExportFormatJSONL       ExportFormat = "jsonl"
	ExportFormatCSV         ExportFormat = "csv"
	ExportFormatOCSFBundle  ExportFormat = "ocsf-bundle"
)

// ParseExportFormat validates + returns the format. Unknown formats
// error with an enum-listing message so an operator immediately sees
// the valid choices.
func ParseExportFormat(s string) (ExportFormat, error) {
	switch ExportFormat(s) {
	case ExportFormatJSONL, ExportFormatCSV, ExportFormatOCSFBundle:
		return ExportFormat(s), nil
	default:
		return "", fmt.Errorf("unknown --export format %q (want one of: jsonl, csv, ocsf-bundle)", s)
	}
}

// ExportOptions configures one export run.
type ExportOptions struct {
	Format ExportFormat
	// CSVColumns overrides DefaultCSVColumns when non-empty.
	CSVColumns []string
}

// Export writes the events to w in the requested format. Every event
// is passed through RedactEvent first so the artifact is safe to share
// downstream.
func Export(w io.Writer, events []Event, opts ExportOptions) error {
	switch opts.Format {
	case ExportFormatJSONL:
		return exportJSONL(w, events)
	case ExportFormatCSV:
		cols := opts.CSVColumns
		if len(cols) == 0 {
			cols = DefaultCSVColumns
		}
		return exportCSV(w, events, cols)
	case ExportFormatOCSFBundle:
		return exportOCSFBundle(w, events)
	default:
		return fmt.Errorf("unknown export format %q", opts.Format)
	}
}

// exportJSONL emits one JSON-encoded event per line, with redaction.
func exportJSONL(w io.Writer, events []Event) error {
	enc := json.NewEncoder(w)
	for _, ev := range events {
		if err := enc.Encode(RedactEvent(ev)); err != nil {
			return fmt.Errorf("export jsonl: %w", err)
		}
	}
	return nil
}

// exportCSV emits the events as RFC 4180 CSV with the requested column
// order. Unknown column names land as empty cells (so a stale
// --csv-columns flag doesn't error the whole run).
func exportCSV(w io.Writer, events []Event, columns []string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(columns); err != nil {
		return fmt.Errorf("export csv header: %w", err)
	}
	for _, ev := range events {
		red := RedactEvent(ev)
		row := make([]string, len(columns))
		for i, col := range columns {
			row[i] = csvFieldValue(red, col)
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("export csv row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvFieldValue returns the string-form value of a column. Mirrors the
// filter field allowlist for parity (same names mean the same things
// across --filter and --csv-columns).
func csvFieldValue(ev Event, col string) string {
	switch col {
	case "timestamp":
		return time.UnixMilli(ev.Time).UTC().Format(time.RFC3339Nano)
	case "severity":
		return ev.Severity
	case "severity_id":
		return strconv.Itoa(ev.SeverityID)
	case "event_type":
		// Prefer explicit event_type when present; otherwise fall back
		// to the OCSF activity_name (e.g. "config.export" for admin
		// actions, "get"/"post"/... for API Activity).
		if ev.Unmapped.IAMJIT.Ext != nil {
			if v, ok := ev.Unmapped.IAMJIT.Ext["event_type"].(string); ok && v != "" {
				return v
			}
			if v, ok := ev.Unmapped.IAMJIT.Ext["admin_action"].(string); ok && v != "" {
				return v
			}
		}
		return ev.ActivityName
	case "actor":
		if ev.Unmapped.IAMJIT.Ext != nil {
			if cc, ok := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any); ok {
				if a, ok := cc["actor"].(string); ok {
					return a
				}
			}
		}
		return ""
	case "operation", "api.operation":
		return ev.API.Operation
	case "verdict":
		return ev.Unmapped.IAMJIT.Verdict
	case "agent.name", "unmapped.iam_jit.agent.name":
		if agent, ok := ev.Unmapped.IAMJIT.Ext["agent"].(map[string]any); ok {
			if v, ok := agent["name"].(string); ok {
				return v
			}
		}
		return ""
	case "agent.session_id", "unmapped.iam_jit.agent.session_id":
		if agent, ok := ev.Unmapped.IAMJIT.Ext["agent"].(map[string]any); ok {
			if v, ok := agent["session_id"].(string); ok {
				return v
			}
		}
		return ""
	case "upstream_host":
		return ev.API.Service.Name
	case "path":
		if len(ev.Resources) > 0 {
			return ev.Resources[0].Name
		}
		return ""
	case "method":
		op := ev.API.Operation
		if i := strings.Index(op, " "); i > 0 {
			return op[:i]
		}
		return op
	case "http_status":
		if ev.Unmapped.IAMJIT.Ext != nil {
			if v, ok := ev.Unmapped.IAMJIT.Ext["http_status"]; ok {
				if n, ok := toFloat(v); ok {
					return strconv.FormatInt(int64(n), 10)
				}
			}
		}
		return ""
	case "activity_id":
		return strconv.Itoa(ev.ActivityID)
	case "status_id":
		return strconv.Itoa(ev.StatusID)
	case "status":
		return ev.Status
	case "decision_id":
		return strconv.FormatInt(ev.Unmapped.IAMJIT.DecisionID, 10)
	default:
		return ""
	}
}

// OCSFDetectionFinding is the class 2004 (Detection Finding) wire
// shape gbounce emits for --export ocsf-bundle.
//
// The bundle is one top-level Detection Finding whose "findings" array
// references the underlying API Activity events. Each contained event
// is passed through RedactEvent first.
//
// Minimal field set (per OCSF v1.1.0 class 2004 spec): metadata, time,
// class_uid (2004), class_name, category_uid (2 — Findings),
// category_name, activity_id (1 — Create), severity_id (highest
// severity across contained events), severity, finding_info, plus an
// iam-jit-specific findings[] array for the contained events.
type OCSFDetectionFinding struct {
	Metadata     OCSFMetadata `json:"metadata"`
	Time         int64        `json:"time"`
	ClassUID     int          `json:"class_uid"`
	ClassName    string       `json:"class_name"`
	CategoryUID  int          `json:"category_uid"`
	CategoryName string       `json:"category_name"`
	ActivityID   int          `json:"activity_id"`
	ActivityName string       `json:"activity_name"`
	TypeUID      int          `json:"type_uid"`
	TypeName     string       `json:"type_name"`
	SeverityID   int          `json:"severity_id"`
	Severity     string       `json:"severity"`
	StatusID     int          `json:"status_id"`
	Status       string       `json:"status"`
	FindingInfo  FindingInfo  `json:"finding_info"`
	// Findings carries the contained, redacted API Activity events.
	// Lives under the OCSF unmapped extension key so a strict v1.1.0
	// validator that doesn't yet know about gbounce still parses the
	// outer envelope.
	Unmapped OCSFDetectionFindingExt `json:"unmapped"`
}

// FindingInfo is the OCSF Detection Finding finding_info sub-object.
type FindingInfo struct {
	UID         string `json:"uid"`
	Title       string `json:"title"`
	CreatedTime int64  `json:"created_time"`
	// EventsCount is non-standard; OCSF spec puts the count under the
	// `count` enrichment. We surface it here in the iam-jit extension
	// instead — see OCSFDetectionFindingExt.
}

// OCSFDetectionFindingExt is the iam-jit-specific extension under the
// unmapped key. Carries the contained events + a count for at-a-glance
// review.
type OCSFDetectionFindingExt struct {
	IAMJIT DetectionFindingIAMJIT `json:"iam_jit"`
}

// DetectionFindingIAMJIT is the iam-jit extension inside the bundle.
type DetectionFindingIAMJIT struct {
	Product     string  `json:"product"`
	EventsCount int     `json:"events_count"`
	Findings    []Event `json:"findings"`
}

// exportOCSFBundle emits the contained events as a single OCSF
// Detection Finding bundle. The severity_id of the wrapper is the
// highest severity across the contained events (so a SIEM dashboard
// sorting by severity sees the bundle's worst-case event).
func exportOCSFBundle(w io.Writer, events []Event) error {
	// Redact every contained event first; never copy raw query-string
	// values into a bundle that's going to a SIEM / Claude thread.
	redacted := make([]Event, len(events))
	maxSev := SeverityInformational
	for i, ev := range events {
		redacted[i] = RedactEvent(ev)
		if ev.SeverityID > maxSev {
			maxSev = ev.SeverityID
		}
	}
	now := time.Now().UTC().UnixMilli()
	bundle := OCSFDetectionFinding{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         now,
		ClassUID:     2004,
		ClassName:    "Detection Finding",
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "create",
		TypeUID:      2004*100 + 1,
		TypeName:     "Detection Finding: Create",
		SeverityID:   maxSev,
		Severity:     severityName(maxSev),
		StatusID:     StatusSuccess,
		Status:       "Success",
		FindingInfo: FindingInfo{
			UID:         fmt.Sprintf("gbounce-audit-tail-export-%d", now),
			Title:       fmt.Sprintf("gbounce audit-tail export (%d events)", len(redacted)),
			CreatedTime: now,
		},
		Unmapped: OCSFDetectionFindingExt{
			IAMJIT: DetectionFindingIAMJIT{
				Product:     ProductName,
				EventsCount: len(redacted),
				Findings:    redacted,
			},
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return fmt.Errorf("export ocsf-bundle: %w", err)
	}
	return nil
}

// severityName maps a severity_id to its OCSF severity string.
func severityName(id int) string {
	switch id {
	case SeverityInformational:
		return "Informational"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	default:
		return "Unknown"
	}
}
