package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseExportFormat(t *testing.T) {
	for _, f := range []string{"jsonl", "csv", "ocsf-bundle"} {
		if _, err := ParseExportFormat(f); err != nil {
			t.Errorf("ParseExportFormat(%q): %v", f, err)
		}
	}
	if _, err := ParseExportFormat("yaml"); err == nil {
		t.Error("ParseExportFormat(yaml) should error")
	}
}

func TestExport_JSONL_RoundtripsViaJQ(t *testing.T) {
	events := []Event{
		mkEvent("GET", "/v1/x", "api.example.com", 200),
		mkEvent("POST", "/v1/y", "api.example.com", 201),
	}
	var buf bytes.Buffer
	if err := Export(&buf, events, ExportOptions{Format: ExportFormatJSONL}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	// `jq` parses one JSON object per line. Re-decode line-by-line to
	// emulate that contract without shelling out.
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines; want 2", len(lines))
	}
	for i, line := range lines {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line %d failed to decode: %v", i, err)
		}
		if ev["class_uid"].(float64) != 6003 {
			t.Errorf("line %d class_uid = %v", i, ev["class_uid"])
		}
	}
}

func TestExport_CSV_ParsesCleanly(t *testing.T) {
	events := []Event{
		mkEvent("GET", "/v1/x", "api.example.com", 200),
		mkEvent("POST", "/v1/y", "api.example.com", 201),
	}
	var buf bytes.Buffer
	if err := Export(&buf, events, ExportOptions{Format: ExportFormatCSV}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	r := csv.NewReader(strings.NewReader(buf.String()))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	// Header + 2 events.
	if len(rows) != 3 {
		t.Fatalf("got %d rows; want 3", len(rows))
	}
	header := rows[0]
	if header[0] != "timestamp" || header[1] != "severity" {
		t.Errorf("unexpected header: %v", header)
	}
	// Find the upstream_host column and assert it's populated.
	hostIdx := -1
	for i, h := range header {
		if h == "upstream_host" {
			hostIdx = i
		}
	}
	if hostIdx < 0 {
		t.Fatal("upstream_host column missing")
	}
	if rows[1][hostIdx] != "api.example.com" {
		t.Errorf("row[1] upstream_host = %q", rows[1][hostIdx])
	}
}

// TestExport_CSV_RedactsTokenSentinel is the load-bearing sentinel test
// per the [[investigate-with-claude]] memo. Seed an audit event with a
// `?token=sentinel-XYZ` query string; assert the literal `sentinel-XYZ`
// string is ABSENT from the CSV bytes. If this test fails, the
// share-export-with-Claude pipeline is leaking tokens to anyone the
// CSV gets pasted to.
func TestExport_CSV_RedactsTokenSentinel(t *testing.T) {
	const sentinel = "sentinel-XYZ"
	ev := mkEvent("GET", "/v1/x?token="+sentinel, "api.example.com", 200)
	var buf bytes.Buffer
	if err := Export(&buf, []Event{ev}, ExportOptions{Format: ExportFormatCSV}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte(sentinel)) {
		t.Errorf("CSV export leaked sentinel %q: %s", sentinel, buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("token=REDACTED")) {
		t.Errorf("CSV export missing redaction placeholder: %s", buf.String())
	}
}

func TestExport_CSV_CustomColumns(t *testing.T) {
	ev := mkEvent("GET", "/v1/x", "api.example.com", 200)
	var buf bytes.Buffer
	if err := Export(&buf, []Event{ev}, ExportOptions{
		Format:     ExportFormatCSV,
		CSVColumns: []string{"method", "http_status"},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	r := csv.NewReader(strings.NewReader(buf.String()))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	if len(rows) != 2 || len(rows[0]) != 2 {
		t.Fatalf("rows shape = %dx%d", len(rows), len(rows[0]))
	}
	if rows[0][0] != "method" || rows[0][1] != "http_status" {
		t.Errorf("custom header = %v", rows[0])
	}
	if rows[1][0] != "GET" || rows[1][1] != "200" {
		t.Errorf("custom row = %v", rows[1])
	}
}

func TestExport_OCSFBundle_ValidatesAsDetectionFinding(t *testing.T) {
	events := []Event{
		mkEvent("GET", "/v1/x", "api.example.com", 200),
	}
	var buf bytes.Buffer
	if err := Export(&buf, events, ExportOptions{Format: ExportFormatOCSFBundle}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(buf.Bytes(), &bundle); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bundle["class_uid"].(float64) != 2004 {
		t.Errorf("class_uid = %v; want 2004 (Detection Finding)", bundle["class_uid"])
	}
	if bundle["class_name"].(string) != "Detection Finding" {
		t.Errorf("class_name = %v", bundle["class_name"])
	}
	if bundle["category_uid"].(float64) != 2 {
		t.Errorf("category_uid = %v; want 2 (Findings)", bundle["category_uid"])
	}
	fi, _ := bundle["finding_info"].(map[string]any)
	if fi == nil {
		t.Fatal("finding_info missing")
	}
	if uid, _ := fi["uid"].(string); uid == "" {
		t.Errorf("finding_info.uid empty")
	}
	unmapped, _ := bundle["unmapped"].(map[string]any)
	if unmapped == nil {
		t.Fatal("unmapped missing")
	}
	jit, _ := unmapped["iam_jit"].(map[string]any)
	if jit == nil {
		t.Fatal("unmapped.iam_jit missing")
	}
	if jit["events_count"].(float64) != 1 {
		t.Errorf("events_count = %v; want 1", jit["events_count"])
	}
	findings, _ := jit["findings"].([]any)
	if len(findings) != 1 {
		t.Errorf("findings len = %d; want 1", len(findings))
	}
}

func TestExport_OCSFBundle_RedactsTokens(t *testing.T) {
	const sentinel = "ocsf-sentinel-99"
	ev := mkEvent("GET", "/v1/x?token="+sentinel, "api.example.com", 200)
	var buf bytes.Buffer
	if err := Export(&buf, []Event{ev}, ExportOptions{Format: ExportFormatOCSFBundle}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte(sentinel)) {
		t.Errorf("ocsf-bundle export leaked sentinel %q:\n%s", sentinel, buf.String())
	}
}

func TestExport_OCSFBundle_MaxSeverityWins(t *testing.T) {
	low := mkEvent("GET", "/x", "h", 200)
	high := mkEvent("GET", "/y", "h", 200)
	high.SeverityID = SeverityHigh
	high.Severity = "High"

	var buf bytes.Buffer
	if err := Export(&buf, []Event{low, high}, ExportOptions{Format: ExportFormatOCSFBundle}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	var bundle map[string]any
	_ = json.Unmarshal(buf.Bytes(), &bundle)
	if bundle["severity_id"].(float64) != float64(SeverityHigh) {
		t.Errorf("bundle severity_id = %v; want %d (High)", bundle["severity_id"], SeverityHigh)
	}
}

func TestExport_EmptyEventsList(t *testing.T) {
	var buf bytes.Buffer
	if err := Export(&buf, nil, ExportOptions{Format: ExportFormatJSONL}); err != nil {
		t.Errorf("jsonl empty: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("empty jsonl should be 0 bytes; got %d", buf.Len())
	}
	buf.Reset()
	if err := Export(&buf, nil, ExportOptions{Format: ExportFormatCSV}); err != nil {
		t.Errorf("csv empty: %v", err)
	}
	// CSV: header only.
	if !strings.Contains(buf.String(), "timestamp") {
		t.Errorf("empty csv missing header: %q", buf.String())
	}
}

func TestExport_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Export(&buf, nil, ExportOptions{Format: "yaml"}); err == nil {
		t.Error("expected error on unknown format")
	}
}
