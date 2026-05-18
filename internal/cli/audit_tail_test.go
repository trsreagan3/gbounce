package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/store"
)

// seedDecisions opens the store at dir/state.db and inserts the given
// rows. Returns the DB path for the CLI to consume.
func seedDecisions(t *testing.T, rows []store.DecisionRow) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.RecordDecision(r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	return dbPath
}

func TestAuditTail_FollowAndSummaryClash(t *testing.T) {
	dbPath := seedDecisions(t, nil)
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--follow", "--summary"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected --follow and --summary to be mutually exclusive")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v", err)
	}
}

func TestAuditTail_ExportRequiresOut(t *testing.T) {
	dbPath := seedDecisions(t, nil)
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--export", "jsonl"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "--out") {
		t.Errorf("expected --out required error; got %v", err)
	}
}

func TestAuditTail_OutRequiresExport(t *testing.T) {
	dbPath := seedDecisions(t, nil)
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--out", "/tmp/x"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "--export") {
		t.Errorf("expected --export required error; got %v", err)
	}
}

func TestAuditTail_FollowAndExportClash(t *testing.T) {
	dbPath := seedDecisions(t, nil)
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--follow", "--export", "jsonl", "--out", "/tmp/x"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually exclusive error; got %v", err)
	}
}

func TestAuditTail_FilterGbounceSpecificFields(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https", UpstreamPort: 443},
		{At: now.Add(time.Second), Method: "POST", Path: "/v1/y", UpstreamHost: "api.example.com", HTTPStatus: 500, UpstreamScheme: "https", UpstreamPort: 443},
		{At: now.Add(2 * time.Second), Method: "GET", Path: "/v1/z", UpstreamHost: "other.example", HTTPStatus: 404, UpstreamScheme: "https", UpstreamPort: 443},
	}
	dbPath := seedDecisions(t, rows)

	// upstream_host filter narrows to two rows; --filter method=GET
	// narrows further to one.
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--filter", "upstream_host=api.example.com",
		"--filter", "method=GET",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "/v1/x") {
		t.Errorf("expected /v1/x in output: %q", out)
	}
	if strings.Contains(out, "/v1/y") || strings.Contains(out, "/v1/z") {
		t.Errorf("filter should have excluded other rows: %q", out)
	}

	// http_status >= 400 narrows to two rows (POST 500, GET 404).
	root2 := newRootCmd()
	buf2 := &bytes.Buffer{}
	root2.SetOut(buf2)
	root2.SetErr(buf2)
	root2.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--filter", "http_status>=400",
	})
	if err := root2.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out2 := buf2.String()
	if !strings.Contains(out2, "/v1/y") || !strings.Contains(out2, "/v1/z") {
		t.Errorf("http_status>=400 missed rows: %q", out2)
	}
	if strings.Contains(out2, "/v1/x") {
		t.Errorf("http_status>=400 should have excluded /v1/x: %q", out2)
	}
}

func TestAuditTail_FilterRegex(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/users/42", UpstreamHost: "h", HTTPStatus: 200, UpstreamScheme: "https"},
		{At: now.Add(time.Second), Method: "GET", Path: "/v1/orders/9", UpstreamHost: "h", HTTPStatus: 200, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--filter", "api.operation~/v1/users/",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "/v1/users/42") {
		t.Errorf("regex missed users row: %q", out)
	}
	if strings.Contains(out, "/v1/orders/9") {
		t.Errorf("regex over-matched orders row: %q", out)
	}
}

func TestAuditTail_SummaryCorrectCounts(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/a", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https"},
		{At: now.Add(time.Second), Method: "GET", Path: "/b", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https"},
		{At: now.Add(2 * time.Second), Method: "POST", Path: "/c", UpstreamHost: "api.example.com", HTTPStatus: 500, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--summary"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Total events: 3") {
		t.Errorf("missing total: %q", out)
	}
	// Gbounce-specific groupings must appear in summary output.
	for _, marker := range []string{
		"By upstream_host:",
		"By method:",
		"By http_status:",
		"By upstream_host+method+http_status:",
		"api.example.com",
		"GET",
		"POST",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("summary missing %q in output:\n%s", marker, out)
		}
	}
}

func TestAuditTail_SummaryEmptyZeroCounts(t *testing.T) {
	dbPath := seedDecisions(t, nil)
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--summary"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "Total events: 0") {
		t.Errorf("empty summary missing zero total: %q", buf.String())
	}
}

func TestAuditTail_ExportJSONL_Roundtrip(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)
	outPath := filepath.Join(t.TempDir(), "out.jsonl")

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--export", "jsonl",
		"--out", outPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Roundtrip per `jq` contract: every line is a valid JSON object.
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestAuditTail_ExportCSV_ParsesCleanly(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)
	outPath := filepath.Join(t.TempDir(), "out.csv")

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--export", "csv",
		"--out", outPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	r := csv.NewReader(bytes.NewReader(data))
	got, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("rows = %d; want 2 (header + 1 event)", len(got))
	}
}

// TestAuditTail_ExportCSV_RedactsSentinelToken is the end-to-end
// load-bearing sentinel test per [[investigate-with-claude]]. Seed an
// audit row whose path includes `?token=sentinel-XYZ`; run `audit tail
// --export csv`; assert the sentinel never appears in the file bytes.
func TestAuditTail_ExportCSV_RedactsSentinelToken(t *testing.T) {
	const sentinel = "sentinel-XYZ"
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{
			At:             now,
			Method:         "GET",
			Path:           "/v1/secret?token=" + sentinel,
			UpstreamHost:   "api.example.com",
			HTTPStatus:     200,
			UpstreamScheme: "https",
		},
	}
	dbPath := seedDecisions(t, rows)
	outPath := filepath.Join(t.TempDir(), "out.csv")

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--export", "csv",
		"--out", outPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte(sentinel)) {
		t.Errorf("CSV export leaked sentinel %q:\n%s", sentinel, data)
	}
	if !bytes.Contains(data, []byte("token=REDACTED")) {
		t.Errorf("CSV export missing redaction placeholder:\n%s", data)
	}
}

func TestAuditTail_ExportOCSFBundle_ValidatesAsDetectionFinding(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)
	outPath := filepath.Join(t.TempDir(), "out.json")

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--export", "ocsf-bundle",
		"--out", outPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if bundle["class_uid"].(float64) != 2004 {
		t.Errorf("class_uid = %v; want 2004", bundle["class_uid"])
	}
	if bundle["class_name"] != "Detection Finding" {
		t.Errorf("class_name = %v", bundle["class_name"])
	}
}

func TestAuditTail_ExportOCSFBundle_RedactsTokens(t *testing.T) {
	const sentinel = "ocsf-bundle-sentinel-77"
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x?token=" + sentinel, UpstreamHost: "h", HTTPStatus: 200, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)
	outPath := filepath.Join(t.TempDir(), "bundle.json")

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--export", "ocsf-bundle",
		"--out", outPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte(sentinel)) {
		t.Errorf("ocsf-bundle leaked sentinel: %s", data)
	}
}

func TestAuditTail_FilterPlusExportComposes(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/a", UpstreamHost: "api.example.com", HTTPStatus: 200, UpstreamScheme: "https"},
		{At: now.Add(time.Second), Method: "POST", Path: "/b", UpstreamHost: "api.example.com", HTTPStatus: 500, UpstreamScheme: "https"},
		{At: now.Add(2 * time.Second), Method: "GET", Path: "/c", UpstreamHost: "other.example", HTTPStatus: 200, UpstreamScheme: "https"},
	}
	dbPath := seedDecisions(t, rows)
	outPath := filepath.Join(t.TempDir(), "filtered.csv")

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"audit", "tail",
		"--db", dbPath,
		"--filter", "upstream_host=api.example.com",
		"--filter", "method=GET",
		"--export", "csv",
		"--out", outPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	r := csv.NewReader(bytes.NewReader(data))
	got, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	// Header + 1 row (only /a survives both filters).
	if len(got) != 2 {
		t.Errorf("filtered csv rows = %d; want 2 (header + /a)", len(got))
	}
}

func TestAuditTail_FollowExitsOnSignal(t *testing.T) {
	dbPath := seedDecisions(t, nil)

	// Swap in a context that we control instead of installing real
	// signal handlers. The follow loop blocks on signalCtxFunc;
	// cancelling our ctx makes it return immediately.
	old := signalCtxFunc
	defer func() { signalCtxFunc = old }()
	cancelCh := make(chan struct{})
	signalCtxFunc = func(parent context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		go func() {
			<-cancelCh
			cancel()
		}()
		return ctx, cancel
	}

	// Seed a row AFTER the follow loop starts, so it's actually printed.
	// We run the follow loop in a goroutine, sleep briefly to let it
	// install its cursor, write a new row, give the polling tick a few
	// hundred ms, then cancel.
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", dbPath, "--follow"})

	done := make(chan error, 1)
	go func() {
		done <- root.Execute()
	}()

	// Wait long enough for the follow loop to start + take its initial
	// cursor (currently 0 since the DB is empty).
	time.Sleep(200 * time.Millisecond)

	// Insert a new row; the next poll tick should see it.
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := st.RecordDecision(store.DecisionRow{
		At:             time.Now().UTC(),
		Method:         "GET",
		Path:           "/follow-test",
		UpstreamHost:   "api.example.com",
		HTTPStatus:     200,
		UpstreamScheme: "https",
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	st.Close()

	// Wait for at least one poll tick (500ms) + a buffer.
	time.Sleep(800 * time.Millisecond)

	// Signal cancellation.
	close(cancelCh)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("follow loop returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow loop did not exit after signal")
	}

	out := buf.String()
	if !strings.Contains(out, "/follow-test") {
		t.Errorf("--follow did not print new row: %q", out)
	}
	if !strings.Contains(out, "audit tail --follow") {
		t.Errorf("--follow banner missing: %q", out)
	}
}
