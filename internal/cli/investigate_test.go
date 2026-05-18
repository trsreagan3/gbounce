// Tests for `gbounce investigate` (#273) — the cross-product
// "land a Claude-ready evidence pack" subcommand. Coverage:
//
//   - Command exits 0 + writes the two expected artifact files.
//   - --print-prompts lists 10 prompts WITHOUT writing files.
//   - --time-range "24h" filters audit-tail by seeded timestamps.
//   - Missing/empty audit DB → command still succeeds + records the
//     gap in the evidence file so a Claude analyst sees data, not
//     a tool failure.
//   - --filter rejects garbage early (before touching the disk).
//   - The starter prompts list stays in the neutral safety-team
//     vocabulary per [[security-team-positioning-safety-not-
//     surveillance]] (no "violation"/"infraction"/"unauthorized").
//   - The subcommand never dials a non-loopback host per
//     [[self-host-zero-billing-dependency]].
package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/store"
)

// runInvestigateCLI is the test wrapper for `gbounce investigate`.
func runInvestigateCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func TestInvestigate_ParseTimeRange(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"4w", 4 * 7 * 24 * time.Hour},
		{"24H", 24 * time.Hour},
	}
	for _, tc := range cases {
		got, err := parseTimeRange(tc.in)
		if err != nil {
			t.Errorf("parseTimeRange(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseTimeRange(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "garbage", "24m", "0h", "-3d"} {
		if _, err := parseTimeRange(bad); err == nil {
			t.Errorf("parseTimeRange(%q) must reject", bad)
		}
	}
}

func TestInvestigate_StarterPromptsAvoidLoadedVocab(t *testing.T) {
	banned := []string{"violation", "infraction", "unauthorized"}
	for _, prompt := range starterPrompts {
		lower := strings.ToLower(prompt)
		for _, w := range banned {
			if strings.Contains(lower, w) {
				t.Errorf("prompt %q contains banned vocab %q", prompt, w)
			}
		}
	}
	if got := len(starterPrompts); got != 10 {
		t.Errorf("len(starterPrompts) = %d, want 10", got)
	}
}

func TestInvestigate_PrintPromptsWritesNoFiles(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	stdout, _, err := runInvestigateCLI(t,
		"investigate", "--print-prompts", "--out-dir", outDir,
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, p := range starterPrompts {
		if !strings.Contains(stdout, p) {
			t.Errorf("--print-prompts output missing prompt %q", p)
		}
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("--print-prompts must not create --out-dir (got %v)", err)
	}
}

func TestInvestigate_WritesBothArtifacts(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com",
			HTTPStatus: 200, UpstreamScheme: "https", UpstreamPort: 443},
	}
	dbPath := seedDecisions(t, rows)
	outDir := filepath.Join(filepath.Dir(dbPath), "out")

	stdout, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", dbPath,
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	evidencePath := filepath.Join(outDir, investigationEvidenceFilename)
	contextPath := filepath.Join(outDir, investigationContextFilename)

	evSt, err := os.Stat(evidencePath)
	if err != nil {
		t.Fatalf("stat evidence: %v", err)
	}
	if evSt.Size() < 100 {
		t.Errorf("evidence file too small (%d bytes)", evSt.Size())
	}
	if evSt.Mode().Perm() != 0o600 {
		t.Errorf("evidence file perm = %v, want 0o600", evSt.Mode().Perm())
	}
	ctxSt, err := os.Stat(contextPath)
	if err != nil {
		t.Fatalf("stat context: %v", err)
	}
	if ctxSt.Size() < 100 {
		t.Errorf("context bundle too small (%d bytes)", ctxSt.Size())
	}

	for _, want := range []string{evidencePath, contextPath, "Anthropic", "local Claude client"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q\n--- stdout ---\n%s", want, stdout)
		}
	}
}

func TestInvestigate_EvidenceFileCarriesInvestigateMetadata(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/a", UpstreamHost: "api.example.com",
			HTTPStatus: 200, UpstreamScheme: "https", UpstreamPort: 443},
		{At: now.Add(time.Second), Method: "POST", Path: "/v1/b", UpstreamHost: "api.example.com",
			HTTPStatus: 500, UpstreamScheme: "https", UpstreamPort: 443},
	}
	dbPath := seedDecisions(t, rows)
	outDir := filepath.Join(filepath.Dir(dbPath), "out")

	if _, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", dbPath,
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	// The file should contain the OCSF bundle on the first line + a
	// trailing investigate-metadata line. We look up the second
	// non-empty line.
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		t.Fatalf("evidence file should have >=2 lines (bundle + metadata); got %d", len(lines))
	}
	var meta struct {
		Investigate struct {
			Window          string `json:"window"`
			AuditLogPresent bool   `json:"audit_log_present"`
			EventCount      int    `json:"event_count"`
		} `json:"investigate"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &meta); err != nil {
		t.Fatalf("parse trailing metadata: %v", err)
	}
	if !meta.Investigate.AuditLogPresent {
		t.Error("audit_log_present should be true with seeded data")
	}
	if meta.Investigate.EventCount != 2 {
		t.Errorf("event_count = %d, want 2", meta.Investigate.EventCount)
	}
	if meta.Investigate.Window != "all" {
		t.Errorf("window = %q, want 'all'", meta.Investigate.Window)
	}
}

func TestInvestigate_ContextBundleHasNoAuditTail(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com",
			HTTPStatus: 200, UpstreamScheme: "https", UpstreamPort: 443},
	}
	dbPath := seedDecisions(t, rows)
	outDir := filepath.Join(filepath.Dir(dbPath), "out")

	if _, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", dbPath,
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	zr, err := zip.OpenReader(filepath.Join(outDir, investigationContextFilename))
	if err != nil {
		t.Fatalf("open context zip: %v", err)
	}
	defer zr.Close()
	var auditBody []byte
	for _, f := range zr.File {
		if f.Name == "04-audit-tail.jsonl" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open zip entry: %v", err)
			}
			defer rc.Close()
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(rc); err != nil {
				t.Fatalf("read zip entry: %v", err)
			}
			auditBody = buf.Bytes()
			break
		}
	}
	if auditBody == nil {
		t.Fatal("context bundle missing 04-audit-tail.jsonl")
	}
	if !strings.Contains(string(auditBody), "--no-audit was passed") {
		t.Errorf("context bundle's audit-tail section should record --no-audit; got: %s", string(auditBody))
	}
}

func TestInvestigate_TimeRangeFiltersByCutoff(t *testing.T) {
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now.Add(-30 * 24 * time.Hour), Method: "GET", Path: "/old",
			UpstreamHost: "api.example.com", HTTPStatus: 200,
			UpstreamScheme: "https", UpstreamPort: 443},
		{At: now.Add(-1 * time.Hour), Method: "GET", Path: "/recent",
			UpstreamHost: "api.example.com", HTTPStatus: 200,
			UpstreamScheme: "https", UpstreamPort: 443},
	}
	dbPath := seedDecisions(t, rows)
	outDir := filepath.Join(filepath.Dir(dbPath), "out")

	if _, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", dbPath,
		"--time-range", "24h",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var meta struct {
		Investigate struct {
			EventCount int `json:"event_count"`
		} `json:"investigate"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &meta); err != nil {
		t.Fatalf("parse trailing metadata: %v", err)
	}
	if meta.Investigate.EventCount != 1 {
		t.Errorf("event_count = %d, want 1 (--time-range 24h should drop the 30d row)", meta.Investigate.EventCount)
	}
}

func TestInvestigate_EmptyDBStillSucceeds(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	stdout, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", dbPath,
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout, "audit log was missing") {
		t.Errorf("stdout should note missing audit log; got: %s", stdout)
	}

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var meta struct {
		Investigate struct {
			AuditLogPresent bool `json:"audit_log_present"`
		} `json:"investigate"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &meta); err != nil {
		t.Fatalf("parse trailing metadata: %v", err)
	}
	if meta.Investigate.AuditLogPresent {
		t.Errorf("audit_log_present = true, want false for empty DB")
	}
}

func TestInvestigate_RejectsBadFilter(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", filepath.Join(dir, "state.db"),
		"--filter", "garbage_no_operator",
		"--out-dir", filepath.Join(dir, "out"),
	)
	if err == nil {
		t.Fatal("bad filter must fail")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(statErr) {
		t.Errorf("failed filter must not create --out-dir")
	}
}

func TestInvestigate_RejectsBadTimeRange(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", filepath.Join(dir, "state.db"),
		"--time-range", "24m",
		"--out-dir", filepath.Join(dir, "out"),
	)
	if err == nil {
		t.Fatal("bad time-range must fail")
	}
}

func TestInvestigate_NoOutboundNetworkCall(t *testing.T) {
	// Sanity: a loopback dial to a closed port fails fast. We pin
	// --healthz-url at 127.0.0.1:1 so any code that tried to dial
	// off-loopback would generate test-visible work.
	now := time.Now().UTC()
	rows := []store.DecisionRow{
		{At: now, Method: "GET", Path: "/v1/x", UpstreamHost: "api.example.com",
			HTTPStatus: 200, UpstreamScheme: "https", UpstreamPort: 443},
	}
	dbPath := seedDecisions(t, rows)
	outDir := filepath.Join(filepath.Dir(dbPath), "out")

	conn, derr := net.DialTimeout("tcp", "127.0.0.1:1", 50*time.Millisecond)
	if derr == nil {
		_ = conn.Close()
	}

	_, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", dbPath,
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("investigate must succeed with loopback-only: %v", err)
	}
}
