// Tests for `gbounce session list / show / export / purge` (#285).
//
// The subcommand surface is read-only over per-session NDJSON files
// written by the proxy. These tests seed a temp recordings dir via the
// audit.SessionRecorder helpers (the same path the proxy uses) and
// exercise each subcommand end-to-end.
//
// Cross-product parity: same test coverage axes (list, show, export,
// purge, dry-run, retention parser, file mode) as the kbouncer +
// dbounce + ibounce session test files per
// [[cross-product-agent-parity]] so regressions in any one product
// surface against the same checklist.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
)

const (
	sessionIDA = "01956c44-c5c1-7c31-9bca-7c0aaa000001"
	sessionIDB = "01956c44-c5c1-7c31-9bca-7c0aaa000099"
)

// makeRecorderEvent fabricates a gbounce audit event with the agent
// session_id wired through the Ext map the recorder reads. Mirrors the
// gbounce recorder_test.go pattern.
func makeRecorderEvent(sid, agentName string) audit.Event {
	return audit.FromRequest(audit.RequestInput{
		At:             time.Now().UTC(),
		Method:         "GET",
		Path:           "/v1/dashboards",
		UpstreamHost:   "api.example.com",
		UpstreamPort:   443,
		UpstreamScheme: "https",
		HTTPStatus:     200,
		AgentSessionID: sid,
		AgentName:      agentName,
	})
}

// seedSessionsDir writes two completed recordings into a fresh temp
// dir and returns its path.
func seedSessionsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	r, err := audit.NewSessionRecorder(audit.SessionRecorderOptions{
		Dir:            dir,
		BouncerProduct: "gbounce",
	})
	if err != nil {
		t.Fatalf("NewSessionRecorder: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.Record(makeRecorderEvent(sessionIDA, "claude-code"))
	r.Record(makeRecorderEvent(sessionIDB, "cursor"))
	r.Stop()
	return dir
}

func runSessionCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestSessionList_ShowsSeededSessions(t *testing.T) {
	dir := seedSessionsDir(t)
	out, err := runSessionCmd(t, "list", "--dir", dir)
	if err != nil {
		t.Fatalf("session list: %v\n%s", err, out)
	}
	for _, want := range []string{sessionIDA, sessionIDB, "claude-code", "cursor", "EVENTS"} {
		if !strings.Contains(out, want) {
			t.Errorf("session list output missing %q\ngot:\n%s", want, out)
		}
	}
}

func TestSessionList_EmptyDir_ShowsNothing(t *testing.T) {
	dir := t.TempDir()
	out, err := runSessionCmd(t, "list", "--dir", dir)
	if err != nil {
		t.Fatalf("session list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no recordings in") {
		t.Errorf("empty-dir output missing 'no recordings in'; got:\n%s", out)
	}
	if strings.Contains(out, sessionIDA) {
		t.Errorf("empty dir leaked session id; got:\n%s", out)
	}
}

func TestSessionShow_BadID_CleanError(t *testing.T) {
	dir := t.TempDir()
	_, err := runSessionCmd(t, "show", "../../etc/passwd", "--dir", dir)
	if err == nil {
		t.Fatal("session show with bad id must error")
	}
	if !strings.Contains(err.Error(), "invalid session_id") {
		t.Errorf("error should mention invalid session_id; got %q", err.Error())
	}
}

func TestSessionShow_PrintsSummary(t *testing.T) {
	dir := seedSessionsDir(t)
	out, err := runSessionCmd(t, "show", sessionIDA, "--dir", dir)
	if err != nil {
		t.Fatalf("session show: %v\n%s", err, out)
	}
	for _, want := range []string{sessionIDA, "claude-code", "gbounce"} {
		if !strings.Contains(out, want) {
			t.Errorf("session show missing %q\ngot:\n%s", want, out)
		}
	}
}

func TestSessionExport_ProducesOCSFDetectionFinding(t *testing.T) {
	dir := seedSessionsDir(t)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "finding.json")
	_, err := runSessionCmd(t, "export", sessionIDA, "--dir", dir, "--out", outPath)
	if err != nil {
		t.Fatalf("session export: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("OCSF export file mode = %o; want 0o600", info.Mode().Perm())
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var finding map[string]any
	if err := json.Unmarshal(raw, &finding); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	encoded, _ := json.Marshal(finding)
	if !strings.Contains(string(encoded), sessionIDA) {
		t.Errorf("finding missing session id %q\n%s", sessionIDA, string(encoded))
	}
}

func TestSessionExport_RequiresOut(t *testing.T) {
	dir := seedSessionsDir(t)
	_, err := runSessionCmd(t, "export", sessionIDA, "--dir", dir)
	if err == nil {
		t.Fatal("session export without --out must error")
	}
	if !strings.Contains(err.Error(), "--out is required") {
		t.Errorf("error missing '--out is required'; got %q", err.Error())
	}
}

func TestSessionPurge_OlderThanRemovesOnlyOld(t *testing.T) {
	dir := seedSessionsDir(t)
	oldPath := filepath.Join(dir, sessionIDA+".ndjson")
	freshPath := filepath.Join(dir, sessionIDB+".ndjson")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldPath, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	out, err := runSessionCmd(t, "purge", "--dir", dir, "--older-than", "1h")
	if err != nil {
		t.Fatalf("session purge: %v\n%s", err, out)
	}
	if !strings.Contains(out, "removed 1 recording") {
		t.Errorf("purge output missing 'removed 1 recording'; got:\n%s", out)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("old recording should be gone; stat err=%v", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Errorf("fresh recording should survive; stat err=%v", err)
	}
}

func TestSessionPurge_DryRunListsWithoutDeleting(t *testing.T) {
	dir := seedSessionsDir(t)
	oldPath := filepath.Join(dir, sessionIDA+".ndjson")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldPath, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	out, err := runSessionCmd(t, "purge", "--dir", dir, "--older-than", "1h", "--dry-run")
	if err != nil {
		t.Fatalf("session purge --dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "would remove 1 recording") {
		t.Errorf("dry-run missing 'would remove 1 recording'; got:\n%s", out)
	}
	if !strings.Contains(out, sessionIDA) {
		t.Errorf("dry-run missing session id; got:\n%s", out)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Errorf("--dry-run must not delete; stat err=%v", err)
	}
}

func TestSessionPurge_RequiresOlderThan(t *testing.T) {
	dir := t.TempDir()
	_, err := runSessionCmd(t, "purge", "--dir", dir)
	if err == nil {
		t.Fatal("session purge without --older-than must error")
	}
	if !strings.Contains(err.Error(), "--older-than is required") {
		t.Errorf("error missing '--older-than is required'; got %q", err.Error())
	}
}

func TestParseRetention_AcceptsSMHD(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"15m", 15 * time.Minute},
		{"2h", 2 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
	}
	for _, c := range cases {
		got, err := parseRetention(c.in)
		if err != nil {
			t.Errorf("parseRetention(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseRetention(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestParseRetention_RejectsBadInput(t *testing.T) {
	bad := []string{"", "30", "abc", "0d", "-1h", "30x"}
	for _, b := range bad {
		if _, err := parseRetention(b); err == nil {
			t.Errorf("parseRetention(%q) should error", b)
		}
	}
}

func TestSessionRecordingsFileMode_IsOwnerOnly(t *testing.T) {
	dir := seedSessionsDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("recording %s mode = %o; want 0o600",
				e.Name(), info.Mode().Perm())
		}
		count++
	}
	if count < 2 {
		t.Errorf("expected at least 2 recordings, got %d", count)
	}
}

// TestFromRequest_PopulatesAgentExt verifies the audit.FromRequest
// builder writes agent_session_id / agent_name into the Ext map the
// SessionRecorder reads. Locks the wire shape so a future event-schema
// change can't silently drop session routing.
func TestFromRequest_PopulatesAgentExt(t *testing.T) {
	ev := audit.FromRequest(audit.RequestInput{
		Method:         "GET",
		Path:           "/x",
		UpstreamHost:   "api.example.com",
		HTTPStatus:     200,
		AgentSessionID: sessionIDA,
		AgentName:      "claude-code",
	})
	if ev.Unmapped.IAMJIT.Ext == nil {
		t.Fatal("Ext map missing")
	}
	if got := ev.Unmapped.IAMJIT.Ext[audit.AgentSessionIDExtKey]; got != sessionIDA {
		t.Errorf("Ext[agent_session_id] = %v; want %q", got, sessionIDA)
	}
	if got := ev.Unmapped.IAMJIT.Ext[audit.AgentNameExtKey]; got != "claude-code" {
		t.Errorf("Ext[agent_name] = %v; want claude-code", got)
	}
	if got := audit.ExtractSessionID(ev); got != sessionIDA {
		t.Errorf("ExtractSessionID = %q; want %q", got, sessionIDA)
	}
}

// TestFromRequest_RejectsInvalidSessionID — defensive belt-and-suspenders
// alongside the recorder's IsValidSessionID gate; a bad session id at
// the request edge MUST be dropped before it lands in the Ext map (so
// the recorder never sees a path-traversal-shaped value).
func TestFromRequest_RejectsInvalidSessionID(t *testing.T) {
	ev := audit.FromRequest(audit.RequestInput{
		Method:         "GET",
		Path:           "/x",
		HTTPStatus:     200,
		AgentSessionID: "../../etc/passwd",
	})
	if ev.Unmapped.IAMJIT.Ext != nil {
		if _, present := ev.Unmapped.IAMJIT.Ext[audit.AgentSessionIDExtKey]; present {
			t.Error("invalid session id must not land in Ext")
		}
	}
}
