package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeSessionBouncer serves /audit/events with the given NDJSON lines.
func fakeSessionBouncer(t *testing.T, lines ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFlightRecorderCmd_StitchesSessionAcrossBouncers(t *testing.T) {
	// ibounce: an AWS deny; gbounce: an HTTP allow — same session, out of order.
	ib := fakeSessionBouncer(t, `{"time":2000,"api":{"operation":"s3:DeleteObject"},"unmapped":{"iam_jit":{"verdict":"deny","deny_reason":"prod bucket","agent":{"session_id":"sess-9"}}}}`)
	gb := fakeSessionBouncer(t, `{"time":1000,"dst_endpoint":{"hostname":"api.github.com"},"unmapped":{"iam_jit":{"verdict":"allow","agent":{"session_id":"sess-9"}}}}`)

	cmd := newFlightRecorderCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{
		"--session", "sess-9",
		"--bouncer", "ibounce=" + ib.URL,
		"--bouncer", "gbounce=" + gb.URL,
		"--bouncer", "dbounce=http://127.0.0.1:1", // unreachable -> coverage gap
		"--format", "timeline-json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v (stderr=%s)", err, errb.String())
	}

	var tl map[string]any
	if err := json.Unmarshal(out.Bytes(), &tl); err != nil {
		t.Fatalf("decode timeline: %v\n%s", err, out.String())
	}
	if tl["schema"] != "flight-recorder/1" {
		t.Errorf("schema=%v", tl["schema"])
	}
	steps, _ := tl["steps"].([]any)
	if len(steps) != 2 {
		t.Fatalf("got %d steps; want 2", len(steps))
	}
	// Time-ordered: gbounce(1000) then ibounce(2000).
	s0 := steps[0].(map[string]any)
	s1 := steps[1].(map[string]any)
	if s0["bouncer"] != "gbounce" || s1["bouncer"] != "ibounce" {
		t.Errorf("steps not ordered: %v, %v", s0["bouncer"], s1["bouncer"])
	}
	if s1["protocol"] != "AWS" || s1["decision"] != "deny" {
		t.Errorf("ibounce step projection wrong: %v", s1)
	}
	// Coverage must flag dbounce unreachable.
	cov := tl["coverage"].(map[string]any)
	if cov["partial"] != true {
		t.Errorf("expected partial coverage (dbounce down)")
	}
}

func TestFlightRecorderCmd_RequiresSession(t *testing.T) {
	cmd := newFlightRecorderCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--format", "summary"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("missing --session must error")
	}
}
