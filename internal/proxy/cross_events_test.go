package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

// fakeBouncer serves a canned /audit/events NDJSON response.
func fakeBouncer(t *testing.T, lines ...string) *httptest.Server {
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

func TestCrossEventsHandler_MergesProjectsAndReportsCoverage(t *testing.T) {
	// Two reachable fake bouncers + one unreachable, exercising the real
	// crossbouncer.Querier fan-out through the handler.
	ib := fakeBouncer(t, `{"time":2000,"api":{"operation":"s3:DeleteBucket"},"unmapped":{"iam_jit":{"verdict":"deny","deny_reason":"too risky"}}}`)
	gb := fakeBouncer(t, `{"time":1000,"dst_endpoint":{"hostname":"api.github.com"},"unmapped":{"iam_jit":{"verdict":"allow"}}}`)

	endpoints := []crossbouncer.Endpoint{
		{Name: "ibounce", MgmtURL: ib.URL},
		{Name: "gbounce", MgmtURL: gb.URL},
		{Name: "dbounce", MgmtURL: "http://127.0.0.1:1"}, // unreachable
	}

	h := crossEventsHandler("", endpoints, crossbouncer.NewQuerier())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/cross/events?since=1h&limit=50", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp crossEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Merged + time-sorted: gbounce(1000) before ibounce(2000).
	if len(resp.Events) != 2 {
		t.Fatalf("got %d events; want 2", len(resp.Events))
	}
	if resp.Events[0].Bouncer != "gbounce" || resp.Events[1].Bouncer != "ibounce" {
		t.Errorf("not time-sorted: %s,%s", resp.Events[0].Bouncer, resp.Events[1].Bouncer)
	}
	// Projection: protocol mapping + verdict + deny reason.
	if resp.Events[1].Protocol != "AWS" || resp.Events[1].Verdict != "deny" || resp.Events[1].Reason != "too risky" {
		t.Errorf("ibounce projection wrong: %+v", resp.Events[1])
	}
	if resp.Events[0].Protocol != "HTTP" || resp.Events[0].Verdict != "allow" {
		t.Errorf("gbounce projection wrong: %+v", resp.Events[0])
	}
	// Coverage: dbounce unreachable -> partial + a note.
	if !resp.Partial {
		t.Errorf("expected partial=true (dbounce unreachable)")
	}
	if resp.Coverage["dbounce"] == "" {
		t.Errorf("dbounce should have a non-empty coverage note")
	}
	if resp.Coverage["ibounce"] != "" || resp.Coverage["gbounce"] != "" {
		t.Errorf("reachable bouncers should have empty notes: %v", resp.Coverage)
	}
}

func TestCrossEventsHandler_RejectsNonGET(t *testing.T) {
	h := crossEventsHandler("", crossbouncer.DefaultEndpoints(false), crossbouncer.NewQuerier())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/cross/events", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST should be 405; got %d", rec.Code)
	}
}
