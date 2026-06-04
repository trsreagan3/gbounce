package crossbouncer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolveEndpoints_DefaultsAndOverrides(t *testing.T) {
	// Empty -> all four default bouncers, no serve.
	eps, skipped := ResolveEndpoints(nil, false)
	if len(eps) != 4 || len(skipped) != 0 {
		t.Fatalf("default set = %d eps, %d skipped; want 4,0", len(eps), len(skipped))
	}

	// Named + comma-split + explicit override + kbouncer alias dedup.
	eps, skipped = ResolveEndpoints([]string{"ibounce,gbounce=http://1.2.3.4:9", "kbouncer", "kbounce"}, false)
	if len(skipped) != 0 {
		t.Fatalf("unexpected skipped: %v", skipped)
	}
	byName := map[string]string{}
	for _, e := range eps {
		byName[e.Name] = e.MgmtURL
	}
	if byName["gbounce"] != "http://1.2.3.4:9" {
		t.Errorf("override lost: %v", byName)
	}
	if _, ok := byName["kbounce"]; !ok {
		t.Errorf("kbouncer should canonicalize to kbounce: %v", byName)
	}
	if len(eps) != 3 { // ibounce, gbounce, kbounce (kbouncer deduped)
		t.Errorf("kbouncer/kbounce should dedup to one; got %d: %v", len(eps), byName)
	}

	// Unknown bare name -> skipped.
	_, skipped = ResolveEndpoints([]string{"nope"}, false)
	if len(skipped) != 1 || skipped[0] != "nope" {
		t.Errorf("unknown name should be skipped; got %v", skipped)
	}
}

func TestEvent_Accessors(t *testing.T) {
	raw := map[string]any{
		"_bouncer":   "ibounce",
		"time":       float64(1780539055512),
		"class_name": "API Activity",
		"api":        map[string]any{"operation": "s3:GetObject"},
		"actor":      map[string]any{"user": map[string]any{"uid": "arn:aws:iam::1:role/r"}},
		"resources":  []any{map[string]any{"uid": "arn:aws:s3:::b/k"}},
		"unmapped": map[string]any{
			"iam_jit": map[string]any{
				"verdict":     "DENY",
				"deny_reason": "scored too risky",
				"agent":       map[string]any{"session_id": "sess-1"},
				"mfa_present": true,
			},
		},
	}
	e := Event{Raw: raw}
	if e.Bouncer() != "ibounce" {
		t.Errorf("Bouncer=%q", e.Bouncer())
	}
	if ms, ok := e.TimeMS(); !ok || ms != 1780539055512 {
		t.Errorf("TimeMS=%d ok=%v", ms, ok)
	}
	if e.Verdict() != "deny" {
		t.Errorf("Verdict=%q want deny", e.Verdict())
	}
	if e.Action() != "s3:GetObject" {
		t.Errorf("Action=%q", e.Action())
	}
	if e.SessionID() != "sess-1" {
		t.Errorf("SessionID=%q", e.SessionID())
	}
	if e.Reason() != "scored too risky" {
		t.Errorf("Reason=%q", e.Reason())
	}
	if !e.MFAGated() {
		t.Errorf("MFAGated=false want true")
	}
	if rs := e.Resources(); len(rs) != 1 || rs[0] != "arn:aws:s3:::b/k" {
		t.Errorf("Resources=%v", rs)
	}
	if e.Principal() != "arn:aws:iam::1:role/r" {
		t.Errorf("Principal=%q", e.Principal())
	}
}

func TestEvent_TimeMS_ISOString(t *testing.T) {
	e := Event{Raw: map[string]any{"time": "2026-06-04T01:30:55Z"}}
	ms, ok := e.TimeMS()
	if !ok {
		t.Fatalf("ISO time not parsed")
	}
	want := time.Date(2026, 6, 4, 1, 30, 55, 0, time.UTC).UnixMilli()
	if ms != want {
		t.Errorf("TimeMS=%d want %d", ms, want)
	}
	// No timestamp -> ok=false.
	if _, ok := (Event{Raw: map[string]any{}}).TimeMS(); ok {
		t.Errorf("missing time should report ok=false")
	}
}

func TestQuerier_FanOut_MergesStampsSorts(t *testing.T) {
	// Two fake bouncers; one returns events out of order, one is down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/x-ndjson" {
			t.Errorf("missing ndjson Accept header")
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		// later event first, to prove server-side sort
		fmt.Fprintln(w, `{"time":2000,"unmapped":{"iam_jit":{"verdict":"allow"}}}`)
		fmt.Fprintln(w, `{"time":1000,"unmapped":{"iam_jit":{"verdict":"deny"}}}`)
		fmt.Fprintln(w, ``)          // blank line tolerated
		fmt.Fprintln(w, `{bad json`) // malformed tolerated
	}))
	defer srv.Close()

	eps := []Endpoint{
		{Name: "gbounce", MgmtURL: srv.URL},
		{Name: "dbounce", MgmtURL: "http://127.0.0.1:1"}, // unreachable
	}
	q := NewQuerier()
	evs, notes := q.QueryEvents(context.Background(), eps, QueryOptions{Limit: 10, Timeout: time.Second})

	if len(evs) != 2 {
		t.Fatalf("got %d events; want 2", len(evs))
	}
	if ms, _ := evs[0].TimeMS(); ms != 1000 {
		t.Errorf("events not sorted ascending: first=%d", ms)
	}
	if evs[0].Bouncer() != "gbounce" {
		t.Errorf("_bouncer not stamped: %q", evs[0].Bouncer())
	}
	if notes["gbounce"] != "" {
		t.Errorf("reachable bouncer should have empty note; got %q", notes["gbounce"])
	}
	if notes["dbounce"] == "" {
		t.Errorf("unreachable bouncer should have a note")
	}
}

func TestQuerier_ExpandWindow(t *testing.T) {
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	q := &Querier{HTTP: &http.Client{}, now: func() time.Time { return fixed }}
	cases := map[string]time.Time{
		"5m": fixed.Add(-5 * time.Minute),
		"2h": fixed.Add(-2 * time.Hour),
		"3d": fixed.AddDate(0, 0, -3),
		"1w": fixed.AddDate(0, 0, -7),
		"6M": fixed.AddDate(0, -6, 0),
		"2y": fixed.AddDate(-2, 0, 0),
	}
	for spec, want := range cases {
		got, err := q.expandWindow(spec)
		if err != nil || !got.Equal(want) {
			t.Errorf("expandWindow(%q)=%v,%v want %v", spec, got, err, want)
		}
	}
	if _, err := q.expandWindow("garbage"); err == nil {
		t.Errorf("garbage spec should error")
	}
	// ISO absolute passes through.
	if got, err := q.expandWindow("2026-01-02T03:04:05Z"); err != nil || got.Year() != 2026 {
		t.Errorf("ISO parse failed: %v %v", got, err)
	}
}
