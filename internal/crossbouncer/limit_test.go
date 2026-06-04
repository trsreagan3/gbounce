package crossbouncer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestQuerier_ClampsLimitToBouncerMax is the regression for the dogfood bug:
// a per-bouncer limit above the bouncers' /audit/events cap (1000) made every
// bouncer reject the request with HTTP 400 → zero events. The querier must
// clamp the limit it sends.
func TestQuerier_ClampsLimitToBouncerMax(t *testing.T) {
	var sawLimit atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawLimit.Store(r.URL.Query().Get("limit"))
		w.Header().Set("Content-Type", "application/x-ndjson")
	}))
	defer srv.Close()

	q := NewQuerier()
	_, notes := q.QueryEvents(context.Background(),
		[]Endpoint{{Name: "gbounce", MgmtURL: srv.URL}},
		QueryOptions{Limit: 5000, Timeout: time.Second})

	if got := sawLimit.Load(); got != "1000" {
		t.Errorf("limit sent to bouncer = %v; want clamped to 1000", got)
	}
	if notes["gbounce"] != "" {
		t.Errorf("reachable bouncer should have empty note; got %q", notes["gbounce"])
	}
}
