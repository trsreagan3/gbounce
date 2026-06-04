// cross_events.go — the cross-bouncer aggregator data endpoint.
//
// GET /cross/events fans out to every bouncer's mgmt /audit/events (ibounce,
// kbounce, dbounce, gbounce), merges the OCSF events into one time-ordered
// stream, and returns a compact projection plus an honest per-bouncer coverage
// map. This is the data behind the cross-bouncer dashboard — gbounce as the
// read-only suite anchor (founder decision 2026-06-04): it only READS each
// bouncer's own mgmt endpoint, never controls another bouncer.
//
// Query params:
//   - since   short-form (5m/1h/2d) or ISO-8601; default 15m
//   - limit   per-bouncer cap; default 200
//   - session when set, filters to one agent session (the cross-bouncer
//     correlation key) — the dashboard's per-session drill-down
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

// crossEventView is the compact per-event projection sent to the dashboard.
type crossEventView struct {
	Time      string   `json:"time"`
	Bouncer   string   `json:"bouncer"`
	Protocol  string   `json:"protocol"`
	Verdict   string   `json:"verdict"`
	Action    string   `json:"action"`
	Principal string   `json:"principal,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// crossEventsResponse is the /cross/events body.
type crossEventsResponse struct {
	Events   []crossEventView  `json:"events"`
	Coverage map[string]string `json:"coverage"` // bouncer -> "" (reachable) | error
	Partial  bool              `json:"partial"`  // true iff any bouncer was unreachable
}

// crossEventsQuerier is the seam the test injects a fake fan-out through.
type crossEventsQuerier interface {
	QueryEvents(ctx context.Context, eps []crossbouncer.Endpoint, opts crossbouncer.QueryOptions) ([]crossbouncer.Event, map[string]string)
	FetchSessionEvents(ctx context.Context, sessionID string, eps []crossbouncer.Endpoint, opts crossbouncer.QueryOptions) ([]crossbouncer.Event, map[string]string)
}

// crossEventsHandler builds the GET /cross/events handler. token is forwarded
// to each bouncer's /audit/events (shared-token deployments); endpoints is the
// fan-out set; q is the querier (nil → a real one).
func crossEventsHandler(token string, endpoints []crossbouncer.Endpoint, q crossEventsQuerier) http.HandlerFunc {
	if q == nil {
		q = crossbouncer.NewQuerier()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAuditError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		// Incoming auth parity with /audit/events: gate when a token is
		// configured (external bind); no-op on loopback (token == "").
		if token != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeAuditError(w, http.StatusUnauthorized, "Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearer(ah)
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(token)) != 1 {
				writeAuditError(w, http.StatusForbidden, "bearer token rejected")
				return
			}
		}
		qs := r.URL.Query()
		since := qs.Get("since")
		if since == "" {
			since = "15m"
		}
		limit := 200
		if v := qs.Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		opts := crossbouncer.QueryOptions{Since: since, Limit: limit, Token: token, Timeout: 5 * time.Second}

		var events []crossbouncer.Event
		var notes map[string]string
		if session := qs.Get("session"); session != "" {
			events, notes = q.FetchSessionEvents(r.Context(), session, endpoints, opts)
		} else {
			events, notes = q.QueryEvents(r.Context(), endpoints, opts)
		}

		resp := crossEventsResponse{
			Events:   make([]crossEventView, 0, len(events)),
			Coverage: notes,
		}
		for _, ev := range events {
			resp.Events = append(resp.Events, crossEventView{
				Time:      ev.TimeISO(),
				Bouncer:   ev.Bouncer(),
				Protocol:  crossbouncer.ProtocolFor(ev.Bouncer()),
				Verdict:   ev.Verdict(),
				Action:    ev.Action(),
				Principal: ev.Principal(),
				Resources: ev.Resources(),
				Reason:    ev.Reason(),
			})
		}
		for _, note := range notes {
			if note != "" {
				resp.Partial = true
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
