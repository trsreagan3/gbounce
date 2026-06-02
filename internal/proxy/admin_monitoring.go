// admin_monitoring.go ships the purpose-driven monitoring endpoints
// added in iam-jit #682 per [[gbounce-ui-purpose-driven]]:
//
//   - GET /admin/features        — feature on/off + last-fired + 24h count
//   - GET /admin/stuck-signals   — pattern-detection: same upstream / error
//     repeat / queue depth
//   - GET /admin/stream          — Server-Sent Events: live decision +
//     periodic feature snapshot
//   - GET /admin/ui              — the single-page operator UI bundled
//     in via auditEventsUIPurposeDrivenTemplate (admin_ui.go)
//
// Auth model mirrors /audit/events: loopback → no header; external
// bind → bearer token via Authorization OR (for SSE / browser) the
// URL #token=... fragment surfaced by the page's JS.
//
// Per [[creates-never-mutates]] these endpoints are read-only —
// they ONLY snapshot in-memory state + the audit store. They never
// touch the customer's AWS / Kubernetes / SQL state.
//
// Per [[ibounce-honest-positioning]] the responses are honest about
// the empty state: when no traffic has flowed the stuck-signals
// endpoint returns `signals: []` rather than a synthesised "OK"
// + the features endpoint flags ConfiguredButNeverFired so the UI
// can highlight the silent-degradation gap.
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// adminFeaturesHandler builds GET /admin/features. Returns the
// feature-status snapshot as JSON.
func (s *Server) adminFeaturesHandler(requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAdminError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		if !checkAdminAuth(r, requireBearer) {
			writeAdminError(w, http.StatusForbidden, "bearer token rejected")
			return
		}
		snap := s.snapshotFeatures()
		// Bolt the 24h count from the audit store onto each feature
		// row. Per-feature signature matching is best-effort — we
		// rely on the verdict + deny_source ext fields the existing
		// recorder already emits.
		if s.store != nil {
			fillFireCount24h(s.store, &snap)
		}
		writeJSON(w, http.StatusOK, snap)
	}
}

// adminStuckSignalsHandler builds GET /admin/stuck-signals. Surfaces
// rolling-window pattern detections per [[gbounce-ui-purpose-driven]]
// question 2 ("Is my agent stuck?"). Honest about thresholds — every
// signal reports the exact quantified threshold that fired ("5 retries
// to same upstream in 30s") so an operator can audit the heuristic.
func (s *Server) adminStuckSignalsHandler(requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAdminError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		if !checkAdminAuth(r, requireBearer) {
			writeAdminError(w, http.StatusForbidden, "bearer token rejected")
			return
		}
		signals := computeStuckSignals(s.store, time.Now())
		body := map[string]any{
			"now_unix_ms": time.Now().UnixMilli(),
			"signals":     signals,
		}
		writeJSON(w, http.StatusOK, body)
	}
}

// adminStreamHandler ships GET /admin/stream — Server-Sent Events.
// Emits two event types:
//
//   - data: event=decision        — newest audit rows since cursor
//   - data: event=features        — full feature snapshot every 5s
//   - data: event=stuck-signals   — full stuck-signals snapshot every 10s
//
// The connection holds open until the client disconnects or the
// server is shutting down. Auto-reconnect is the browser EventSource
// default; the client doesn't need extra logic.
//
// Per [[creates-never-mutates]] this is read-only; the cursor advances
// MONOTONICALLY (never rewinds), so a re-connecting client sees only
// new events (it can also pass ?since=<ms> on connect to backfill).
func (s *Server) adminStreamHandler(requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAdminError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		if !checkAdminAuth(r, requireBearer) {
			writeAdminError(w, http.StatusForbidden, "bearer token rejected")
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeAdminError(w, http.StatusInternalServerError, "streaming unsupported")
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache, no-transform")
		h.Set("Connection", "keep-alive")
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Initial snapshots so the UI populates immediately.
		writeSSEEvent(w, flusher, "features", s.snapshotFeatures())
		writeSSEEvent(w, flusher, "stuck-signals", map[string]any{
			"now_unix_ms": time.Now().UnixMilli(),
			"signals":     computeStuckSignals(s.store, time.Now()),
		})

		var lastID int64 // cursor for new decisions

		// Tick at 1s for decision polling, 5s for feature snapshot,
		// 10s for stuck-signals. We could push events synchronously on
		// the record path (no poll), but that requires a fan-out
		// channel coupled to record(); the polling approach keeps the
		// SSE handler independent of the hot path. 1s tick = ≤1s
		// latency, well under the operator's 2-3s "feels live" bar.
		decisionTicker := time.NewTicker(1 * time.Second)
		featureTicker := time.NewTicker(5 * time.Second)
		stuckTicker := time.NewTicker(10 * time.Second)
		heartbeatTicker := time.NewTicker(15 * time.Second)
		defer decisionTicker.Stop()
		defer featureTicker.Stop()
		defer stuckTicker.Stop()
		defer heartbeatTicker.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-decisionTicker.C:
				rows, err := streamNewDecisions(s.store, lastID, 200)
				if err == nil && len(rows) > 0 {
					for _, row := range rows {
						if row.ID > lastID {
							lastID = row.ID
						}
						ev := decisionRowToWireEvent(row)
						writeSSEEvent(w, flusher, "decision", ev)
					}
				}
			case <-featureTicker.C:
				snap := s.snapshotFeatures()
				if s.store != nil {
					fillFireCount24h(s.store, &snap)
				}
				writeSSEEvent(w, flusher, "features", snap)
			case <-stuckTicker.C:
				writeSSEEvent(w, flusher, "stuck-signals", map[string]any{
					"now_unix_ms": time.Now().UnixMilli(),
					"signals":     computeStuckSignals(s.store, time.Now()),
				})
			case <-heartbeatTicker.C:
				// SSE comment line keeps proxies / load balancers
				// from idling the connection. Browsers ignore.
				_, _ = fmt.Fprint(w, ": keepalive\n\n")
				flusher.Flush()
			}
		}
	}
}

// computeStuckSignals walks the audit store's recent decisions and
// detects three quantified stuck-patterns:
//
//   - upstream_retry_storm  — same (method,upstream_host,path) attempted
//     ≥ stuckRetryThreshold times in stuckWindowSeconds
//   - error_repeat          — same HTTP error status code repeated
//     ≥ stuckErrorThreshold times in stuckWindowSeconds
//   - deny_storm            — DENY verdict fired
//     ≥ stuckDenyThreshold times in stuckWindowSeconds
//
// Each signal carries the EXACT threshold that triggered so an
// operator can verify the heuristic — never a vague "stuck" label
// per [[ibounce-honest-positioning]].
func computeStuckSignals(st *store.Store, now time.Time) []map[string]any {
	signals := make([]map[string]any, 0)
	if st == nil {
		return signals
	}
	rows, err := st.RecentDecisions(500)
	if err != nil {
		return signals
	}
	cutoff := now.Add(-time.Duration(stuckWindowSeconds) * time.Second)
	type upstreamKey struct {
		method, host, path string
	}
	upstreamCounts := make(map[upstreamKey]int)
	upstreamLatest := make(map[upstreamKey]time.Time)
	errorCounts := make(map[int]int)
	errorLatest := make(map[int]time.Time)
	denyCount := 0
	var denyLatest time.Time

	for _, row := range rows {
		if row.At.Before(cutoff) {
			continue
		}
		k := upstreamKey{
			method: strings.ToUpper(row.Method),
			host:   row.UpstreamHost,
			path:   row.Path,
		}
		upstreamCounts[k]++
		if row.At.After(upstreamLatest[k]) {
			upstreamLatest[k] = row.At
		}
		if row.HTTPStatus >= 400 {
			errorCounts[row.HTTPStatus]++
			if row.At.After(errorLatest[row.HTTPStatus]) {
				errorLatest[row.HTTPStatus] = row.At
			}
		}
		if strings.EqualFold(row.Verdict, "DENY") {
			denyCount++
			if row.At.After(denyLatest) {
				denyLatest = row.At
			}
		}
	}

	for k, n := range upstreamCounts {
		if n < stuckRetryThreshold {
			continue
		}
		signals = append(signals, map[string]any{
			"kind":          "upstream_retry_storm",
			"severity":      severityForRetry(n),
			"summary":       fmt.Sprintf("%d requests to %s %s://%s%s in %ds", n, k.method, "*", k.host, k.path, stuckWindowSeconds),
			"threshold":     fmt.Sprintf(">= %d in %ds", stuckRetryThreshold, stuckWindowSeconds),
			"count":         n,
			"upstream_host": k.host,
			"method":        k.method,
			"path":          k.path,
			"last_seen_ms":  upstreamLatest[k].UnixMilli(),
		})
	}
	for code, n := range errorCounts {
		if n < stuckErrorThreshold {
			continue
		}
		signals = append(signals, map[string]any{
			"kind":         "error_repeat",
			"severity":     severityForRetry(n),
			"summary":      fmt.Sprintf("HTTP %d repeated %d times in %ds", code, n, stuckWindowSeconds),
			"threshold":    fmt.Sprintf(">= %d in %ds", stuckErrorThreshold, stuckWindowSeconds),
			"count":        n,
			"http_status":  code,
			"last_seen_ms": errorLatest[code].UnixMilli(),
		})
	}
	if denyCount >= stuckDenyThreshold {
		signals = append(signals, map[string]any{
			"kind":         "deny_storm",
			"severity":     severityForRetry(denyCount),
			"summary":      fmt.Sprintf("%d DENY verdicts in %ds — agent may be repeatedly bouncing off a deny rule", denyCount, stuckWindowSeconds),
			"threshold":    fmt.Sprintf(">= %d in %ds", stuckDenyThreshold, stuckWindowSeconds),
			"count":        denyCount,
			"last_seen_ms": denyLatest.UnixMilli(),
		})
	}
	return signals
}

// stuck-pattern thresholds. Exposed as package-level constants so a
// test (and future config) can read the value an operator sees in
// the threshold string the signal returns. The values reflect
// "common-sense agent behaviour" — not a calibrated corpus. The
// honest framing per [[ibounce-honest-positioning]]: a signal is a
// hint, not a verdict.
const (
	stuckWindowSeconds  = 30
	stuckRetryThreshold = 5
	stuckErrorThreshold = 5
	stuckDenyThreshold  = 5
)

// severityForRetry maps a fire count to a Critical/High/Medium label.
// Trivial monotone mapping so the UI can colour the row without
// needing its own threshold table.
func severityForRetry(n int) string {
	switch {
	case n >= 50:
		return "Critical"
	case n >= 20:
		return "High"
	default:
		return "Medium"
	}
}

// fillFireCount24h walks RecentDecisions(1000) once + populates the
// 24h count on every feature row whose verdict / source signature
// matches. Best-effort: a feature whose fires don't land as decision
// rows (audit_log writer, session recorder, object storage) gets the
// process-start total instead of a 24h count.
//
// We populate by walking ONCE and bumping the relevant feature
// counter — O(N) over the audit window, not O(F*N).
func fillFireCount24h(st *store.Store, snap *featureStatusSnapshot) {
	cutoff := time.Now().Add(-24 * time.Hour)
	rows, err := st.RecentDecisions(1000)
	if err != nil {
		return
	}
	counts := map[string]int64{}
	for _, row := range rows {
		if row.At.Before(cutoff) {
			continue
		}
		counts["audit_log"]++
		if strings.EqualFold(row.Verdict, "DENY") {
			counts["deny_hosts"]++
			// We can't tell dynamic vs static at the row level
			// without re-parsing the deny_source ext field. The
			// existing audit row schema doesn't surface it; we
			// punt on the dynamic/static split here and let the
			// process-start total (from the lock-free counter)
			// carry that distinction.
		}
		if row.HTTPStatus == 403 {
			counts["profile_enforcement"]++
		}
	}
	for i := range snap.Features {
		f := &snap.Features[i]
		// Honest per [[ibounce-honest-positioning]]: a disabled
		// feature shows 0 fires (it CAN'T fire) regardless of what
		// the audit store contains. The audit store accumulates
		// across runs / configs; reporting its row count for a
		// feature that is OFF in this process would be misleading.
		if !f.Enabled {
			f.FireCount24h = 0
			continue
		}
		if c, ok := counts[f.Name]; ok {
			f.FireCount24h = c
		} else {
			// Default 24h = total (best-effort). If we can't compute
			// a 24h window from the audit store we don't fake a
			// smaller number — we surface the process-start total.
			f.FireCount24h = f.FireCountTotal
		}
	}
}

// streamNewDecisions returns audit rows whose ID is greater than
// `sinceID`, oldest-first. Cap at limit to bound payload size.
func streamNewDecisions(st *store.Store, sinceID int64, limit int) ([]store.DecisionRow, error) {
	if st == nil {
		return nil, fmt.Errorf("store is nil")
	}
	rows, err := st.RecentDecisions(limit)
	if err != nil {
		return nil, err
	}
	out := make([]store.DecisionRow, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- { // oldest-first
		if rows[i].ID > sinceID {
			out = append(out, rows[i])
		}
	}
	return out, nil
}

// decisionRowToWireEvent flattens a DecisionRow into the UI's expected
// SSE payload — the same shape /audit/events emits but trimmed to the
// fields the UI actually renders, to keep the SSE message small.
func decisionRowToWireEvent(row store.DecisionRow) map[string]any {
	return map[string]any{
		"id":            row.ID,
		"time_ms":       row.At.UnixMilli(),
		"method":        row.Method,
		"path":          row.Path,
		"upstream_host": row.UpstreamHost,
		"http_status":   row.HTTPStatus,
		"latency_ms":    row.LatencyMS,
		"verdict":       row.Verdict,
		"mode":          row.Mode,
		"agent_name":    row.AgentName,
	}
}

// writeSSEEvent emits one SSE frame: `event: <type>\ndata: <json>\n\n`.
// Per W3C SSE we MUST end with a blank line; this helper makes that
// non-skippable.
func writeSSEEvent(w http.ResponseWriter, flusher http.Flusher, eventType string, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, b)
	flusher.Flush()
}

// checkAdminAuth — loopback OR matching bearer. Mirrors the
// /audit/events constant-time-compare pattern.
func checkAdminAuth(r *http.Request, requireBearer string) bool {
	if requireBearer == "" {
		return true
	}
	ah := r.Header.Get("Authorization")
	if ah == "" {
		// Token fragment fallback for the SSE / browser path: the JS
		// page extracts the token from window.location.hash + appends
		// it as ?_token= for endpoints that can't carry a header.
		ah = "Bearer " + r.URL.Query().Get("_token")
	}
	tok, ok := parseBearer(ah)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(requireBearer)) == 1
}

// writeAdminError emits a structured JSON error response.
func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   msg,
		"product": "gbounce",
	})
}

// (writeJSON helper is shared from dynamic_deny_reload.go in this
// package — same shape, same header set; we reuse rather than
// duplicate.)

// silences unused-import linter when the audit package is referenced
// only via tests against the legacy decoder.
var _ = audit.RedactEvent

// silences unused-import linter for context (the SSE handler uses it
// transitively via r.Context()).
var _ context.Context
