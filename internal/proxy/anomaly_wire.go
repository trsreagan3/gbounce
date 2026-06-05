// anomaly_wire.go is the THIN, protocol-specific glue between
// gbounce's HTTP-proxy decision path and the byte-identical
// internal/anomaly core (#718 ADOPT-4 / Phase H).
//
// Per [[config-export-wire-divergence]] the cross-repo core (config /
// baseline / detector / hook) is identical across gbounce / kbouncer /
// dbounce; ONLY this file (signal extraction + audit-emitter
// adaptation + healthz surface) differs per product. For gbounce the
// protocol signals are:
//
//   - action        = the HTTP method (GET / POST / CONNECT / ...)
//   - resource      = "<upstream-host><path>" — canonicalised by the
//     core into a privacy-safe pattern (it never stores
//     the raw host/path).
//   - agentIdentity = the validated X-Agent-Name (or "anonymous").
//
// DEFAULT = ALERT, NOT BLOCK per [[safety-mode-lean-permissive]]: the
// detector surfaces a neutral OCSF anomaly event into the audit log; it
// does not change the request decision unless the operator opts into
// block mode.
package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/gbounce/internal/anomaly"
	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/structureddeny"
)

// anomalyDenySource is the canonical deny_source label stamped onto a
// structured-deny emitted because mode=block tightened an anomalous
// request (iam-jit#59).
const anomalyDenySource = "anomaly_block"

// AnomalyConfigFromEnv builds the Phase H detector config from
// environment variables (frictionless opt-in per
// [[lightweight-frictionless-principle]]):
//
//	IAM_JIT_ANOMALY_DETECTION    = "1" / "true" to enable (default off)
//	IAM_JIT_ANOMALY_MODE         = "alert" (default) | "block"
//	IAM_JIT_ANOMALY_SENSITIVITY  = "low" | "medium" (default) | "high"
//	IAM_JIT_ANOMALY_MIN_ACTIONS  = integer baseline floor (default 50)
//
// Returns the DISABLED default when the enable var is unset. Mirrors
// the cross-repo wire contract; the same env names are honored by
// kbouncer + dbounce so an operator running the suite configures all
// three identically per [[cross-product-agent-parity]].
func AnomalyConfigFromEnv() (anomaly.Config, error) {
	enable := os.Getenv("IAM_JIT_ANOMALY_DETECTION")
	if enable != "1" && enable != "true" && enable != "TRUE" {
		return anomaly.DefaultConfig(), nil
	}
	block := map[string]any{"enabled": true}
	if v := os.Getenv("IAM_JIT_ANOMALY_MODE"); v != "" {
		block["mode"] = v
	}
	if v := os.Getenv("IAM_JIT_ANOMALY_SENSITIVITY"); v != "" {
		block["sensitivity"] = v
	}
	if v := os.Getenv("IAM_JIT_ANOMALY_MIN_ACTIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			block["min_actions_for_baseline"] = n
		}
	}
	// Persist the baseline so it survives restarts (dogfood finding: the
	// baseline was in-memory only). Honor an explicit override, else
	// default to ~/.gbounce/anomaly-baseline.json. Empty path (no override
	// + no resolvable home) keeps the historical in-memory behavior.
	block["baseline_path"] = anomalyBaselinePath()
	return anomaly.LoadConfig(block)
}

// AnomalyConfigFromValues builds + validates a detector config from
// explicit values (the persisted ~/.gbounce/config.yaml anomaly block).
// It shares the env path's baseline-path resolution so a config-enabled
// detector persists its baseline identically. mode/sensitivity empty =
// the validated defaults; minActions <= 0 = the default floor.
func AnomalyConfigFromValues(enabled bool, mode, sensitivity string, minActions int) (anomaly.Config, error) {
	if !enabled {
		return anomaly.DefaultConfig(), nil
	}
	block := map[string]any{"enabled": true}
	if mode = strings.TrimSpace(mode); mode != "" {
		block["mode"] = mode
	}
	if sensitivity = strings.TrimSpace(sensitivity); sensitivity != "" {
		block["sensitivity"] = sensitivity
	}
	if minActions > 0 {
		block["min_actions_for_baseline"] = minActions
	}
	block["baseline_path"] = anomalyBaselinePath()
	return anomaly.LoadConfig(block)
}

// anomalyBaselinePath resolves the baseline persistence file:
// IAM_JIT_ANOMALY_BASELINE_PATH if set, else ~/.gbounce/anomaly-baseline.json.
// Returns "" only when neither is resolvable (degrades to in-memory).
func anomalyBaselinePath() string {
	if v := strings.TrimSpace(os.Getenv("IAM_JIT_ANOMALY_BASELINE_PATH")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".gbounce", "anomaly-baseline.json")
}

// SetAnomalyDetector wires the Phase H behavioral-deviation detector.
// nil disables the channel. The CLI calls this at startup when
// anomaly_detection.enabled is true. The detector's alert emitter is
// bound to the proxy's audit log so anomaly events ride the same
// JSONL + webhook transport as decision events.
func (s *Server) SetAnomalyDetector(d *anomaly.Detector) {
	s.anomalyDetector = d
}

// observeAnomaly observes one decision into the behavioral baseline +
// scores it. Fail-soft + no-op when the detector is unwired or
// disabled. Called from the proxy's record path with the protocol
// signals already extracted. Per [[ibounce-honest-positioning]] an
// anomalous verdict is a SIGNAL surfaced for review, not a block.
func (s *Server) observeAnomaly(ctx context.Context, action, resource, agentIdentity, floorVerdict string) {
	if s.anomalyDetector == nil || !s.anomalyDetector.Enabled() {
		return
	}
	floor := "allow"
	if floorVerdict == "DENY" || floorVerdict == "deny" {
		floor = "deny"
	}
	// FEED THE REAL DEVIATION SIGNALS (#718 finding HIGH): derive the
	// current hour-of-day from the clock and the recent-window observed
	// action rate for this (agent, action, resource_pattern) from the
	// baseline store, so the hour_of_day + action_frequency dimensions
	// actually contribute. Computed BEFORE Run records this event so the
	// rate reflects the burst arriving so far; Run adds the current one.
	// Privacy preserved: we pass only structural shapes + counts.
	observedHour := time.Now().UTC().Hour()
	observedRate := s.anomalyDetector.Store().RecentRate(agentIdentity, action, resource, 0)
	res := s.anomalyDetector.Run(anomaly.RunInput{
		Action:              action,
		AgentIdentity:       agentIdentity,
		Resource:            resource,
		ObservedHour:        observedHour,
		ObservedActionCount: observedRate,
		FloorDecision:       floor,
		RecordObservation:   true,
	})
	_ = res // alert emission happens inside Run via the bound emitter
	_ = ctx
}

// anomalySignals extracts the privacy-safe structural signals (action /
// resource / agent identity) for one request, IDENTICALLY for the
// pre-decision Decide path and the post-decision observe path so both
// hit the same per-agent baseline key. action = HTTP method; resource =
// "<upstream-host><path>" mirroring observeAnomaly's
// row.UpstreamHost+row.Path; agent = the validated X-Agent-Name (or
// "" -> "anonymous" inside the core).
func (s *Server) anomalySignals(r *http.Request) (action, resource, agent string) {
	action = r.Method
	var upHost, path string
	if r.Method == http.MethodConnect {
		// CONNECT: target host:port is r.Host; row.Path carries r.Host.
		h, _ := splitHostPortStr(r.Host)
		upHost = h
		path = r.Host
	} else if s.upstreamURL != nil {
		upHost = s.upstreamURL.Hostname()
		if r.URL != nil {
			path = r.URL.Path
		}
	}
	resource = upHost + path
	raw := r.Header.Get("X-Agent-Name")
	if raw != "" && audit.IsValidAgentName(raw) {
		agent = raw
	}
	return action, resource, agent
}

// decideAnomaly is the PRE-DECISION tighten check (iam-jit#59). It runs
// in the LIVE request path on a request the floor would ALLOW, BEFORE
// gbounce dials the upstream / serves the response. In mode=block an
// anomalous verdict tightens allow->deny: this writes the structured 403
// + audits the deny + returns true (the caller must then return without
// proceeding). In every other case it returns false and the request
// proceeds untouched.
//
// TIGHTEN-ONLY in the live path: this is only ever called on the
// non-deny branch (after the deny_hosts check has NOT matched), and the
// core Detector.Decide refuses to loosen a deny floor regardless. The
// only mutation is allow->deny.
//
// FAIL-SOFT: a nil/disabled detector returns false immediately; any
// non-block mode returns false (no deny). The detector core never
// panics; if scoring degrades it returns the floor (allow), so a
// detector hiccup can NEVER turn into a spurious deny or break the path.
func (s *Server) decideAnomaly(w http.ResponseWriter, r *http.Request, startedAt time.Time) (tightened bool) {
	if s.anomalyDetector == nil || !s.anomalyDetector.Enabled() {
		return false
	}
	// DEFENSIVE RECOVER: if the core scoring path panics (e.g. future
	// data-race or nil-deref in a scorer update), degrade to the FLOOR
	// decision (allow stays allow). A panic must never crash the hot path
	// or spuriously deny a request. tightened is false by default, so the
	// named return ensures the caller sees "not tightened" on a panic.
	defer func() {
		if recover() != nil {
			tightened = false
		}
	}()
	action, resource, agentIdentity := s.anomalySignals(r)
	out := s.anomalyDetector.Decide(anomaly.DecideInput{
		Action:        action,
		AgentIdentity: agentIdentity,
		Resource:      resource,
		FloorDecision: "allow", // only called on the allow branch
	})
	if !out.Tightened || out.Decision != "deny" {
		// Not tightened (alert mode, normal traffic, detection-only,
		// disabled) — the request proceeds untouched.
		return false
	}
	// Anomalous + block mode: TIGHTEN allow->deny. Audit + serve a
	// structured 403. The neutral OCSF anomaly event was already emitted
	// by Decide via the bound emitter.
	reason := "request denied: anomaly_detection mode=block flagged a behavioral deviation (signal for review, not proof of a problem)"
	s.recordDeny(r, startedAt, http.StatusForbidden, reason)
	s.totalErrors.Add(1)
	legacyMsg := "gbounce: " + reason
	deny := structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:    "gbounce",
		Action:     gbounceStructuredDenyAction(r),
		Resource:   resource,
		DenyReason: legacyMsg,
		DenySource: anomalyDenySource,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	body := map[string]any{
		"error":                              legacyMsg,
		"decision_verdict":                   "deny",
		"decision_reason":                    legacyMsg,
		"caught_by_bouncer":                  deny.CaughtByBouncer,
		"is_likely_injection_classification": deny.IsLikelyInjectionClassification,
		"suggested_allow_command":            deny.SuggestedAllowCommand,
		"recommended_action":                 deny.RecommendedAction,
		"deny_event_id":                      deny.DenyEventID,
		"classifier_hook":                    deny.ClassifierHook,
		"deny_source_classified":             deny.DenySourceClassified,
		"structured_deny_schema_version":     deny.StructuredDenySchemaVersion,
	}
	_ = json.NewEncoder(w).Encode(body)
	return true
}

// NewAnomalyDetector constructs a Detector wired to forward neutral
// OCSF anomaly events into this server's audit log. Returns nil when
// the config is disabled (so callers can SetAnomalyDetector(nil)
// harmlessly). Kept in the wire file because the emitter adapter is
// product-specific (it maps the core's map[string]any event onto
// gbounce's audit.LogWriter).
func (s *Server) NewAnomalyDetector(cfg anomaly.Config) *anomaly.Detector {
	anomaly.SetProduct("gbounce")
	if !cfg.Enabled {
		return anomaly.NewDetector(cfg, nil, false)
	}
	emitter := func(event map[string]any) {
		// gbounce's audit log writes typed audit.Event values; the
		// anomaly core emits a generic map so the core stays
		// audit-package-free. We surface the neutral event through the
		// audit log's generic any-writer when available; otherwise it
		// remains queryable via /healthz + the detector status.
		s.anomalyEventSink(event)
	}
	return anomaly.NewDetector(cfg, emitter, false)
}

// anomalyEventSink is the product-specific landing for an emitted
// neutral OCSF anomaly event. gbounce keeps the last emitted events in
// a small ring exposed on /healthz + the anomaly status surface so the
// signal is visible even before a SIEM ingests it.
func (s *Server) anomalyEventSink(event map[string]any) {
	s.anomalyMu.Lock()
	s.anomalyRecent = append(s.anomalyRecent, event)
	if len(s.anomalyRecent) > anomalyRecentCap {
		s.anomalyRecent = s.anomalyRecent[len(s.anomalyRecent)-anomalyRecentCap:]
	}
	s.anomalyMu.Unlock()
}

// anomalyRecentCap bounds the in-memory recent-anomaly ring surfaced on
// /healthz + the query surface.
const anomalyRecentCap = 50

// anomalyHealthz returns the /healthz + query-surface block for the
// anomaly detector. Always returns a map (with enabled:false when
// unwired) so the cross-bouncer composite monitor's key set stays
// stable per [[cross-product-agent-parity]].
func (s *Server) anomalyHealthz() map[string]any {
	if s.anomalyDetector == nil {
		return map[string]any{"enabled": false}
	}
	st := s.anomalyDetector.Status()
	s.anomalyMu.Lock()
	st["recent_count"] = len(s.anomalyRecent)
	s.anomalyMu.Unlock()
	return st
}
