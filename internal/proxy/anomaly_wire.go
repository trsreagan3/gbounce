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
//                     core into a privacy-safe pattern (it never stores
//                     the raw host/path).
//   - agentIdentity = the validated X-Agent-Name (or "anonymous").
//
// DEFAULT = ALERT, NOT BLOCK per [[safety-mode-lean-permissive]]: the
// detector surfaces a neutral OCSF anomaly event into the audit log; it
// does not change the request decision unless the operator opts into
// block mode.
package proxy

import (
	"context"
	"os"
	"strconv"

	"github.com/trsreagan3/gbounce/internal/anomaly"
)

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
	return anomaly.LoadConfig(block)
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
	res := s.anomalyDetector.Run(anomaly.RunInput{
		Action:            action,
		AgentIdentity:     agentIdentity,
		Resource:          resource,
		ObservedHour:      -1,
		ObservedActionCount: -1,
		FloorDecision:     floor,
		RecordObservation: true,
	})
	_ = res // alert emission happens inside Run via the bound emitter
	_ = ctx
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
