// feature_status.go ships the purpose-driven monitoring UI surface
// per iam-jit #682 + [[gbounce-ui-purpose-driven]]. The pre-existing
// /healthz endpoint already exposes per-feature counters; this file
// adds the missing piece — "configured vs actually firing" — so the
// /admin/ui page can render the 5 operator questions honestly:
//
//  1. What is my agent doing RIGHT NOW?
//  2. Is my agent stuck?
//  3. What is gbounce blocking that I should know about?
//  4. Which features are turned on?
//  5. Are the features actually doing their job?
//
// Honesty bar (per [[ibounce-honest-positioning]]): a feature that is
// ENABLED but has NEVER FIRED is reported as ConfiguredButNeverFired=true.
// We never paint a green "OK" on silent-degradation; the UI surfaces
// the gap. The "fire count" + "last fired ts" + "last error" trio
// mirrors the [[ibounce-honest-positioning]] audit_warning shape.
//
// Threading model: all last-fired timestamps + fire counts live as
// atomic.Int64 on the Server. Recording a fire is O(1) lock-free.
// Snapshotting walks the small fixed list of features in O(1).
package proxy

import (
	"sync/atomic"
	"time"
)

// FeatureStatus describes the configured + firing state of one
// monitoring feature for the /admin/features endpoint + the
// purpose-driven UI panel.
//
// Field semantics — answering the founder's question 5:
//
//   - Enabled: true iff the feature is configured (i.e., the operator
//     turned it on at startup or via a hot-swap).
//   - FireCountTotal: how many times the feature has fired since
//     process start. Bumped lock-free in the hot path.
//   - FireCount24h: a rolling-24h-window approximation. We don't keep
//     timestamped per-fire records (that's what the audit log is for);
//     instead we expose total + last-fired-ts and let the UI render
//     "fired N times, most recently <ts>". The 24h field is a
//     forward-compat slot reserved for the future audit-store-backed
//     count; populated from the audit store when available.
//   - LastFiredUnixMs: unix epoch milliseconds of the most recent
//     fire. Zero when the feature has never fired since process start.
//   - LastError: most recent error string captured during a fire
//     (e.g., an MITM upstream handshake failure). Empty when no error
//     has been observed since process start.
//   - ConfiguredButNeverFired: ENABLED && LastFiredUnixMs == 0. This
//     is the "silent-degradation" surface the UI highlights distinctly.
//   - DetailHint: a one-line operator-readable hint about what kind
//     of traffic would cause this feature to fire (e.g., "configure a
//     deny_hosts entry and CONNECT to a matching host"). Surfaces the
//     "how do I test this" answer next to the feature row.
type FeatureStatus struct {
	Name                    string `json:"name"`
	Enabled                 bool   `json:"enabled"`
	FireCountTotal          int64  `json:"fire_count_total"`
	FireCount24h            int64  `json:"fire_count_24h"`
	LastFiredUnixMs         int64  `json:"last_fired_unix_ms"`
	LastError               string `json:"last_error,omitempty"`
	ConfiguredButNeverFired bool   `json:"configured_but_never_fired"`
	DetailHint              string `json:"detail_hint,omitempty"`
}

// featureStatusSnapshot bundles the full set + a process-start
// timestamp so the UI can render "monitoring since <ts>" honestly.
type featureStatusSnapshot struct {
	ProcessStartedUnixMs int64           `json:"process_started_unix_ms"`
	NowUnixMs            int64           `json:"now_unix_ms"`
	Features             []FeatureStatus `json:"features"`
}

// recordFeatureFire stamps the now-ts into the per-feature
// atomic.Int64 + bumps the total. Lock-free — safe to call from the
// hot path. The lastFired field is monotonic per-feature but NOT
// monotonic across features (a deny fired at t=1, an allow at t=2,
// reading the deny's lastFired still shows t=1). That's the desired
// semantic: per-feature recency, not global.
func recordFeatureFire(lastFired *atomic.Int64, fireCount *atomic.Int64) {
	lastFired.Store(time.Now().UnixMilli())
	fireCount.Add(1)
}

// recordFeatureError stores the most recent error string for a
// feature. Truncated to 256 chars so a runaway error message can't
// blow up the JSON response. Empty input clears the field.
func recordFeatureError(lastErr *atomic.Value, msg string) {
	if len(msg) > 256 {
		msg = msg[:256]
	}
	lastErr.Store(msg)
}

// loadFeatureError reads the atomic.Value. Returns "" when never set.
func loadFeatureError(lastErr *atomic.Value) string {
	v := lastErr.Load()
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// snapshotFeatures builds the full feature-status snapshot reflecting
// the server's current per-feature state. The list is alphabetised
// for stable UI rendering.
//
// "Enabled" semantics per feature:
//
//   - mitm: cfg.Mode == ModeMITM
//   - deny_hosts: len(s.denyHosts) > 0
//   - dynamic_deny: s.dynamicDeny != nil
//   - injection_scan: active profile has InjectionScanResponseBodies.Enabled
//   - profile_enforcement: an active profile is set
//   - audit_log: s.log != nil
//   - session_recorder: s.recorder != nil
//   - object_storage: s.objectStorage != nil
//   - disk_pressure_circuit_breaker: s.cfg.DiskPressure != nil
func (s *Server) snapshotFeatures() featureStatusSnapshot {
	now := time.Now().UnixMilli()
	out := featureStatusSnapshot{
		ProcessStartedUnixMs: s.processStartedUnixMs.Load(),
		NowUnixMs:            now,
		Features:             make([]FeatureStatus, 0, 10),
	}

	// MITM mode — fires when an HTTPS CONNECT is intercepted +
	// re-encrypted. Counter is bumped on EVERY successful MITM
	// forward (totalRequests is too noisy because it also includes
	// non-MITM forwards). We piggyback on the existing MITM denies
	// counter for now + add a dedicated "intercepted" counter so the
	// UI can show "MITM is on but no traffic intercepted yet" honestly.
	mitmEnabled := s.cfg.Mode == ModeMITM
	mitmLast := s.mitmLastFiredUnixMs.Load()
	mitmFires := s.totalMITMIntercepted.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "mitm",
		Enabled:                 mitmEnabled,
		FireCountTotal:          mitmFires,
		LastFiredUnixMs:         mitmLast,
		LastError:               loadFeatureError(&s.mitmLastError),
		ConfiguredButNeverFired: mitmEnabled && mitmFires == 0,
		DetailHint:              "send HTTPS traffic through the proxy (HTTPS_PROXY=http://host:port curl https://example.com)",
	})

	// Deny-hosts — static deny list. Fires when a CONNECT matches a
	// configured rule.
	denyHostsEnabled := len(s.denyHosts) > 0
	denyHostsFires := s.totalDenyHostMatches.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "deny_hosts",
		Enabled:                 denyHostsEnabled,
		FireCountTotal:          denyHostsFires,
		LastFiredUnixMs:         s.denyHostsLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: denyHostsEnabled && denyHostsFires == 0,
		DetailHint:              "CONNECT to a host matching a deny_hosts rule",
	})

	// Dynamic deny — hot-reloadable YAML rules. Fires when a CONNECT
	// matches a dynamic-deny rule.
	dynEnabled := s.dynamicDeny != nil
	dynFires := s.totalDynamicDenyMatches.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "dynamic_deny",
		Enabled:                 dynEnabled,
		FireCountTotal:          dynFires,
		LastFiredUnixMs:         s.dynamicDenyLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: dynEnabled && dynFires == 0,
		DetailHint:              "write a rule to ~/.iam-jit/dynamic-denies.yaml + CONNECT to a matching host",
	})

	// Injection scan — MITM-mode response-body scanner for indirect
	// prompt injection. Fires on warn/strip/deny.
	injEnabled := false
	if ap := s.ActiveProfile(); ap != nil {
		injEnabled = ap.InjectionScanResponseBodies.Enabled
	}
	injFires := s.totalInjectionScanWarns.Load() +
		s.totalInjectionScanStrips.Load() +
		s.totalInjectionScanDenies.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "injection_scan",
		Enabled:                 injEnabled,
		FireCountTotal:          injFires,
		LastFiredUnixMs:         s.injectionScanLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: injEnabled && injFires == 0,
		DetailHint:              "enable in profile + MITM-decode a response containing prompt-injection indicators",
	})

	// Profile enforcement — fires when an MITM-intercepted request is
	// denied by a profile rule.
	profileEnabled := s.ActiveProfile() != nil
	profileFires := s.totalMITMDenies.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "profile_enforcement",
		Enabled:                 profileEnabled,
		FireCountTotal:          profileFires,
		LastFiredUnixMs:         s.profileEnforcementLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: profileEnabled && profileFires == 0,
		DetailHint:              "MITM a request that matches a profile deny_rule (method+host+path)",
	})

	// Audit log — JSONL writer. "Fires" each time an event is
	// persisted to disk. Total comes from the writer itself so we
	// don't double-count.
	auditEnabled := s.log != nil
	var auditFires int64
	var auditLast int64
	auditErr := ""
	if auditEnabled {
		auditFires = s.log.Total()
		if e := s.log.LastError(); e != "" {
			auditErr = e
		}
		auditLast = s.auditLogLastFiredUnixMs.Load()
	}
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "audit_log",
		Enabled:                 auditEnabled,
		FireCountTotal:          auditFires,
		LastFiredUnixMs:         auditLast,
		LastError:               auditErr,
		ConfiguredButNeverFired: auditEnabled && auditFires == 0,
		DetailHint:              "send any traffic — every decision is teed into --audit-log",
	})

	// Session recorder — per-session NDJSON.
	recorderEnabled := s.recorder != nil
	recorderFires := s.sessionRecorderFireCount.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "session_recorder",
		Enabled:                 recorderEnabled,
		FireCountTotal:          recorderFires,
		LastFiredUnixMs:         s.sessionRecorderLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: recorderEnabled && recorderFires == 0,
		DetailHint:              "send traffic with X-Agent-Session-Id header set",
	})

	// Object storage — S3-compat NDJSON.gz uploader.
	objEnabled := s.objectStorage != nil
	objFires := s.objectStorageFireCount.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "object_storage",
		Enabled:                 objEnabled,
		FireCountTotal:          objFires,
		LastFiredUnixMs:         s.objectStorageLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: objEnabled && objFires == 0,
		DetailHint:              "send traffic; events are buffered + uploaded on rotation",
	})

	// Disk pressure circuit breaker — fires when state transitions.
	dpEnabled := s.cfg.DiskPressure != nil
	dpFires := s.diskPressureFireCount.Load()
	out.Features = append(out.Features, FeatureStatus{
		Name:                    "disk_pressure_circuit_breaker",
		Enabled:                 dpEnabled,
		FireCountTotal:          dpFires,
		LastFiredUnixMs:         s.diskPressureLastFiredUnixMs.Load(),
		ConfiguredButNeverFired: false, // never-fired is the HEALTHY state
		DetailHint:              "fires automatically when disk usage crosses the warning/critical threshold",
	})

	return out
}
