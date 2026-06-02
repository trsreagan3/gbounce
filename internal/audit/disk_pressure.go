// disk_pressure.go is the Go port of Python ibounce's
// iam_jit.bouncer.audit_export.disk_pressure module (#461 / §A63c)
// for gbounce.
//
// Closes the LAUNCH-BLOCKER §A63c gap that until this slice landed,
// the cross-product DiskStatus primitive (rotation.go:GetDiskStatus,
// shipped in #311) was ONLY consulted by the `gbounce doctor logs`
// CLI. The proxy's /healthz handler ignored disk state, no periodic
// check fired between operator-invoked CLI runs, and the documented
// --stop-on-disk-critical flag was a ghost reference. A gbounce
// sitting on a 99%-full disk would silently fail audit writes,
// losing the compliance value the audit log is supposed to provide.
//
// Three operator-selectable modes per the §A63c spec:
//
//   - pause-requests (compliance-heavy default) — at the critical
//     threshold the proxy REFUSES new requests with HTTP 503 + the
//     #459 structured-deny body shape. Audit integrity is prioritised
//     over liveness. Per [[creates-never-mutates]] we don't drop
//     archives or mutate existing state.
//
//   - rotate-aggressively (dev mode) — at critical drops the oldest
//     rotated audit-*.jsonl.gz / audit-*.db.gz archives until disk
//     usage falls back below the warn threshold.
//
//   - archive-and-purge (hybrid) — at critical emits an admin-action
//     hint that operator's #317 object-storage sink should ship the
//     oldest archives, THEN drops the oldest local archives.
//
// Wire shape parity with Python ibounce + kbouncer + dbounce per
// [[cross-product-agent-parity]] — same field names, same admin-
// action kind, same disk_pressure_mode strings.
package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DiskPressureModePauseRequests      = "pause-requests"
	DiskPressureModeRotateAggressively = "rotate-aggressively"
	DiskPressureModeArchiveAndPurge    = "archive-and-purge"
)

// DefaultDiskPressureMode is the cross-product compliance-heavy
// default. gbounce uses this directly — HTTP proxies don't get the
// same dev-laptop assumption kbouncer does.
const DefaultDiskPressureMode = DiskPressureModePauseRequests

// DiskPressureCheckInterval is the periodic-tick cadence.
const DiskPressureCheckInterval = 60 * time.Second

// DefaultDiskEmergencyPercent is the emergency tier ABOVE crit.
const DefaultDiskEmergencyPercent = 99

// PauseRequestsRefusalReasonTemplate is the operator-friendly
// refusal body template used by the 503 response.
const PauseRequestsRefusalReasonTemplate = "bouncer paused — disk pressure at %.1f%% used " +
	"(threshold %d%%); audit-log writes would risk loss if we " +
	"forwarded. Configure disk_pressure_mode=rotate-aggressively " +
	"or archive-and-purge to change behavior, or clear space + restart."

var KnownDiskPressureModes = []string{
	DiskPressureModePauseRequests,
	DiskPressureModeRotateAggressively,
	DiskPressureModeArchiveAndPurge,
}

// NormalizeDiskPressureMode validates + normalizes operator input.
// Empty returns the default; case-insensitive; unknown values error.
func NormalizeDiskPressureMode(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return DefaultDiskPressureMode, nil
	}
	norm := strings.ToLower(strings.TrimSpace(value))
	for _, k := range KnownDiskPressureModes {
		if norm == k {
			return norm, nil
		}
	}
	return "", fmt.Errorf("unknown disk_pressure_mode %q; expected one of %v",
		value, KnownDiskPressureModes)
}

// DiskPressureState is the live in-process state for one bouncer's
// disk-pressure subsystem.
type DiskPressureState struct {
	mu sync.RWMutex

	mode             string
	currentStatus    string
	lastObserved     *DiskStatus
	lastCheckUnix    int64
	warnPct          int
	critPct          int
	emergencyPct     int
	// warnFreeBytes / critFreeBytes are the absolute-free-space floors (bytes).
	// A volume is OK only when BOTH the percentage is below warnPct AND
	// free bytes exceed warnFreeBytes. Either threshold hit triggers warn/crit.
	// 0 disables the absolute-free check for that level.
	warnFreeBytes    int64
	critFreeBytes    int64
	logDir           string
	refuseRequests   bool
	transitionsCount int64
	lastActionTaken  string
	archiveCount     int
	archiveSizeBytes int64
	// ignoreDiskPressure disables the check entirely when set.
	// Writes audit events at any disk state; warns once at startup.
	ignoreDiskPressure bool
}

// DiskPressureSnapshot is the JSON-encodable view of state, used by
// /healthz + the 503 refusal body.
type DiskPressureSnapshot struct {
	Mode               string      `json:"disk_pressure_mode"`
	Status             string      `json:"status"`
	DiskFreePct        *float64    `json:"disk_free_pct"`
	DiskFreeBytes      *int64      `json:"disk_free_bytes"`
	UsedPct            *float64    `json:"used_pct"`
	WarnPct            int         `json:"warn_pct"`
	CritPct            int         `json:"crit_pct"`
	EmergencyPct       int         `json:"emergency_pct"`
	WarnThresholdBytes int64       `json:"warn_threshold_bytes"`
	CritThresholdBytes int64       `json:"crit_threshold_bytes"`
	Path               string      `json:"path"`
	RefuseRequests     bool        `json:"refuse_requests"`
	ArchiveCount       int         `json:"current_archive_count"`
	ArchiveSizeBytes   int64       `json:"current_archive_size_bytes"`
	TransitionsCount   int64       `json:"transitions_count"`
	LastCheckUnix      *int64      `json:"last_check_unix"`
	LastActionTaken    string      `json:"last_action_taken,omitempty"`
	Reason             string      `json:"reason,omitempty"`
	LastRotationAt     string      `json:"last_rotation_at,omitempty"`
	LastObservedRaw    *DiskStatus `json:"-"`
	IgnoreDiskPressure bool        `json:"ignore_disk_pressure,omitempty"`
}

// NewDiskPressureState constructs the state with operator-declared
// mode + thresholds. Invalid threshold ordering collapses to defaults.
// warnFreeBytes / critFreeBytes set the absolute-free-space floors; pass 0
// to use the package defaults (DefaultDiskWarnFreeBytes / DefaultDiskCritFreeBytes).
func NewDiskPressureState(mode, logDir string, warnPct, critPct, emergencyPct int) *DiskPressureState {
	return NewDiskPressureStateFull(mode, logDir, warnPct, critPct, emergencyPct, 0, 0, false)
}

// NewDiskPressureStateFull is the extended constructor that also accepts
// absolute-free-space floors and the ignore flag.
func NewDiskPressureStateFull(
	mode, logDir string,
	warnPct, critPct, emergencyPct int,
	warnFreeBytes, critFreeBytes int64,
	ignoreDiskPressure bool,
) *DiskPressureState {
	if warnPct <= 0 {
		warnPct = DefaultDiskWarnPercent
	}
	if critPct <= 0 || critPct < warnPct {
		critPct = DefaultDiskCritPercent
	}
	if emergencyPct <= 0 || emergencyPct < critPct {
		emergencyPct = DefaultDiskEmergencyPercent
	}
	if mode == "" {
		mode = DefaultDiskPressureMode
	}
	if warnFreeBytes <= 0 {
		warnFreeBytes = DefaultDiskWarnFreeBytes
	}
	if critFreeBytes <= 0 {
		critFreeBytes = DefaultDiskCritFreeBytes
	}
	return &DiskPressureState{
		mode:               mode,
		currentStatus:      "ok",
		warnPct:            warnPct,
		critPct:            critPct,
		emergencyPct:       emergencyPct,
		warnFreeBytes:      warnFreeBytes,
		critFreeBytes:      critFreeBytes,
		logDir:             logDir,
		ignoreDiskPressure: ignoreDiskPressure,
	}
}

func (s *DiskPressureState) Mode() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

func (s *DiskPressureState) RefuseRequests() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refuseRequests
}

func (s *DiskPressureState) Status() string {
	if s == nil {
		return "ok"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentStatus
}

func (s *DiskPressureState) Snapshot() DiskPressureSnapshot {
	if s == nil {
		return DiskPressureSnapshot{Mode: DefaultDiskPressureMode, Status: "ok"}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *DiskPressureState) snapshotLocked() DiskPressureSnapshot {
	snap := DiskPressureSnapshot{
		Mode:               s.mode,
		Status:             s.currentStatus,
		WarnPct:            s.warnPct,
		CritPct:            s.critPct,
		EmergencyPct:       s.emergencyPct,
		WarnThresholdBytes: s.warnFreeBytes,
		CritThresholdBytes: s.critFreeBytes,
		Path:               s.logDir,
		RefuseRequests:     s.refuseRequests,
		ArchiveCount:       s.archiveCount,
		ArchiveSizeBytes:   s.archiveSizeBytes,
		TransitionsCount:   s.transitionsCount,
		LastActionTaken:    s.lastActionTaken,
		IgnoreDiskPressure: s.ignoreDiskPressure,
	}
	if s.lastObserved != nil {
		freePct := 100.0 - s.lastObserved.UsedPct
		usedPct := s.lastObserved.UsedPct
		snap.DiskFreePct = &freePct
		snap.UsedPct = &usedPct
		snap.Reason = s.lastObserved.Reason
		if s.lastObserved.Path != "" {
			snap.Path = s.lastObserved.Path
		}
		snap.LastObservedRaw = s.lastObserved
		// Surface absolute free bytes (from FreeBytes field if available,
		// else compute from total when FreeBytes was not set by old code paths).
		fb := s.lastObserved.FreeBytes
		snap.DiskFreeBytes = &fb
	}
	if s.lastCheckUnix != 0 {
		t := s.lastCheckUnix
		snap.LastCheckUnix = &t
	}
	if s.logDir != "" {
		if t := lastRotationTimeDP(s.logDir); !t.IsZero() {
			snap.LastRotationAt = t.UTC().Format(time.RFC3339)
		}
	}
	return snap
}

// EvaluateAndReact runs one tick.
func (s *DiskPressureState) EvaluateAndReact(
	ctx context.Context,
	lw *LogWriter,
	diskStatFn func(path string, warnPct, critPct int) (DiskStatus, error),
	now time.Time,
) DiskPressureSnapshot {
	if s == nil {
		return DiskPressureSnapshot{Mode: DefaultDiskPressureMode, Status: "ok"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheckUnix = now.Unix()
	// When --ignore-disk-pressure is set, skip all threshold checks.
	// Status is "ignored"; refuse_requests stays false.
	if s.ignoreDiskPressure {
		s.currentStatus = "ignored"
		s.refuseRequests = false
		return s.snapshotLocked()
	}
	if s.logDir == "" {
		s.currentStatus = "ok"
		s.refuseRequests = false
		return s.snapshotLocked()
	}
	if diskStatFn == nil {
		diskStatFn = func(path string, warnPct, critPct int) (DiskStatus, error) {
			return GetDiskStatusFull(path, warnPct, critPct, s.warnFreeBytes, s.critFreeBytes)
		}
	}
	snap, _ := diskStatFn(s.logDir, s.warnPct, s.critPct)
	s.lastObserved = &snap
	newStatus := classifyDiskStatusWithEmergencyDP(snap, s.warnPct, s.critPct, s.emergencyPct)
	s.archiveCount, s.archiveSizeBytes = countAuditArchivesDP(s.logDir)
	transitioned := newStatus != s.currentStatus
	priorStatus := s.currentStatus
	s.currentStatus = newStatus
	if transitioned {
		s.transitionsCount++
		emitDiskPressureTransition(ctx, lw, priorStatus, newStatus, snap, s.mode, s.logDir)
	}
	s.refuseRequests = computeRefuseRequestsDP(s.mode, s.currentStatus)
	if newStatus == "critical" || newStatus == "emergency" {
		switch s.mode {
		case DiskPressureModePauseRequests:
			s.lastActionTaken = fmt.Sprintf(
				"refusing new agent requests at %.1f%% used",
				snap.UsedPct,
			)
		case DiskPressureModeRotateAggressively:
			removed := dropOldestArchivesDP(s.logDir, s.warnPct)
			s.lastActionTaken = fmt.Sprintf(
				"dropped %d oldest archive(s) to recover space at %.1f%% used",
				len(removed), snap.UsedPct,
			)
			s.archiveCount, s.archiveSizeBytes = countAuditArchivesDP(s.logDir)
		case DiskPressureModeArchiveAndPurge:
			removed := dropOldestArchivesDP(s.logDir, s.warnPct)
			s.lastActionTaken = fmt.Sprintf(
				"archive-and-purge: dropped %d oldest archive(s) "+
					"(operator-configured object-storage sink should ship "+
					"before next tick) at %.1f%% used",
				len(removed), snap.UsedPct,
			)
			s.archiveCount, s.archiveSizeBytes = countAuditArchivesDP(s.logDir)
		}
	} else {
		s.lastActionTaken = ""
	}
	return s.snapshotLocked()
}

func classifyDiskStatusWithEmergencyDP(snap DiskStatus, warnPct, critPct, emergencyPct int) string {
	if snap.Status == "ok" {
		return "ok"
	}
	if snap.UsedPct >= float64(emergencyPct) {
		return "emergency"
	}
	if snap.UsedPct >= float64(critPct) {
		return "critical"
	}
	if snap.UsedPct >= float64(warnPct) {
		return "degraded"
	}
	return snap.Status
}

func computeRefuseRequestsDP(mode, currentStatus string) bool {
	if mode != DiskPressureModePauseRequests {
		return false
	}
	return currentStatus == "critical" || currentStatus == "emergency"
}

func countAuditArchivesDP(logDir string) (int, int64) {
	if logDir == "" {
		return 0, 0
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return 0, 0
	}
	count := 0
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "audit-") {
			continue
		}
		if !(strings.HasSuffix(n, ".jsonl.gz") || strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		count++
		total += info.Size()
	}
	return count, total
}

func dropOldestArchivesDP(logDir string, warnPct int) []string {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}
	type candidate struct {
		path  string
		mtime time.Time
	}
	var cands []candidate
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "audit-") {
			continue
		}
		if !(strings.HasSuffix(n, ".jsonl.gz") || strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, candidate{
			path:  filepath.Join(logDir, n),
			mtime: info.ModTime(),
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mtime.Before(cands[j].mtime) })
	var removed []string
	for _, c := range cands {
		cur, err := GetDiskStatus(logDir, warnPct, 100)
		if err == nil && cur.UsedPct < float64(warnPct) {
			break
		}
		if err := os.Remove(c.path); err != nil {
			continue
		}
		removed = append(removed, c.path)
	}
	return removed
}

func lastRotationTimeDP(logDir string) time.Time {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return time.Time{}
	}
	var latest time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "audit-") {
			continue
		}
		if !(strings.HasSuffix(n, ".jsonl.gz") || strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest
}

func emitDiskPressureTransition(
	ctx context.Context,
	lw *LogWriter,
	fromStatus, toStatus string,
	snap DiskStatus,
	mode, logDir string,
) {
	if lw == nil {
		return
	}
	EmitAdminAction(ctx, lw, AdminActionInput{
		Action:     AdminActionDiskPressureTransition,
		EntityKind: "audit_log_directory",
		EntityName: logDir,
		Source:     AdminActionSourceCLI,
		Before:     map[string]any{"status": fromStatus},
		After: map[string]any{
			"status":   toStatus,
			"used_pct": roundFloatDP(snap.UsedPct, 2),
		},
		ExtraExt: map[string]any{
			"from_status": fromStatus,
			"to_status":   toStatus,
			"used_pct":    roundFloatDP(snap.UsedPct, 2),
			"mode":        mode,
			"reason":      snap.Reason,
			"path":        snap.Path,
		},
	})
}

func roundFloatDP(v float64, places int) float64 {
	if places <= 0 {
		return float64(int64(v + 0.5))
	}
	mult := 1.0
	for i := 0; i < places; i++ {
		mult *= 10
	}
	return float64(int64(v*mult+0.5)) / mult
}

// ResolveLogDir maps the audit-log-path (file path) to the directory
// that holds it + the rotated archives.
func ResolveLogDir(auditLogPath string) string {
	if auditLogPath == "" {
		return ""
	}
	return filepath.Dir(auditLogPath)
}

// RunDiskPressureLoop is the background goroutine that ticks every
// DiskPressureCheckInterval. Exits cleanly when stop is closed.
func RunDiskPressureLoop(
	ctx context.Context,
	state *DiskPressureState,
	lw *LogWriter,
	stop <-chan struct{},
) {
	if state == nil {
		return
	}
	state.EvaluateAndReact(ctx, lw, nil, time.Now())
	t := time.NewTicker(DiskPressureCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			state.EvaluateAndReact(ctx, lw, nil, now)
		}
	}
}
