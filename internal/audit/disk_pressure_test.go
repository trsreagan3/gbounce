// disk_pressure_test.go — unit tests for the disk-pressure circuit
// breaker (#461 / §A63c) for gbounce.
package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeDiskStatDP(usedPct float64) func(path string, warnPct, critPct int) (DiskStatus, error) {
	return func(path string, warnPct, critPct int) (DiskStatus, error) {
		return ClassifyDiskStatusForTest(usedPct, warnPct, critPct, path), nil
	}
}

func TestDiskStatus_ReturnsExpectedFields(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	snap := st.Snapshot()
	if snap.Mode != DiskPressureModePauseRequests {
		t.Fatalf("Mode = %q; want %q", snap.Mode, DiskPressureModePauseRequests)
	}
	if snap.WarnPct != DefaultDiskWarnPercent {
		t.Fatalf("WarnPct = %d; want %d", snap.WarnPct, DefaultDiskWarnPercent)
	}
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(20.0), time.Now())
	snap = st.Snapshot()
	if snap.UsedPct == nil || *snap.UsedPct < 19.0 || *snap.UsedPct > 21.0 {
		t.Fatalf("UsedPct = %v; want ~20.0", snap.UsedPct)
	}
}

// --- Threshold-matrix regression tests (fix/disk-pressure-absolute-free) ---

// TestThresholdMatrix_23GBFreeOn228GB is the primary regression for the
// operator's real machine: 89.86% used but 23 GiB free → must be ok.
func TestThresholdMatrix_23GBFreeOn228GB(t *testing.T) {
	// 228 GiB total, 23 GiB free ≈ 89.86% used.
	totalBytes := int64(228 * 1024 * 1024 * 1024)
	freeBytes := int64(23 * 1024 * 1024 * 1024)
	usedPct := 100.0 * float64(totalBytes-freeBytes) / float64(totalBytes)
	snap := ClassifyDiskStatusFullForTest(usedPct, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "ok" {
		t.Fatalf("23GiB free on 228GiB (%.2f%% used): status=%q; want ok (absolute-free check should win)", usedPct, snap.Status)
	}
}

// TestThresholdMatrix_500MBFree_Critical asserts absolute-free CRIT fires.
func TestThresholdMatrix_500MBFree_Critical(t *testing.T) {
	// 228 GiB total, 500 MiB free — extreme low headroom.
	totalBytes := int64(228 * 1024 * 1024 * 1024)
	freeBytes := int64(500 * 1024 * 1024)
	usedPct := 100.0 * float64(totalBytes-freeBytes) / float64(totalBytes)
	snap := ClassifyDiskStatusFullForTest(usedPct, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "critical" {
		t.Fatalf("500MiB free: status=%q; want critical", snap.Status)
	}
}

// TestThresholdMatrix_95PctUsed_12GBFree_OK: 95% used but 12 GB free →
// under both 96% warn AND 1 GiB free floor → status=ok.
func TestThresholdMatrix_95PctUsed_12GBFree_OK(t *testing.T) {
	freeBytes := int64(12 * 1024 * 1024 * 1024)
	usedPct := 95.0 // manually set; 12 GiB free on ~240 GiB ≈ 95%
	snap := ClassifyDiskStatusFullForTest(usedPct, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "ok" {
		t.Fatalf("95%% used with 12GiB free: status=%q; want ok", snap.Status)
	}
}

// TestThresholdMatrix_97PctUsed_7GBFree_Warn: 97% used (≥96 warn, <98 crit)
// with 7 GiB free (>1 GiB floor) → status=degraded (pct-warn fires).
func TestThresholdMatrix_97PctUsed_7GBFree_Warn(t *testing.T) {
	freeBytes := int64(7 * 1024 * 1024 * 1024)
	usedPct := 97.0
	snap := ClassifyDiskStatusFullForTest(usedPct, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "degraded" {
		t.Fatalf("97%% used with 7GiB free: status=%q; want degraded", snap.Status)
	}
}

// TestThresholdMatrix_98PctUsed_Critical: 98% used → critical (pct-crit fires).
func TestThresholdMatrix_98PctUsed_Critical(t *testing.T) {
	freeBytes := int64(5 * 1024 * 1024 * 1024)
	snap := ClassifyDiskStatusFullForTest(98.0, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "critical" {
		t.Fatalf("98%% used: status=%q; want critical", snap.Status)
	}
}

// TestThresholdMatrix_IgnoreDiskPressure: with ignore flag all checks return
// status "ignored" regardless of disk state.
func TestThresholdMatrix_IgnoreDiskPressure(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureStateFull(DiskPressureModePauseRequests, tmp, 0, 0, 0, 0, 0, true)
	// Drive extremely bad disk state.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(99.9), time.Now())
	if got := st.Status(); got != "ignored" {
		t.Fatalf("Status with ignore flag at 99.9%% used = %q; want ignored", got)
	}
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests must be false when --ignore-disk-pressure is set")
	}
	snap := st.Snapshot()
	if !snap.IgnoreDiskPressure {
		t.Fatal("Snapshot.IgnoreDiskPressure must be true")
	}
}

func TestDiskPressureMode_PauseRequestsRefuses503AtCritical(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(20.0), time.Now())
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests at 20%% used; want false")
	}
	// 96% is the warn threshold (degraded), not critical. Pause-requests
	// does NOT refuse at degraded — only at critical/emergency.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(96.0), time.Now())
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests at 96%% (warn/degraded) in pause mode; want false — crit is 98%%")
	}
	if got := st.Status(); got != "degraded" {
		t.Fatalf("Status at 96%% = %q; want degraded", got)
	}
	// 98.5% crosses the crit threshold → critical → refuse.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(98.5), time.Now())
	if !st.RefuseRequests() {
		t.Fatal("RefuseRequests at 98.5%% used in pause mode; want true")
	}
	if got := st.Status(); got != "critical" {
		t.Fatalf("Status at 98.5%% = %q; want critical", got)
	}
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(99.0), time.Now())
	if got := st.Status(); got != "emergency" {
		t.Fatalf("Status at 99%% = %q; want emergency", got)
	}
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(30.0), time.Now())
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests after recovery to 30%% used; want false")
	}
}

func TestDiskPressureMode_RotateAggressivelyDropsOldestAtCritical(t *testing.T) {
	tmp := t.TempDir()
	for i, name := range []string{
		"audit-2026-05-21-100000.jsonl.gz",
		"audit-2026-05-22-100000.jsonl.gz",
		"audit-2026-05-23-100000.jsonl.gz",
	} {
		p := filepath.Join(tmp, name)
		_ = os.WriteFile(p, []byte("test"), 0o600)
		mt := time.Now().Add(time.Duration(-72+i*24) * time.Hour)
		_ = os.Chtimes(p, mt, mt)
	}
	st := NewDiskPressureState(DiskPressureModeRotateAggressively, tmp, 0, 0, 0)
	// Use 98.5% to cross the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(98.5), time.Now())
	if st.RefuseRequests() {
		t.Fatal("rotate-aggressively must NEVER refuse requests")
	}
	if got := st.Status(); got != "critical" {
		t.Fatalf("Status = %q; want critical", got)
	}
	snap := st.Snapshot()
	if !strings.Contains(snap.LastActionTaken, "dropped") {
		t.Fatalf("LastActionTaken = %q; want 'dropped ...' substring", snap.LastActionTaken)
	}
}

func TestDiskPressureMode_ArchiveAndPurgeShipsToSinkAtCritical(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModeArchiveAndPurge, tmp, 0, 0, 0)
	// Use 98.5% to cross the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(98.5), time.Now())
	if st.RefuseRequests() {
		t.Fatal("archive-and-purge must NEVER refuse requests")
	}
	snap := st.Snapshot()
	if !strings.Contains(snap.LastActionTaken, "archive-and-purge") {
		t.Fatalf("LastActionTaken = %q; want archive-and-purge prefix", snap.LastActionTaken)
	}
}

func TestDiskPressureTransition_EmitsAdminActionOCSF(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	lw, err := NewLogWriter(context.Background(), LogWriterOptions{Path: logPath})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	defer lw.Close()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// ok → ok: no transition.
	st.EvaluateAndReact(context.Background(), lw, fakeDiskStatDP(20.0), time.Now())
	// ok → critical: one transition event (98.5% crosses default crit=98%).
	st.EvaluateAndReact(context.Background(), lw, fakeDiskStatDP(98.5), time.Now())
	// critical → critical: no new event.
	st.EvaluateAndReact(context.Background(), lw, fakeDiskStatDP(98.5), time.Now())
	// critical → emergency: one event.
	st.EvaluateAndReact(context.Background(), lw, fakeDiskStatDP(99.0), time.Now())
	// emergency → ok: one event.
	st.EvaluateAndReact(context.Background(), lw, fakeDiskStatDP(20.0), time.Now())

	// Force the log writer to flush by closing.
	lw.Close()

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	count := strings.Count(string(body), string(AdminActionDiskPressureTransition))
	// Each emit creates the action string in the JSON event body
	// twice (once in ActivityName, once in unmapped.iam_jit.config_change.type).
	// So 3 transitions × 2 occurrences = 6 expected substring hits.
	if count < 3 {
		t.Fatalf("audit log has %d occurrences of %q; want >= 3 (one per transition)\nbody=%s",
			count, string(AdminActionDiskPressureTransition), body)
	}
	if got := st.Snapshot().TransitionsCount; got != 3 {
		t.Fatalf("TransitionsCount = %d; want 3", got)
	}
}

func TestStopOnDiskCriticalAliasEquivalentToPauseMode(t *testing.T) {
	tmp := t.TempDir()
	longForm := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	aliased, _ := NormalizeDiskPressureMode("pause-requests")
	aliasState := NewDiskPressureState(aliased, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold — both should refuse.
	longForm.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(98.5), time.Now())
	aliasState.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(98.5), time.Now())
	if longForm.RefuseRequests() != aliasState.RefuseRequests() {
		t.Fatalf("alias RefuseRequests = %t; long form = %t",
			aliasState.RefuseRequests(), longForm.RefuseRequests())
	}
}

func TestNormalizeDiskPressureMode_RejectsUnknownValues(t *testing.T) {
	if _, err := NormalizeDiskPressureMode("bogus"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
	if got, _ := NormalizeDiskPressureMode(""); got != DefaultDiskPressureMode {
		t.Fatalf("empty mode = %q; want default %q", got, DefaultDiskPressureMode)
	}
}

func TestSnapshotSerialization_HealthzBlockShape(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatDP(98.5), time.Now())
	snap := st.Snapshot()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		`"disk_pressure_mode":"pause-requests"`,
		`"status":"critical"`,
		`"refuse_requests":true`,
		`"current_archive_count":`,
		`"current_archive_size_bytes":`,
		`"transitions_count":1`,
		`"disk_free_pct":`,
		`"disk_free_bytes":`,
		`"warn_threshold_bytes":`,
		`"crit_threshold_bytes":`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("snapshot JSON missing %q\ngot: %s", want, body)
		}
	}
}

func TestRunDiskPressureLoop_ExitsOnStopClose(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		RunDiskPressureLoop(context.Background(), st, nil, stop)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit within 2s of stop close")
	}
	if st.Snapshot().LastCheckUnix == nil {
		t.Fatal("first eager tick did not populate LastCheckUnix")
	}
}

func TestResolveLogDir(t *testing.T) {
	if got := ResolveLogDir(""); got != "" {
		t.Fatalf("empty path = %q; want empty", got)
	}
	if got := ResolveLogDir("/var/log/gbounce/audit.jsonl"); got != "/var/log/gbounce" {
		t.Fatalf("file path = %q; want /var/log/gbounce", got)
	}
}
