// disk_pressure_test.go — proxy-layer integration tests for the
// #461 / §A63c disk-pressure circuit breaker (gbounce).
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

func freshStoreForDP(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func fakeDiskStatFnDP(usedPct float64) func(path string, warnPct, critPct int) (audit.DiskStatus, error) {
	return func(path string, warnPct, critPct int) (audit.DiskStatus, error) {
		return audit.ClassifyDiskStatusForTest(usedPct, warnPct, critPct, path), nil
	}
}

func TestHealthzIncludesAuditLogBlock(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatFnDP(20.0), time.Now())
	srv, err := NewServer(Config{DiskPressure: st, UpstreamURL: "http://localhost:1"}.Normalize(), freshStoreForDP(t), nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Code = %d; want 200", rec.Code)
	}
	body := rec.Body.Bytes()
	for _, want := range []string{
		`"audit_log"`,
		`"disk_pressure_mode":"pause-requests"`,
		`"refuse_requests":false`,
		`"current_archive_count":`,
		`"current_archive_size_bytes":`,
		`"warn_pct":`,
		`"crit_pct":`,
		`"emergency_pct":`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("/healthz body missing %s\nbody=%s", want, body)
		}
	}
}

func TestHealthz503AtCriticalInPauseMode(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// 98.5% crosses the critical threshold (default 98%); 96% is only degraded.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatFnDP(98.5), time.Now())
	srv, err := NewServer(Config{DiskPressure: st, UpstreamURL: "http://localhost:1"}.Normalize(), freshStoreForDP(t), nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Code = %d; want 503", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"refuse_requests":true`) {
		t.Errorf("/healthz body missing refuse_requests=true: %s", body)
	}
}

func TestHandle_DiskPressurePauseReturns503WithStructuredDeny(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// 98.5% crosses the critical threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatFnDP(98.5), time.Now())
	srv, err := NewServer(Config{DiskPressure: st, UpstreamURL: "http://localhost:1"}.Normalize(), freshStoreForDP(t), nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	srv.handle(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Code = %d; want 503", rec.Code)
	}
	if got := rec.Header().Get("x-gbounce-refusal"); got != "disk-pressure-pause" {
		t.Fatalf("x-gbounce-refusal = %q; want disk-pressure-pause", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v\nraw=%s", err, rec.Body.String())
	}
	if got := body["caught_by_bouncer"]; got != "gbounce" {
		t.Fatalf("caught_by_bouncer = %v; want gbounce", got)
	}
	if _, ok := body["recommended_action"]; !ok {
		t.Fatal("body missing recommended_action key")
	}
	if _, ok := body["structured_deny_schema_version"]; !ok {
		t.Fatal("body missing structured_deny_schema_version key")
	}
	if _, ok := body["disk_pressure"]; !ok {
		t.Fatal("body missing disk_pressure block")
	}
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "bouncer paused") {
		t.Fatalf("message = %q; want 'bouncer paused' framing", msg)
	}
}

func TestHandle_DiskPressureRotateAggressivelyPasses(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModeRotateAggressively, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatFnDP(96.0), time.Now())
	srv, err := NewServer(Config{DiskPressure: st, UpstreamURL: "http://localhost:1"}.Normalize(), freshStoreForDP(t), nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	srv.handle(rec, req)
	if rec.Code == http.StatusServiceUnavailable && rec.Header().Get("x-gbounce-refusal") == "disk-pressure-pause" {
		t.Fatal("rotate-aggressively must NOT 503 on disk pressure")
	}
}
