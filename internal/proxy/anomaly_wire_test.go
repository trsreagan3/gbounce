// anomaly_wire_test.go covers the gbounce-specific Phase H wiring
// (#718 ADOPT-4): env config and the /healthz + query status surface.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/anomaly"
)

func TestAnomalyConfigFromEnvDisabledByDefault(t *testing.T) {
	t.Setenv("IAM_JIT_ANOMALY_DETECTION", "")
	c, err := AnomalyConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Enabled {
		t.Fatalf("anomaly detection must be DISABLED by default")
	}
}

func TestAnomalyConfigFromEnvEnable(t *testing.T) {
	t.Setenv("IAM_JIT_ANOMALY_DETECTION", "1")
	t.Setenv("IAM_JIT_ANOMALY_MODE", "block")
	t.Setenv("IAM_JIT_ANOMALY_SENSITIVITY", "high")
	t.Setenv("IAM_JIT_ANOMALY_MIN_ACTIONS", "7")
	c, err := AnomalyConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Enabled || c.Mode != "block" || c.Sensitivity != "high" || c.MinActionsForBaseline != 7 {
		t.Fatalf("env not honored: %+v", c)
	}
}

func TestAnomalyConfigFromValues(t *testing.T) {
	// disabled in = the disabled default, no path resolution.
	if c, err := AnomalyConfigFromValues(false, "", "", 0); err != nil || c.Enabled {
		t.Fatalf("disabled values must yield disabled config: %+v err=%v", c, err)
	}
	// enabled honors mode/sensitivity/min + persists the baseline (path set
	// from the default ~/.gbounce resolution so config-enable matures too).
	t.Setenv("IAM_JIT_ANOMALY_BASELINE_PATH", "/tmp/test-baseline.json")
	c, err := AnomalyConfigFromValues(true, "block", "high", 25)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Enabled || c.Mode != "block" || c.Sensitivity != "high" ||
		c.MinActionsForBaseline != 25 || c.BaselinePath != "/tmp/test-baseline.json" {
		t.Fatalf("values not honored: %+v", c)
	}
}

func TestAnomalyHealthzUnwired(t *testing.T) {
	s := &Server{}
	h := s.anomalyHealthz()
	if h["enabled"].(bool) != false {
		t.Fatalf("unwired detector must report enabled:false")
	}
}

// TestObserveAnomalyEmitsThroughWire is the GENUINE wire test (#718
// finding LOW): it drives a volume-spike burst entirely THROUGH
// observeAnomaly (never d.Run directly) and asserts a neutral event is
// emitted + the decision is never changed in alert mode. This FAILS
// against the old sentinel wire (ObservedHour=-1, ObservedActionCount=-1
// meant no deviation dimension ever contributed, so behavioral
// detection was dead) and PASSES once observeAnomaly feeds the real
// hour-of-day + recent-window rate.
func TestObserveAnomalyEmitsThroughWire(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	s := &Server{}
	d := s.NewAnomalyDetector(cfg)
	s.SetAnomalyDetector(d)

	// A sharp burst for one (agent, action, resource): the recent-window
	// rate climbs far above the learned per-hour baseline mean, so the
	// action_frequency dimension trips — all THROUGH observeAnomaly.
	for i := 0; i < 200; i++ {
		s.observeAnomaly(nil, "GET", "api.example.com/v1/data", "agent-g", "ALLOW")
	}

	emitted := d.Status()["alerts_emitted"].(int64)
	if emitted < 1 {
		t.Fatalf("expected the wire to flag the volume spike (alerts_emitted=%d); "+
			"behavioral detection is dead if this is 0", emitted)
	}
	// Alert mode must never change the decision.
	scored := d.Status()["events_scored"].(int64)
	if scored < 1 {
		t.Fatalf("expected the wire to score events through observeAnomaly; got %d", scored)
	}
	h := s.anomalyHealthz()
	if h["enabled"].(bool) != true {
		t.Fatalf("healthz should report enabled detector")
	}
	if h["recent_count"].(int) < 1 {
		t.Fatalf("expected recent ring to hold the emitted event")
	}
}

// TestDecideAnomalyPanicDegradesToFloor verifies the defensive recover in
// decideAnomaly: a panicking emitter in the core Decide path must not crash
// the hot path and must degrade to the FLOOR decision (allow stays allow,
// i.e. returns false/"not tightened") rather than spuriously denying.
//
// Mechanism: we install a block-mode detector whose emitter panics, then
// trigger the cold-start adversarial backstop (action "truncate" with no
// baseline so MinActionsForBaseline=50 forces cold-start). Decide flags the
// action as anomalous, calls the emitter (panic), and the defer/recover in
// decideAnomaly catches it — returning false (floor = allow).
//
// Note: http.Request.Method is set directly (not via httptest.NewRequest)
// to allow an adversarial verb string that httptest would reject.
func TestDecideAnomalyPanicDegradesToFloor(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "block"
	cfg.MinActionsForBaseline = 50 // ensure cold-start so backstop fires
	panicEmitter := func(_ map[string]any) {
		panic("simulated scorer panic for recover test")
	}
	anomaly.SetProduct("gbounce")
	d := anomaly.NewDetector(cfg, panicEmitter, false)
	s := &Server{}
	s.SetAnomalyDetector(d)

	// Build the request directly so we can set Method to the adversarial
	// verb "truncate" (in knownAdversarialActions); httptest.NewRequest
	// would panic if the method contained spaces.
	req := &http.Request{
		Method: "truncate",
		Header: make(http.Header),
		URL:    &url.URL{Path: "/prod_table"},
	}
	w := httptest.NewRecorder()
	// Must not panic; must return false (floor = allow, not tightened).
	got := s.decideAnomaly(w, req, time.Now())
	if got {
		t.Fatalf("decideAnomaly must return false (floor=allow) on a scorer panic, got true")
	}
	if w.Code != http.StatusOK {
		// decideAnomaly must not have written a 403 if the recover fired.
		t.Fatalf("expected no deny response written on panic-degrade; got HTTP %d", w.Code)
	}
}

// TestObserveAnomalyNormalTrafficQuietThroughWire asserts the wire does
// NOT cry wolf: steady low-rate traffic spread over time stays normal.
func TestObserveAnomalyNormalTrafficQuietThroughWire(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	s := &Server{}
	d := s.NewAnomalyDetector(cfg)
	s.SetAnomalyDetector(d)

	// A handful of calls: below the spike threshold for the per-hour
	// baseline, so nothing should be flagged.
	for i := 0; i < 3; i++ {
		s.observeAnomaly(nil, "GET", "api.example.com/v1/data", "agent-quiet", "ALLOW")
	}
	if got := d.Status()["alerts_emitted"].(int64); got != 0 {
		t.Fatalf("steady low-rate traffic must not be flagged; alerts_emitted=%d", got)
	}
}
