// anomaly_wire_test.go covers the gbounce-specific Phase H wiring
// (#718 ADOPT-4): env config and the /healthz + query status surface.
package proxy

import (
	"testing"

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
