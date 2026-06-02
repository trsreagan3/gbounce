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

// TestObserveAnomalyEmitsAfterBaseline asserts the detector surfaces a
// neutral event on a spike but never changes the decision in alert mode.
func TestObserveAnomalyEmitsAfterBaseline(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	s := &Server{}
	d := s.NewAnomalyDetector(cfg)
	s.SetAnomalyDetector(d)

	for i := 0; i < 40; i++ {
		s.observeAnomaly(nil, "GET", "api.example.com/v1/data", "agent-g", "ALLOW")
	}
	before := d.Status()["alerts_emitted"].(int64)
	out := d.Run(anomaly.RunInput{
		Action:              "GET",
		AgentIdentity:       "agent-g",
		Resource:            "api.example.com/v1/data",
		ObservedHour:        -1,
		ObservedActionCount: 100000,
		FloorDecision:       "allow",
		RecordObservation:   true,
	})
	if out.Decision != "allow" {
		t.Fatalf("alert mode must not block; got %q", out.Decision)
	}
	after := d.Status()["alerts_emitted"].(int64)
	if after <= before {
		t.Fatalf("expected an alert emitted on the spike (before=%d after=%d)", before, after)
	}
	h := s.anomalyHealthz()
	if h["enabled"].(bool) != true {
		t.Fatalf("healthz should report enabled detector")
	}
	if h["recent_count"].(int) < 1 {
		t.Fatalf("expected recent ring to hold the emitted event")
	}
}
