package compliance

import (
	"testing"

	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

func ev(bouncer, action, verdict string, extra map[string]any) crossbouncer.Event {
	raw := map[string]any{
		"_bouncer": bouncer,
		"api":      map[string]any{"operation": action},
		"unmapped": map[string]any{"iam_jit": map[string]any{"verdict": verdict}},
	}
	for k, v := range extra {
		raw[k] = v
	}
	return crossbouncer.Event{Raw: raw}
}

func findFW(res Result, id string) *FrameworkCoverage {
	for i := range res.Coverage {
		if res.Coverage[i].Framework == id {
			return &res.Coverage[i]
		}
	}
	return nil
}

func TestBuildOverlay_MapsActivityToControlsHonestly(t *testing.T) {
	events := []crossbouncer.Event{
		ev("ibounce", "s3:DeleteBucket", "deny", nil),    // deny + destructive
		ev("ibounce", "iam:PutRolePolicy", "allow", nil), // allow + priv-esc
		ev("gbounce", "GET", "allow", nil),               // plain allow
	}
	res := BuildOverlay("sess-1", events, "", nil)

	if res.EventsAnalyzed != 3 {
		t.Errorf("events_analyzed=%d want 3", res.EventsAnalyzed)
	}
	if res.IsPartial {
		t.Errorf("should not be partial (events present, no bouncer errors)")
	}
	// least_privilege_deny fires on the deny -> NIST-AC-6 touched.
	nist := findFW(res, "nist")
	if nist == nil {
		t.Fatal("nist coverage missing")
	}
	var ac6 *ControlTouched
	for i := range nist.ControlsTouched {
		if nist.ControlsTouched[i].Control == "NIST-AC-6" {
			ac6 = &nist.ControlsTouched[i]
		}
	}
	if ac6 == nil {
		t.Errorf("NIST-AC-6 should be touched (deny + priv-esc + destructive)")
	}
	// Honest gap disclosure: controls_not_touched must be populated.
	if len(nist.ControlsNotTouched) == 0 {
		t.Errorf("controls_not_touched must enumerate untouched controls")
	}
	if nist.ControlsTouchedCount+len(nist.ControlsNotTouched) != nist.ControlsInCatalog {
		t.Errorf("touched + not_touched must equal catalog size")
	}
	// Disclaimer is always present + honest.
	if res.Disclaimer == "" || !contains(res.Disclaimer, "NOT a certification") {
		t.Errorf("disclaimer must carry the 'NOT a certification' honesty")
	}
}

func TestBuildOverlay_AnomalyAndMFASignals(t *testing.T) {
	events := []crossbouncer.Event{
		ev("ibounce", "sts:GetCallerIdentity", "allow", map[string]any{
			"unmapped": map[string]any{"iam_jit": map[string]any{
				"verdict": "allow", "anomaly_verdict": "anomalous", "mfa_present": true,
			}},
		}),
	}
	res := BuildOverlay("s", events, "", nil)
	soc2 := findFW(res, "soc2")
	touched := map[string]bool{}
	for _, c := range soc2.ControlsTouched {
		touched[c.Control] = true
	}
	if !touched["SOC2-CC7.2"] {
		t.Errorf("anomalous event should touch SOC2-CC7.2 (anomaly monitoring)")
	}
	if !touched["SOC2-CC6.6"] {
		t.Errorf("mfa-present event should touch SOC2-CC6.6")
	}
}

func TestBuildOverlay_PartialOnNoEventsAndBouncerGaps(t *testing.T) {
	res := BuildOverlay("s", nil, "", map[string]string{"dbounce": "unreachable"})
	if !res.IsPartial {
		t.Errorf("should be partial (0 events + a bouncer gap)")
	}
	if len(res.PartialReasons) < 2 {
		t.Errorf("expected both no_events + bouncer_gaps reasons; got %v", res.PartialReasons)
	}
}

func TestBuildOverlay_FrameworkFilter(t *testing.T) {
	res := BuildOverlay("s", []crossbouncer.Event{ev("ibounce", "s3:Get", "allow", nil)}, "nist", nil)
	if len(res.Coverage) != 1 || res.Coverage[0].Framework != "nist" {
		t.Errorf("framework filter should restrict to nist; got %d frameworks", len(res.Coverage))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
