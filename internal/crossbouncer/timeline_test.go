package crossbouncer

import (
	"encoding/json"
	"strings"
	"testing"
)

func mkEvent(bouncer string, timeMS any, verdict, action, sess string) Event {
	raw := map[string]any{
		"_bouncer": bouncer,
		"api":      map[string]any{"operation": action},
		"unmapped": map[string]any{"iam_jit": map[string]any{
			"verdict": verdict,
			"agent":   map[string]any{"session_id": sess},
		}},
	}
	if timeMS != nil {
		raw["time"] = timeMS
	}
	return Event{Raw: raw}
}

func TestAssembleTimeline_OrdersStitchesAndCoversHonestly(t *testing.T) {
	events := []Event{
		mkEvent("gbounce", float64(3000), "allow", "http:GET", "s1"),
		mkEvent("ibounce", float64(1000), "deny", "s3:DeleteBucket", "s1"),
		mkEvent("dbounce", nil, "allow", "sql:SELECT", "s1"), // no timestamp -> sorts last
	}
	notes := map[string]string{
		"ibounce": "",
		"gbounce": "",
		"dbounce": "",
		"kbounce": "unreachable: connection refused", // probed, no events, errored
	}
	tl := AssembleTimeline("s1", events, notes, "1h", "")

	if tl.Schema != "flight-recorder/1" {
		t.Errorf("schema=%q", tl.Schema)
	}
	if tl.StepCount != 3 || len(tl.Steps) != 3 {
		t.Fatalf("step count=%d", tl.StepCount)
	}
	// Order: ibounce(1000), gbounce(3000), dbounce(no-ts last).
	if tl.Steps[0].Bouncer != "ibounce" || tl.Steps[1].Bouncer != "gbounce" || tl.Steps[2].Bouncer != "dbounce" {
		t.Errorf("bad order: %s,%s,%s", tl.Steps[0].Bouncer, tl.Steps[1].Bouncer, tl.Steps[2].Bouncer)
	}
	// Re-indexed 0..2.
	for i, s := range tl.Steps {
		if s.Index != i {
			t.Errorf("step %d has index %d", i, s.Index)
		}
	}
	// No-timestamp step.
	if tl.Steps[2].HasTimestamp || tl.Steps[2].TimeMS != nil || tl.Steps[2].Time != nil {
		t.Errorf("dbounce step should have no timestamp")
	}
	// Protocols.
	if tl.Steps[0].Protocol != "AWS" || tl.Steps[1].Protocol != "HTTP" {
		t.Errorf("protocol mapping wrong")
	}
	// Coverage honesty.
	c := tl.Coverage
	if !c.Partial {
		t.Errorf("should be partial (kbounce unreachable)")
	}
	if len(c.BouncersUnreachable) != 1 || c.BouncersUnreachable[0].Bouncer != "kbounce" {
		t.Errorf("unreachable=%v", c.BouncersUnreachable)
	}
	if len(c.BouncersProbed) != 4 {
		t.Errorf("probed=%v", c.BouncersProbed)
	}
	if len(c.Gaps) != 1 || !strings.Contains(c.Gaps[0], "kbounce") {
		t.Errorf("gaps=%v", c.Gaps)
	}
	// Meta.
	if tl.Meta.EventsAnalyzed != 3 {
		t.Errorf("events_analyzed=%d", tl.Meta.EventsAnalyzed)
	}
	if tl.Meta.Since == nil || *tl.Meta.Since != "1h" {
		t.Errorf("since meta wrong")
	}
	if tl.Meta.Until != nil {
		t.Errorf("until should be null")
	}
	if tl.Meta.FirstStepTime == nil || tl.Meta.LastStepTime == nil {
		t.Errorf("first/last step time should be set")
	}
}

func TestAssembleTimeline_NullableFieldsSerializeAsNull(t *testing.T) {
	// An event with no reason/principal/iam_context must emit explicit null,
	// matching the Python emitter the replay UI consumes.
	tl := AssembleTimeline("s1",
		[]Event{mkEvent("gbounce", float64(1000), "allow", "http:GET", "s1")},
		map[string]string{"gbounce": ""}, "", "")
	b, err := json.Marshal(tl)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"reason":null`, `"principal":null`, `"iam_context":null`, `"resources":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in: %s", want, s)
		}
	}
	// since/until null at top of meta.
	if !strings.Contains(s, `"since":null`) || !strings.Contains(s, `"until":null`) {
		t.Errorf("since/until should be null: %s", s)
	}
}
