package structureddeny

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStructuredDeny_IncludesCaughtByBouncer asserts the lead-with-
// caught_by_bouncer framing per
// [[ambient-value-prop-and-friction-framing]].
func TestStructuredDeny_IncludesCaughtByBouncer(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "gbounce"})
	if sd.CaughtByBouncer != "gbounce" {
		t.Fatalf("CaughtByBouncer = %q; want %q", sd.CaughtByBouncer, "gbounce")
	}
	if _, ok := sd.AsMap()["caught_by_bouncer"]; !ok {
		t.Fatalf("AsMap missing caught_by_bouncer key")
	}
}

func TestStructuredDeny_IncludesClassifierField(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "gbounce", Action: "GET:/api/v1/foo"})
	if sd.ClassifierHook != ClassifierHookGoHeuristic {
		t.Fatalf("ClassifierHook = %q; want %q", sd.ClassifierHook, ClassifierHookGoHeuristic)
	}
}

func TestStructuredDeny_IncludesSuggestedAllowCommand(t *testing.T) {
	cmd := "gbounce profile allow --target evil.example.com --action GET:/api/v1/foo --reason ..."
	sd := Build(BuildOptions{
		Bouncer:               "gbounce",
		Action:                "GET:/api/v1/foo",
		Resource:              "evil.example.com",
		SuggestedAllowCommand: cmd,
	})
	if sd.SuggestedAllowCommand != cmd {
		t.Fatalf("SuggestedAllowCommand = %q; want %q", sd.SuggestedAllowCommand, cmd)
	}
}

func TestStructuredDeny_IncludesRecommendedAction(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "gbounce", Action: "GET:/api/v1/foo"})
	switch sd.RecommendedAction {
	case RecommendedActionEasyAllow, RecommendedActionHaltEscalate, RecommendedActionRephraseRetry:
	default:
		t.Fatalf("RecommendedAction = %q; want one of the canonical three", sd.RecommendedAction)
	}
}

// TestStructuredDeny_HeuristicClassifierAdversarialBackstop verifies
// the KNOWN_ADVERSARIAL_PATTERNS work against gbounce's action shape
// METHOD:/path-prefix.
func TestStructuredDeny_HeuristicClassifierAdversarialBackstop(t *testing.T) {
	cases := []struct {
		action string
		want   string
	}{
		{"DELETE:/api/v1/users/42", InjectionAppearsAdversarial}, // method-side delete
		{"POST:/api/admin/destroy", InjectionAppearsAdversarial}, // path-side destroy
		{"GET:/api/v1/users/42", InjectionAmbiguous},
		{"POST:/api/v1/users", InjectionAmbiguous},
		{"GET:/api/v1/healthz", InjectionAmbiguous},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			sd := Build(BuildOptions{Bouncer: "gbounce", Action: c.action})
			if sd.IsLikelyInjectionClassification != c.want {
				t.Fatalf("classification for %q = %q; want %q",
					c.action, sd.IsLikelyInjectionClassification, c.want)
			}
		})
	}
}

func TestStructuredDeny_SchemaVersionFieldPresent(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "gbounce"})
	if sd.StructuredDenySchemaVersion != SchemaVersion {
		t.Fatalf("StructuredDenySchemaVersion = %q; want %q",
			sd.StructuredDenySchemaVersion, SchemaVersion)
	}
}

func TestStructuredDeny_DenyEventIDDeterministic(t *testing.T) {
	opts := BuildOptions{
		Bouncer: "gbounce", Action: "DELETE:/api/v1/users",
		Resource: "evil.example.com", When: "2026-05-23T12:00:00Z",
	}
	a := Build(opts)
	b := Build(opts)
	if a.DenyEventID != b.DenyEventID {
		t.Fatalf("DenyEventID not deterministic: %q vs %q", a.DenyEventID, b.DenyEventID)
	}
	if !strings.HasPrefix(a.DenyEventID, "evt_gbounce_") {
		t.Fatalf("DenyEventID = %q; want evt_gbounce_ prefix", a.DenyEventID)
	}
}

func TestStructuredDeny_DynamicDenyMeansRephraseRetry(t *testing.T) {
	sd := Build(BuildOptions{
		Bouncer:    "gbounce",
		Action:     "GET:/api/v1/foo",
		DenySource: "dynamic_deny",
	})
	if sd.RecommendedAction != RecommendedActionRephraseRetry {
		t.Fatalf("dynamic_deny recommended=%q; want %q",
			sd.RecommendedAction, RecommendedActionRephraseRetry)
	}
}

func TestStructuredDeny_AsMapMatchesWireSchema(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "gbounce"})
	m := sd.AsMap()
	wantKeys := []string{
		"caught_by_bouncer",
		"is_likely_injection_classification",
		"suggested_allow_command",
		"recommended_action",
		"deny_event_id",
		"classifier_hook",
		"deny_source_classified",
		"structured_deny_schema_version",
	}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("AsMap missing wire-schema key %q", k)
		}
	}
}

func TestStructuredDeny_JSONRoundTripsCanonicalShape(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "gbounce"})
	b, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	out := string(b)
	for _, want := range []string{
		`"caught_by_bouncer":"gbounce"`,
		`"structured_deny_schema_version":"1.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q; got %s", want, out)
		}
	}
}
