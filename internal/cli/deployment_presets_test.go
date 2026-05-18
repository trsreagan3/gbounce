// Tests for #254 — `gbounce run --preset security-observe`.
//
// gbounce variant: G-Slice 1 is discovery-only (no profile / rule
// engine / heartbeat / alert-rules surfaces yet). The preset's
// applicable values are slim:
//   - HARD: --mode (discovery; the gbounce equivalent of the other
//     products' "transparent + audit-only" shape)
//   - SOFT: --audit-log-path (per-product default path)
//
// The other cross-product canonical settings (default-policy /
// alert-rules / heartbeat-interval) are NOT in the preset's
// values dict — they land in the FormatBanner's "not applicable
// to this product" annotation list (so an operator who sees the
// same preset across all four products knows what's intentionally
// missing here).
//
// Per [[cross-product-agent-parity]] the framework + override
// semantics match ibounce / kbounce / dbounce.

package cli

import (
	"strings"
	"testing"
)

func TestSecurityObserve_ActivatesCanonicalSettings(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	if preset == nil {
		t.Fatal("expected non-nil preset")
	}
	want := map[string]string{
		"mode":           "discovery",
		"audit-log-path": DefaultAuditLogPath("gbounce"),
	}
	for k, v := range want {
		got, ok := preset.Values[k]
		if !ok {
			t.Errorf("preset missing key %q", k)
			continue
		}
		if got.Value != v {
			t.Errorf("preset[%q] = %q; want %q", k, got.Value, v)
		}
	}
}

func TestSecurityObserve_HardOverridesModeOnly(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	hard := []string{}
	for k, v := range preset.Values {
		if v.Policy == PresetHard {
			hard = append(hard, k)
		}
	}
	if len(hard) != 1 || hard[0] != "mode" {
		t.Errorf("expected exactly one HARD key (mode); got %v", hard)
	}
}

func TestApplyPreset_HardOverrideErrors(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	_, err := ApplyPreset(
		preset,
		map[string]bool{"mode": true},
		map[string]string{"mode": "profile", "audit-log-path": ""},
		nil,
	)
	if err == nil {
		t.Fatal("expected HARD-override error")
	}
	msg := err.Error()
	for _, want := range []string{"security-observe", "mode", "HARD", "drop the --preset", "drop the explicit"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func TestApplyPreset_SoftOverrideAllowed(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	res, err := ApplyPreset(
		preset,
		map[string]bool{"audit-log-path": true},
		map[string]string{"mode": "", "audit-log-path": "/custom/siem.jsonl"},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, k := range res.OverriddenKeys {
		if k == "audit-log-path" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected audit-log-path in OverriddenKeys; got %v", res.OverriddenKeys)
	}
}

func TestFormatBanner_ShowsPresetAndDerivedKeys(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	res, err := ApplyPreset(preset, nil, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := FormatBanner(preset, res)
	if !strings.Contains(lines[0], "deployment preset: security-observe") {
		t.Errorf("first line should name preset: %q", lines[0])
	}
	joined := strings.Join(lines, "\n")
	// The two preset-relevant keys must appear with their values.
	for _, key := range []string{"mode", "audit-log-path"} {
		if !strings.Contains(joined, "--"+key) {
			t.Errorf("banner missing --%s: %s", key, joined)
		}
	}
	// The cross-product canonical settings gbounce doesn't have a
	// surface for must appear as "not applicable" annotations so an
	// operator switching between products sees them.
	for _, key := range []string{"default-policy", "alert-rules", "heartbeat-interval"} {
		if !strings.Contains(joined, "--"+key+":") {
			t.Errorf("banner missing 'not applicable' annotation for --%s: %s", key, joined)
		}
		if !strings.Contains(joined, "not applicable to this product") {
			t.Error("banner should annotate with 'not applicable to this product'")
		}
	}
}

func TestSecurityObserve_NeutralLanguageNoViolationTerms(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	blob := strings.ToLower(preset.Description)
	for _, forbidden := range []string{"violation", "infraction", "unauthorized"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("preset description leaks %q: %s", forbidden, preset.Description)
		}
	}
}

func TestSecurityObserve_NoPhoneHome(t *testing.T) {
	preset := GetPreset("security-observe", "gbounce")
	if _, ok := preset.Values["audit-webhook-url"]; ok {
		t.Error("preset must NOT set audit-webhook-url")
	}
}

func TestUnknownPreset_ReturnsNil(t *testing.T) {
	if GetPreset("does-not-exist", "gbounce") != nil {
		t.Error("expected nil for unknown preset")
	}
}

func TestListPresetNames_OnlySecurityObserve(t *testing.T) {
	names := ListPresetNames()
	if len(names) != 1 || names[0] != "security-observe" {
		t.Errorf("v1.0 should ship exactly security-observe; got %v", names)
	}
}

// Integration test: actual `gbounce run --preset security-observe
// --mode profile` cobra invocation. The HARD-override error fires
// BEFORE any listener bind.
func TestRunCmd_HardOverrideErrorsBeforeBind(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{
		"run",
		"--preset", "security-observe",
		"--mode", "profile",
		"--upstream", "http://example.com",
		"--port", "0",
		"--mgmt-port", "0",
		"--db", t.TempDir() + "/db.db",
	})
	root.SetOut(devNull{})
	root.SetErr(devNull{})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected HARD-override error")
	}
	msg := err.Error()
	for _, want := range []string{"security-observe", "mode", "HARD"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }
