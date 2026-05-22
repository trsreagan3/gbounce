// Tests for `gbounce profile doctor` (task #321 / KNOWN-CAVEATS §A19).
//
// v1.0 contract: gbounce has no shipped-default profiles to be behind
// (profile rules are explicit-file via --profile-rules-file). The
// doctor surface exists for cross-product CLI parity; these tests
// verify the no-op behavior + the honest Notes line.
//
// G-Slice 2 will populate the catalog + bring the test matrix in line
// with the dbounce / kbouncer / ibounce versions.

package profile

import (
	"strings"
	"testing"
)

func TestDoctor_v1_NeverReportsGaps(t *testing.T) {
	rep, err := Check("/tmp/does-not-exist-and-should-not-be-read.yaml")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rep.MissingFields) != 0 {
		t.Fatalf("v1.0 should never report gaps; got %+v", rep.MissingFields)
	}
	if rep.HasSafetyFloorGap() {
		t.Fatalf("v1.0 should never report safety-floor gap")
	}
	if rep.Notes == "" {
		t.Fatalf("v1.0 report should include honest Notes about architectural difference")
	}
	if !strings.Contains(rep.Notes, "G-Slice 2") {
		t.Fatalf("Notes should reference G-Slice 2 forward-compat; got %q", rep.Notes)
	}
}

func TestDoctor_v1_StartupBannerNeverFires(t *testing.T) {
	if line := StartupBannerLine("gbounce", "/tmp/nonexistent"); line != "" {
		t.Fatalf("v1.0 startup banner must not fire; got %q", line)
	}
}

func TestDoctor_v1_IsAcknowledgedAlwaysTrue(t *testing.T) {
	if !IsAcknowledged("/tmp/nonexistent") {
		t.Fatalf("v1.0 IsAcknowledged should default true")
	}
}

func TestDoctor_v1_ApplyIsNoOp(t *testing.T) {
	result, err := Apply("/tmp/nonexistent")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(result.AppliedFields) != 0 {
		t.Fatalf("v1.0 Apply should not modify anything; got %+v", result.AppliedFields)
	}
	if result.BackupPath != "" {
		t.Fatalf("v1.0 Apply should not write a backup; got %q", result.BackupPath)
	}
}

func TestDoctor_v1_FormatReportMentionsNotes(t *testing.T) {
	rep, _ := Check("")
	out := FormatReport("gbounce", rep)
	if !strings.Contains(out, "matches shipped defaults") {
		t.Fatalf("expected 'matches shipped defaults' in output; got %q", out)
	}
	if !strings.Contains(out, "G-Slice 2") {
		t.Fatalf("expected Notes to render with the G-Slice 2 forward-compat reference; got %q", out)
	}
}
