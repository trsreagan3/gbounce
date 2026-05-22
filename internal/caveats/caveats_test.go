// Tests for the caveats discoverability surfaces. Keeps the package
// behavior pinned even when the canonical KNOWN-CAVEATS.md anchor
// list grows; if we add more entries we want the existing surface to
// keep working.
package caveats

import (
	"strings"
	"testing"
)

func TestAllEntriesHaveURLs(t *testing.T) {
	for _, e := range All {
		if e.ID == "" {
			t.Errorf("entry without ID: %+v", e)
		}
		if e.Anchor == "" {
			t.Errorf("entry %s without anchor", e.ID)
		}
		u := e.URL()
		if !strings.HasPrefix(u, "https://github.com/") {
			t.Errorf("entry %s URL does not look like GitHub: %s", e.ID, u)
		}
		if !strings.Contains(u, e.Anchor) {
			t.Errorf("entry %s URL %s does not contain its anchor %s",
				e.ID, u, e.Anchor)
		}
		if e.DoctorBlurb == "" {
			t.Errorf("entry %s missing DoctorBlurb", e.ID)
		}
	}
}

func TestByIDFound(t *testing.T) {
	if e := ByID("B8"); e == nil {
		t.Fatal("ByID(B8) returned nil")
	}
	if e := ByID("B9"); e == nil {
		t.Fatal("ByID(B9) returned nil")
	}
	if e := ByID("BNONE"); e != nil {
		t.Fatalf("ByID(BNONE) should be nil, got %+v", e)
	}
}

func TestLinkSuffixContainsURL(t *testing.T) {
	got := LinkSuffix("B8")
	if !strings.Contains(got, "KNOWN-CAVEATS §B8:") {
		t.Errorf("LinkSuffix missing §B8: %q", got)
	}
	if !strings.Contains(got, "github.com") {
		t.Errorf("LinkSuffix missing github URL: %q", got)
	}
	if got := LinkSuffix("BNONE"); got != "" {
		t.Errorf("LinkSuffix for unknown id should be empty, got %q", got)
	}
}

func TestBannerLinesTriggered(t *testing.T) {
	// Both triggers active → both banner lines (B8 + B9) emitted.
	lines := BannerLines(Trigger{DiscoveryMode: true, AllowConnect: true})
	if len(lines) != 2 {
		t.Fatalf("expected 2 banner lines, got %d: %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "§B8") {
		t.Errorf("banner missing §B8 line: %v", lines)
	}
	if !strings.Contains(joined, "§B9") {
		t.Errorf("banner missing §B9 line: %v", lines)
	}

	// Nothing triggered → no lines (the founder's "useful, not noise"
	// directive).
	if lines := BannerLines(Trigger{}); len(lines) != 0 {
		t.Errorf("expected 0 banner lines for empty Trigger, got %v", lines)
	}
}

func TestDoctorEntriesCoversCrossProduct(t *testing.T) {
	ids := map[string]bool{}
	for _, e := range DoctorEntries() {
		ids[e.ID] = true
	}
	for _, must := range []string{"B8", "B9", "B13", "B14", "B15"} {
		if !ids[must] {
			t.Errorf("doctor entries missing %s", must)
		}
	}
}

func TestCanonicalDocURL(t *testing.T) {
	got := CanonicalDocURL()
	if !strings.HasSuffix(got, "/KNOWN-CAVEATS.md") {
		t.Errorf("CanonicalDocURL should end with /KNOWN-CAVEATS.md, got %q", got)
	}
}
