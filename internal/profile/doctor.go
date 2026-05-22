// Package profile — doctor.go
//
// `gbounce profile doctor` — cross-product parity surface for the
// upgrade-blindness detection introduced in task #321 / KNOWN-CAVEATS
// §A19. Same command + flag shape as ibounce + kbouncer + dbounce per
// [[cross-product-agent-parity]] so orchestrators can run
// `<product> profile doctor` uniformly.
//
// Architectural honesty: gbounce v1.0 does NOT manage a
// profiles.yaml in the home directory the way the other three
// bouncers do. gbounce's profile-rules shape is a JSON file the
// operator passes explicitly via `--profile-rules-file` (or the
// per-host deny shape via `--deny-host` / `--deny-hosts-file`).
// There's no shipped-default profile that could silently go behind
// without the operator's knowledge, because there's no shipped-
// default profile at all in v1.0.
//
// What this surface DOES today (v1.0):
//
//   - `gbounce profile doctor` reports "no shipped defaults to
//     compare against" — honest about the architectural difference.
//   - `gbounce profile doctor --check` exits 0 (current shape:
//     nothing can be behind).
//   - `gbounce profile doctor --json` emits the same JSON envelope
//     as the sibling products so cross-product orchestrators get a
//     consistent shape.
//
// What this surface WILL do in v1.1 (when G-Slice 2 ships the YAML
// profiles surface):
//
//   - Same Check / Apply / Acknowledge semantics as dbounce +
//     kbouncer + ibounce, with the shipped-defaults catalog
//     populated as G-Slice 2 adds safety floors.
//
// Per [[security-team-positioning-safety-not-surveillance]]: framed
// as "your profile is behind" not "you are non-compliant."

package profile

import (
	"fmt"
	"strings"
)

// FieldCategory mirrors the cross-product enum. Kept here so the
// JSON output shape matches even though gbounce currently has zero
// shipped defaults to report against.
type FieldCategory string

const (
	CategorySafetyFloor FieldCategory = "safety-floor"
	CategoryDetection   FieldCategory = "detection"
	CategoryAudit       FieldCategory = "audit"
	CategoryConvenience FieldCategory = "convenience"
)

// FieldGap mirrors the cross-product shape.
type FieldGap struct {
	ProfileName  string
	Field        string
	Category     FieldCategory
	WhyMatters   string
	AddedIn      string
	DefaultValue any
}

// Report mirrors the cross-product shape. v1.0: MissingFields is
// always empty for gbounce (no shipped defaults to be behind).
type Report struct {
	MissingFields          []FieldGap
	InstalledPath          string
	ShippedDefaultsVersion string
	// Notes carries the architectural-honesty line shown to the
	// operator when there's nothing to report. Empty in the sibling
	// products' Reports (they don't need to explain "we have shipped
	// defaults"; their existence is implicit).
	Notes string
}

// HasSafetyFloorGap returns false in v1.0 (no shipped defaults).
func (r *Report) HasSafetyFloorGap() bool {
	if r == nil {
		return false
	}
	for _, g := range r.MissingFields {
		if g.Category == CategorySafetyFloor {
			return true
		}
	}
	return false
}

// ShippedDefaultsVersion is the version stamp baked into the
// embedded defaults. Bumped in lockstep with the other bouncers
// when gbounce ships its first shipped-default profile.
const ShippedDefaultsVersion = "2026-05-22-321"

// shippedDefaultsCatalog is empty in v1.0. G-Slice 2 will populate
// it as profiles ship.
var shippedDefaultsCatalog = []FieldGap{}

// Check returns a Report that's always current in v1.0. The
// ``Notes`` field explains the architectural difference so an
// operator who runs the command isn't left wondering whether the
// silence is a bug.
func Check(_ string) (*Report, error) {
	return &Report{
		ShippedDefaultsVersion: ShippedDefaultsVersion,
		Notes: "gbounce v1.0 does not ship a default profiles.yaml; " +
			"profile rules are loaded explicitly via " +
			"--profile-rules-file (JSON) or --deny-host / " +
			"--deny-hosts-file (newline / YAML list). There are no " +
			"shipped defaults to be behind. G-Slice 2 will introduce " +
			"a YAML profiles surface alongside the existing shapes; " +
			"this surface will populate the doctor catalog at that " +
			"time so older installs surface missing safety floors " +
			"the same way dbounce / kbouncer / ibounce do today.",
	}, nil
}

// ApplyResult mirrors the cross-product shape. v1.0: always zero.
type ApplyResult struct {
	BackupPath    string
	AppliedFields []FieldGap
}

// Apply is a no-op in v1.0 (no shipped defaults to merge). Returns
// a zero ApplyResult so callers don't need a special-case branch.
func Apply(_ string) (*ApplyResult, error) {
	return &ApplyResult{}, nil
}

// Acknowledge is a no-op in v1.0 (nothing to acknowledge). Returns
// the path it WOULD write to so the CLI message stays useful.
func Acknowledge(profilesPath string) (string, error) {
	if profilesPath == "" {
		profilesPath = "~/.gbounce/profiles.yaml"
	}
	return profilesPath + ".acknowledged-version-placeholder", nil
}

// IsAcknowledged returns true in v1.0 (nothing requires
// acknowledgement, so we report acknowledged-by-default).
func IsAcknowledged(_ string) bool {
	return true
}

// StartupBannerLine returns "" in v1.0 — there are no shipped
// defaults to be behind, so no startup caveat fires. Kept for cross-
// product parity so `gbounce run` can call it uniformly.
func StartupBannerLine(_ string, _ string) string {
	return ""
}

// FormatReport mirrors the cross-product shape.
func FormatReport(product string, r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"%s: profile doctor — installed profile matches shipped defaults (version %s).\n",
		product, ShippedDefaultsVersion)
	if r != nil && r.Notes != "" {
		fmt.Fprintf(&b, "\n%s\n", r.Notes)
	}
	return b.String()
}
