// Package caveats surfaces relevant §B entries from the canonical
// KNOWN-CAVEATS.md doc at three discoverability surfaces:
//
//   - `gbounce run` startup banner (one-line hints when a triggering
//     config is detected)
//   - `gbounce doctor caveats` (full §B explanation per matched entry,
//     plus link to canonical doc)
//   - HTTP error response bodies on §A-classified denies (link to the
//     specific §B/§A entry so an operator hitting a deny doesn't have
//     to grep)
//
// The canonical caveat content lives in
// https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md.
// THIS package does NOT duplicate the full content — only the short
// summary string + the anchor — because:
//   - the canonical doc is owned by the iam-roles repo (concurrent edit
//     hazard if we copy verbatim across four repos);
//   - the one-line banner + the doctor's short blurb is enough to point
//     an operator at the linked anchor for the full read.
//
// Per [[deliberate-feature-completion]]: each Bounce product surfaces
// only the §B entries that genuinely apply to ITS shape. Cross-product
// entries (B13 / B14 / B15) appear in every product's caveats list;
// product-specific entries appear only in the matching repo.
//
// Per [[security-team-positioning-safety-not-surveillance]]: the
// language across the banner + doctor + error surfaces is helpful
// ("here's what's happening + here's the doc") not accusatory.
package caveats

import "fmt"

// canonicalDocURL is the GitHub-rendered KNOWN-CAVEATS.md URL all
// surfaces link to. Kept centralized so a future repo move only
// updates one constant.
const canonicalDocURL = "https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md"

// Entry describes one row from KNOWN-CAVEATS §B that gbounce surfaces.
// The Anchor field is the GitHub auto-generated markdown anchor; the
// URL() helper builds the full link.
type Entry struct {
	// ID is the short identifier (e.g. "B8") that an operator + a
	// docs reader can pivot on.
	ID string
	// Anchor is the GitHub auto-generated markdown anchor for the
	// matching §B subsection in KNOWN-CAVEATS.md. Format:
	// lowercase + hyphens + no punctuation; matches GitHub's renderer.
	Anchor string
	// BannerLine is the SINGLE LINE the startup banner emits when this
	// caveat's triggering config is detected. Empty when the entry has
	// no banner surface (some caveats only appear in `doctor caveats`).
	BannerLine string
	// DoctorBlurb is the 2-3 sentence explanation `gbounce doctor
	// caveats` prints. Kept short on purpose — the linked anchor is
	// the canonical source.
	DoctorBlurb string
}

// URL builds the full GitHub URL pointing at this entry's anchor.
func (e Entry) URL() string {
	return canonicalDocURL + "#" + e.Anchor
}

// All gbounce-relevant §B entries. Selected per task #304:
//   - product-specific: B8, B9
//   - cross-product: B13, B14, B15
//
// Per the founder direction "don't pile every caveat onto every
// surface" — gbounce does NOT carry ibounce/kbounce/dbounce
// product-specific entries. An operator using gbounce shouldn't see
// SigV4 / kubectl / SQL-redaction noise.
var All = []Entry{
	{
		ID:     "B8",
		Anchor: "b8-gbounce---allow-connect-only-sees-hostport-design",
		BannerLine: "  caveat: HTTPS CONNECT tunnels show host:port only " +
			"(no MITM); see KNOWN-CAVEATS §B8. " +
			"Run `gbounce ca install` + `gbounce run --mode mitm` (#315) " +
			"to opt into URL-level visibility.",
		DoctorBlurb: "HTTPS through gbounce shows `CONNECT host:443` only " +
			"in the default discovery mode. The TLS tunnel is spliced " +
			"blindly (no MITM), so URL paths + request bodies are NOT " +
			"visible in the audit log. This is the deliberate honest-" +
			"positioning trade-off per [[ibounce-honest-positioning]] " +
			"— more privacy + deployability at the cost of URL-level " +
			"audit visibility. For URL-level visibility, opt INTO MITM " +
			"mode (#315 / §A13): run `gbounce ca install` to generate " +
			"a local CA, add it to your OS trust store, then start the " +
			"proxy with `--mode mitm`. Cert-pinning SDKs will break " +
			"under MITM — flip those back to discovery mode.",
	},
	{
		ID:     "B9",
		Anchor: "b9-gbounce-g-slice-1--discovery-only-gap--v11",
		BannerLine: "  caveat: G-Slice 1 is discovery-only (observation, " +
			"no blocking); v1.1 adds profile gating per KNOWN-CAVEATS §B9",
		DoctorBlurb: "gbounce v1.0 (G-Slice 1) ships discovery mode only — " +
			"every request is observed + audit-logged + forwarded. There is " +
			"NO profile-mode gating yet (queued for G-Slice 2, v1.1). If you " +
			"need to BLOCK traffic in v1.0, point gbounce at an egress " +
			"firewall or a network policy upstream.",
	},
	{
		ID:     "B13",
		Anchor: "b13-cross-product-1-3-concurrent-terminals-in-v10-gap--v11-raises-to-20",
		DoctorBlurb: "gbounce shares the cross-product 1-3 concurrent " +
			"terminal limit with ibounce + kbounce + dbounce. Session " +
			"attribution gets noisy past 3 concurrent terminals. v1.1 " +
			"task #296 raises this to 20.",
	},
	{
		ID:     "B14",
		Anchor: "b14-cross-product-defense-in-depth--unified-product-design-per-four-products-one-brand",
		DoctorBlurb: "gbounce is one of four Bounce products under one " +
			"brand — NOT a unified suite. ~10% of decisions show TRUE " +
			"multi-layer composition per UAT. The honest framing per " +
			"[[ibounce-honest-positioning]]: complementary products, not " +
			"a single integrated suite.",
	},
	{
		ID:     "B15",
		Anchor: "b15-cross-product-no-unified-deny-prompt-ui-in-v10-gap--v11",
		DoctorBlurb: "Each bouncer (gbounce / kbounce / dbounce / ibounce) " +
			"prompts independently in v1.0. v1.1 brings a unified prompt-" +
			"inbox UI across the suite.",
	},
}

// ByID returns the Entry with the given ID (e.g. "B9"), or nil if no
// entry matches. Used by error-message helpers that want to link to a
// specific anchor without hard-coding the URL string.
func ByID(id string) *Entry {
	for i := range All {
		if All[i].ID == id {
			return &All[i]
		}
	}
	return nil
}

// LinkSuffix returns "(see <URL>)" for an entry by ID, suitable for
// appending to an HTTP error response body. Empty string when the ID
// isn't recognized — callers should still emit the bare error rather
// than a malformed link.
func LinkSuffix(id string) string {
	e := ByID(id)
	if e == nil {
		return ""
	}
	return fmt.Sprintf(" (see KNOWN-CAVEATS §%s: %s)", e.ID, e.URL())
}

// CanonicalDocURL returns the base URL operators can read for the
// full caveat list (without an anchor). Surfaced in `doctor caveats`
// output's footer + the README "Known Limitations" link.
func CanonicalDocURL() string {
	return canonicalDocURL
}

// Trigger captures the runtime conditions that determine which §B
// entries the startup banner + `doctor caveats` should surface.
//
// Per the founder direction: only print a banner / doctor line when
// the triggering config actually fires — don't spam the operator with
// every §B entry on every run.
type Trigger struct {
	// DiscoveryMode is true when the proxy runs in discovery mode
	// (the only G-Slice 1 mode). Triggers B9.
	DiscoveryMode bool
	// AllowConnect is true when `--allow-connect` is set. Triggers B8
	// (HTTPS CONNECT visibility limit).
	AllowConnect bool
	// #315 / §A13 — MITMMode is true when `--mode mitm` is set.
	// Triggers the MITM-mode honest-positioning banner (cert-pinning
	// SDKs break + bodies are redacted by default).
	MITMMode bool
}

// BannerLines returns the per-line banner output for the matched
// caveats given the runtime trigger. Returned as a slice so the
// caller can iterate + emit each on its own line via the proxy's
// existing banner-write loop.
func BannerLines(t Trigger) []string {
	var out []string
	if t.AllowConnect {
		if e := ByID("B8"); e != nil && e.BannerLine != "" {
			out = append(out, e.BannerLine)
		}
	}
	if t.DiscoveryMode {
		if e := ByID("B9"); e != nil && e.BannerLine != "" {
			out = append(out, e.BannerLine)
		}
	}
	if t.MITMMode {
		out = append(out,
			"  #315 / §A13 — MITM mode is ACTIVE: TLS intercepted via the local CA, "+
				"bodies redacted by default. Cert-pinning SDKs (some AWS SDKs, banking "+
				"SDKs, mobile SDKs) WILL break; flip those clients back to "+
				"`--mode discovery --allow-connect`. See docs/MITM-MODE.md.")
	}
	return out
}

// DoctorEntries returns the entries `gbounce doctor caveats` should
// print. ALL gbounce-relevant entries are listed (not just triggered
// ones) so the operator gets the full picture from `doctor caveats`
// regardless of how the proxy was started.
func DoctorEntries() []Entry {
	return All
}
