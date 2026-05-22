// `gbounce doctor` — operator-friendly health + caveat surface.
//
// Per task #304 + the founder direction "caveats must be easily
// discoverable to users + agents, not buried in docs/KNOWN-CAVEATS.md":
// `gbounce doctor caveats` lists every §B entry that genuinely applies
// to gbounce + links to the canonical doc.
//
// Sibling Bounce products ship the same `*bounce doctor caveats`
// subcommand shape per [[cross-product-agent-parity]] so an operator's
// muscle memory ("run doctor on the bouncer you're confused by") works
// uniformly across kbounce / dbounce / ibounce / gbounce.
//
// Per [[creates-never-mutates]]: this is a strictly READ-ONLY command.
// Per [[security-team-positioning-safety-not-surveillance]]: language
// is helpful, never accusatory.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/caveats"
)

// newDoctorCmd assembles `gbounce doctor` + the `caveats` subcommand.
// Registered with no aliases — `doctor` is the cross-product canonical
// shape (matches ibounce/kbounce/dbounce per cross-product-agent-
// parity).
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Operator-friendly health + caveat surfaces",
		Long: `Subcommands:

  caveats   Print the §B entries from KNOWN-CAVEATS.md that apply to
            gbounce (including cross-product entries shared with the
            other Bounce products).

Sibling Bounce products (ibounce / kbounce / dbounce) ship the same
` + "`{product} doctor caveats`" + ` subcommand. The full canonical doc
lives at ` + caveats.CanonicalDocURL() + `.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return fmt.Errorf("gbounce doctor: subcommand required (try `gbounce doctor caveats`)")
	}
	cmd.AddCommand(newDoctorCaveatsCmd())
	// #311 / §A10 — audit-log integrity / freshness / disk check.
	cmd.AddCommand(newDoctorLogsCmd())
	return cmd
}

// newDoctorCaveatsCmd prints the gbounce-relevant §B entries from
// KNOWN-CAVEATS.md. Per task #304: deterministic list (every
// gbounce-applicable entry); no inference from runtime state. The
// banner already surfaces the runtime-triggered subset on startup;
// `doctor caveats` is the "everything that could possibly apply" view
// for an operator doing pre-flight reading.
func newDoctorCaveatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "caveats",
		Short: "Print KNOWN-CAVEATS §B entries that apply to gbounce",
		Long: `Print the §B (documented limits, not launch-blocking) entries
from KNOWN-CAVEATS.md that apply to gbounce. Includes product-specific
caveats (B8, B9) + cross-product caveats shared with kbounce/dbounce/
ibounce (B13, B14, B15).

Full canonical doc: ` + caveats.CanonicalDocURL() + `

Per [[creates-never-mutates]]: read-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "gbounce: KNOWN-CAVEATS §B entries that apply to this product")
			fmt.Fprintln(w, "Full canonical doc:", caveats.CanonicalDocURL())
			fmt.Fprintln(w)
			for _, e := range caveats.DoctorEntries() {
				fmt.Fprintf(w, "§%s\n", e.ID)
				fmt.Fprintf(w, "  %s\n", e.DoctorBlurb)
				fmt.Fprintf(w, "  link: %s\n\n", e.URL())
			}
			return nil
		},
	}
}
