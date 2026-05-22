// Cobra `gbounce profile ...` subcommands.
//
// v1.0 carries only the `doctor` subcommand per cross-product CLI
// parity (task #321 / KNOWN-CAVEATS §A19). gbounce doesn't ship a
// profiles.yaml in v1.0 — profile rules are explicit-file via
// --profile-rules-file (JSON) — but the doctor surface exists so an
// orchestrator can run `<product> profile doctor` against any
// Bounce product without per-product branching. G-Slice 2 will
// extend this with list / show / install once gbounce gains a YAML
// profiles surface.

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/profile"
)

// newProfileCmd implements `gbounce profile ...`.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage gbounce profiles (v1.0: doctor only — see G-Slice 2 for list/show/install)",
		Long: `gbounce v1.0 ships only the ` + "`gbounce profile doctor`" + ` subcommand
for cross-product CLI parity with ibounce + kbouncer + dbounce.

gbounce profile rules are loaded via ` + "`--profile-rules-file`" + ` (JSON)
or ` + "`--deny-host`" + ` / ` + "`--deny-hosts-file`" + ` (newline / YAML list) on
` + "`gbounce run`" + `, not from a shipped-default profiles.yaml in the
home directory. There's no shipped-default profile that could
silently go behind in v1.0 — so ` + "`gbounce profile doctor`" + ` always
reports "current" + a Notes line explaining the architectural
difference.

G-Slice 2 (queued) will add the YAML profiles surface + the full
doctor / list / show / install surface in lockstep with the other
three bouncers.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			fmt.Fprintln(c.ErrOrStderr(),
				"gbounce: missing subcommand for \"profile\"; see `gbounce profile --help` for valid subs")
			os.Exit(1)
		}
		fmt.Fprintf(c.ErrOrStderr(),
			"gbounce: unknown subcommand %q for \"profile\"; see `gbounce profile --help` for valid subs\n",
			args[0])
		os.Exit(1)
		return nil
	}
	cmd.AddCommand(newProfileDoctorCmd())
	return cmd
}

// newProfileDoctorCmd implements `gbounce profile doctor` per task
// #321 / KNOWN-CAVEATS §A19. v1.0: reports "current" (no shipped
// defaults). Same flag shape as the sibling products so a cross-
// product orchestrator's invocation works uniformly.
func newProfileDoctorCmd() *cobra.Command {
	var (
		profilesPath string
		apply        bool
		acknowledge  bool
		checkOnly    bool
		jsonOut      bool
		showDiff     bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diff installed profile against shipped defaults (v1.0: no-op — see Notes)",
		Long: `Compare gbounce's installed profile against the shipped defaults
and report any fields the operator's local file is missing.

v1.0 contract: gbounce ships no default profiles.yaml; profile
rules are explicit-file. The doctor surface always reports "current"
+ a Notes line explaining the architectural difference. Same flag
shape as ibounce / kbouncer / dbounce per [[cross-product-agent-parity]].

  gbounce profile doctor              # report missing fields (v1.0: none)
  gbounce profile doctor --apply      # no-op in v1.0
  gbounce profile doctor --acknowledge # no-op in v1.0
  gbounce profile doctor --check      # silent; exit 0 (no gaps possible in v1.0)
  gbounce profile doctor --json       # machine-readable JSON envelope
  gbounce profile doctor --diff       # show YAML --apply would write (v1.0: empty)

G-Slice 2 ships the full doctor surface with the YAML profiles
addition.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if apply && acknowledge {
				return fmt.Errorf("--apply and --acknowledge are mutually exclusive")
			}
			rep, err := profile.Check(profilesPath)
			if err != nil {
				return err
			}
			if apply {
				result, aerr := profile.Apply(profilesPath)
				if aerr != nil {
					return aerr
				}
				if len(result.AppliedFields) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"gbounce: profile doctor — nothing to apply; installed profile matches shipped defaults (version %s).\n",
						profile.ShippedDefaultsVersion)
					if rep.Notes != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", rep.Notes)
					}
					return nil
				}
				return nil
			}
			if acknowledge {
				path, aerr := profile.Acknowledge(profilesPath)
				if aerr != nil {
					return aerr
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"gbounce: profile doctor --acknowledge — recorded %s at %s (v1.0 no-op; nothing to acknowledge yet)\n",
					profile.ShippedDefaultsVersion, path)
				return nil
			}
			if checkOnly {
				if len(rep.MissingFields) > 0 {
					os.Exit(2)
				}
				return nil
			}
			if jsonOut {
				type jsonGap struct {
					Profile  string `json:"profile"`
					Field    string `json:"field"`
					Category string `json:"category"`
					Why      string `json:"why"`
					AddedIn  string `json:"added_in"`
					Default  any    `json:"default"`
				}
				out := struct {
					Version       string    `json:"shipped_defaults_version"`
					InstalledPath string    `json:"installed_path"`
					Missing       []jsonGap `json:"missing"`
					Notes         string    `json:"notes,omitempty"`
				}{
					Version: rep.ShippedDefaultsVersion, InstalledPath: rep.InstalledPath,
					Notes: rep.Notes,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				if len(rep.MissingFields) > 0 {
					os.Exit(2)
				}
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), profile.FormatReport("gbounce", rep))
			if showDiff && len(rep.MissingFields) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "--- YAML that --apply would add ---")
				for _, g := range rep.MissingFields {
					fmt.Fprintf(cmd.OutOrStdout(),
						"profiles.%s.%s: %v\n",
						g.ProfileName, g.Field, g.DefaultValue)
				}
			}
			if len(rep.MissingFields) > 0 {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (v1.0: gbounce doesn't ship one; reserved for G-Slice 2).")
	cmd.Flags().BoolVar(&apply, "apply", false,
		"Additively merge missing default fields (v1.0: no-op).")
	cmd.Flags().BoolVar(&acknowledge, "acknowledge", false,
		"Record the current shipped-defaults version as acknowledged (v1.0: no-op).")
	cmd.Flags().BoolVar(&showDiff, "diff", false,
		"Print the YAML fragment --apply would add (v1.0: always empty).")
	cmd.Flags().BoolVar(&checkOnly, "check", false,
		"Silent mode: exit 0 if current (v1.0: always current).")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"Emit machine-readable JSON envelope (matches sibling products).")
	return cmd
}
