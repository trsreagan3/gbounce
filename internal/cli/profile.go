// Cobra `gbounce profile ...` subcommands.
//
// v1.0 ships:
//
//   - `gbounce profile doctor` — cross-product CLI parity surface
//     (task #321 / KNOWN-CAVEATS §A19).
//
//   - `gbounce profile install` — §A27 (#352): install a YAML profile
//     bundle emitted by `iam-jit profile generate-from-audit` (or
//     hand-authored). Pre-§A27 the generator's `gbounce.yaml` slot
//     had no install path, breaking the launch claim that "the
//     generator emits a working profile for all 4 bouncers."
//
//   - `gbounce profile list` — §A42 (#378): print all profiles in
//     profiles.yaml + mark which is active. Mirrors kbouncer +
//     dbounce + ibouncer shape per [[cross-product-agent-parity]].
//
//   - `gbounce profile show NAME` — §A42 (#378): print the profile's
//     fields for inspection. Mirrors siblings' shape.

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/profile"
)

// newProfileCmd implements `gbounce profile ...`.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage gbounce profiles (doctor + install)",
		Long: `gbounce profile management.

  gbounce profile doctor    diff installed profile against shipped
                            defaults (v1.0: no-op — gbounce ships no
                            defaults yet; surface exists for cross-
                            product CLI parity with ibounce + kbouncer
                            + dbounce per [[cross-product-agent-parity]])

  gbounce profile install   install profile YAML from a URL / file /
                            generator-emitted bundle directory.
                            Accepts the canonical ` + "`profiles:`" + `
                            shape AND the per-bouncer single-profile
                            shape (` + "`schema_version` + `profile_name`" + ` +
                            ` + "`bouncer` + `denies` + `allows`" + `)
                            emitted by ` + "`iam-jit profile generate-from-audit`" + `.`,
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
	cmd.AddCommand(newProfileInstallCmd())
	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileShowCmd())
	cmd.AddCommand(newProfileAllowCmd())
	return cmd
}

// newProfileListCmd implements `gbounce profile list` per #378 / §A42.
// Symmetric with kbouncer / dbounce / ibouncer per
// [[cross-product-agent-parity]]. Prints all profiles in profiles.yaml
// + marks the one named by --profile (or GBOUNCE_PROFILE) as active.
func newProfileListCmd() *cobra.Command {
	var (
		profileName  string
		profilesPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available profiles and show which is active",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profileName == "" {
				profileName = os.Getenv("GBOUNCE_PROFILE")
			}
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			profiles, err := profile.LoadProfiles(profilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			active, _ := profiles.Active(profileName)
			source := "embedded defaults"
			if profiles.Path != "" {
				source = profiles.Path
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"gbounce profiles (source: %s)\n", source)
			if profileName != "" && active == nil {
				fmt.Fprintf(cmd.OutOrStdout(),
					"WARNING: requested profile %q is not in this file. "+
						"`gbounce run --profile %q` would refuse to start.\n",
					profileName, profileName)
			}
			names := profiles.NamesSorted()
			if len(names) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(),
					"  (no profiles installed; use `gbounce profile install --from URL_OR_PATH`)")
				return nil
			}
			for _, name := range names {
				p := profiles.All[name]
				marker := "  "
				if active != nil && p.Name == active.Name && profileName != "" {
					marker = "* "
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%-20s %s\n", marker, name, p.Description)
				if len(p.DenyHosts) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_hosts:  %s\n", strings.Join(p.DenyHosts, ", "))
				}
				if n := len(p.DenyRules); n > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_rules:  %d\n", n)
				}
				if n := len(p.AllowRules); n > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    allow_rules: %d (enforced in MITM mode; overrides deny_rules, not deny_hosts)\n", n)
				}
				if p.Source != "" && p.Source != "local" {
					fmt.Fprintf(cmd.OutOrStdout(), "    source:      %s (READ-ONLY)\n", p.Source)
				}
			}
			if profileName == "" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"\n(no profile selected; pass --profile NAME or set GBOUNCE_PROFILE)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Profile to mark as active in the listing. Falls back to GBOUNCE_PROFILE.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.gbounce/profiles.yaml).")
	return cmd
}

// newProfileShowCmd implements `gbounce profile show NAME` per
// #378 / §A42. Prints the named profile's fields for inspection.
// Symmetric with kbouncer / dbounce / ibouncer per
// [[cross-product-agent-parity]].
func newProfileShowCmd() *cobra.Command {
	var profilesPath string
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show full detail for a single profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			profiles, err := profile.LoadProfiles(profilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			p, err := profiles.Active(name)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"gbounce: profile %q not found (loaded: %s)\n",
					name, strings.Join(profiles.NamesSorted(), ", "))
				os.Exit(1)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "name:         %s\n", p.Name)
			if p.Description != "" {
				fmt.Fprintf(w, "description:  %s\n", p.Description)
			}
			source := p.Source
			if source == "" {
				source = "local"
			}
			fmt.Fprintf(w, "source:       %s\n", source)
			if len(p.DenyHosts) > 0 {
				fmt.Fprintln(w, "deny_hosts:")
				for _, h := range p.DenyHosts {
					fmt.Fprintf(w, "  - %s\n", h)
				}
			}
			if n := len(p.DenyRules); n > 0 {
				fmt.Fprintf(w, "deny_rules: %d\n", n)
				for _, r := range p.DenyRules {
					line := r.Host
					if r.PathPrefix != "" {
						line += " path_prefix=" + r.PathPrefix
					}
					if r.Path != "" {
						line += " path=" + r.Path
					}
					if r.PathRegex != "" {
						line += " path_regex=" + r.PathRegex
					}
					switch m := r.Method.(type) {
					case string:
						if m != "" {
							line += " method=" + m
						}
					case []string:
						if len(m) > 0 {
							line += " methods=" + strings.Join(m, ",")
						}
					}
					if r.Reason != "" {
						line += " (" + r.Reason + ")"
					}
					fmt.Fprintf(w, "  - %s\n", line)
				}
			}
			if n := len(p.AllowRules); n > 0 {
				fmt.Fprintf(w, "allow_rules: %d (enforced in MITM mode; overrides deny_rules, not deny_hosts)\n", n)
				for _, r := range p.AllowRules {
					fmt.Fprintf(w, "  - %s\n", r.Host)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.gbounce/profiles.yaml).")
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
		"Path to profiles.yaml (default: ~/.gbounce/profiles.yaml; honors GBOUNCE_PROFILES_PATH).")
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

// newProfileInstallCmd implements `gbounce profile install` per
// §A27 (#352). Symmetric with kbouncer / dbounce / ibouncer `profile
// install`; same exit-code mapping; same source URL semantics.
//
// Exit codes:
//
//	0  success
//	1  payload / fetch problem (malformed YAML, validation error,
//	   fetch failed) — usually an upstream-curator issue
//	2  operator-fixable problem (unknown scheme, sha256 mismatch,
//	   conflict without --force)
func newProfileInstallCmd() *cobra.Command {
	var (
		fromURL        string
		expectedSHA256 string
		force          bool
		timeoutSecs    int
		profilesPath   string
		auditLogPath   string
	)
	cmd := &cobra.Command{
		Use:   "install --from URL_OR_PATH [--sha256 HEX] [--force] [--timeout 10]",
		Short: "Fetch + install profiles from a URL, file, or generator bundle",
		Long: `Install profiles from any of:

  * an HTTPS URL — preferred + recommended distribution channel
    (IT teams publish curated profiles at an internal URL, engineers
    install them on day 1).

      gbounce profile install --from https://internal.example/profiles.yaml

  * an HTTP URL — accepted for local-dev parity with the audit-export
    HTTP surface. A one-line WARN fires for non-loopback hosts;
    loopback gets a silent pass.

  * file:///abs/path/...  or a bare local path (relative or absolute)
    — accepts a single YAML file OR a bundle directory produced by
    ` + "`iam-jit profile generate-from-audit`" + `; the directory
    form looks for ` + "`gbounce.yaml`" + ` first then falls back to
    ` + "`index.yaml`" + ` + the bouncer entry naming gbounce.

      gbounce profile install --from ./profiles/

The source string becomes the ` + "`source`" + ` of each installed
profile. Profiles with a non-local source are READ-ONLY at the CLI
surface — engineers cannot edit them to bypass org guardrails (the
canonical write entry point, UpsertProfile, refuses to overwrite).

Conflict policy: if a profile of the same name already exists,
install refuses without --force. --force overrides the conflict
gate but still records the new source.

Generator schema bridge: the generator emits a per-bouncer YAML with
top-level ` + "`schema_version` + `profile_name` + `bouncer` + `denies` + `allows`" + `
fields. gbounce's parser accepts BOTH that shape and the canonical
` + "`profiles:`" + ` shape, mapping ` + "`denies[].target`" + ` (hostname or
` + "`*.domain`" + `) into ` + "`deny_hosts`" + ` and rules with
explicit ` + "`actions:` / `target: host/path`" + ` into ` + "`deny_rules`" + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := profile.InstallOptions{
				From:           fromURL,
				ExpectedSHA256: expectedSHA256,
				Force:          force,
				Timeout:        time.Duration(timeoutSecs) * time.Second,
				ProfilesPath:   profilesPath,
			}
			// Per §A26 mirror: WARN for non-loopback http://. We do
			// NOT block at the profile package layer (local-dev parity
			// with the audit-export HTTP surface); the warning surfaces
			// at the CLI so the operator sees it.
			if parsed, perr := neturl.Parse(fromURL); perr == nil &&
				strings.EqualFold(parsed.Scheme, "http") {
				host := parsed.Hostname()
				isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
				if !isLoopback {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"WARN: fetching %q over plaintext HTTP — a network "+
							"attacker can MITM-substitute a permissive profile. "+
							"Prefer https:// for IT-distributed profiles. This "+
							"warning does NOT block the install (per §A26 local-"+
							"dev parity with audit-export HTTP).\n", fromURL)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "loading %s ...\n", fromURL)
			result, err := profile.Install(cmd.Context(), opts)
			if err != nil {
				var ie *profile.InstallError
				if errors.As(err, &ie) {
					fmt.Fprintln(cmd.ErrOrStderr(), ie.Message)
					os.Exit(ie.ExitCode)
				}
				return err
			}

			// Admin-action audit event per [[cross-product-agent-parity]]:
			// kbounce + dbounce + ibouncer emit the same OCSF row on
			// install. Only fires when --audit-log-path is set (gbounce's
			// established pattern across backup / config / diagnostics).
			emitAdminAction(auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionProfileInstall,
				Actor:      currentActor(),
				EntityKind: "profile",
				EntityName: strings.Join(result.InstalledNames, ","),
				Source:     audit.AdminActionSourceCLI,
				Before:     nil,
				After: map[string]any{
					"installed_profiles": result.InstalledNames,
					"source":             result.SourceURL,
					"sha256":             result.SHA256,
				},
				ExtraExt: map[string]any{
					"source":          result.SourceURL,
					"sha256":          result.SHA256,
					"sha256_verified": result.SHA256Verified,
					"installed_count": len(result.InstalledNames),
					"profiles_path":   result.ProfilesPath,
				},
			})

			if result.SHA256Verified {
				fmt.Fprintf(cmd.OutOrStdout(), "sha256 verified: %s\n", result.SHA256)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "sha256 (no pin given): %s\n", result.SHA256)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"installed %d profile(s) into %s:\n",
				len(result.InstalledNames), result.ProfilesPath)
			for _, name := range result.InstalledNames {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", name)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(),
				"These profiles are READ-ONLY (sourced from URL); "+
					"edit the upstream YAML + re-install to update.")
			return nil
		},
	}
	cmd.Flags().StringVar(&fromURL, "from", "",
		"URL or local path of a profile YAML / bundle. Required.")
	_ = cmd.MarkFlagRequired("from")
	cmd.Flags().StringVar(&expectedSHA256, "sha256", "",
		"Optional SHA-256 (hex) of the fetched bytes. Mismatch → exit 2.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite existing profiles of the same name.")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 10,
		"HTTPS fetch timeout in seconds.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.gbounce/profiles.yaml; honors GBOUNCE_PROFILES_PATH).")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Append the admin-action OCSF event to this JSONL audit log. "+
			"When empty, the install is performed but NOT recorded in the "+
			"audit-export channel. Point this at the same file the proxy "+
			"daemon's --audit-log-path uses so all events land in one stream.")
	return cmd
}

