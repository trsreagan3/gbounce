// ca.go — `gbounce ca {install,uninstall,info,rotate}` subcommands.
// #315 / §A13. The CA lifecycle commands for the optional MITM mode.
//
// Default-off: the operator must explicitly run `gbounce ca install`
// before `gbounce run --mode mitm` will start. Per
// `[[creates-never-mutates]]` MITM is additive — the install command
// writes the CA cert + key to disk; the OS trust-store install is a
// separate operator step (we print the platform-specific command and
// let them run it).
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/mitm"
	"github.com/trsreagan3/gbounce/internal/profile"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the local MITM CA (install / uninstall / info / rotate)",
		Long: `Manage the local MITM CA used by ` + "`gbounce run --mode mitm`" + `.

The CA lives at ~/.iam-jit/gbounce/ca/. It is generated locally + never
phones home (per [[self-host-zero-billing-dependency]]); the cert
Common Name is the generic string "iam-jit gbounce local CA" — no
personally identifying info.

Lifecycle:

  gbounce ca install     generate the CA cert + key + print the
                         platform-specific OS-trust-store install
                         command (operator runs that themselves)

  gbounce ca info        print cert subject / issuer / validity /
                         SHA-256 fingerprint

  gbounce ca rotate      generate a new CA cert + key (the OLD cert
                         must be removed from the OS trust store
                         separately; print the reminder)

  gbounce ca uninstall   remove the CA cert + key from disk + print
                         the OS-trust-store cleanup reminder

Cert-pinning SDKs (most modern AWS SDKs, banking SDKs, some mobile
SDKs) will REFUSE to talk to a MITM'd upstream — gbounce returns a
clear error message in that case so the operator knows to flip back
to CONNECT mode for those clients.`,
	}
	cmd.AddCommand(newCAInstallCmd())
	cmd.AddCommand(newCAUninstallCmd())
	cmd.AddCommand(newCAInfoCmd())
	cmd.AddCommand(newCARotateCmd())
	return cmd
}

func newCAInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Generate a local MITM CA at ~/.iam-jit/gbounce/ca/",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := mitm.DefaultCAPaths()
			if err != nil {
				return err
			}
			cert, _, err := mitm.GenerateCA(paths, false /*overwrite*/)
			if err != nil {
				return err
			}
			info, err := mitm.Info(paths)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "gbounce CA generated:\n")
			fmt.Fprintf(w, "  cert: %s\n", paths.CertFile)
			fmt.Fprintf(w, "  key:  %s (mode 0600)\n", paths.KeyFile)
			fmt.Fprintf(w, "  subject:      %s\n", info.Subject)
			fmt.Fprintf(w, "  fingerprint:  %s\n", info.Fingerprint)
			fmt.Fprintf(w, "  valid until:  %s\n", cert.NotAfter.Format(time.RFC3339))
			for _, line := range mitm.PlatformInstallInstructions(paths) {
				fmt.Fprintln(w, line)
			}
			return nil
		},
	}
}

func newCAUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the local MITM CA from disk",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := mitm.DefaultCAPaths()
			if err != nil {
				return err
			}
			if err := mitm.Uninstall(paths); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			for _, line := range mitm.PlatformUninstallReminder() {
				fmt.Fprintln(w, line)
			}
			return nil
		},
	}
}

func newCAInfoCmd() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "info",
		Short: "Print the local MITM CA's subject / fingerprint / validity",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := mitm.DefaultCAPaths()
			if err != nil {
				return err
			}
			info, err := mitm.Info(paths)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if jsonOut {
				return json.NewEncoder(w).Encode(info)
			}
			fmt.Fprintf(w, "subject:      %s\n", info.Subject)
			fmt.Fprintf(w, "issuer:       %s\n", info.Issuer)
			fmt.Fprintf(w, "not_before:   %s\n", info.NotBefore.Format(time.RFC3339))
			fmt.Fprintf(w, "not_after:    %s\n", info.NotAfter.Format(time.RFC3339))
			fmt.Fprintf(w, "fingerprint:  %s\n", info.Fingerprint)
			fmt.Fprintf(w, "cert_file:    %s\n", paths.CertFile)
			fmt.Fprintf(w, "key_file:     %s\n", paths.KeyFile)
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "emit a JSON object instead of plain text")
	return c
}

func newCARotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new local MITM CA (replaces the existing one on disk)",
		Long: `Generate a NEW local MITM CA at ~/.iam-jit/gbounce/ca/, replacing
the existing one on disk.

IMPORTANT: the OLD cert is still trusted by your OS trust store until
you remove it manually. After running ` + "`gbounce ca rotate`" + ` you must:

  1. Add the NEW cert to your trust store (the platform-specific
     command is printed below).
  2. Remove the OLD cert from your trust store (a different
     platform-specific command — see ` + "`gbounce ca uninstall`" + `'s output).

Until step 2 completes BOTH the old and the new CA can sign valid
gbounce-MITM certs — that's a transient widening of the trust surface.
For most operators this is acceptable (the old key is gone from disk
the moment rotate finishes; nobody can mint NEW certs with it). If
that's not acceptable, plan a maintenance window.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := mitm.DefaultCAPaths()
			if err != nil {
				return err
			}
			cert, _, err := mitm.GenerateCA(paths, true /*overwrite*/)
			if err != nil {
				return err
			}
			info, err := mitm.Info(paths)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "gbounce CA rotated:\n")
			fmt.Fprintf(w, "  cert: %s\n", paths.CertFile)
			fmt.Fprintf(w, "  key:  %s (mode 0600)\n", paths.KeyFile)
			fmt.Fprintf(w, "  subject:      %s\n", info.Subject)
			fmt.Fprintf(w, "  fingerprint:  %s\n", info.Fingerprint)
			fmt.Fprintf(w, "  valid until:  %s\n", cert.NotAfter.Format(time.RFC3339))
			for _, line := range mitm.PlatformInstallInstructions(paths) {
				fmt.Fprintln(w, line)
			}
			fmt.Fprintln(w, "")
			fmt.Fprintln(w, "REMINDER: the OLD CA is still in your OS trust store. Remove it with")
			fmt.Fprintln(w, "the platform-specific command listed under `gbounce ca uninstall --help`.")
			return nil
		},
	}
}

// loadProfileRulesFile loads + compiles MITM-mode profile rules from
// a JSON file. We accept JSON (not YAML) at v1.0 to avoid pulling in
// a YAML dependency for the gbounce repo; a future slice may add
// YAML by routing through the same parser the other Bounce products
// use. JSON shape:
//
//	{ "deny_rules": [ {RuleSpec}, ... ] }
//
// File-not-found returns a clear error; parse / compile errors carry
// the file path + the rule index so the operator can find the
// offending entry.
func loadProfileRulesFile(path string) ([]profile.Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		DenyRules []profile.RuleSpec `json:"deny_rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse %s as JSON: %w", path, err)
	}
	rules, err := profile.ParseRules(doc.DenyRules)
	if err != nil {
		return nil, fmt.Errorf("compile rules from %s: %w", path, err)
	}
	return rules, nil
}
