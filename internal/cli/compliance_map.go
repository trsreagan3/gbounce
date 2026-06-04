// compliance_map.go — `gbounce compliance-map`.
//
// Maps one agent session's observed cross-bouncer activity to 5 compliance
// frameworks (OWASP Agentic / MITRE ATT&CK / NIST 800-53 / SOC 2 / EU AI Act),
// fanning out to each bouncer's /audit/events. Honest by design: enumerates the
// controls NOT touched + carries the "evidence on-ramp, NOT a certification"
// disclaimer. Ported from iam-jit's Python `compliance-map`.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/compliance"
	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

func newComplianceMapCmd() *cobra.Command {
	var (
		session   string
		framework string
		bouncers  []string
		since     string
		until     string
		format    string
		limit     int
		token     string
		output    string
	)
	cmd := &cobra.Command{
		Use:   "compliance-map",
		Short: "Map a session's observed activity to compliance framework controls",
		Long: "Fan out to every bouncer's /audit/events for one agent session, then\n" +
			"map the observed activity to OWASP Agentic / MITRE ATT&CK / NIST 800-53 /\n" +
			"SOC 2 / EU AI Act controls. Enumerates controls NOT touched and carries an\n" +
			"honest 'evidence on-ramp, NOT a certification' disclaimer — this is\n" +
			"technical-control evidence, not a compliance attestation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(session) == "" {
				return fmt.Errorf("gbounce: --session is required")
			}
			if framework != "" && !compliance.IsValidFramework(framework) {
				return fmt.Errorf("gbounce: --framework must be one of owasp|mitre|nist|soc2|eu-ai-act (got %q)", framework)
			}
			if format != "json" && format != "summary" {
				return fmt.Errorf("gbounce: --format must be json or summary (got %q)", format)
			}
			eps, skipped := crossbouncer.ResolveEndpoints(bouncers, false)
			for _, s := range skipped {
				fmt.Fprintf(cmd.ErrOrStderr(), "gbounce: skipping unknown bouncer %q\n", s)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			q := crossbouncer.NewQuerier()
			events, notes := q.FetchSessionEvents(ctx, session, eps, crossbouncer.QueryOptions{
				Since: since, Until: until, Limit: limit, Token: token,
			})
			res := compliance.BuildOverlay(session, events, framework, notes)

			var out []byte
			if format == "json" {
				b, err := json.MarshalIndent(res, "", "  ")
				if err != nil {
					return err
				}
				out = append(b, '\n')
			} else {
				out = []byte(renderComplianceSummary(res))
			}
			if output != "" && output != "-" {
				return os.WriteFile(output, out, 0o600)
			}
			_, _ = cmd.OutOrStdout().Write(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&session, "session", "", "REQUIRED — agent session id")
	cmd.Flags().StringVar(&framework, "framework", "", "restrict to one framework: owasp|mitre|nist|soc2|eu-ai-act")
	cmd.Flags().StringArrayVar(&bouncers, "bouncer", nil, "bouncer(s) to fan out to (repeatable; 'name' or 'name=URL'); default: all")
	cmd.Flags().StringVar(&since, "since", "1h", "lookback window (5m/1h/2d or ISO-8601)")
	cmd.Flags().StringVar(&until, "until", "", "upper bound (optional)")
	cmd.Flags().StringVar(&format, "format", "summary", "output format: json | summary")
	cmd.Flags().IntVar(&limit, "limit", 1000, "per-bouncer event cap")
	cmd.Flags().StringVar(&token, "audit-events-token", "", "bearer token forwarded to each bouncer's /audit/events")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to file instead of stdout")
	return cmd
}

func renderComplianceSummary(res compliance.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Compliance overlay — session %s\n", res.SessionID)
	fmt.Fprintf(&b, "Events analyzed: %d   Tagged events: %d\n", res.EventsAnalyzed, len(res.Overlay))
	if res.FrameworkFilter != "" {
		fmt.Fprintf(&b, "Framework filter: %s\n", res.FrameworkFilter)
	}
	b.WriteString("\n")
	for _, fc := range res.Coverage {
		fmt.Fprintf(&b, "%s (%s) — %d of %d mapped controls touched\n",
			fc.Name, fc.Version, fc.ControlsTouchedCount, fc.ControlsInCatalog)
		for _, c := range fc.ControlsTouched {
			fmt.Fprintf(&b, "  + %-18s (%dx)  %s\n", c.Control, c.EventCount, c.Title)
		}
	}
	if res.IsPartial {
		b.WriteString("\nPARTIAL — this overlay is incomplete:\n")
		for _, r := range res.PartialReasons {
			fmt.Fprintf(&b, "  ! %s\n", r)
		}
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	fmt.Fprintf(&b, "\n%s\n", res.Disclaimer)
	return b.String()
}
