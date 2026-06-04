// audit_query.go — `gbounce audit query`.
//
// Cross-bouncer audit query: fans out to every bouncer's mgmt /audit/events,
// merges into one time-ordered stream, and prints jsonl / csv / summary. The
// local-only sibling is `gbounce audit tail` (this machine's SQLite); `query`
// is the suite-wide read via the crossbouncer aggregator (founder decision
// 2026-06-04: gbounce is the read-only anchor). Ported from iam-jit's Python
// `audit query`.
package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

func newAuditQueryCmd() *cobra.Command {
	var (
		bouncers []string
		since    string
		until    string
		filters  []string
		limit    int
		format   string
		session  string
		token    string
		output   string
	)
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Cross-bouncer audit query (fan-out + merge across all bouncers)",
		Long: "Fan out to every bouncer's mgmt /audit/events, merge the OCSF events\n" +
			"into one time-ordered stream, and print them. --format jsonl (default)\n" +
			"emits one OCSF event per line; csv is a flat table; summary is per-\n" +
			"bouncer counts. Unreachable bouncers surface as coverage notes on\n" +
			"stderr — never a silent gap.",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch format {
			case "jsonl", "csv", "summary":
			default:
				return fmt.Errorf("gbounce: --format must be jsonl, csv, or summary (got %q)", format)
			}
			if session != "" {
				filters = append(filters, "unmapped.iam_jit.agent.session_id="+session)
			}
			eps, skipped := crossbouncer.ResolveEndpoints(bouncers, false)
			for _, s := range skipped {
				fmt.Fprintf(cmd.ErrOrStderr(), "gbounce: skipping unknown bouncer %q\n", s)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			q := crossbouncer.NewQuerier()
			events, notes := q.QueryEvents(ctx, eps, crossbouncer.QueryOptions{
				Since: since, Until: until, Filters: filters, Limit: limit, Token: token,
			})

			// Coverage notes always go to stderr so they never pollute piped output.
			for _, name := range sortedStringKeys(notes) {
				if notes[name] != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "gbounce: %s unreachable: %s\n", name, notes[name])
				}
			}

			out := cmd.OutOrStdout()
			var sink *os.File
			if output != "" && output != "-" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("gbounce: create %q: %w", output, err)
				}
				defer f.Close()
				sink = f
			}
			if sink != nil {
				out = sink
			}

			switch format {
			case "jsonl":
				enc := json.NewEncoder(out)
				for _, ev := range events {
					if err := enc.Encode(ev.Raw); err != nil {
						return err
					}
				}
			case "csv":
				cw := csv.NewWriter(out)
				_ = cw.Write([]string{"time", "bouncer", "protocol", "verdict", "action", "principal", "resources", "reason"})
				for _, ev := range events {
					_ = cw.Write([]string{
						ev.TimeISO(), ev.Bouncer(), crossbouncer.ProtocolFor(ev.Bouncer()),
						ev.Verdict(), ev.Action(), ev.Principal(),
						strings.Join(ev.Resources(), " "), ev.Reason(),
					})
				}
				cw.Flush()
				if err := cw.Error(); err != nil {
					return err
				}
			case "summary":
				perBouncer := map[string]int{}
				verdicts := map[string]int{}
				for _, ev := range events {
					perBouncer[ev.Bouncer()]++
					verdicts[ev.Verdict()]++
				}
				fmt.Fprintf(out, "Cross-bouncer audit — %d events (since %s)\n\n", len(events), since)
				fmt.Fprintf(out, "By bouncer:\n")
				for _, b := range sortedKeysInt(perBouncer) {
					fmt.Fprintf(out, "  %-14s %d\n", b, perBouncer[b])
				}
				fmt.Fprintf(out, "By verdict:\n")
				for _, v := range sortedKeysInt(verdicts) {
					fmt.Fprintf(out, "  %-14s %d\n", v, verdicts[v])
				}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&bouncers, "bouncer", nil, "bouncer(s) to fan out to (repeatable; 'name' or 'name=URL'); default: all")
	cmd.Flags().StringVar(&since, "since", "1h", "lookback window (5m/1h/2d/30d or ISO-8601)")
	cmd.Flags().StringVar(&until, "until", "", "upper bound (optional)")
	cmd.Flags().StringArrayVar(&filters, "filter", nil, "server-side filter expression (repeatable; field=value)")
	cmd.Flags().IntVar(&limit, "limit", 100, "per-bouncer event cap")
	cmd.Flags().StringVar(&format, "format", "jsonl", "output format: jsonl | csv | summary")
	cmd.Flags().StringVar(&session, "session", "", "shorthand for --filter unmapped.iam_jit.agent.session_id=<id>")
	cmd.Flags().StringVar(&token, "audit-events-token", "", "bearer token forwarded to each bouncer's /audit/events")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to file instead of stdout")
	return cmd
}

func sortedKeysInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
