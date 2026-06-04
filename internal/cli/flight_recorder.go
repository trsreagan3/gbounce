// flight_recorder.go — `gbounce flight-recorder`.
//
// Stitches one agent session across every bouncer in the suite (AWS/ibounce,
// HTTP/gbounce, K8s/kbounce, SQL/dbounce) into a single ordered timeline, by
// fanning out to each bouncer's mgmt /audit/events filtered on the session-id
// correlation key. gbounce is the read-only suite anchor (founder decision
// 2026-06-04). Ported from iam-jit's Python `flight-recorder`; emits the same
// flight-recorder/1 JSON the replay UI consumes, so the two are interchangeable.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

func newFlightRecorderCmd() *cobra.Command {
	var (
		session  string
		bouncers []string
		since    string
		until    string
		format   string
		limit    int
		token    string
		output   string
	)
	cmd := &cobra.Command{
		Use:   "flight-recorder",
		Short: "Stitch one agent session across all bouncers into a timeline",
		Long: "Fan out to every bouncer's mgmt /audit/events filtered on the agent\n" +
			"session id, then stitch the events into one ordered cross-protocol\n" +
			"timeline. --format timeline-json emits the machine timeline the replay\n" +
			"UI loads; --format summary is a human coverage + step read.\n\n" +
			"gbounce only READS each bouncer's mgmt endpoint — it never controls\n" +
			"another bouncer. Unreachable bouncers surface as honest coverage gaps.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(session) == "" {
				return fmt.Errorf("gbounce: --session is required (the cross-bouncer correlation key)")
			}
			if format != "timeline-json" && format != "summary" {
				return fmt.Errorf("gbounce: --format must be timeline-json or summary (got %q)", format)
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
			tl := crossbouncer.AssembleTimeline(session, events, notes, since, until)

			var out []byte
			switch format {
			case "timeline-json":
				b, err := json.MarshalIndent(tl, "", "  ")
				if err != nil {
					return fmt.Errorf("gbounce: marshal timeline: %w", err)
				}
				out = append(b, '\n')
			case "summary":
				out = []byte(renderTimelineSummary(tl))
			}

			if output != "" && output != "-" {
				if err := os.WriteFile(output, out, 0o600); err != nil {
					return fmt.Errorf("gbounce: write %q: %w", output, err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "gbounce: wrote %d bytes to %s\n", len(out), output)
				return nil
			}
			_, _ = cmd.OutOrStdout().Write(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&session, "session", "", "REQUIRED — agent session id (cross-bouncer correlation key)")
	cmd.Flags().StringArrayVar(&bouncers, "bouncer", nil, "bouncer(s) to fan out to (repeatable; 'name' or 'name=URL'); default: all")
	cmd.Flags().StringVar(&since, "since", "1h", "lookback window (5m/1h/2d/30d or ISO-8601)")
	cmd.Flags().StringVar(&until, "until", "", "upper bound (optional; ISO-8601 or short-form)")
	cmd.Flags().StringVar(&format, "format", "summary", "output format: timeline-json | summary")
	cmd.Flags().IntVar(&limit, "limit", 1000, "per-bouncer event cap")
	cmd.Flags().StringVar(&token, "audit-events-token", "", "bearer token forwarded to each bouncer's /audit/events")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to file instead of stdout ('-' = stdout)")
	return cmd
}

// renderTimelineSummary is the human-readable --format summary, mirroring
// iam-jit's flight-recorder summary shape.
func renderTimelineSummary(tl crossbouncer.Timeline) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Session: %s\n", tl.SessionID)
	fmt.Fprintf(&b, "Steps: %d  (events analyzed: %d)\n\n", tl.StepCount, tl.Meta.EventsAnalyzed)

	fmt.Fprintf(&b, "Coverage:\n")
	fmt.Fprintf(&b, "  probed:        %s\n", joinOrNone(tl.Coverage.BouncersProbed))
	fmt.Fprintf(&b, "  contributing:  %s\n", joinOrNone(tl.Coverage.BouncersContributing))
	if len(tl.Coverage.BouncersUnreachable) > 0 {
		fmt.Fprintf(&b, "  unreachable:\n")
		for _, u := range tl.Coverage.BouncersUnreachable {
			fmt.Fprintf(&b, "    ! %s: %s\n", u.Bouncer, u.Reason)
		}
	}
	if len(tl.Coverage.BouncersReachableNoEvents) > 0 {
		fmt.Fprintf(&b, "  reachable, 0 events: %s\n", strings.Join(tl.Coverage.BouncersReachableNoEvents, ", "))
	}
	if tl.Coverage.Partial {
		fmt.Fprintf(&b, "  PARTIAL — at least one probed bouncer did not answer; the timeline may be incomplete.\n")
	}

	if len(tl.Meta.ProtocolsRepresented) > 0 {
		fmt.Fprintf(&b, "\nSteps per protocol:\n")
		for _, p := range tl.Meta.ProtocolsRepresented {
			fmt.Fprintf(&b, "  %s: %d\n", p, tl.Meta.StepsPerProtocol[p])
		}
	}

	if tl.StepCount > 0 {
		fmt.Fprintf(&b, "\nTimeline:\n")
		for _, s := range tl.Steps {
			ts := "—"
			if s.Time != nil {
				ts = *s.Time
			}
			reason := ""
			if s.Reason != nil && *s.Reason != "" {
				reason = "  (" + *s.Reason + ")"
			}
			fmt.Fprintf(&b, "  %2d. %-19s [%-4s] %-7s %s%s\n",
				s.Index, ts, s.Protocol, s.Decision, s.Action, reason)
		}
	}
	return b.String()
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}
