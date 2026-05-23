// profile_allow.go — `gbounce profile allow` + `gbounce denies
// recent` CLI commands per #388 / §A25 Phase 2.

package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/profileallow"
	"github.com/trsreagan3/gbounce/internal/store"
)

func newProfileAllowCmd() *cobra.Command {
	var (
		target       string
		actions      []string
		reason       string
		duration     string
		profileName  string
		profilesPath string
		jsonOut      bool
	)
	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Add an allow rule to a gbounce profile (operator easy-allow)",
		Long: `Append a profile allow rule with provenance metadata.

  gbounce profile allow --target 'api.staging.io' \
    --action 'GET:/v1/' \
    --reason "agent reads staging API"

For gbounce the action shape is 'METHOD:/path-prefix' (e.g. 'GET:/v1/foo')
or 'METHOD:*' for no path predicate. Refuses --target '*' (force
operator specificity).

Mirrors the iam-jit Python + kbouncer + dbounce CLI surface per
[[cross-product-agent-parity]].`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := profileallow.AddProfileAllowRule(profileallow.Options{
				Target:       target,
				Actions:      actions,
				Reason:       reason,
				Duration:     duration,
				ProfileName:  profileName,
				ProfilesPath: profilesPath,
				Source:       profileallow.SourceCLI,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(res)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"gbounce: %s allow rule(s) appended to profile %q (now %d rule(s))\n"+
					"  target  : %s\n"+
					"  actions : %s\n"+
					"  reason  : %s\n"+
					"  written : %s\n",
				res.Status, res.ProfileName, res.RuleCountAfter,
				res.Target, strings.Join(res.Actions, ", "),
				res.Reason, res.ProfilePath)
			if res.ExpiresAt != "" {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  expires : %s (advisory metadata)\n", res.ExpiresAt)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "",
		"Target host pattern (e.g. 'api.staging.io' or '*.staging.io'). '*' is refused.")
	cmd.Flags().StringSliceVar(&actions, "action", nil,
		"One or more 'METHOD:/path' strings (use METHOD:* for no path predicate).")
	cmd.Flags().StringVar(&reason, "reason", "", "Operator-supplied explanation.")
	cmd.Flags().StringVar(&duration, "duration", "",
		"Optional Go-style duration; empty/'permanent' = permanent.")
	cmd.Flags().StringVar(&profileName, "profile", "", "Profile to mutate (REQUIRED for gbounce).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.gbounce/profiles.yaml).")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON.")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("action")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("profile")
	return cmd
}

func newDeniesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "denies",
		Short: "Inspect recent DENY decisions",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, args []string) error {
		return c.Help()
	}
	cmd.AddCommand(newDeniesRecentCmd())
	return cmd
}

func newDeniesRecentCmd() *cobra.Command {
	var (
		dbPath         string
		since          string
		limit          int
		jsonOut        bool
		agentSessionID string
	)
	cmd := &cobra.Command{
		Use:   "recent",
		Short: "List recent DENY decisions from the local audit store",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath == "" {
				p, err := store.DefaultDBPath()
				if err != nil {
					return err
				}
				dbPath = p
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("gbounce: open store at %s: %w", dbPath, err)
			}
			defer st.Close()
			lower, perr := parseSinceFlag(since)
			if perr != nil {
				return perr
			}
			rows, err := profileallow.RecentDenies(profileallow.RecentDeniesOptions{
				Store:          st,
				Since:          lower,
				AgentSessionID: agentSessionID,
				Limit:          limit,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "gbounce: no recent denies")
				return nil
			}
			for _, r := range rows {
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s  action=%s  resource=%s  source=%s\n  suggested: %s\n",
					r.When, r.Action, r.Resource, r.DenySource, r.SuggestedAllowCommand)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"Path to gbounce SQLite store (default: ~/.gbounce/state.db).")
	cmd.Flags().StringVar(&since, "since", "5m", "Lower bound (5m / 1h / 1d / ISO).")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max rows.")
	cmd.Flags().StringVar(&agentSessionID, "agent-session", "", "Filter to one MCP session.")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON.")
	return cmd
}

func parseSinceFlag(spec string) (time.Time, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.Contains(s, "T") || (len(s) >= 10 && s[4] == '-') {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("gbounce: --since %q: %w", spec, err)
		}
		return t, nil
	}
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("gbounce: --since %q: too short", spec)
	}
	unit := s[len(s)-1]
	qty, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return time.Time{}, fmt.Errorf("gbounce: --since %q: %w", spec, err)
	}
	var d time.Duration
	switch unit {
	case 's':
		d = time.Duration(qty) * time.Second
	case 'm':
		d = time.Duration(qty) * time.Minute
	case 'h':
		d = time.Duration(qty) * time.Hour
	case 'd':
		d = time.Duration(qty) * 24 * time.Hour
	case 'w':
		d = time.Duration(qty) * 7 * 24 * time.Hour
	default:
		return time.Time{}, fmt.Errorf("gbounce: --since %q: unknown unit %q", spec, string(unit))
	}
	return time.Now().UTC().Add(-d), nil
}
