// `gbounce investigate` — one-shot Claude-ready evidence pack helper.
//
// Per [[cross-product-agent-parity]] this is the gbounce sibling of
// ibounce / kbounce / dbounce's same-named subcommand. Shape:
//
//	gbounce investigate [--out-dir DIR]
//	                    [--time-range 24h | 7d | 4w]
//	                    [--filter EXPR ...]
//	                    [--print-prompts]
//	                    [--db PATH]
//	                    [--healthz-url URL]
//	                    [--audit-log-path PATH]
//
// Composes the existing #268 audit-tail OCSF export + #277 diagnostics
// bundle into a single command that lands a Claude-ready evidence
// pack on disk. The operator drops both artifacts into THEIR local
// Claude client (Claude Code / Cursor / desktop Claude / the
// Anthropic console — whichever they use) and asks an investigative
// question.
//
// gbounce never calls Anthropic. Per [[self-host-zero-billing-
// dependency]] the only network call is the same local /healthz GET
// the existing `diagnostics bundle` makes. Per [[creates-never-
// mutates]] the command is read-only — it produces output files in
// --out-dir; it never edits the store or the audit log.
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// starter-prompt vocabulary stays neutral ("denial", "scope
// mismatch", "policy mismatch") — nothing reads as accusation.
//
// Per [[don't-tailor-to-lighthouse]] the prompts don't name a
// specific Claude client. The operator picks the surface; gbounce
// just lands evidence.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// investigationEvidenceFilename + investigationContextFilename are
// the stable on-disk artifact names. Stable so a follow-up
// `gbounce investigate` from the same operator overwrites the
// previous pack rather than leaving a forest of timestamped files.
const (
	investigationEvidenceFilename = "gbounce-investigation.ndjson"
	investigationContextFilename  = "gbounce-investigation-context.zip"
)

// investigateRowCap is the upper bound for events pulled from the
// SQLite store. Generous so a 24h window against a busy proxy
// doesn't truncate.
const investigateRowCap = 10000

// starterPrompts are the 10 generic investigative prompts the
// subcommand suggests. Per [[cross-product-agent-parity]] the list
// matches the ibounce / kbounce / dbounce siblings with gbounce-
// specific token swaps where relevant (upstream host drift,
// suspicious paths). Per [[don't-tailor-to-lighthouse]] no
// specific Claude client is named.
var starterPrompts = []string{
	"Review the past 24h of gbounce audit data. Anything that looks " +
		"off?",
	"Which agent generated the most denies? Was it consistent or a " +
		"one-shot spike?",
	"Did the heartbeat gap ever exceed 60s? If yes, when + how often?",
	"Are there bursts of similar requests from one client in a short " +
		"window? Identify actor + time range + path set.",
	"Did any admin-action audit event happen outside normal working " +
		"hours? List them with timestamps.",
	"Cross-reference the rule-trigger times against the audit-export " +
		"channel's failures (if any). Any correlation?",
	"Are any upstream hosts being contacted that don't match the " +
		"normal traffic pattern? Group by upstream host + agent.",
	"Which URL paths appear in the most denies? Does that match the " +
		"intended scope for this proxy?",
	"Did the same agent.session_id show up across multiple gbounce " +
		"deployments or restarts? Was that expected?",
	"Summarize the most common denial reasons and what they imply " +
		"about the active rules / policy.",
}

// timeRangePattern matches the supported `<N>{h,d,w}` time-range
// shape. Matches the ibounce + kbounce + dbounce siblings exactly
// so an operator's muscle memory transfers across the Bounce suite.
var timeRangePattern = regexp.MustCompile(`^(?i)(\d+)([hdw])$`)

// parseTimeRange parses a `<N>h | <N>d | <N>w` expression into a
// duration. Mirrors the cross-product spec for parity.
func parseTimeRange(expr string) (time.Duration, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, errors.New("time-range expression cannot be empty")
	}
	m := timeRangePattern.FindStringSubmatch(expr)
	if m == nil {
		return 0, fmt.Errorf(
			"time-range %q: expected <N>h | <N>d | <N>w "+
				"(e.g. '24h', '7d', '4w')", expr)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("time-range %q: N must be a positive integer", expr)
	}
	switch strings.ToLower(m[2]) {
	case "h":
		return time.Duration(n) * time.Hour, nil
	case "d":
		return time.Duration(n) * 24 * time.Hour, nil
	case "w":
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("time-range %q: unknown unit", expr)
}

// InvestigateOptions controls a one-shot investigate run. Split
// from the cobra handler so tests can drive the worker without a
// cobra runner.
type InvestigateOptions struct {
	// OutDir is the directory both artifacts land in. Required.
	OutDir string
	// Window optionally restricts the evidence to events whose Time
	// is >= now - Window. Zero = no time filter.
	Window time.Duration
	// FilterExprs forwards the audit-tail filter expressions (same
	// grammar as `gbounce audit tail --filter`). Validated up front.
	FilterExprs []string
	// DBPath overrides the SQLite store path; empty = default.
	DBPath string
	// AuditLogPath is the JSONL audit log path used for the
	// diagnostics bundle's bookkeeping (the bundle is built with
	// --no-audit so the log is NOT included; the evidence file
	// carries it instead). Empty = none.
	AuditLogPath string
	// HealthzURL is the local /healthz endpoint the diagnostics
	// bundle probes. Empty = the gbounce default.
	HealthzURL string
	// Now lets tests pin "now" for windowed filtering. Zero = real
	// wall clock at call time.
	Now time.Time
	// Stderr receives non-fatal warnings. Nil = os.Stderr.
	Stderr io.Writer
}

// InvestigateArtifacts is the return value the CLI handler uses to
// format the "now what" block. Exposed for tests.
type InvestigateArtifacts struct {
	EvidencePath    string
	ContextPath     string
	EvidenceBytes   int64
	ContextBytes    int64
	EventCount      int
	AuditLogPresent bool
}

// newInvestigateCmd registers the `gbounce investigate` subcommand.
// Cobra command exposed via cli.go's newRootCmd.
func newInvestigateCmd() *cobra.Command {
	var (
		outDir       string
		timeRangeRaw string
		filterExprs  []string
		printPrompts bool
		dbPath       string
		auditLogPath string
		healthzURL   string
	)
	cmd := &cobra.Command{
		Use:   "investigate",
		Short: "Land a Claude-ready evidence pack for local investigation",
		Long: `Compose the existing audit-tail OCSF export (#268) + the
diagnostics bundle (#277) into a single command that writes a
Claude-ready evidence pack on disk:

  gbounce-investigation.ndjson           OCSF Detection Finding
                                          wrapping the filtered
                                          audit-tail events
  gbounce-investigation-context.zip      redacted diagnostics
                                          bundle (config /
                                          healthz / system info)

The subcommand does NOT call Claude. Open YOUR local Claude
client (Claude Code, Cursor's Claude integration, the desktop
app — whichever you use), drop both files into the conversation,
then ask an investigative question. See docs/INVESTIGATE-WITH-
CLAUDE.md for the full workflow + the 10 starter prompts.

Per [[self-host-zero-billing-dependency]] the only network call
is a single LOCAL /healthz GET on loopback. Per [[creates-never-
mutates]] read-only — never edits the store or audit log.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if printPrompts {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), renderPrintPromptsBlock())
				return err
			}

			// Validate filters + time-range up front so a typo fails
			// before we touch the disk.
			if _, err := audit.ParseFilters(filterExprs); err != nil {
				return err
			}
			var window time.Duration
			if timeRangeRaw != "" {
				w, err := parseTimeRange(timeRangeRaw)
				if err != nil {
					return err
				}
				window = w
			}

			resolvedOutDir := outDir
			if resolvedOutDir == "" {
				ts := time.Now().UTC().Format("20060102T150405Z")
				resolvedOutDir = filepath.Join(
					os.TempDir(),
					fmt.Sprintf("gbounce-investigate-%s", ts),
				)
			}

			opts := InvestigateOptions{
				OutDir:       resolvedOutDir,
				Window:       window,
				FilterExprs:  filterExprs,
				DBPath:       dbPath,
				AuditLogPath: auditLogPath,
				HealthzURL:   healthzURL,
				Stderr:       cmd.ErrOrStderr(),
			}
			artifacts, err := RunInvestigate(opts)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), renderNowWhatBlock(artifacts))
			return err
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "",
		"Directory to write the two artifact files into. Default: a "+
			"per-invocation tmpdir at "+
			"$TMPDIR/gbounce-investigate-{UTC-timestamp}. Created on "+
			"demand; existing same-named files are overwritten so a "+
			"follow-up run inside the same --out-dir refreshes the "+
			"pack without leaving stale copies.")
	cmd.Flags().StringVar(&timeRangeRaw, "time-range", "",
		"Filter the audit-tail evidence to events from the last "+
			"<N>{h,d,w} (e.g. '24h', '7d', '4w'). Default: no time "+
			"filter (all events in the log).")
	cmd.Flags().StringSliceVar(&filterExprs, "filter", nil,
		"Extra filter expression forwarded to the audit-tail layer "+
			"(same grammar as `gbounce audit tail --filter`). "+
			"Repeatable; AND-combined.")
	cmd.Flags().BoolVar(&printPrompts, "print-prompts", false,
		"Print the 10 starter investigative prompts as a paste-able "+
			"block and exit WITHOUT writing artifact files.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.gbounce/state.db, or GBOUNCE_DB env).")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"JSONL audit-log path; passed through to the diagnostics "+
			"bundle's admin-action emitter (the bundle itself uses "+
			"--no-audit since the evidence file carries the audit "+
			"content).")
	cmd.Flags().StringVar(&healthzURL, "healthz-url", "http://127.0.0.1:8769/healthz",
		"URL of the running gbounce proxy's /healthz endpoint. The "+
			"context bundle records 'unreachable' + the error reason "+
			"if the GET fails; the command does NOT abort.")
	return cmd
}

// RunInvestigate is the worker the cobra handler delegates to.
// Reads the audit DB, builds the OCSF Detection Finding evidence
// file, then writes the diagnostics bundle with --no-audit (the
// evidence file already carries the audit content).
func RunInvestigate(opts InvestigateOptions) (*InvestigateArtifacts, error) {
	if opts.OutDir == "" {
		return nil, errors.New("gbounce: InvestigateOptions.OutDir is required")
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir out-dir: %w", err)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	events, auditLogPresent, err := collectInvestigateEvents(opts, now)
	if err != nil {
		return nil, err
	}

	evidencePath := filepath.Join(opts.OutDir, investigationEvidenceFilename)
	if err := writeInvestigationEvidence(
		evidencePath, events, opts.Window, auditLogPresent,
	); err != nil {
		return nil, fmt.Errorf("write evidence: %w", err)
	}
	evSt, err := os.Stat(evidencePath)
	if err != nil {
		return nil, fmt.Errorf("stat evidence: %w", err)
	}

	contextPath := filepath.Join(opts.OutDir, investigationContextFilename)
	bundleOpts := BundleOptions{
		OutPath:          contextPath,
		IncludeAuditTail: 0,
		NoAudit:          true,
		DBPath:           opts.DBPath,
		AuditLogPath:     opts.AuditLogPath,
		HealthzURL:       opts.HealthzURL,
		Stderr:           opts.Stderr,
	}
	bundleSummary, err := WriteDiagnosticsBundle(bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("write context bundle: %w", err)
	}

	return &InvestigateArtifacts{
		EvidencePath:    evidencePath,
		ContextPath:     contextPath,
		EvidenceBytes:   evSt.Size(),
		ContextBytes:    bundleSummary.TotalBytes,
		EventCount:      len(events),
		AuditLogPresent: auditLogPresent,
	}, nil
}

// collectInvestigateEvents reads + filters the audit DB rows,
// projecting them to OCSF events. Returns (events, auditLogPresent,
// err). The bool flag lets the CLI distinguish "quiet day" from
// "audit DB was wiped".
func collectInvestigateEvents(opts InvestigateOptions, now time.Time) ([]audit.Event, bool, error) {
	st, err := store.Open(opts.DBPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr,
			"gbounce: investigate: audit DB unreadable (%v); "+
				"writing evidence with no events.\n", err)
		return nil, false, nil
	}
	defer st.Close()

	rows, err := st.RecentDecisions(investigateRowCap)
	if err != nil {
		return nil, false, fmt.Errorf("recent decisions: %w", err)
	}
	auditLogPresent := len(rows) > 0
	events := rowsToEvents(rows)

	filters, err := audit.ParseFilters(opts.FilterExprs)
	if err != nil {
		return nil, false, err
	}
	if len(filters) > 0 {
		events = filterEvents(events, filters)
	}
	if opts.Window > 0 {
		cutoff := now.Add(-opts.Window).UnixMilli()
		kept := events[:0]
		for _, ev := range events {
			if ev.Time >= cutoff {
				kept = append(kept, ev)
			}
		}
		events = kept
	}
	return events, auditLogPresent, nil
}

// writeInvestigationEvidence materialises the OCSF Detection
// Finding bundle to disk by delegating to audit.Export with
// ExportFormatOCSFBundle. Same wire shape `gbounce audit tail
// --export ocsf-bundle` produces, with one extra investigation
// metadata line appended so a Claude analyst can distinguish
// "quiet window" from "wiped log".
//
// File layout: the OCSF Detection Finding JSON object first, then
// a single NDJSON line carrying the investigate metadata. The
// .ndjson extension fits the two-object shape, and a downstream
// parser reading the first line gets the OCSF document directly.
func writeInvestigationEvidence(
	path string,
	events []audit.Event,
	window time.Duration,
	auditLogPresent bool,
) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()

	if err := audit.Export(f, events, audit.ExportOptions{
		Format: audit.ExportFormatOCSFBundle,
	}); err != nil {
		return fmt.Errorf("encode evidence bundle: %w", err)
	}

	// Append the investigate metadata as a trailing NDJSON line.
	// Same key set as the ibounce / kbounce / dbounce siblings so
	// a cross-product Claude prompt can read the same fields out
	// of all four packs.
	now := time.Now().UTC()
	metaLine := fmt.Sprintf(
		"\n{\"investigate\":{\"window\":%q,\"audit_log_present\":%t,"+
			"\"event_count\":%d,\"generated_at\":%q}}\n",
		windowLabel(window), auditLogPresent, len(events),
		now.Format(time.RFC3339))
	if _, werr := f.WriteString(metaLine); werr != nil {
		return fmt.Errorf("append investigate metadata: %w", werr)
	}
	return nil
}

// windowLabel renders a duration as the user-facing window label.
// Zero = "all" so the Claude analyst sees the unrestricted set
// explicitly.
func windowLabel(d time.Duration) string {
	if d <= 0 {
		return "all"
	}
	return d.String()
}

// renderNowWhatBlock is the post-write CLI message. Three of the
// ten prompts so the default exit screen stays scannable; the full
// list is behind --print-prompts. Per [[don't-tailor-to-lighthouse]]
// the wording stays generic re: which Claude surface to use.
func renderNowWhatBlock(artifacts *InvestigateArtifacts) string {
	var b strings.Builder
	b.WriteString("\nArtifacts written:\n")
	fmt.Fprintf(&b, "  evidence  %s  (%d bytes, %d event(s))\n",
		artifacts.EvidencePath, artifacts.EvidenceBytes, artifacts.EventCount)
	fmt.Fprintf(&b, "  context   %s  (%d bytes)\n",
		artifacts.ContextPath, artifacts.ContextBytes)
	if !artifacts.AuditLogPresent {
		b.WriteString("  note: the audit log was missing or empty for " +
			"the selected window; the evidence file records the gap " +
			"so your Claude analyst doesn't treat it as a bug.\n")
	}
	b.WriteString("\nNext steps:\n")
	b.WriteString("  1. Open your local Claude client (Claude Code, " +
		"Cursor's Claude integration, the desktop app — whichever " +
		"you use).\n")
	b.WriteString("  2. Drop BOTH files into the conversation so the " +
		"analyst has the events + the deployment context.\n")
	b.WriteString("  3. Start with one of these prompts (run " +
		"`gbounce investigate --print-prompts` for the full list):\n")
	for i := 0; i < 3 && i < len(starterPrompts); i++ {
		fmt.Fprintf(&b, "     - %s\n", starterPrompts[i])
	}
	b.WriteString("\nPrivacy: gbounce does NOT send any data to " +
		"Anthropic. The files stay on this host; the Claude session " +
		"is YOURS. See docs/INVESTIGATE-WITH-CLAUDE.md for the full " +
		"privacy story.")
	return b.String()
}

// renderPrintPromptsBlock renders the full --print-prompts block —
// numbered list of all 10 starter prompts + a one-line privacy
// reminder. Designed to copy-paste cleanly into a runbook or notes
// file.
func renderPrintPromptsBlock() string {
	var b strings.Builder
	b.WriteString("gbounce investigate — starter prompts\n")
	b.WriteString(strings.Repeat("=", 50))
	b.WriteString("\n\nPaste any of these into your local Claude " +
		"client AFTER uploading the two artifact files.\n\n")
	for i, p := range starterPrompts {
		fmt.Fprintf(&b, "%2d. %s\n", i+1, p)
	}
	b.WriteString("\nPrivacy reminder: these prompts run inside YOUR " +
		"Claude session. gbounce never calls Anthropic; the audit " +
		"data leaves your host only if you choose to paste it.")
	return b.String()
}
