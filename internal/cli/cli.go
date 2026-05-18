// Command gbounce is the generic HTTP/HTTPS forward proxy in the
// Bounce product suite. See cmd/gbounce/main.go for the binary entry
// point + the package-level doc comment.
//
// G-Slice 1 (this slice) ships:
//   - `gbounce run`             discovery-mode forward proxy
//   - `gbounce audit tail`      print recent decision rows
//   - `gbounce version-check`   opt-in informational update check
//   - `gbounce --version`       print build metadata
//
// Later slices add: profile mode (G-2), tap mode (G-3), auto-
// recommender (G-4), MCP server (G-5), webhook export (G-6).
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/proxy"
	"github.com/trsreagan3/gbounce/internal/store"
)

// loopbackHosts mirrors the kbounce/dbounce CRIT closure: gbounce
// holds inbound bearer tokens long enough to forward them; binding
// externally exposes that surface to anyone on the network. Refuse
// non-loopback bindings unless the operator passed
// --i-know-this-binds-externally to acknowledge they read the threat
// model.
var loopbackHosts = map[string]struct{}{
	"127.0.0.1":     {},
	"::1":           {},
	"localhost":     {},
	"ip6-localhost": {},
	"ip6-loopback":  {},
}

// version / commit / buildTime are stamped at build time via
// -ldflags "-X github.com/trsreagan3/gbounce/internal/cli.<name>=...".
// Unstamped builds report "dev" / "none" / "unknown".
var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

// Main is the exported entry point so cmd/gbounce can stay a 3-line
// shim. Threads the linker-stamped version into the audit package +
// runs the root cobra command.
func Main() {
	audit.SetBuildVersion(version)
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// versionString returns the human-readable version surfaced via
// `gbounce --version`. Format mirrors kbounce/dbounce.
func versionString() string {
	return fmt.Sprintf("gbounce %s (commit %s, built %s)", version, commit, buildTime)
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "gbounce",
		Short:         "Generic HTTP/HTTPS forward proxy with audit-export",
		Long:          rootLongHelp,
		Version:       versionString(),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newRunCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newDiagnosticsCmd())
	root.AddCommand(newDiagAliasCmd())
	root.AddCommand(newInvestigateCmd())
	root.AddCommand(newVersionCheckCmd())
	root.AddCommand(newBackupCmd())
	root.AddCommand(newRestoreCmd())
	return root
}

const rootLongHelp = `gbounce is the 5th product in the Bounce suite: a generic HTTP/HTTPS
forward proxy that observes every request, emits an OCSF v1.1.0 class
6003 (API Activity) audit event per request/response pair, and (in
future slices) can gate calls against a profile.

G-Slice 1 ships discovery mode only — observation + audit, no
filtering. Use it to:

  * Build a baseline trace of what an AI agent or dev workflow actually
    calls against an HTTP/HTTPS API.
  * Tee API activity into a SIEM via the JSONL audit log (point
    Fluent Bit / Vector / logrotate at the file).
  * Audit what flows through a CONNECT tunnel (host:port granularity;
    TLS passthrough — no MITM).

Honest positioning (per [[ibounce-honest-positioning]] +
[[gbounce-generic-proxy]]): gbounce is a deterrent + audit trail, not
a security boundary. An operator who controls the agent's network can
route around it. The product value is visibility + the future
profile-mode gating (G-Slice 2), not enforcement an adversarial agent
can't bypass.

Later slices add profile mode (G-2), tap mode (G-3), auto-recommender
(G-4), MCP server (G-5), and webhook export (G-6).`

func newRunCmd() *cobra.Command {
	var (
		port              int
		host              string
		mgmtPort          int
		mgmtHost          string
		upstreamURL       string
		allowConnect      bool
		dbPath            string
		auditLogPath      string
		auditLogFsync     bool
		forceExternalBind bool
		forwardTimeout    int
		mode              string
		auditEventsToken  string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the gbounce forward proxy",
		Long: `Start the gbounce HTTP/HTTPS forward proxy.

In discovery mode (the only G-Slice 1 mode), every inbound request is
forwarded verbatim to --upstream and an OCSF audit event is emitted.

Two TLS shapes:

  * --upstream https://api.target.com (default forward shape):
    clients send plain HTTP requests to gbounce's listener; gbounce
    rewrites them onto the upstream's scheme/host/port. URL path +
    method + status are visible to the audit log; bodies stream
    through unmodified.

  * --allow-connect: gbounce accepts HTTP CONNECT verbs to tunnel
    HTTPS through. gbounce splices the two sockets blindly (no MITM,
    no body inspection); host:port + method=CONNECT land in the
    audit log. Use this when an SDK / browser is configured for a
    forward proxy.

Audit log: --audit-log-path PATH appends one JSON-per-line OCSF event
per request. The proxy uses an in-memory bounded queue; if a slow disk
fills the queue, events are dropped + counted (the SQLite decision
table is the canonical source of truth).

Bind safety: gbounce holds inbound bearer tokens long enough to
forward them. The listener refuses non-loopback binds unless you
pass --i-know-this-binds-externally to acknowledge the threat model.

Management endpoint: /healthz lives on a SEPARATE port (default 8769)
so liveness probes never touch the proxy data path.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch mode {
			case "discovery":
				// G-Slice 1: the only supported mode.
			case "profile":
				return fmt.Errorf("--mode profile is not in G-Slice 1; queued for G-Slice 2")
			case "tap":
				return fmt.Errorf("--mode tap is not in G-Slice 1; queued for G-Slice 3")
			default:
				return fmt.Errorf("--mode %q not recognized; G-Slice 1 supports: discovery", mode)
			}
			if upstreamURL == "" && !allowConnect {
				return fmt.Errorf("--upstream is required (or pass --allow-connect for CONNECT-tunnel mode)")
			}
			if _, ok := loopbackHosts[host]; !ok && !forceExternalBind {
				return fmt.Errorf(
					"refusing to bind proxy listener on non-loopback host %q; gbounce "+
						"forwards inbound bearer tokens long enough to relay them. "+
						"Re-run with --i-know-this-binds-externally to acknowledge the "+
						"threat model, or use --host 127.0.0.1 (the default).",
					host)
			}
			if _, ok := loopbackHosts[mgmtHost]; !ok && !forceExternalBind {
				return fmt.Errorf(
					"refusing to bind /healthz on non-loopback host %q. "+
						"Re-run with --i-know-this-binds-externally to override.",
					mgmtHost)
			}
			// #271 — GET /audit/events lives on the same mgmt port; an
			// external bind without a bearer token would expose recent
			// audit events (which can include URL paths the operator
			// considers sensitive). Refuse to start in that shape.
			if _, ok := loopbackHosts[mgmtHost]; !ok && auditEventsToken == "" {
				return fmt.Errorf(
					"--audit-events-token TOKEN is required when mgmt-host %q is non-loopback "+
						"(GET /audit/events would otherwise be exposed without auth)",
					mgmtHost)
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()

			var lw *audit.LogWriter
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if auditLogPath != "" {
				lw, err = audit.NewLogWriter(ctx, audit.LogWriterOptions{
					Path:  auditLogPath,
					Fsync: auditLogFsync,
				})
				if err != nil {
					return err
				}
				defer lw.Close()
			}

			cfg := proxy.Config{
				Host:                  host,
				Port:                  port,
				MgmtHost:              mgmtHost,
				MgmtPort:              mgmtPort,
				UpstreamURL:           upstreamURL,
				AllowConnect:          allowConnect,
				ForwardTimeoutSeconds: forwardTimeout,
				AuditLogPath:          auditLogPath,
				AuditLogFsync:         auditLogFsync,
				AuditEventsToken:      auditEventsToken,
				Mode:                  proxy.ModeDiscovery,
			}
			srv, err := proxy.NewServer(cfg, st, lw)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"gbounce listening on %s (mgmt %s); upstream=%q allow_connect=%v audit_log=%q\n",
				srv.Addr(), srv.MgmtAddr(),
				upstreamURL, allowConnect, auditLogPath)
			return srv.Serve(ctx)
		},
	}
	cmd.Flags().IntVar(&port, "port", 8080, "proxy listener port")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "proxy listener host")
	cmd.Flags().IntVar(&mgmtPort, "mgmt-port", 8769, "management (/healthz) listener port")
	cmd.Flags().StringVar(&mgmtHost, "mgmt-host", "127.0.0.1", "management listener host")
	cmd.Flags().StringVar(&upstreamURL, "upstream", "", "upstream URL to forward to (e.g. https://api.target.com)")
	cmd.Flags().BoolVar(&allowConnect, "allow-connect", false, "accept HTTP CONNECT verbs for HTTPS tunneling (TLS passthrough; no MITM)")
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite audit DB path (default ~/.gbounce/state.db; honors GBOUNCE_DB)")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "", "also append OCSF events to this JSONL file (opt-in)")
	cmd.Flags().BoolVar(&auditLogFsync, "audit-log-fsync", false, "fsync after every audit-log write (slower; safer on crash)")
	cmd.Flags().BoolVar(&forceExternalBind, "i-know-this-binds-externally", false, "acknowledge the threat model of binding off loopback")
	cmd.Flags().IntVar(&forwardTimeout, "forward-timeout-seconds", 60, "per-request forward timeout in seconds")
	cmd.Flags().StringVar(&mode, "mode", "discovery", "operating mode (G-Slice 1: discovery only; G-Slice 2 adds profile; G-Slice 3 adds tap)")
	cmd.Flags().StringVar(&auditEventsToken, "audit-events-token", "", "bearer token required for GET /audit/events when the mgmt port is bound externally; empty = loopback-only (no auth)")
	return cmd
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the local decision audit log",
	}
	cmd.AddCommand(newAuditTailCmd())
	return cmd
}

// followPollInterval is how often `--follow` polls the SQLite DB for
// new rows. 500ms matches the cross-product spec (ibounce + kbounce +
// dbounce all use the same interval per [[cross-product-agent-parity]])
// — fast enough to feel live, slow enough that a quiet proxy doesn't
// spam the disk with empty queries.
const followPollInterval = 500 * time.Millisecond

// signalCtxFunc is the constructor for the SIGINT/SIGTERM context the
// `--follow` loop respects. Indirected through a package variable so
// tests can swap in a context that cancels on a test-controlled
// channel instead of installing real signal handlers.
var signalCtxFunc = func(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
}

func newAuditTailCmd() *cobra.Command {
	var (
		dbPath     string
		limit      int
		follow     bool
		filterRaw  []string
		summary    bool
		exportFmt  string
		exportOut  string
		csvColumns []string
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Print the most recent decision rows from the local SQLite audit log",
		Long: `Print decisions from the local audit log.

Default mode: print the most recent N decision rows (newest first),
one row per line.

` + "`--follow`" + ` polls the audit DB every 500ms for new rows and prints
them as they arrive; exit with SIGINT (Ctrl-C). Mutually exclusive with
` + "`--summary`" + `.

` + "`--filter EXPR`" + ` narrows the output (AND semantics — repeatable):

  field=value   string equality
  field~regex   Go RE2 regex match
  field>=N      numeric greater-or-equal
  field<=N      numeric less-or-equal

Supported fields (cross-product OCSF + gbounce-specific):
` + "  " + strings.Join(audit.SupportedFilterFields(), "\n  ") + `

` + "`--summary`" + ` prints a count-summary keyed by event_type, severity_id,
actor.user.name, api.operation, plus the gbounce-specific groupings
upstream_host, method, http_status, and the composite request-shape
key upstream_host+method+http_status.

` + "`--export FORMAT --out PATH`" + ` writes a file in one of three formats:

  jsonl         one redacted OCSF event per line
  csv           tabular (default columns; override with --csv-columns)
  ocsf-bundle   one OCSF v1.1.0 Detection Finding wrapping the events

All exports apply URL-token redaction: query-string params named
` + "`token`" + `, ` + "`api_key`" + `, ` + "`password`" + `, ` + "`secret`" + `, ` + "`bearer`" + `, ` + "`key`" + `,
` + "`authorization`" + ` (case-insensitive) are replaced with the literal
string REDACTED. The live tail leaves the raw value in place so an
operator can see what an agent called in-context.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > 1000 {
				return fmt.Errorf("--limit must be in 1-1000 (got %d)", limit)
			}
			if follow && summary {
				return fmt.Errorf("--follow and --summary are mutually exclusive (one is a live stream, the other is a fixed-snapshot aggregation)")
			}
			if exportFmt != "" && exportOut == "" {
				return fmt.Errorf("--export requires --out PATH")
			}
			if exportOut != "" && exportFmt == "" {
				return fmt.Errorf("--out requires --export FORMAT")
			}
			if follow && exportFmt != "" {
				return fmt.Errorf("--follow and --export are mutually exclusive (an export is a one-shot snapshot)")
			}
			filters, err := audit.ParseFilters(filterRaw)
			if err != nil {
				return err
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()

			if follow {
				return runFollowLoop(cmd, st, filters)
			}

			rows, err := st.RecentDecisions(limit)
			if err != nil {
				return err
			}
			events := rowsToEvents(rows)
			if len(filters) > 0 {
				events = filterEvents(events, filters)
			}

			if summary {
				s := audit.Summarize(events)
				fmt.Fprint(cmd.OutOrStdout(), audit.RenderSummary(s))
				return nil
			}

			if exportFmt != "" {
				format, err := audit.ParseExportFormat(exportFmt)
				if err != nil {
					return err
				}
				f, err := os.OpenFile(exportOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				if err != nil {
					return fmt.Errorf("open export --out: %w", err)
				}
				defer f.Close()
				if err := audit.Export(f, events, audit.ExportOptions{
					Format:     format,
					CSVColumns: csvColumns,
				}); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"wrote %d event(s) to %s (format=%s; URL-token redaction applied)\n",
					len(events), exportOut, format)
				return nil
			}

			if len(events) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no decisions recorded yet)")
				return nil
			}
			printRows(cmd.OutOrStdout(), rows, filters, events)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite audit DB path (default ~/.gbounce/state.db; honors GBOUNCE_DB)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max rows to print (1..1000)")
	cmd.Flags().BoolVar(&follow, "follow", false, "live-tail: poll the audit DB every 500ms; exit on SIGINT")
	cmd.Flags().StringArrayVar(&filterRaw, "filter", nil, "filter expression (repeatable; AND semantics); see --help for grammar")
	cmd.Flags().BoolVar(&summary, "summary", false, "print a count-summary instead of individual rows")
	cmd.Flags().StringVar(&exportFmt, "export", "", "export FORMAT (jsonl|csv|ocsf-bundle); requires --out")
	cmd.Flags().StringVar(&exportOut, "out", "", "export output file (requires --export)")
	cmd.Flags().StringSliceVar(&csvColumns, "csv-columns", nil, "comma-separated columns for --export csv (overrides default)")
	return cmd
}

// runFollowLoop polls the audit DB for new rows + prints them as they
// arrive. Exits cleanly on SIGINT/SIGTERM.
func runFollowLoop(cmd *cobra.Command, st *store.Store, filters []audit.Filter) error {
	ctx, stop := signalCtxFunc(cmd.Context())
	defer stop()

	cursor, err := st.MaxDecisionID()
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "# gbounce audit tail --follow (poll=%s; cursor=%d); Ctrl-C to exit\n",
		followPollInterval, cursor)

	ticker := time.NewTicker(followPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			rows, newCursor, err := st.DecisionsAfterID(cursor)
			if err != nil {
				return err
			}
			cursor = newCursor
			if len(rows) == 0 {
				continue
			}
			events := rowsToEvents(rows)
			if len(filters) > 0 {
				events = filterEvents(events, filters)
			}
			printRows(w, rows, filters, events)
		}
	}
}

// rowsToEvents builds an OCSF Event for each row so filter / summary /
// export logic can work against a single shape regardless of source.
func rowsToEvents(rows []store.DecisionRow) []audit.Event {
	out := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.FromRequest(audit.RequestInput{
			At:             r.At,
			DecisionID:     r.ID,
			Mode:           r.Mode,
			Method:         r.Method,
			Path:           r.Path,
			UpstreamHost:   r.UpstreamHost,
			UpstreamPort:   r.UpstreamPort,
			UpstreamScheme: r.UpstreamScheme,
			ClientHost:     r.ClientHost,
			ClientPort:     r.ClientPort,
			HTTPStatus:     r.HTTPStatus,
			ResponseSize:   r.ResponseSize,
			LatencyMS:      r.LatencyMS,
		}))
	}
	return out
}

// filterEvents returns the subset of events that match ALL filters.
func filterEvents(events []audit.Event, filters []audit.Filter) []audit.Event {
	out := make([]audit.Event, 0, len(events))
	for _, ev := range events {
		if audit.MatchAll(ev, filters) {
			out = append(out, ev)
		}
	}
	return out
}

// printRows is the bare display shape (`audit tail` and `audit tail
// --follow`). Iterates rows (not events) so the printed line keeps the
// raw HTTP fields the operator wants in-context — the unredacted path
// is intentional here per the spec (the live tail shows the raw
// value; exports apply redaction).
//
// When filters are non-empty, only rows whose corresponding event
// matched are printed. The events slice mirrors the rows slice in
// order; we re-derive the membership rather than threading a "kept"
// bool through the call chain.
func printRows(w io.Writer, rows []store.DecisionRow, filters []audit.Filter, events []audit.Event) {
	if len(filters) == 0 {
		for _, r := range rows {
			printOneRow(w, r)
		}
		return
	}
	// Build a set of decision_id values that survived filtering.
	keep := make(map[int64]struct{}, len(events))
	for _, ev := range events {
		keep[ev.DecisionID] = struct{}{}
	}
	for _, r := range rows {
		if _, ok := keep[r.ID]; ok {
			printOneRow(w, r)
		}
	}
}

func printOneRow(w io.Writer, r store.DecisionRow) {
	fmt.Fprintf(w,
		"%s  %-6s %d  %-22s %s\n",
		r.At.Format("2006-01-02T15:04:05Z"),
		strings.ToUpper(r.Method),
		r.HTTPStatus,
		r.UpstreamHost,
		r.Path,
	)
}
