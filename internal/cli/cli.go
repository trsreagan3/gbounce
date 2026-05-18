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
	"os"
	"os/signal"
	"strings"
	"syscall"

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

func newAuditTailCmd() *cobra.Command {
	var (
		dbPath string
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Print the most recent decision rows from the local SQLite audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()
			rows, err := st.RecentDecisions(limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no decisions recorded yet)")
				return nil
			}
			// Print newest first; one row per line. Keep the shape
			// stable so shell tooling can grep it.
			for _, r := range rows {
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s  %-6s %d  %-22s %s\n",
					r.At.Format("2006-01-02T15:04:05Z"),
					strings.ToUpper(r.Method),
					r.HTTPStatus,
					r.UpstreamHost,
					r.Path,
				)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite audit DB path (default ~/.gbounce/state.db; honors GBOUNCE_DB)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max rows to print (1..1000)")
	return cmd
}
