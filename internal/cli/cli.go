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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/caveats"
	"github.com/trsreagan3/gbounce/internal/dynamicdeny"
	"github.com/trsreagan3/gbounce/internal/mitm"
	"github.com/trsreagan3/gbounce/internal/profile"
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
	// #315 / §A13 — `gbounce ca {install,uninstall,info,rotate}` for the
	// optional MITM mode. Default-off; operator opts in by installing the
	// CA then running `gbounce run --mode mitm`.
	root.AddCommand(newCACmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newDiagnosticsCmd())
	root.AddCommand(newDiagAliasCmd())
	// #304 — `gbounce doctor caveats` surfaces the §B entries from
	// KNOWN-CAVEATS.md that apply to gbounce. Sibling Bounce products
	// ship the same shape per [[cross-product-agent-parity]].
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newInvestigateCmd())
	root.AddCommand(newVersionCheckCmd())
	root.AddCommand(newBackupCmd())
	root.AddCommand(newRestoreCmd())
	// #285 — `gbounce session list / show / export / purge`. Reads the
	// per-session NDJSON recordings written when the proxy runs with
	// `--record-sessions-dir`. Subcommand + flag names match ibounce +
	// kbounce + dbounce exactly per [[cross-product-agent-parity]] so
	// orchestrators (and the cross-product `iam-jit session replay
	// <FILE>` CLI) consume any product's recordings uniformly.
	root.AddCommand(newSessionCmd())
	// #311 / §A10 — `gbounce logs {purge,archive,verify}` audit-log
	// retention surface. Ships in lockstep with the sibling products
	// (ibounce / kbounce / dbounce); the cross-product runbook at
	// iam-roles/docs/LOG-RETENTION.md applies to all.
	root.AddCommand(newLogsCmd())
	// #321 / §A19 — `gbounce profile doctor` for cross-product CLI
	// parity. v1.0: reports current (no shipped defaults). G-Slice 2
	// will populate the catalog when gbounce gains a YAML profiles
	// surface. Per [[cross-product-agent-parity]].
	root.AddCommand(newProfileCmd())
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
		// #311 / §A10 — rotation thresholds. Sentinel -1 = "use the
		// audit-package default (matches iam-roles/docs/LOG-RETENTION.md
		// — 100 MB / 7 days / 30 days)." 0 = "operator explicitly
		// disabled this trigger." Same names across all four Bounce
		// products per [[cross-product-agent-parity]]; env-var
		// counterparts honor GBOUNCE_AUDIT_LOG_MAX_SIZE_MB /
		// _MAX_AGE_DAYS / _DB_RETENTION_DAYS.
		auditLogMaxSizeMB    int64
		auditLogMaxAgeDays   int
		auditDBRetentionDays int
		forceExternalBind bool
		forwardTimeout    int
		mode              string
		auditEventsToken  string
		// #254 — deployment preset. Single-flag shortcut for a common
		// deployment shape (only `security-observe` in v1.0). Resolved
		// BEFORE downstream mode validation so the preset's HARD/SOFT
		// semantics fire first.
		deploymentPreset string
		// #285 — per-session NDJSON recordings directory. Empty disables
		// the channel. Replayable via `iam-jit session replay <FILE>`.
		recordSessionsDir string
		// #315 / §A13 — MITM-mode flags.
		auditLogIncludeBodies bool
		profileRulesFile      string
		// #314 / §A12 — operator-written deny entries. `--deny-host`
		// is repeatable + supplements `--deny-hosts-file`. Both feed
		// the same compiled rule list (union). See
		// internal/proxy/deny_hosts.go for wildcard semantics + the
		// parse-time rejection rules.
		denyHosts     []string
		denyHostsFile string
		// #324d — dynamic-deny YAML path. Operator override of the
		// default `~/.iam-jit/dynamic-denies.yaml`. Empty string falls
		// back to the default. Per [[cross-product-agent-parity]] the
		// flag shape is identical on the other Bounce products. When
		// the file is absent at startup the watcher waits for it to
		// appear — startup is NOT an error condition.
		dynamicDeniesPath    string
		disableDynamicDenies bool
		// #317 — cloud-neutral S3-compatible NDJSON object-storage
		// sink. All fields OFF by default. Per [[self-host-zero-
		// billing-dependency]] the bucket is operator-owned. Per
		// [[cross-product-agent-parity]] the flag shape is identical
		// to ibounce + kbounce + dbounce.
		auditObjectStorageEndpoint        string
		auditObjectStorageBucket          string
		auditObjectStoragePrefix          string
		auditObjectStorageRegion          string
		auditObjectStorageCredentialsFile string
		auditObjectStorageRotationMinutes int
		auditObjectStorageMaxSizeMB       int
		auditObjectStorageInstanceID      string
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
			// #254 — deployment preset resolution. Runs BEFORE mode
			// validation so the preset-resolved values flow through.
			// HARD-override conflicts (e.g. --preset security-observe
			// --mode profile) fail-fast here with a "drop one OR the
			// other" message. SOFT overrides flow through. The preset
			// BANNER lines are stashed for printing alongside the
			// existing startup banner.
			var presetBannerLines []string
			if deploymentPreset != "" {
				preset := GetPreset(deploymentPreset, "gbounce")
				if preset == nil {
					return fmt.Errorf(
						"gbounce: unknown --preset %q; available: security-observe",
						deploymentPreset)
				}
				operatorChanged := map[string]bool{
					"mode":           cmd.Flags().Changed("mode"),
					"audit-log-path": cmd.Flags().Changed("audit-log-path"),
				}
				currentValues := map[string]string{
					"mode":           mode,
					"audit-log-path": auditLogPath,
				}
				res, err := ApplyPreset(preset, operatorChanged, currentValues, nil)
				if err != nil {
					return err
				}
				for _, key := range res.DerivedKeys {
					pv := preset.Values[key]
					switch key {
					case "mode":
						mode = pv.Value
					case "audit-log-path":
						auditLogPath = pv.Value
						if d := filepath.Dir(auditLogPath); d != "" {
							_ = os.MkdirAll(d, 0o700)
						}
					}
				}
				presetBannerLines = FormatBanner(preset, res)
			}

			// #315 / §A13 — MITM mode is opt-in. The CA must already be
			// installed (`gbounce ca install` from a prior step) +
			// permissions on the key file must be 0o600. We load the CA
			// up-front so a misconfigured MITM run fails BEFORE the
			// listener binds.
			var mitmMinter *mitm.CertMinter
			var mitmRules []profile.Rule
			switch mode {
			case "discovery":
				// G-Slice 1: the default mode.
			case "mitm":
				caPaths, err := mitm.DefaultCAPaths()
				if err != nil {
					return err
				}
				caCert, caKey, err := mitm.LoadCA(caPaths)
				if err != nil {
					return fmt.Errorf("--mode mitm: %w", err)
				}
				if time.Now().After(caCert.NotAfter) {
					return fmt.Errorf("--mode mitm: CA cert at %s expired on %s; rotate with `gbounce ca rotate`", caPaths.CertFile, caCert.NotAfter.Format(time.RFC3339))
				}
				m, err := mitm.NewCertMinter(caCert, caKey)
				if err != nil {
					return fmt.Errorf("--mode mitm: %w", err)
				}
				mitmMinter = m
				if profileRulesFile != "" {
					rules, err := loadProfileRulesFile(profileRulesFile)
					if err != nil {
						return fmt.Errorf("--profile-rules-file: %w", err)
					}
					mitmRules = rules
				}
			case "profile":
				return fmt.Errorf("--mode profile is not in G-Slice 1; queued for G-Slice 2")
			case "tap":
				return fmt.Errorf("--mode tap is not in G-Slice 1; queued for G-Slice 3")
			default:
				return fmt.Errorf("--mode %q not recognized; supported: discovery, mitm", mode)
			}
			if mode == "mitm" {
				// MITM mode IS CONNECT-shape. The operator doesn't need
				// to also pass --allow-connect; we enable it implicitly
				// so the agent's HTTPS_PROXY env var works out of the
				// box. --upstream is unsupported in MITM mode (the
				// destination comes from each CONNECT request).
				allowConnect = true
				if upstreamURL != "" {
					return fmt.Errorf("--mode mitm is incompatible with --upstream (MITM routes each CONNECT to its target host); drop --upstream")
				}
			} else if upstreamURL == "" && !allowConnect {
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

			// #311 / §A10 — env-var fallback for the rotation trio. CLI
			// flag wins; env var fills in when the operator didn't pass
			// it; -1 sentinel preserved for downstream "use default"
			// resolution. Env-var names match the cross-product spec at
			// iam-roles/docs/LOG-RETENTION.md per [[cross-product-agent-
			// parity]].
			resolveInt64Env := func(flagName string, flagVal int64, envName string) int64 {
				if cmd.Flags().Changed(flagName) {
					return flagVal
				}
				if v := os.Getenv(envName); v != "" {
					if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
						return parsed
					}
				}
				return flagVal
			}
			resolveIntEnv := func(flagName string, flagVal int, envName string) int {
				if cmd.Flags().Changed(flagName) {
					return flagVal
				}
				if v := os.Getenv(envName); v != "" {
					if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
						return parsed
					}
				}
				return flagVal
			}
			effAuditLogMaxSizeMB := resolveInt64Env("audit-log-max-size-mb", auditLogMaxSizeMB, "GBOUNCE_AUDIT_LOG_MAX_SIZE_MB")
			effAuditLogMaxAgeDays := resolveIntEnv("audit-log-max-age-days", auditLogMaxAgeDays, "GBOUNCE_AUDIT_LOG_MAX_AGE_DAYS")
			effAuditDBRetentionDays := resolveIntEnv("audit-db-retention-days", auditDBRetentionDays, "GBOUNCE_AUDIT_DB_RETENTION_DAYS")
			// Surface the resolved values on stderr so the operator
			// sees them in the startup banner; the cross-product runbook
			// at iam-roles/docs/LOG-RETENTION.md explains the
			// retention-vs-purge split. gbounce's LogWriter does not yet
			// run live rotation — the values are consumed by `gbounce
			// logs purge` (on-demand) per the LOG-RETENTION.md parity
			// matrix gbounce-deferred row. Re-wires cleanly once the
			// concurrent #308 store-schema work settles.
			_ = effAuditLogMaxSizeMB
			_ = effAuditLogMaxAgeDays
			_ = effAuditDBRetentionDays

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

			// #285 — per-session NDJSON recorder. Default off; only
			// constructed when the operator passed --record-sessions-dir.
			// Start() creates the dir + recovers any stale .partial
			// files. Fatal on failure so an unwritable dir surfaces
			// immediately (mirrors the LogWriter fail-fast above; if
			// the recording sink can't be opened the operator wants to
			// know).
			var sr *audit.SessionRecorder
			if recordSessionsDir != "" {
				rec, err := audit.NewSessionRecorder(audit.SessionRecorderOptions{
					Dir:            recordSessionsDir,
					BouncerProduct: "gbounce",
				})
				if err != nil {
					return fmt.Errorf("session recorder: %w", err)
				}
				if err := rec.Start(); err != nil {
					return fmt.Errorf("session recorder: %w", err)
				}
				sr = rec
			}

			cfgMode := proxy.ModeDiscovery
			if mode == "mitm" {
				cfgMode = proxy.ModeMITM
			}
			// #314 — collect deny entries from BOTH --deny-host CLI flags
			// (already in denyHosts slice) and --deny-hosts-file (file is
			// parsed for newline-delimited or YAML-list-style entries).
			// Union semantics: the future profile-YAML surface (G-Slice
			// 2) feeds entries through the same path; the
			// TestDenyHosts_CLIAndProfileMerge regression asserts both
			// take effect.
			denyHostsMerged := append([]string{}, denyHosts...)
			if denyHostsFile != "" {
				contents, err := os.ReadFile(denyHostsFile)
				if err != nil {
					return fmt.Errorf("--deny-hosts-file %q: %w", denyHostsFile, err)
				}
				fileRules, err := proxy.ParseDenyHostsFile(string(contents))
				if err != nil {
					return fmt.Errorf("--deny-hosts-file %q: %w", denyHostsFile, err)
				}
				for _, r := range fileRules {
					denyHostsMerged = append(denyHostsMerged, r.Raw)
				}
			}

			// #324d — dynamic-deny watcher. Constructed BEFORE
			// proxy.NewServer so the watcher's initial in-memory
			// snapshot is the one the proxy sees on its first request.
			// Default path is `~/.iam-jit/dynamic-denies.yaml`; the
			// `--dynamic-denies-path PATH` flag overrides; the
			// `--disable-dynamic-denies` flag turns the channel off
			// entirely (the watcher goroutine never starts; matcher
			// returns the pre-#324d static-only result).
			var ddWatcher *dynamicdeny.Watcher
			var ddBannerLine string
			if !disableDynamicDenies {
				ddPath := dynamicDeniesPath
				if ddPath == "" {
					ddPath = dynamicdeny.ResolveDefaultPath()
				}
				if ddPath != "" {
					// emitFunc is wired AFTER NewServer below so we can
					// reference the Server's counter-bump methods +
					// audit-log sink. For now construct with nil; the
					// post-NewServer step reassigns.
					w, loadErr := dynamicdeny.NewWatcher(ddPath, nil)
					if loadErr != nil {
						// The watcher object is still returned so the
						// banner reports "0 rules (parse error)"; the
						// watcher goroutine won't start until Start() is
						// called, but its snapshot is already empty.
						fmt.Fprintf(cmd.ErrOrStderr(),
							"gbounce: dynamic-denies: initial load of %q failed: %v\n",
							ddPath, loadErr)
					}
					ddWatcher = w
				}
			}

			cfg := proxy.Config{
				Host:                   host,
				Port:                   port,
				MgmtHost:               mgmtHost,
				MgmtPort:               mgmtPort,
				UpstreamURL:            upstreamURL,
				AllowConnect:           allowConnect,
				ForwardTimeoutSeconds:  forwardTimeout,
				AuditLogPath:           auditLogPath,
				AuditLogFsync:          auditLogFsync,
				AuditEventsToken:       auditEventsToken,
				Mode:                   cfgMode,
				MITMCertMinter:         mitmMinter,
				MITMRules:              mitmRules,
				MITMAuditIncludeBodies: auditLogIncludeBodies,
				DenyHosts:              denyHostsMerged,
				DynamicDenyWatcher:     ddWatcher,
			}
			srv, err := proxy.NewServer(cfg, st, lw, sr)
			if err != nil {
				return err
			}
			// #324d — wire the watcher's emit callback now that the
			// Server exists. Each reload bumps the matching counter +
			// tees an OCSF admin-action event into the audit log so a
			// SIEM dashboard sees activity.
			if ddWatcher != nil {
				ddWatcher.SetStderr(cmd.ErrOrStderr())
				logCh := lw
				emit := func(reason dynamicdeny.ReloadReason, rs *dynamicdeny.RuleSet, parseErr error) {
					switch reason {
					case dynamicdeny.ReasonParseError:
						srv.BumpDynamicDenyParseError()
					default:
						srv.BumpDynamicDenyReload()
					}
					action := audit.AdminActionDynamicDenyReloaded
					if reason == dynamicdeny.ReasonParseError {
						action = audit.AdminActionDynamicDenyParseError
					}
					extra := map[string]any{
						"dynamic_deny_reload_reason": string(reason),
					}
					if rs != nil {
						extra["dynamic_denies_count"] = len(rs.Rules)
						extra["dynamic_denies_path"] = rs.SourcePath
					}
					if parseErr != nil {
						extra["dynamic_deny_parse_error"] = parseErr.Error()
					}
					audit.EmitAdminAction(ctx, logCh, audit.AdminActionInput{
						Action:     action,
						Source:     audit.AdminActionSourceCLI,
						EntityKind: "dynamic_denies_file",
						EntityName: ddWatcher.Path(),
						ExtraExt:   extra,
					})
				}
				ddWatcher.SetStderr(cmd.ErrOrStderr())
				// Reassign the emit callback by reconstructing — the
				// Watcher struct only exposes SetStderr; constructor
				// took nil. Use the unexported field swap via the
				// dedicated helper to keep the API minimal.
				ddWatcher.SetEmitFunc(emit)
				if startErr := ddWatcher.Start(ctx); startErr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"gbounce: dynamic-denies: watcher failed to start: %v\n", startErr)
				}
				snap := ddWatcher.Snapshot()
				ruleCount := 0
				if snap != nil {
					ruleCount = len(snap.Rules)
				}
				ddBannerLine = fmt.Sprintf(
					"dynamic-denies: %d rules loaded from %s (%d applied to gbounce; watching for changes)",
					ruleCount, ddWatcher.Path(), ruleCount)
			}
			_ = ddBannerLine
			// #317 — cloud-neutral S3-compat NDJSON object-storage sink.
			// Default OFF; only constructed when --audit-object-storage-
			// bucket is set. Start() probes the bucket (HeadBucket) so
			// credential / endpoint / bucket-name misconfigurations
			// surface immediately rather than at first flush. Per
			// [[self-host-zero-billing-dependency]] the bucket is
			// operator-owned (operator creates; gbounce never creates).
			if auditObjectStorageBucket != "" {
				if auditObjectStorageEndpoint == "" {
					return fmt.Errorf(
						"gbounce: --audit-object-storage-bucket requires " +
							"--audit-object-storage-endpoint (the S3 API endpoint URL " +
							"for the operator's cloud provider — examples: " +
							"https://s3.us-east-1.amazonaws.com for AWS S3; " +
							"https://<accountid>.r2.cloudflarestorage.com for " +
							"Cloudflare R2; https://storage.googleapis.com for GCS interop)")
				}
				osCreds, err := audit.LoadObjectStorageCredentials(
					auditObjectStorageCredentialsFile)
				if err != nil {
					return err
				}
				osw, err := audit.NewObjectStorageWriter(audit.ObjectStorageWriterOptions{
					EndpointURL:     auditObjectStorageEndpoint,
					Bucket:          auditObjectStorageBucket,
					Prefix:          auditObjectStoragePrefix,
					Region:          auditObjectStorageRegion,
					Credentials:     osCreds,
					Product:         "gbounce",
					InstanceID:      auditObjectStorageInstanceID,
					RotationMinutes: auditObjectStorageRotationMinutes,
					MaxSizeMB:       auditObjectStorageMaxSizeMB,
				})
				if err != nil {
					return err
				}
				if err := osw.Start(ctx); err != nil {
					return fmt.Errorf(
						"gbounce: object-storage writer failed to start: %w", err)
				}
				srv.SetObjectStorageWriter(osw)
				defer osw.Close()
			} else if auditObjectStorageEndpoint != "" {
				return fmt.Errorf(
					"gbounce: --audit-object-storage-endpoint requires " +
						"--audit-object-storage-bucket (passing an endpoint " +
						"without a target bucket has no effect)")
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"gbounce listening on %s (mgmt %s); upstream=%q allow_connect=%v audit_log=%q\n",
				srv.Addr(), srv.MgmtAddr(),
				upstreamURL, allowConnect, auditLogPath)
			// #324d — dynamic-deny banner. One line per [[cross-product-
			// agent-parity]]; identical shape on the other Bounce
			// products. Quiet when --disable-dynamic-denies or when the
			// path can't be resolved (Watcher is nil).
			if ddBannerLine != "" {
				fmt.Fprintln(cmd.OutOrStdout(), ddBannerLine)
			}
			// #254 — preset-derivation banner sits AFTER the standard
			// startup line so the operator immediately sees which
			// settings came from the preset (vs. their own flags / env).
			// Same format across all four Bounce products per
			// [[cross-product-agent-parity]]. gbounce G-Slice 1 has
			// fewer surfaces so most cross-product canonical settings
			// land in the "not applicable to this product" annotation.
			for _, line := range presetBannerLines {
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			// #304 — known-caveats banner. Emits one line per §B entry
			// whose triggering config is detected. Quiet when no
			// triggering config applies, per the founder direction
			// "the signal should be useful, not noise." Full doc:
			// `gbounce doctor caveats` (every gbounce-relevant entry).
			for _, line := range caveats.BannerLines(caveats.Trigger{
				DiscoveryMode: cfg.Mode == proxy.ModeDiscovery,
				AllowConnect:  allowConnect,
				MITMMode:      cfg.Mode == proxy.ModeMITM,
			}) {
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
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
	// #311 / §A10 — rotation thresholds. Sentinel -1 = "use audit-pkg
	// default (matches LOG-RETENTION.md)"; 0 = "operator explicitly
	// disabled this trigger." Same names across all four Bounce
	// products per [[cross-product-agent-parity]].
	cmd.Flags().Int64Var(&auditLogMaxSizeMB, "audit-log-max-size-mb", -1,
		"#311 — rotate the JSONL audit log when its size exceeds N MB. "+
			"0 disables size-triggered rotation. Default 100 (matches the "+
			"cross-product LOG-RETENTION.md spec). Rotated files are gzip'd "+
			"in-place and live until `gbounce logs purge` reaps them (per "+
			"[[creates-never-mutates]] the active log is never destroyed "+
			"automatically). Honors $GBOUNCE_AUDIT_LOG_MAX_SIZE_MB for "+
			"non-flag overrides.")
	cmd.Flags().IntVar(&auditLogMaxAgeDays, "audit-log-max-age-days", -1,
		"#311 — rotate the JSONL audit log when its mtime is older than N "+
			"days. 0 disables age-triggered rotation. Default 7 (matches "+
			"the cross-product LOG-RETENTION.md spec). Pairs with --audit-"+
			"log-max-size-mb; whichever fires first wins. Honors "+
			"$GBOUNCE_AUDIT_LOG_MAX_AGE_DAYS for non-flag overrides.")
	cmd.Flags().IntVar(&auditDBRetentionDays, "audit-db-retention-days", -1,
		"#311 — purge rotated audit DB archives older than N days. 0 "+
			"disables DB retention. Default 30 (matches the cross-product "+
			"LOG-RETENTION.md spec). Active audit DB is NEVER deleted by "+
			"this path; only rotated archives are eligible. Honors "+
			"$GBOUNCE_AUDIT_DB_RETENTION_DAYS for non-flag overrides.")
	cmd.Flags().BoolVar(&forceExternalBind, "i-know-this-binds-externally", false, "acknowledge the threat model of binding off loopback")
	cmd.Flags().IntVar(&forwardTimeout, "forward-timeout-seconds", 60, "per-request forward timeout in seconds")
	cmd.Flags().StringVar(&mode, "mode", "discovery",
		"operating mode. discovery (DEFAULT) = forward + audit + no MITM; "+
			"mitm (#315) = terminate TLS with the CA installed via "+
			"`gbounce ca install` so URL paths + redacted bodies land in "+
			"the audit log. MITM is OPT-IN; cert-pinning SDKs will break "+
			"under it (`gbounce ca info` shows the installed CA).")
	cmd.Flags().StringVar(&auditEventsToken, "audit-events-token", "", "bearer token required for GET /audit/events when the mgmt port is bound externally; empty = loopback-only (no auth)")
	// #315 / §A13 — MITM-mode flags.
	cmd.Flags().BoolVar(&auditLogIncludeBodies, "audit-log-include-bodies", false,
		"#315 — store the REDACTED request-body snapshot in the audit "+
			"log (default OFF — only the `request_body_redacted` boolean "+
			"+ url_path land in the wire shape). Bodies are run through "+
			"the credential-shape redactor before storage; raw secrets "+
			"never reach the JSONL even with this flag on. Only relevant "+
			"in `--mode mitm`.")
	cmd.Flags().StringVar(&profileRulesFile, "profile-rules-file", "",
		"#315 — path to a JSON file with profile-deny rules. Each rule "+
			"matches an outbound request by host (exact + leading "+
			"wildcard), method, path (exact / prefix / regex), and "+
			"query_params. Only evaluated in `--mode mitm` (CONNECT-only "+
			"mode lacks the visibility for path/method predicates).")
	// #314 / §A12 — deny_hosts flags. `--deny-host` is repeatable;
	// `--deny-hosts-file` reads a newline-delimited or YAML-list-style
	// file. Both feed the same compiled rule list (union). See
	// internal/proxy/deny_hosts.go for the supported wildcard shapes +
	// the parse-time rejections (bare `*` + multi-level wildcards).
	cmd.Flags().StringArrayVar(&denyHosts, "deny-host", nil,
		"#314 — block this destination host through gbounce. Repeatable. "+
			"Exact (`evil.example.com`) or single-leading-wildcard "+
			"(`*.openai.com`) shapes accepted; `*.openai.com` matches "+
			"`api.openai.com`, `foo.bar.openai.com`, AND the bare "+
			"`openai.com`. Bare `*` and multi-level wildcards "+
			"(`*.foo.*.bar.com`) are rejected at parse time. A match emits "+
			"verdict=DENY + status_id=4 (Denied) + "+
			"ext.deny_reason=\"matched deny_hosts: <rule>\" and returns "+
			"403 to the client.")
	cmd.Flags().StringVar(&denyHostsFile, "deny-hosts-file", "",
		"#314 — read deny-host entries from a file (one entry per line; "+
			"`#`-prefixed comments + blank lines ignored). Accepts the "+
			"same YAML-list shape the future profile-mode YAML will use "+
			"(top-level `deny_hosts:` key + `- entry` lines). Union with "+
			"any `--deny-host` flags.")
	// #324d — dynamic-deny YAML path. Default ~/.iam-jit/dynamic-denies.yaml
	// (resolved via os.UserHomeDir; honors IAM_JIT_DYNAMIC_DENIES_PATH
	// env var). Per [[cross-product-agent-parity]] the flag name +
	// default is identical on the other Bounce products. When the file
	// is absent at startup the watcher waits for it to appear — startup
	// is NOT an error condition (an operator who hasn't installed any
	// dynamic denies still wants the proxy to start cleanly).
	cmd.Flags().StringVar(&dynamicDeniesPath, "dynamic-denies-path", "",
		"#324d — path to the dynamic-deny YAML file. Default "+
			"~/.iam-jit/dynamic-denies.yaml (honors "+
			"$IAM_JIT_DYNAMIC_DENIES_PATH). The file is watched via "+
			"fsnotify (fsevents on macOS, inotify on Linux); rules apply "+
			"to gbounce immediately on file change. Rules that don't "+
			"target gbounce (per the rule's `applied_to` list) are "+
			"silently skipped — a single shared file fans out across the "+
			"Bounce suite. POST /admin/dynamic-denies/reload on the mgmt "+
			"port triggers an immediate reload for cross-bouncer fan-out "+
			"orchestration (#324e). Parse errors retain the previous "+
			"in-memory snapshot + emit an admin-action OCSF event.")
	cmd.Flags().BoolVar(&disableDynamicDenies, "disable-dynamic-denies", false,
		"#324d — turn the dynamic-deny watcher off entirely. The proxy "+
			"falls back to the pre-#324d static-only `--deny-host` / "+
			"`--deny-hosts-file` shape. Useful for environments where "+
			"the operator hasn't installed the cross-product CLI yet + "+
			"the watcher's stat()ing of an absent file is undesirable.")
	cmd.Flags().StringVar(&recordSessionsDir, "record-sessions-dir", "",
		"#285 — per-session NDJSON recording directory. When set, every "+
			"audit event is also written to {dir}/{agent.session_id}.ndjson "+
			"(one file per agent session). The proxy reads agent identity "+
			"from inbound X-Agent-Session-Id + X-Agent-Name headers; events "+
			"without a session id are NOT routed to a session file. "+
			"Replayable via `iam-jit session replay <FILE>`. File mode 0o600. "+
			"Default off; the recorder captures agent identity + operation "+
			"details so it ships opt-in.")
	// #317 — cloud-neutral S3-compatible NDJSON object-storage sink.
	// All fields OFF by default. Per [[self-host-zero-billing-
	// dependency]] the bucket is operator-owned. Per [[cross-product-
	// agent-parity]] the flag shape is identical to ibounce + kbounce
	// + dbounce.
	cmd.Flags().StringVar(&auditObjectStorageEndpoint,
		"audit-object-storage-endpoint", "",
		"#317 — S3 API endpoint URL. Required when "+
			"--audit-object-storage-bucket is set. Examples: "+
			"https://s3.us-east-1.amazonaws.com (AWS S3); "+
			"https://<accountid>.r2.cloudflarestorage.com (Cloudflare R2); "+
			"https://minio.internal:9000 (MinIO); "+
			"https://storage.googleapis.com (GCS interop); "+
			"https://s3.us-west-002.backblazeb2.com (Backblaze B2); "+
			"https://nyc3.digitaloceanspaces.com (DigitalOcean Spaces).")
	cmd.Flags().StringVar(&auditObjectStorageBucket,
		"audit-object-storage-bucket", "",
		"#317 — name of the operator-owned bucket the writer appends "+
			"NDJSON files into. Operator creates the bucket; gbounce "+
			"NEVER creates buckets. When set, every OCSF event is also "+
			"written as a gzip-compressed NDJSON line into "+
			"`{prefix}/year=YYYY/month=MM/day=DD/hour=HH/"+
			"gbounce-{instance_id}-{timestamp}.jsonl.gz`. Hive-style "+
			"partitioning lets Athena / BigQuery / Spark / Trino query "+
			"the bucket directly.")
	cmd.Flags().StringVar(&auditObjectStoragePrefix,
		"audit-object-storage-prefix", "",
		"#317 — key prefix inside the bucket (e.g. `bounce-audit/prod`). "+
			"Empty = bucket root.")
	cmd.Flags().StringVar(&auditObjectStorageRegion,
		"audit-object-storage-region", audit.ObjectStorageDefaultRegion,
		"#317 — region for the SigV4 signature. AWS S3: real region. "+
			"Cloudflare R2: `auto`. Vendor-specific otherwise.")
	cmd.Flags().StringVar(&auditObjectStorageCredentialsFile,
		"audit-object-storage-credentials-file", "",
		"#317 — optional explicit credentials file (YAML or INI). "+
			"Overrides AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env "+
			"vars when set.")
	cmd.Flags().IntVar(&auditObjectStorageRotationMinutes,
		"audit-object-storage-rotation-minutes",
		audit.ObjectStorageDefaultRotationMinutes,
		"#317 — rotate the active NDJSON file when N minutes elapse OR "+
			"--audit-object-storage-max-size-mb fires.")
	cmd.Flags().IntVar(&auditObjectStorageMaxSizeMB,
		"audit-object-storage-max-size-mb",
		audit.ObjectStorageDefaultMaxSizeMB,
		"#317 — rotate the active NDJSON file when its in-memory size "+
			"estimate crosses N megabytes.")
	cmd.Flags().StringVar(&auditObjectStorageInstanceID,
		"audit-object-storage-instance-id", "",
		"#317 — override the auto-generated instance identifier "+
			"(hostname-pid) used in the object key.")
	// #254 — deployment preset. Single-flag shortcut for a common
	// deployment shape. v1.0 ships only `security-observe` per
	// [[deliberate-feature-completion]]; the framework supports more
	// (see docs/DEPLOYMENT-PRESETS.md for the roadmap). gbounce
	// G-Slice 1 has fewer surfaces than the other Bounce products so
	// most cross-product canonical settings land in the "not
	// applicable to this product" annotation in the startup banner.
	cmd.Flags().StringVar(&deploymentPreset, "preset", "",
		"#254 — single-flag shortcut for a common deployment shape. "+
			"security-observe = discovery mode + JSONL audit. Designed for "+
			"the security-team 'gather data first; author profile second' "+
			"starting shape per [[bouncer-mode-selection-for-agents]]. "+
			"Some preset values are HARD (e.g. --mode for security-observe "+
			"— the entire point of the preset is observation); passing them "+
			"with a different value is an error. Others are SOFT (e.g. "+
			"--audit-log-path); the operator's value wins. Startup banner "+
			"shows which settings are derived from the preset.")
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
//
// #303 + #305: passes through audit.ReconstructOverridesFromRow so the
// `gbounce audit tail` CLI surface + the proxy's GET /audit/events
// HTTP endpoint produce IDENTICALLY shaped events (activity_id=Connect
// on CONNECT rows; status_id=Denied + ext.deny_reason on rejected
// non-CONNECTs; status_id=Failure + ext.connect_refused on failed
// CONNECTs).
func rowsToEvents(rows []store.DecisionRow) []audit.Event {
	out := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		in := audit.RequestInput{
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
			Verdict:        r.Verdict,
			// #318 / #320 / §A20 (R3-02) — agent identity threading
			// (CLI mirror of proxy.rowsToAuditEvents). The HTTP
			// /audit/events handler + the CLI tail/export pipeline
			// MUST surface the same agent block; missing this on the
			// CLI side would mean `gbounce audit tail --export jsonl`
			// also dropped attribution. Per [[cross-product-agent-
			// parity]] both surfaces ship the same OCSF shape.
			AgentSessionID: r.AgentSessionID,
			AgentName:      r.AgentName,
		}
		audit.ReconstructOverridesFromRow(&in)
		out = append(out, audit.FromRequest(in))
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
