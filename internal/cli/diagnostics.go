// `gbounce diagnostics bundle` — single-command support-package ZIP
// for debugging a gbounce deployment WITHOUT exposing secrets.
//
// Per [[basic-app-hygiene-features]] TIER 1 + the #277 spec: every
// well-behaved product ships a "give us a ZIP we can debug" command.
// Until this slice, the operator-side answer to "gbounce is hanging /
// not forwarding / dropping audit events" was a multi-step manual
// collection of (1) version, (2) config, (3) audit-log tail,
// (4) /healthz output, (5) system info — each of those carrying its
// own redaction concern (tokens, webhook URLs, hostnames, user
// identifiers in audit rows). This command does all of it in one
// shot AND applies a uniform redactor so the resulting bundle is safe
// to share with support OR pasted to a Claude agent for analysis (per
// [[investigate-with-claude]] + #273).
//
// Bundle contents (each as a separate file in the ZIP):
//
//   00-README.txt                — top-level "what's in this bundle"
//   01-version.txt               — `gbounce --version` output + Go +
//                                  OS/ARCH from runtime
//   02-config-redacted.json      — current config redacted; reuses the
//                                  #275 BuildExport pipeline + nulls
//                                  webhook_url since the bundle is
//                                  shareable
//   03-active-mode.txt           — current mode (G-Slice 1: discovery
//                                  only). gbounce genuinely lacks the
//                                  profile / rule / task / alert-rule
//                                  subsystems sibling products ship
//                                  per [[deliberate-feature-completion]];
//                                  this section carries the equivalent
//                                  "what is the proxy doing" info.
//   04-audit-tail.jsonl          — last N=200 OCSF audit events; user
//                                  identifiers stably hashed via
//                                  sha256:<12hex> (matches the dbounce
//                                  convention per [[cross-product-
//                                  agent-parity]])
//   05-healthz.json              — output of /healthz; degrades to
//                                  "unreachable" gracefully
//   06-system.txt                — OS / kernel / hostname-redacted /
//                                  env KEYS only (no values)
//   07-listener.json             — wire port + mgmt port + (best-
//                                  effort) current request counters
//                                  from /healthz; NEVER remote IPs
//   08-panics.txt                — optional panic-log tail; redacted
//                                  via regex pass for URLs / IPs /
//                                  token-shapes
//   09-manifest.json             — file list + sha256 each; magic
//                                  string "gbounce.diagnostics" so a
//                                  support engineer can tell at a
//                                  glance which product produced it
//
// Token-leak invariant: every secret-bearing surface goes through the
// SAME redactor as `config export` (secretRedactedMarker) so a grep
// of the bundle for any known token shape returns ZERO hits. The
// test suite enforces this by seeding known-marker tokens + webhook
// URLs into fixtures and grepping the resulting ZIP.
//
// Per [[creates-never-mutates]]: this is a strictly READ-ONLY
// command. It never modifies the store, config, or audit log.
// Per [[self-host-zero-billing-dependency]]: no network calls except
// the LOCAL /healthz GET (loopback only by default).
package cli

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
)

// defaultAuditTailLines is the default count of audit-log lines
// included in the bundle's 04-audit-tail.jsonl. Override with
// --include-audit-tail. 200 matches the #277 spec + the dbounce /
// kbounce defaults so cross-product muscle memory works.
const defaultAuditTailLines = 200

// healthzProbeTimeout caps the GET to /healthz inside the bundle.
// Short enough that a misconfigured proxy (wrong port, dead socket)
// doesn't stall the bundle command for minutes.
const healthzProbeTimeout = 3 * time.Second

// userIDHashLen is the truncation length for the stable sha256
// user-id hashes. Matches the dbounce convention (sha256:<12hex>)
// per [[cross-product-agent-parity]] so a cross-product reviewer
// recognises the shape on sight.
const userIDHashLen = 12

// redactedPlaceholder is the sentinel substituted into the bundle
// wherever a secret-bearing value would otherwise appear. Reuses
// the config-export marker so a SIEM analyst grepping across the
// Bounce-suite surfaces sees one uniform redaction token.
const redactedPlaceholder = secretRedactedMarker

// diagnosticsBundleVersion stamps the manifest's bundle_version
// field; bumped only when the bundle SHAPE changes (a renamed file,
// a removed section). Additive section additions don't bump because
// consumers tolerate unknown files via the manifest entries.
const diagnosticsBundleVersion = 1

// diagnosticsBundleFormat is the magic string in the manifest so a
// support engineer can tell at a glance which product produced the
// bundle. Sibling agents in kbounce + dbounce use their own product-
// namespaced strings.
const diagnosticsBundleFormat = "gbounce.diagnostics"

// bundleEpoch is the deterministic modtime stamped on every ZIP
// entry so two bundles built from byte-identical inputs hash the
// same. We pick the Bounce-suite epoch (2026-05-17 rename day) so
// the timestamp itself is recognisable across the four products.
var bundleEpoch = time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)

// newDiagnosticsCmd assembles the `diagnostics` subcommand group +
// its `bundle` action. Registered with the `diag` alias so the
// operator's muscle memory (`gbounce diag bundle ...`) works on
// the first attempt — matches the kbounce / dbounce / ibounce
// alias contract.
func newDiagnosticsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "diagnostics",
		Aliases: []string{"diag"},
		Short:   "Produce a redacted support bundle (ZIP) for debugging",
		Long: `Group for gbounce diagnostics tools. Subcommands:

  bundle   Produce a ZIP containing the operator's redacted config +
           audit-log tail + /healthz snapshot + system info, suitable
           for sharing with support OR pasting to a Claude agent for
           analysis (per #273).

The bundle is strictly READ-ONLY (no store / config / audit-log
mutations) and performs no network calls except a single LOCAL
/healthz GET on the loopback management port.

Sibling agents in kbounce + dbounce + ibounce ship the same subcommand
shape + flag names so cross-product muscle memory works (one
` + "`{product} diag bundle --out ./bundle.zip`" + ` invocation across
all four).`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return fmt.Errorf("gbounce diagnostics: subcommand required (try `gbounce diagnostics bundle`)")
	}
	cmd.AddCommand(newDiagnosticsBundleCmd())
	return cmd
}

// newDiagAliasCmd registers the top-level `gbounce diag` shorthand
// (matches `kbounce diag` + `dbounce diag`). Forwards to the same
// `diagnostics bundle` worker — operators who type `gbounce diag
// bundle ...` get the same behavior as `gbounce diagnostics bundle`.
func newDiagAliasCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diag",
		Short: "Alias for `gbounce diagnostics`",
		Long: `Alias for ` + "`gbounce diagnostics`" + `. Same subcommand surface, same
flag names. Provided per [[cross-product-agent-parity]] so the muscle
memory ` + "`{product} diag bundle ...`" + ` works identically across
ibounce / kbounce / dbounce / gbounce.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return fmt.Errorf("gbounce diag: subcommand required (try `gbounce diag bundle`)")
	}
	cmd.AddCommand(newDiagnosticsBundleCmd())
	return cmd
}

// newDiagnosticsBundleCmd implements `gbounce diagnostics bundle`.
// Honors --out, --include-audit-tail, --no-audit, --panic-log,
// --insecure-skip-verify, --audit-log-path; defaults documented in
// the flag help text.
func newDiagnosticsBundleCmd() *cobra.Command {
	var (
		outPath          string
		includeAuditTail int
		noAudit          bool
		dbPath           string
		auditLogPath     string
		healthzURL       string
		insecureSkipTLS  bool
		panicLogPath     string
	)
	cmd := &cobra.Command{
		Use:   "bundle [--out PATH] [--include-audit-tail N] [--no-audit]",
		Short: "Write a redacted diagnostics ZIP to disk",
		Long: `Produce a ZIP file containing the operator's:

  - gbounce version + Go runtime + OS/ARCH
  - active config (REDACTED — webhook URL + token masked, license
    bytes never emitted)
  - active mode (G-Slice 1: discovery only)
  - audit-log tail (default last 200 events, user IDs hashed)
  - /healthz snapshot (or "unreachable" + error reason)
  - system info (OS / kernel / hostname-redacted, env KEYS only)
  - listener status (ports + counters from /healthz; NEVER remote IPs)
  - optional panic-log tail (REDACTED for URLs / IPs / token shapes)
  - file manifest with sha256 of each entry

Default output path: ./gbounce-diagnostics-{ISO8601-UTC}.zip
Override with --out PATH.

--no-audit ships a bundle with everything EXCEPT the audit-log tail,
for paranoid operators who treat the JSONL log as sensitive even
after the user-ID hashing pass.

Per [[creates-never-mutates]]: read-only; no state mutation.
Per [[self-host-zero-billing-dependency]]: no network calls except a
local /healthz GET on the loopback port.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if includeAuditTail < 0 {
				return errors.New(
					"gbounce: --include-audit-tail must be >= 0")
			}
			if includeAuditTail == 0 {
				includeAuditTail = defaultAuditTailLines
			}

			// Resolve the output path. Default = working-dir +
			// timestamp suffix so an operator running back-to-back
			// captures (e.g. before / after a config change) gets
			// distinct files without --out plumbing.
			if outPath == "" {
				ts := time.Now().UTC().Format("20060102T150405Z")
				outPath = fmt.Sprintf("./gbounce-diagnostics-%s.zip", ts)
			}

			opts := BundleOptions{
				OutPath:               outPath,
				IncludeAuditTail:      includeAuditTail,
				NoAudit:               noAudit,
				DBPath:                dbPath,
				AuditLogPath:          auditLogPath,
				HealthzURL:            healthzURL,
				InsecureSkipTLSVerify: insecureSkipTLS,
				PanicLogPath:          panicLogPath,
				Stderr:                cmd.ErrOrStderr(),
				GeneratedAt:           time.Now().UTC(),
			}

			summary, err := WriteDiagnosticsBundle(opts)
			if err != nil {
				return err
			}

			// One-line stderr summary so the operator sees "where did
			// the bundle land + how big is it" without piping stdout
			// (reserved for a possible future --format=json mode).
			fmt.Fprintf(cmd.ErrOrStderr(),
				"gbounce: diagnostics bundle written to %s "+
					"(%d files, %d bytes, %d audit lines included)\n",
				summary.OutPath, summary.FileCount,
				summary.TotalBytes, summary.AuditLines)

			// Admin-action audit event — fires regardless of --out so
			// a security team has a witness for "who pulled
			// diagnostics + when?". EntityName carries the output
			// path. The after-snapshot captures only counts / flags
			// (never bundle bytes) so the audit row remains size-
			// stable across captures.
			snapshot := map[string]any{
				"file_count":  summary.FileCount,
				"total_bytes": summary.TotalBytes,
				"audit_lines": summary.AuditLines,
				"no_audit":    opts.NoAudit,
				"healthz_ok":  summary.HealthzOK,
				"bundle_path": summary.OutPath,
			}
			emitAdminAction(auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionDiagnosticsBundle,
				Actor:      currentActor(),
				EntityKind: "diagnostics_bundle",
				EntityName: summary.OutPath,
				Source:     audit.AdminActionSourceCLI,
				After:      snapshot,
				ExtraExt: map[string]any{
					"audit_lines": summary.AuditLines,
					"no_audit":    opts.NoAudit,
					"healthz_ok":  summary.HealthzOK,
					"file_count":  summary.FileCount,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "",
		"Write the bundle ZIP to this path (default: "+
			"./gbounce-diagnostics-{ISO8601-UTC}.zip). Parent dirs are "+
			"created 0o700; the file is written 0o600.")
	cmd.Flags().IntVar(&includeAuditTail, "include-audit-tail", defaultAuditTailLines,
		"Include the last N audit-log lines (REDACTED). Default 200. "+
			"Pass 0 to use the default; pass --no-audit to skip the "+
			"audit tail entirely.")
	cmd.Flags().BoolVar(&noAudit, "no-audit", false,
		"Skip the audit-log tail entirely. Use when the audit log "+
			"itself is the surface you don't want to ship (paranoid "+
			"operators / regulated environments where even user-ID-"+
			"hashed events are considered sensitive).")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.gbounce/state.db, or GBOUNCE_DB env).")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Path to the proxy's JSONL audit log to tail. When empty, the "+
			"04-audit-tail.jsonl section is empty + a placeholder note "+
			"records the reason. This flag ALSO doubles as the destination "+
			"for the admin-action diagnostics.bundle event — point it at "+
			"the same file the running proxy's --audit-log-path uses so "+
			"all events land in one stream.")
	cmd.Flags().StringVar(&healthzURL, "healthz-url", "http://127.0.0.1:8769/healthz",
		"URL of the running gbounce proxy's /healthz endpoint. Bundle "+
			"records \"unreachable\" + the error reason when the GET "+
			"fails — the command does NOT abort.")
	cmd.Flags().BoolVar(&insecureSkipTLS, "insecure-skip-verify", false,
		"Skip TLS verification on the /healthz GET. Useful for dev-cert "+
			"deployments behind a self-signed cert.")
	cmd.Flags().StringVar(&panicLogPath, "panic-log", "",
		"Path to a captured stderr / panic log to include (REDACTED). "+
			"Optional — bundle works without it. URLs, IPs, and token-"+
			"shape strings are scrubbed before inclusion.")
	return cmd
}

// BundleOptions controls a one-shot diagnostics-bundle write. All
// fields except OutPath have sensible defaults; tests pass explicit
// values to keep the run hermetic.
type BundleOptions struct {
	// OutPath is the on-disk ZIP path to write. Required.
	OutPath string
	// IncludeAuditTail is the count of audit lines to include from
	// AuditLogPath. Ignored when NoAudit is true.
	IncludeAuditTail int
	// NoAudit, when true, suppresses the audit-tail section entirely.
	NoAudit bool
	// DBPath is the SQLite file the bundle's config-export step
	// reads. Empty → store.DefaultDBPath via the export path.
	DBPath string
	// AuditLogPath is the audit JSONL path to tail. Empty → no
	// audit section (treated like NoAudit but with a different
	// reason string in the bundle).
	AuditLogPath string
	// HealthzURL is the local /healthz endpoint to probe. Empty →
	// no health snapshot (recorded as "skipped").
	HealthzURL string
	// InsecureSkipTLSVerify controls TLS verification on the
	// /healthz GET. Off by default.
	InsecureSkipTLSVerify bool
	// PanicLogPath is an optional captured-panics file path. Empty
	// → the bundle records "no panic-log configured".
	PanicLogPath string
	// Stderr is the writer the bundler logs non-fatal warnings to.
	// Nil → os.Stderr.
	Stderr io.Writer
	// GeneratedAt is the timestamp stamped into the manifest +
	// README. Defaults to time.Now().UTC().
	GeneratedAt time.Time
}

// BundleSummary is returned by WriteDiagnosticsBundle so the CLI can
// print a one-line stderr summary + the admin-action audit event has
// stable fields to hash. Also useful to tests that want to assert on
// the bundle's high-level shape without having to re-open the ZIP.
type BundleSummary struct {
	OutPath    string `json:"out_path"`
	FileCount  int    `json:"file_count"`
	TotalBytes int64  `json:"total_bytes"`
	AuditLines int    `json:"audit_lines"`
	HealthzOK  bool   `json:"healthz_ok"`
}

// WriteDiagnosticsBundle is the load-bearing worker. Builds each
// section in turn (collecting errors as warnings, never aborting the
// overall bundle — a partial bundle is more useful than no bundle),
// writes them to the ZIP, then writes the manifest as the last entry
// so its sha256s cover the full set.
//
// Section ordering inside the ZIP is the digit-prefixed filenames
// (00-README → 09-manifest); operators who `unzip -p ... | less` see
// the README first, manifest last.
func WriteDiagnosticsBundle(opts BundleOptions) (*BundleSummary, error) {
	if opts.OutPath == "" {
		return nil, errors.New("gbounce: BundleOptions.OutPath is required")
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}

	// Create parent dir + open the ZIP for write.
	if dir := filepath.Dir(opts.OutPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(opts.OutPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", opts.OutPath, err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	// Don't defer zw.Close() — we need its error and must Close()
	// BEFORE os.Stat() to get the on-disk size.

	summary := &BundleSummary{OutPath: opts.OutPath}
	entries := []bundleEntry{}

	// 00-README — top-level explainer so a recipient who unzips
	// without reading any docs still knows what they're looking at.
	entries = append(entries, bundleEntry{
		Name: "00-README.txt",
		Body: []byte(buildBundleReadme(opts)),
	})

	// 01-version — versionString + Go runtime info.
	entries = append(entries, bundleEntry{
		Name: "01-version.txt",
		Body: []byte(buildVersionSection()),
	})

	// 02-config-redacted — reuse config-export with redact-secrets.
	cfgBody, cfgErr := buildRedactedConfigSection(opts)
	if cfgErr != nil {
		fmt.Fprintf(opts.Stderr,
			"gbounce: diagnostics: config-export degraded: %v\n", cfgErr)
		cfgBody = []byte(fmt.Sprintf(
			"{\"error\": %q, \"note\": \"config export degraded; partial bundle\"}\n",
			cfgErr.Error()))
	}
	entries = append(entries, bundleEntry{Name: "02-config-redacted.json", Body: cfgBody})

	// 03-active-mode — gbounce-specific: G-Slice 1 ships discovery
	// only. Sibling products carry a profile.json here; gbounce
	// genuinely lacks the profile subsystem so we surface what we
	// DO have ("the proxy is in mode X") in its place.
	entries = append(entries, bundleEntry{
		Name: "03-active-mode.txt",
		Body: []byte(buildActiveModeSection(opts)),
	})

	// 04-audit-tail — opt-out via --no-audit; uses opts.AuditLogPath.
	auditBody, auditLines := buildAuditTailSection(opts)
	summary.AuditLines = auditLines
	entries = append(entries, bundleEntry{Name: "04-audit-tail.jsonl", Body: auditBody})

	// 05-healthz — local GET; failure is recorded, not fatal. We
	// reuse the parsed body for the listener section below to avoid
	// a second HTTP roundtrip + keep "no live proxy" fallback uniform.
	healthBody, healthRaw, healthOK := buildHealthzSection(opts)
	summary.HealthzOK = healthOK
	entries = append(entries, bundleEntry{Name: "05-healthz.json", Body: healthBody})

	// 06-system — OS / kernel / hostname-redacted / env KEYS only.
	entries = append(entries, bundleEntry{
		Name: "06-system.txt",
		Body: []byte(buildSystemSection()),
	})

	// 07-listener — wire/mgmt port + counters from /healthz.
	entries = append(entries, bundleEntry{
		Name: "07-listener.json",
		Body: buildListenerSection(opts, healthRaw),
	})

	// 08-panics — optional; "no panic-log configured" placeholder
	// when unset.
	entries = append(entries, bundleEntry{
		Name: "08-panics.txt",
		Body: buildPanicSection(opts),
	})

	// Write all the leading entries; we'll append the manifest last
	// so it can include sha256s of everything else.
	manifestEntries := []map[string]any{}
	for _, e := range entries {
		if err := writeZipEntry(zw, e.Name, e.Body, opts.GeneratedAt); err != nil {
			_ = zw.Close()
			return nil, fmt.Errorf("write %s: %w", e.Name, err)
		}
		sum := sha256.Sum256(e.Body)
		manifestEntries = append(manifestEntries, map[string]any{
			"name":   e.Name,
			"size":   len(e.Body),
			"sha256": hex.EncodeToString(sum[:]),
		})
		summary.FileCount++
	}

	// 09-manifest — sha256 of every other entry + the format magic
	// string so a cross-product reviewer pivots on which Bounce
	// product produced the bundle. Determinism: entries list mirrors
	// the write order so a diff across two bundles is line-stable.
	manifestPayload := map[string]any{
		"format":           diagnosticsBundleFormat,
		"bundle_version":   diagnosticsBundleVersion,
		"product":          ConfigProduct,
		"binary_version":   version,
		"generated_at":     opts.GeneratedAt.Format(time.RFC3339),
		"entries":          manifestEntries,
		"redaction_marker": redactedPlaceholder,
	}
	manifestBody, err := json.MarshalIndent(manifestPayload, "", "  ")
	if err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeZipEntry(zw, "09-manifest.json", manifestBody, opts.GeneratedAt); err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	summary.FileCount++

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalize zip: %w", err)
	}
	if st, serr := f.Stat(); serr == nil {
		summary.TotalBytes = st.Size()
	}

	return summary, nil
}

// bundleEntry is the simple {name, body} pair the bundler walks to
// populate the ZIP. Kept as a tiny inner type so the worker reads
// top-to-bottom.
type bundleEntry struct {
	Name string
	Body []byte
}

// writeZipEntry creates a zip.FileHeader with the Bounce-suite epoch
// modtime so two bundles built from byte-identical inputs hash the
// same. The deterministic timestamp is itself recognisable
// (2026-05-17 — Bounce-suite rename day) so a reviewer eyeballing
// an `unzip -l` output spots the convention.
func writeZipEntry(zw *zip.Writer, name string, body []byte, _ time.Time) error {
	hdr := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: bundleEpoch,
	}
	hdr.SetMode(0o600)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// buildBundleReadme is the top-of-bundle explainer. Kept short +
// factual so a Claude agent can use the first ~10 lines as context.
func buildBundleReadme(opts BundleOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gbounce diagnostics bundle\n")
	fmt.Fprintf(&b, "generated_at: %s\n", opts.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "format: %s\n", diagnosticsBundleFormat)
	fmt.Fprintf(&b, "bundle_version: %d\n", diagnosticsBundleVersion)
	fmt.Fprintf(&b, "binary_version: %s\n\n", version)
	fmt.Fprintf(&b, "Contents:\n")
	fmt.Fprintf(&b, "  00-README.txt              this file\n")
	fmt.Fprintf(&b, "  01-version.txt             gbounce build info\n")
	fmt.Fprintf(&b, "  02-config-redacted.json    operator config (tokens + webhook URL MASKED)\n")
	fmt.Fprintf(&b, "  03-active-mode.txt         current proxy mode (G-Slice 1: discovery)\n")
	fmt.Fprintf(&b, "  04-audit-tail.jsonl        last N audit events (user IDs hashed)\n")
	fmt.Fprintf(&b, "  05-healthz.json            /healthz snapshot\n")
	fmt.Fprintf(&b, "  06-system.txt              OS / kernel / hostname-redacted / env keys\n")
	fmt.Fprintf(&b, "  07-listener.json           bind ports + request counters\n")
	fmt.Fprintf(&b, "  08-panics.txt              captured panics (if any)\n")
	fmt.Fprintf(&b, "  09-manifest.json           file list + sha256 of each\n\n")
	fmt.Fprintf(&b, "Redaction:\n")
	fmt.Fprintf(&b, "  - audit-webhook tokens + URLs replaced with %q\n", redactedPlaceholder)
	fmt.Fprintf(&b, "  - user identifiers in audit events replaced with stable hash (sha256:<12hex>)\n")
	fmt.Fprintf(&b, "  - hostnames / IPs / env-var VALUES suppressed (keys only kept)\n")
	fmt.Fprintf(&b, "  - license bytes NEVER emitted\n")
	if opts.NoAudit {
		fmt.Fprintf(&b, "\nNOTE: --no-audit was passed; 04-audit-tail.jsonl is intentionally omitted.\n")
	}
	return b.String()
}

// buildVersionSection captures version + Go runtime + OS/ARCH so a
// support engineer sees the binary's full identity at a glance.
func buildVersionSection() string {
	var b strings.Builder
	fmt.Fprintln(&b, versionString())
	fmt.Fprintf(&b, "go_version: %s\n", runtime.Version())
	fmt.Fprintf(&b, "go_os: %s\n", runtime.GOOS)
	fmt.Fprintf(&b, "go_arch: %s\n", runtime.GOARCH)
	fmt.Fprintf(&b, "num_cpu: %d\n", runtime.NumCPU())
	return b.String()
}

// buildRedactedConfigSection reuses the #275 config-export pipeline
// with --redact-secrets so the bundle's config section is byte-
// identical to what `gbounce config export --redact-secrets` would
// produce. Single source of truth for redaction logic per
// [[deliberate-feature-completion]] — duplicating the redactor would
// let one fork drift relative to the other.
//
// Additionally nulls out webhook_url in the export: the config-export
// path masks the TOKEN under --redact-secrets but leaves the URL
// visible because in the export context the URL is the destination,
// not the credential. For a SHAREABLE diagnostics bundle the URL is
// ALSO sensitive — it identifies the operator's SIEM endpoint — so
// we apply belt-and-suspenders redaction at this site.
func buildRedactedConfigSection(opts BundleOptions) ([]byte, error) {
	exp, err := BuildExport(ExportOptions{
		DBPath:        opts.DBPath,
		RedactSecrets: true, // FORCED — diagnostics MUST redact
		RuntimeConfig: RuntimeConfigBlock{
			Mode:         "discovery",
			AuditLogPath: opts.AuditLogPath,
		},
		AuditWebhook: AuditWebhookBlock{},
	})
	if err != nil {
		return nil, err
	}
	// Belt-and-suspenders: even if a future BuildExport path leaves
	// the URL visible (e.g. someone passes --with-secrets when wiring
	// the diagnostics caller), null it out here.
	if exp.AuditWebhook.URL != "" && exp.AuditWebhook.URL != redactedPlaceholder {
		exp.AuditWebhook.URL = redactedPlaceholder
	}
	// audit_log_path identifies an operator filesystem layout; redact
	// in the bundle context too (the path can carry a username or
	// org-specific directory naming).
	if exp.RuntimeConfig.AuditLogPath != "" {
		exp.RuntimeConfig.AuditLogPath = redactedPlaceholder
	}
	out, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// buildActiveModeSection records the proxy's current operating mode.
// G-Slice 1 only supports discovery; later G-Slices will record
// profile / tap mode in the same section. This is the gbounce-
// specific equivalent of kbounce's 03-active-profile.json — gbounce
// genuinely lacks the profile subsystem (per the #275 ship note) so
// we ship the equivalent "what is the proxy doing" info here.
func buildActiveModeSection(opts BundleOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "active_mode: discovery\n")
	fmt.Fprintf(&b, "mode_source: g-slice-1-only-supports-discovery\n")
	fmt.Fprintf(&b, "captured_at: %s\n", opts.GeneratedAt.Format(time.RFC3339))
	if opts.AuditLogPath != "" {
		fmt.Fprintf(&b, "audit_log_configured: true\n")
	} else {
		fmt.Fprintf(&b, "audit_log_configured: false\n")
	}
	// Surface a hint that profile / tap modes are queued for later
	// G-Slices — context for a Claude agent reading the bundle.
	fmt.Fprintf(&b, "future_modes:\n")
	fmt.Fprintf(&b, "  profile: queued for G-Slice 2\n")
	fmt.Fprintf(&b, "  tap: queued for G-Slice 3\n")
	return b.String()
}

// buildAuditTailSection reads the last N lines from the audit log +
// applies the audit-line redactor. Returns the body + the count of
// lines included so the CLI summary + admin-action event have
// matching numbers.
func buildAuditTailSection(opts BundleOptions) ([]byte, int) {
	if opts.NoAudit {
		return []byte("# --no-audit was passed; audit tail intentionally omitted.\n"), 0
	}
	if opts.AuditLogPath == "" {
		return []byte("# no audit log path configured (pass --audit-log-path to include " +
			"the audit-log tail); section empty.\n"), 0
	}
	lines, err := tailLines(opts.AuditLogPath, opts.IncludeAuditTail)
	if err != nil {
		return []byte(fmt.Sprintf(
			"# audit-tail unavailable: %v\n", err)), 0
	}
	var b strings.Builder
	count := 0
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		redacted := redactAuditLine(ln)
		b.WriteString(redacted)
		b.WriteByte('\n')
		count++
	}
	if count == 0 {
		return []byte("# audit log is present but empty (no events to tail).\n"), 0
	}
	return []byte(b.String()), count
}

// buildHealthzSection issues a local GET to opts.HealthzURL +
// records the response body (or an error reason). Always returns a
// non-empty body so the section is never silently missing. Returns
// (prettyBody, parsedBody, ok) — the parsed body is reused by the
// listener section to avoid a second roundtrip.
func buildHealthzSection(opts BundleOptions) ([]byte, map[string]any, bool) {
	if opts.HealthzURL == "" {
		out := []byte(`{"status": "skipped", "note": "no --healthz-url configured"}` + "\n")
		return out, nil, false
	}
	transport := http.DefaultTransport
	if opts.InsecureSkipTLSVerify {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user opted in
		}
	}
	client := &http.Client{
		Timeout:   healthzProbeTimeout,
		Transport: transport,
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthzProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.HealthzURL, nil)
	if err != nil {
		body := map[string]any{
			"health": "unreachable",
			"reason": "build request: " + err.Error(),
			"probed": opts.HealthzURL,
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		return append(out, '\n'), nil, false
	}
	req.Header.Set("User-Agent", "gbounce-diagnostics/"+version)
	resp, err := client.Do(req)
	if err != nil {
		body := map[string]any{
			"health": "unreachable",
			"reason": err.Error(),
			"probed": opts.HealthzURL,
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		return append(out, '\n'), nil, false
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	// Try to parse + re-emit pretty so the bundle is human-friendly.
	var parsed map[string]any
	if jerr := json.Unmarshal(bodyBytes, &parsed); jerr == nil {
		wrap := map[string]any{
			"http_status": resp.StatusCode,
			"probed":      opts.HealthzURL,
			"body":        parsed,
		}
		out, _ := json.MarshalIndent(wrap, "", "  ")
		ok := resp.StatusCode >= 200 && resp.StatusCode < 300
		return append(out, '\n'), parsed, ok
	}
	wrap := map[string]any{
		"http_status": resp.StatusCode,
		"probed":      opts.HealthzURL,
		"raw_body":    string(bodyBytes),
	}
	out, _ := json.MarshalIndent(wrap, "", "  ")
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return append(out, '\n'), nil, ok
}

// buildSystemSection runs `uname -a` (best-effort) + records
// GOOS/GOARCH/Go version + lists GBOUNCE_* env KEYS (never values).
// Sensitive bits (hostname / FQDN) are scrubbed from `uname` output.
func buildSystemSection() string {
	var b strings.Builder
	fmt.Fprintf(&b, "os: %s\n", runtime.GOOS)
	fmt.Fprintf(&b, "arch: %s\n", runtime.GOARCH)
	fmt.Fprintf(&b, "go_version: %s\n", runtime.Version())
	fmt.Fprintf(&b, "num_cpu: %d\n\n", runtime.NumCPU())

	// uname -a — strip the hostname field (output is
	// "Darwin <host> 24.1.0 ..."; we replace the second token).
	if out, err := runCmdSafe("uname", "-a"); err == nil {
		fmt.Fprintln(&b, "uname:")
		fmt.Fprintln(&b, "  "+scrubHostnameInUname(out))
	} else {
		fmt.Fprintf(&b, "uname: <unavailable: %v>\n", err)
	}

	// Env var KEYS only — never values — for any GBOUNCE_* var.
	// Lets a recipient see "operator has GBOUNCE_DB set" without
	// learning the path.
	fmt.Fprintln(&b, "\nenv_keys (values intentionally NOT included):")
	keys := []string{}
	for _, e := range os.Environ() {
		eq := strings.IndexByte(e, '=')
		if eq < 0 {
			continue
		}
		k := e[:eq]
		if strings.HasPrefix(k, "GBOUNCE_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s\n", k)
	}
	if len(keys) == 0 {
		fmt.Fprintln(&b, "  (none)")
	}
	return b.String()
}

// buildListenerSection records the configured wire / mgmt ports +
// (when /healthz is reachable) the live request counters. Remote
// IPs are NEVER recorded — only counters + port numbers leave the
// bundle.
func buildListenerSection(opts BundleOptions, healthBody map[string]any) []byte {
	listener := map[string]any{
		"default_wire_port": 8080,
		"default_mgmt_port": 8769,
		"healthz_probed":    opts.HealthzURL,
		"note": "live connection count is sourced from /healthz when " +
			"the proxy is reachable. Remote addresses are NEVER recorded.",
	}
	if v := os.Getenv("GBOUNCE_DB"); v != "" {
		listener["env_GBOUNCE_DB_set"] = true
	}

	// Pull request counters from /healthz when reachable. We
	// intentionally pick only counter / mode fields — never any
	// hostname-shaped surface — even though the proxy's /healthz body
	// is operator-controlled, we err on the side of leaking less.
	if healthBody != nil {
		listener["live_proxy"] = true
		for _, k := range []string{
			"mode",
			"allow_connect",
			"total_requests",
			"total_errors",
			"audit_log_total",
			"audit_log_dropped",
			"audit_log_last_error",
		} {
			if v, ok := healthBody[k]; ok {
				listener[k] = v
			}
		}
	} else {
		listener["live_proxy"] = false
	}

	body, _ := json.MarshalIndent(listener, "", "  ")
	return append(body, '\n')
}

// buildPanicSection includes the captured panic-log file (if
// configured + readable). The body is passed through the audit
// redactor since panic stack frames sometimes carry env-var values
// or partial tokens.
func buildPanicSection(opts BundleOptions) []byte {
	if opts.PanicLogPath == "" {
		return []byte("# no --panic-log configured; section empty.\n")
	}
	raw, err := os.ReadFile(opts.PanicLogPath)
	if err != nil {
		return []byte(fmt.Sprintf(
			"# panic-log unreadable (%s): %v\n", opts.PanicLogPath, err))
	}
	if len(raw) == 0 {
		return []byte("# panic-log is empty (no captured panics).\n")
	}
	// Cap at 256 KiB so a runaway log doesn't bloat the bundle.
	const maxPanicBytes = 256 << 10
	if len(raw) > maxPanicBytes {
		raw = append(raw[:maxPanicBytes], []byte("\n... (truncated)\n")...)
	}
	// Light redaction: scrub URLs + obvious token-shaped strings.
	scrubbed := redactPlainText(string(raw))
	return []byte(scrubbed)
}

// runCmdSafe runs an external command with a short timeout and
// captures stdout. Returns ("", err) on any failure; the caller
// records that as "<unavailable>" rather than aborting.
func runCmdSafe(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// scrubHostnameInUname strips the hostname (2nd whitespace-separated
// token) from a uname -a output. We replace with "<hostname-redacted>"
// rather than deleting so the output's column count stays parseable.
func scrubHostnameInUname(s string) string {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return s
	}
	parts[1] = "<hostname-redacted>"
	return strings.Join(parts, " ")
}

// tailLines reads the last n non-empty lines from a file. Used for
// the audit-tail section. For typical N (<= 10_000) we seek to the
// tail region + slice the tail — keeps the implementation simple at
// the cost of memory for very large logs. The 64 MiB read cap below
// prevents pathological cases.
func tailLines(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxBytes = 64 << 20 // 64 MiB cap
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() == 0 {
		return nil, nil
	}
	const tailRegion = 1 << 20 // 1 MiB tail
	var startOff int64
	if stat.Size() > tailRegion {
		startOff = stat.Size() - tailRegion
		if _, err := f.Seek(startOff, io.SeekStart); err != nil {
			return nil, err
		}
	}
	reader := bufio.NewReader(io.LimitReader(f, maxBytes))
	lines := []string{}
	scanner := bufio.NewScanner(reader)
	// Allow large single-line entries (OCSF events can be several
	// KiB) by raising the scanner buffer.
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 4*1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// If we seeked, the first line is probably partial. Drop it.
	if startOff > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// userIDFields names the JSON keys we treat as user identifiers in
// audit events. Each key encountered in a parsed audit line has its
// value replaced with a stable SHA-256-prefixed hash so two events
// for the same actor produce the same redacted token (cross-event
// correlation is preserved) without leaking the identity itself.
//
// Keys are case-INsensitive; the matcher lowercases before compare.
// We list the OCSF actor fields + the gbounce-side identifier surfaces
// (impersonated_role / profile_name / task_id) that future G-Slices
// will surface in audit rows.
var userIDFields = []string{
	"name",
	"user_name",
	"username",
	"uid",
	"user_uid",
	"sub",
	"email",
	"impersonated_role",
	"profile_name",
	"task_id",
}

// urlPattern matches absolute http(s) URLs anywhere in a string.
// Used by redactPlainText for the panic-log scrubber + as a fallback
// when an audit line failed to JSON-parse.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// ipPattern matches IPv4 + IPv6 literals. Loose-but-acceptable: the
// bundle is a debugging artifact, not a court exhibit; false
// positives just over-redact.
var ipPattern = regexp.MustCompile(
	`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+)\b`)

// tokenLikePattern matches common token shapes: long random-looking
// strings of 32+ chars OR a `Bearer <token>` Authorization header.
// Heuristic — we accept false positives over false negatives since
// the bundle is meant to be shared.
var tokenLikePattern = regexp.MustCompile(
	`(?i)(bearer\s+[A-Za-z0-9._\-]+|[A-Za-z0-9+/=_\-]{32,})`)

// emailPattern matches RFC 5322-ish email shapes. Audit events
// frequently carry actor emails; we want them masked even when the
// surrounding key isn't on the userIDFields list.
var emailPattern = regexp.MustCompile(
	`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// redactAuditLine parses one JSONL audit-event line + walks it
// recursively, replacing values under userIDFields with a stable
// hash. Non-JSON lines (operator commentary, malformed entries)
// pass through redactPlainText unchanged so they're still scrubbed
// of obvious tokens / URLs.
func redactAuditLine(line string) string {
	var v any
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		return redactPlainText(line)
	}
	redactWalk(v)
	out, err := json.Marshal(v)
	if err != nil {
		return redactPlainText(line)
	}
	return string(out)
}

// redactWalk recursively descends a parsed JSON value, replacing
// userID-shaped values with a stable hash + scrubbing URLs / IPs
// inside string values that aren't user IDs. Also masks any field
// whose KEY looks token-shaped (token / api_key / secret / bearer /
// authorization) since those are unambiguously sensitive.
func redactWalk(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isUserIDKey(k) {
				if s, ok := val.(string); ok && s != "" {
					t[k] = hashUserID(s)
					continue
				}
			}
			if isURLKey(k) {
				if s, ok := val.(string); ok && s != "" {
					t[k] = redactedPlaceholder
					continue
				}
			}
			if isSensitiveKey(k) {
				// Token / secret / api_key shapes — mask the value
				// regardless of its concrete type so booleans / nested
				// objects under a "secret" key still get redacted.
				t[k] = redactedPlaceholder
				continue
			}
			// String values that aren't categorized above still get a
			// scrub pass so an inline URL / token-shape embedded in a
			// freeform "message" or "raw_data" field is not leaked.
			if s, ok := val.(string); ok {
				t[k] = redactPlainText(s)
				continue
			}
			// Recurse into nested objects / arrays.
			redactWalk(val)
		}
	case []any:
		for i, item := range t {
			if s, ok := item.(string); ok {
				t[i] = redactPlainText(s)
				continue
			}
			redactWalk(item)
		}
	}
}

// isURLKey returns true for any JSON field name that conventionally
// carries a URL (which the bundle treats as sensitive — the URL
// identifies an operator's SIEM / webhook endpoint).
func isURLKey(k string) bool {
	lk := strings.ToLower(k)
	if lk == "url" || lk == "webhook_url" || lk == "endpoint" ||
		lk == "upstream" || lk == "upstream_url" {
		return true
	}
	return strings.HasSuffix(lk, "_url")
}

// sensitiveKeyFragments names the substrings that mark a field as
// secret-bearing. Case-insensitive substring match: a key like
// "auth_token" or "x-api-key" or "client_secret" matches.
var sensitiveKeyFragments = []string{
	"token",
	"secret",
	"api_key",
	"apikey",
	"password",
	"passwd",
	"bearer",
	"authorization",
	"private_key",
	"webhook_token",
	"hec_token",
}

// isSensitiveKey returns true when the field key contains any of
// the sensitiveKeyFragments (case-insensitive).
func isSensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, frag := range sensitiveKeyFragments {
		if strings.Contains(lk, frag) {
			return true
		}
	}
	return false
}

// isUserIDKey returns true for any audit-event field name that
// carries a user identifier per the OCSF + Bounce-suite schemas.
// Case-insensitive match.
func isUserIDKey(k string) bool {
	lk := strings.ToLower(k)
	for _, f := range userIDFields {
		if lk == f {
			return true
		}
	}
	return false
}

// hashUserID returns a "sha256:<12hex>" stable token for an input
// identifier. Matches the dbounce convention so a cross-product
// reviewer recognises the shape on sight. Empty input round-trips
// to empty so an unpopulated optional field doesn't render as a
// hash of "".
func hashUserID(id string) string {
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return "sha256:" + hex.EncodeToString(sum[:])[:userIDHashLen]
}

// redactPlainText scrubs obvious token / URL / IP / email shapes
// from an arbitrary string. Used for the panic-log section + as a
// fallback when a "JSONL" audit line failed to parse.
func redactPlainText(s string) string {
	s = urlPattern.ReplaceAllString(s, redactedPlaceholder)
	s = emailPattern.ReplaceAllString(s, redactedPlaceholder)
	s = tokenLikePattern.ReplaceAllString(s, redactedPlaceholder)
	s = ipPattern.ReplaceAllString(s, redactedPlaceholder)
	return s
}
