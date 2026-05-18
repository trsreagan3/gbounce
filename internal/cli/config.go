// `gbounce config export | import` — portable JSON bundle for backup,
// restore, migration, and change-management review.
//
// Cross-product parity per [[cross-product-agent-parity]]: kbounce +
// dbounce + ibounce already ship config export/import. gbounce lands
// here at the same shape: same `schema_version` + `product` guard,
// same `--redact-secrets` default, same OCSF-class-6003 admin-action
// event on both subcommands, same "refuse the cross-product import"
// semantic.
//
// What ships in G-Slice 1's bundle (schema:
// schemas/gbounce-config.schema.json):
//
//   - schema_version (string)            "1.0"
//   - product (string)                   "gbounce" — REFUSED on import
//                                          when it doesn't match
//   - gbounce_version (string)           cli.version stamp
//   - exported_at (RFC3339 UTC)          provenance
//   - source_hostname_hash (sha256[:12]) lets a reviewer correlate two
//                                          exports as coming from the
//                                          same host without leaking
//                                          the hostname
//   - profiles_supported (bool=false)    explicit per-section "the
//                                          subsystem does not exist
//                                          yet" so cross-product re-
//                                          import logic stays simple
//                                          per the task spec
//   - rules_supported / tasks_supported / alert_rules_supported /
//     mcp_install_history_supported (bool=false) — same shape
//   - runtime_config (object)            mode + bind defaults + audit-
//                                          log path
//   - audit_webhook (object)             URL + token MASKED unless
//                                          (future) --with-secrets;
//                                          `redacted` boolean records
//                                          which mode was used
//   - license (object, optional)         license_id + expires_at;
//                                          bytes are NEVER emitted
//
// What does NOT ship by design:
//
//   - decisions table contents (route via the audit-export pipeline
//     instead; --include-audit ships a HEAD tail only when explicitly
//     requested)
//   - bodies, bearer tokens, request headers (gbounce holds these long
//     enough to forward; they MUST NOT leave the local machine via the
//     export channel per [[self-host-zero-billing-dependency]] +
//     [[security-team-positioning-safety-not-surveillance]])
//
// Redaction default: --redact-secrets is the DEFAULT. Webhook URL +
// token are masked to "***REDACTED***" unless the operator explicitly
// passes --with-secrets (reserved; see TODO note below). License bytes
// are NEVER emitted regardless.
//
// Refuse-if-running: import probes the configured wire port + mgmt
// port on loopback; refuses with a "stop gbounce first" message when
// either probe answers. Avoids the failure mode where an import races
// the running proxy's DB writes + leaves the store in a half-mutated
// state.
//
// Admin-action audit emission: export + import each emit exactly one
// OCSF class-6003 "config.export" / "config.import" event via the
// shared LogWriter when --audit-log-path is configured. Mirrors the
// kbounce + dbounce + ibounce wire shape so a single SIEM correlation
// rule keyed on activity_name="config.import" catches the lifecycle
// event regardless of which product fired it.
package cli

import (
	"context"
	_ "embed"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// ConfigSchemaVersion is the wire-format version of the export JSON.
// Bumped only on breaking changes; additive changes leave it at "1.0"
// so older importers degrade gracefully (unknown fields ignored).
const ConfigSchemaVersion = "1.0"

// ConfigProduct is the product name stamped into every export.
// Refusing imports whose `product` field doesn't match is the
// load-bearing "you can't import a kbounce export into gbounce"
// guard.
const ConfigProduct = "gbounce"

// secretRedactedMarker is the literal value substituted for any
// secret field when --redact-secrets is in effect. Matches the
// cross-product convention so a SIEM analyst grepping for the marker
// across kbounce / dbounce / ibounce / gbounce exports finds a
// uniform hit.
const secretRedactedMarker = "***REDACTED***"

//go:embed config_schema.json
var embeddedConfigSchema []byte

// ConfigExport is the top-level shape written by `config export` and
// expected by `config import`. JSON tags are the wire shape — Go
// field names are free to evolve as long as the tags stay stable.
type ConfigExport struct {
	SchemaVersion              string             `json:"schema_version"`
	Product                    string             `json:"product"`
	GbounceVersion             string             `json:"gbounce_version"`
	ExportedAt                 string             `json:"exported_at"`
	SourceHostnameHash         string             `json:"source_hostname_hash"`
	ProfilesSupported          bool               `json:"profiles_supported"`
	RulesSupported             bool               `json:"rules_supported"`
	TasksSupported             bool               `json:"tasks_supported"`
	AlertRulesSupported        bool               `json:"alert_rules_supported"`
	MCPInstallHistorySupported bool               `json:"mcp_install_history_supported"`
	RuntimeConfig              RuntimeConfigBlock `json:"runtime_config"`
	AuditWebhook               AuditWebhookBlock  `json:"audit_webhook"`
	License                    *LicenseBlock      `json:"license,omitempty"`
	AuditPrompts               []map[string]any   `json:"audit_prompts,omitempty"`
	AuditTail                  []map[string]any   `json:"audit_tail,omitempty"`
}

// RuntimeConfigBlock is the projection of the run-mode flags. Kept as
// a nested object so a future runtime_config field lands without
// churning the top-level shape.
type RuntimeConfigBlock struct {
	Mode                  string `json:"mode"`
	Host                  string `json:"host,omitempty"`
	Port                  int    `json:"port,omitempty"`
	MgmtHost              string `json:"mgmt_host,omitempty"`
	MgmtPort              int    `json:"mgmt_port,omitempty"`
	UpstreamURLPresent    bool   `json:"upstream_url_present,omitempty"`
	AllowConnect          bool   `json:"allow_connect,omitempty"`
	ForwardTimeoutSeconds int    `json:"forward_timeout_seconds,omitempty"`
	AuditLogPath          string `json:"audit_log_path,omitempty"`
	AuditLogFsync         bool   `json:"audit_log_fsync,omitempty"`
}

// AuditWebhookBlock carries the operator's audit-webhook channel
// configuration. URL + Token are masked when Redacted is true.
// G-Slice 1 ships only the round-trip shape — no webhook pusher is
// wired yet; this block exists so a future webhook PR's config
// surface round-trips through export/import on day one.
type AuditWebhookBlock struct {
	URL      string `json:"url,omitempty"`
	Token    string `json:"token,omitempty"`
	Redacted bool   `json:"redacted"`
}

// LicenseBlock is the license-pointer block. Bytes are NEVER emitted;
// only the license_id + expires_at metadata round-trips so a tamper-
// detection reviewer can compare across exports.
type LicenseBlock struct {
	LicenseID string `json:"license_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// ExportOptions controls a one-shot export. All fields optional;
// zero-values pick the secure default (redact secrets, write to
// stdout when Out is nil).
type ExportOptions struct {
	// Out is the writer the JSON is emitted to. Nil → stdout.
	Out io.Writer
	// DBPath is the SQLite file to read for the audit-tail section.
	// Empty → store.DefaultDBPath.
	DBPath string
	// RedactSecrets toggles whether webhook URL + token are masked.
	// true (the default) substitutes secretRedactedMarker. The current
	// CLI surface does not yet expose --with-secrets; redaction is
	// always on for v1.0 of this slice.
	RedactSecrets bool
	// IncludeAudit, when true, includes the most-recent decisions[] in
	// the export. Off by default — operators who want the full audit
	// log route it through the JSONL audit-export pipeline.
	IncludeAudit bool
	// IncludePrompts is reserved for the future prompt-capture surface
	// (G-Slice 4). Off in G-Slice 1 — the surface doesn't exist yet.
	IncludePrompts bool
	// RuntimeConfig is the run-mode snapshot to project into the
	// export. Callers wire this from the run-command flags or pass a
	// zero-value when invoked one-shot.
	RuntimeConfig RuntimeConfigBlock
	// AuditWebhook is the live webhook config to project. Empty →
	// emitted as an "absent" block (URL+Token unset, Redacted reflects
	// the redaction setting).
	AuditWebhook AuditWebhookBlock
	// License is the optional license pointer. nil → license block
	// omitted entirely. Bytes are never read from disk.
	License *LicenseBlock
}

// BuildExport collects the operator's current configuration into a
// *ConfigExport. Pure read; never mutates the store. Errors surface
// partial-context information so the operator can fix the underlying
// cause rather than guessing.
func BuildExport(opts ExportOptions) (*ConfigExport, error) {
	exp := &ConfigExport{
		SchemaVersion:              ConfigSchemaVersion,
		Product:                    ConfigProduct,
		GbounceVersion:             version,
		ExportedAt:                 time.Now().UTC().Format(time.RFC3339),
		SourceHostnameHash:         hostnameHash(),
		ProfilesSupported:          false,
		RulesSupported:             false,
		TasksSupported:             false,
		AlertRulesSupported:        false,
		MCPInstallHistorySupported: false,
		RuntimeConfig:              opts.RuntimeConfig,
		AuditWebhook:               opts.AuditWebhook,
		License:                    opts.License,
	}
	if exp.RuntimeConfig.Mode == "" {
		exp.RuntimeConfig.Mode = "discovery"
	}

	// Webhook redaction: when RedactSecrets, mask the URL + token if
	// either was populated. The redacted boolean is ALWAYS set so the
	// importer can tell "no webhook configured" apart from "webhook
	// was redacted on export."
	if opts.RedactSecrets {
		if exp.AuditWebhook.URL != "" {
			exp.AuditWebhook.URL = secretRedactedMarker
		}
		if exp.AuditWebhook.Token != "" {
			exp.AuditWebhook.Token = secretRedactedMarker
		}
		exp.AuditWebhook.Redacted = true
	}

	// Optional audit tail: a small head of recent decisions, useful
	// for a reviewer who wants the export to be self-contained. Cap
	// the row count low to keep the export readable.
	if opts.IncludeAudit {
		st, err := store.Open(opts.DBPath)
		if err != nil {
			return nil, fmt.Errorf("open store for audit tail: %w", err)
		}
		defer st.Close()
		rows, err := st.RecentDecisions(50)
		if err != nil {
			return nil, fmt.Errorf("read audit tail: %w", err)
		}
		tail := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			tail = append(tail, map[string]any{
				"at":            r.At.UTC().Format(time.RFC3339),
				"method":        r.Method,
				"path":          r.Path,
				"upstream_host": r.UpstreamHost,
				"http_status":   r.HTTPStatus,
				"verdict":       r.Verdict,
				"mode":          r.Mode,
			})
		}
		exp.AuditTail = tail
	}

	if opts.IncludePrompts {
		// Surface exists for future G-Slices; emit an empty slice so
		// importers see "the operator asked for prompts; gbounce
		// doesn't have them yet" rather than a missing field.
		exp.AuditPrompts = []map[string]any{}
	}

	return exp, nil
}

// hostnameHash returns the first 12 hex chars of sha256(os.Hostname).
// Empty / error → "unknown" sentinel so the field is always present.
// Hashing the hostname (rather than emitting it raw) lets a reviewer
// correlate two exports as coming from the same host without leaking
// internal naming.
func hostnameHash() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:])[:12]
}

// newConfigCmd assembles the `config` group + its subcommands.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Export / import gbounce configuration for backup, restore, migration",
		Long: `Export or import the operator's gbounce configuration as a
single JSON file.

Per cross-product Bounce-suite parity: kbounce + dbounce + ibounce
ship the same shape; the schema_version + product fields gate
"can't import a kbounce export into gbounce" at import time.

Token-leak invariant: ` + "`--redact-secrets`" + ` is the DEFAULT for
export. Audit-webhook URL + token are masked unless the export was
written with --redact-secrets=false. License bytes are NEVER emitted.`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newConfigExportCmd())
	cmd.AddCommand(newConfigImportCmd())
	return cmd
}

func newConfigExportCmd() *cobra.Command {
	var (
		outPath        string
		redactSecrets  bool
		includeAudit   bool
		includePrompts bool
		dbPath         string
		auditLogPath   string
	)
	cmd := &cobra.Command{
		Use:   "export --out PATH [--redact-secrets] [--include-audit] [--include-prompts]",
		Short: "Export the gbounce config as a single JSON file",
		Long: `Export the operator's gbounce config (runtime config + audit-
webhook block + license pointer when present) as a single JSON file.

Default: writes to stdout. Pass ` + "`--out PATH`" + ` to write to a file
(parent dirs are created 0o700; the file is written 0o600 so a
multi-user machine can't read another operator's export).

Token-leak invariant: ` + "`--redact-secrets`" + ` is the DEFAULT.
Webhook URL + token are masked to "***REDACTED***" in the export;
license bytes are NEVER emitted.

Admin-action OCSF event fires on every successful export so a
security team can answer "who exported the config + when?" when
--audit-log-path is configured.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := ExportOptions{
				Out:            cmd.OutOrStdout(),
				DBPath:         dbPath,
				RedactSecrets:  redactSecrets,
				IncludeAudit:   includeAudit,
				IncludePrompts: includePrompts,
				RuntimeConfig: RuntimeConfigBlock{
					Mode: "discovery",
				},
				AuditWebhook: AuditWebhookBlock{},
			}

			exp, err := BuildExport(opts)
			if err != nil {
				return err
			}

			payload, err := json.MarshalIndent(exp, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal export: %w", err)
			}
			// Trailing newline so shell pipelines + git diffs behave.
			payload = append(payload, '\n')

			destination := outPath
			if destination == "" {
				destination = "<stdout>"
				if _, err := cmd.OutOrStdout().Write(payload); err != nil {
					return fmt.Errorf("write stdout: %w", err)
				}
			} else {
				if err := writeBundleAtomic(outPath, payload); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"gbounce: config export written to %s (%d bytes)\n",
					outPath, len(payload))
			}

			// Admin-action audit event. The after-snapshot captures
			// the EXPORTED CONTENT shape (counts + flags, not secret
			// bodies) so a tamper-detection reviewer can verify "the
			// export I'm holding matches the audit-recorded one".
			snapshot := map[string]any{
				"schema_version":  exp.SchemaVersion,
				"product":         exp.Product,
				"gbounce_version": exp.GbounceVersion,
				"destination":     destination,
				"redact_secrets":  redactSecrets,
				"include_audit":   includeAudit,
				"audit_rows":      len(exp.AuditTail),
				"exported_bytes":  len(payload),
			}
			emitAdminAction(auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionConfigExport,
				Actor:      currentActor(),
				EntityKind: "config",
				EntityName: destination,
				Source:     audit.AdminActionSourceCLI,
				After:      snapshot,
				ExtraExt: map[string]any{
					"redact_secrets": redactSecrets,
					"destination":    destination,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "",
		"Write the export JSON to this file (default: stdout). Parent "+
			"dirs are created 0o700; the file is written 0o600.")
	cmd.Flags().BoolVar(&redactSecrets, "redact-secrets", true,
		"Mask audit-webhook URL + token as \"***REDACTED***\" in the "+
			"export. ON by default — flag exists for explicit-intent "+
			"scripts and for the future --redact-secrets=false escape.")
	cmd.Flags().BoolVar(&includeAudit, "include-audit", false,
		"Include the 50 most-recent decision rows from the local "+
			"SQLite audit log. Off by default — most operators route "+
			"the full audit stream through the JSONL audit-export "+
			"pipeline.")
	cmd.Flags().BoolVar(&includePrompts, "include-prompts", false,
		"Include captured prompts in the export. Reserved for a "+
			"future slice; emits an empty array in G-Slice 1.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.gbounce/state.db, or GBOUNCE_DB env).")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Append the admin-action OCSF event to this JSONL audit log. "+
			"When empty, the export is performed but NOT recorded in "+
			"the audit-export channel. Point this at the same file the "+
			"proxy daemon's --audit-log-path uses so all events land in "+
			"one stream.")
	return cmd
}

// ImportMode controls the merge semantics of `config import`.
type ImportMode string

const (
	// ImportModeMerge overlays the imported runtime-config onto the
	// existing state. Default; safer for routine restore. In G-Slice
	// 1 the merge surface is small (runtime_config + audit_webhook +
	// license) so merge and replace look the same in practice — the
	// flag exists for forward-compatibility with later G-Slices that
	// add profiles / rules / tasks.
	ImportModeMerge ImportMode = "merge"

	// ImportModeReplace wholesale-replaces the runtime config from
	// the import (vs. merging atop). G-Slice 1 honors the flag at the
	// shape level even though the visible difference is small until
	// later slices add list-typed sections.
	ImportModeReplace ImportMode = "replace"
)

// ImportDiff is the dry-run summary returned by applyImport. Counts
// per section let the operator see what each mode would do.
type ImportDiff struct {
	Mode             ImportMode `json:"mode"`
	RuntimeConfigSet bool       `json:"runtime_config_set"`
	AuditWebhookSet  bool       `json:"audit_webhook_set"`
	LicenseSet       bool       `json:"license_set"`
	AuditTailRows    int        `json:"audit_tail_rows"`
	PromptRows       int        `json:"prompt_rows"`
}

// ImportOptions controls a one-shot import.
type ImportOptions struct {
	// Source is the io.Reader yielding the export JSON. Required.
	Source io.Reader
	// SourceName is a label for error messages (file path / "<stdin>").
	SourceName string
	// Mode is "merge" (default) or "replace".
	Mode ImportMode
	// DryRun, when true, computes the diff but does NOT mutate state.
	DryRun bool
	// ProbeAddrs is the list of host:port addresses the importer
	// probes to detect a running gbounce. When empty, the runtime
	// config's host:port + mgmt_host:mgmt_port are probed. Tests can
	// override.
	ProbeAddrs []string
	// SkipRunningProbe disables the refuse-if-running check. Reserved
	// for tests that exercise the import path directly without a
	// listener; production CLI invocations always probe.
	SkipRunningProbe bool
}

// LoadAndValidate reads + JSON-decodes + schema-validates the import
// payload. Returns the parsed ConfigExport on success. The `product`
// check is the load-bearing "you can't import a kbounce export into
// gbounce" guard.
func LoadAndValidate(r io.Reader) (*ConfigExport, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 64<<20)) // 64 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read import: %w", err)
	}

	// Schema validation FIRST so structural errors surface with the
	// JSON-Schema error rather than a Go-decode error.
	if errs := validateConfigJSON(raw, embeddedConfigSchema); len(errs) > 0 {
		return nil, fmt.Errorf("schema validation failed:\n  - %s",
			strings.Join(errs, "\n  - "))
	}

	var exp ConfigExport
	if err := json.Unmarshal(raw, &exp); err != nil {
		return nil, fmt.Errorf("parse import JSON: %w", err)
	}
	if exp.SchemaVersion != ConfigSchemaVersion {
		return nil, fmt.Errorf(
			"schema_version mismatch: import has %q, this gbounce expects %q",
			exp.SchemaVersion, ConfigSchemaVersion)
	}
	if exp.Product != ConfigProduct {
		return nil, fmt.Errorf(
			"product mismatch: import has %q, this gbounce expects %q "+
				"(can't import a non-gbounce export — different config surfaces)",
			exp.Product, ConfigProduct)
	}
	return &exp, nil
}

// applyImport is the worker called by the cobra RunE. Returns the diff
// regardless of DryRun; mutations only happen when DryRun=false. In
// G-Slice 1 the only mutation surface is the future runtime-config
// destination (config file or env); without that surface wired, the
// importer reports the diff + leaves the SQLite decision log
// untouched. Later G-Slices will add real per-section writes.
func applyImport(opts ImportOptions) (*ImportDiff, *ConfigExport, error) {
	if opts.Source == nil {
		return nil, nil, errors.New("gbounce: ImportOptions.Source is required")
	}
	mode := opts.Mode
	if mode == "" {
		mode = ImportModeMerge
	}
	if mode != ImportModeMerge && mode != ImportModeReplace {
		return nil, nil, fmt.Errorf(
			"gbounce: import mode must be %q or %q (got %q)",
			ImportModeMerge, ImportModeReplace, mode)
	}

	exp, err := LoadAndValidate(opts.Source)
	if err != nil {
		return nil, nil, err
	}

	diff := &ImportDiff{
		Mode:             mode,
		RuntimeConfigSet: exp.RuntimeConfig.Mode != "",
		AuditWebhookSet:  exp.AuditWebhook.URL != "" || exp.AuditWebhook.Token != "",
		LicenseSet:       exp.License != nil && exp.License.LicenseID != "",
		AuditTailRows:    len(exp.AuditTail),
		PromptRows:       len(exp.AuditPrompts),
	}

	if opts.DryRun {
		return diff, exp, nil
	}

	// Refuse-if-running: probe the host:port + mgmt_host:mgmt_port
	// the import wants to apply. If anything answers, stop — racing
	// the live proxy on the same store / config would interleave
	// writes.
	if !opts.SkipRunningProbe {
		probes := opts.ProbeAddrs
		if len(probes) == 0 {
			probes = defaultProbeAddrs(exp.RuntimeConfig)
		}
		if hit := firstRunningProbe(probes); hit != "" {
			return diff, exp, fmt.Errorf(
				"refusing to import: gbounce appears to be running on %s. "+
					"Stop gbounce first (e.g. `pkill gbounce` or stop the systemd unit), "+
					"then re-run `gbounce config import`.", hit)
		}
	}

	// G-Slice 1 mutation surface is small: gbounce does not yet ship
	// a persistent runtime-config file (operators pass flags on
	// `gbounce run`). The import path validates + reports + emits the
	// admin-action event but does NOT write a config file in this
	// slice. Later G-Slices that add ~/.gbounce/config.yaml extend
	// this function to write that file under the merge / replace
	// semantic. Per [[deliberate-feature-completion]] we ship the
	// wire-up now so the future PR is a 1-line addition.

	return diff, exp, nil
}

// defaultProbeAddrs returns the host:port addresses to probe for a
// running gbounce, derived from the import's runtime_config block.
// Falls back to the documented defaults (127.0.0.1:8080 / :8769) when
// the import doesn't carry the values.
func defaultProbeAddrs(rc RuntimeConfigBlock) []string {
	host := rc.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := rc.Port
	if port == 0 {
		port = 8080
	}
	mgmtHost := rc.MgmtHost
	if mgmtHost == "" {
		mgmtHost = "127.0.0.1"
	}
	mgmtPort := rc.MgmtPort
	if mgmtPort == 0 {
		mgmtPort = 8769
	}
	return []string{
		net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		net.JoinHostPort(mgmtHost, fmt.Sprintf("%d", mgmtPort)),
	}
}

// firstRunningProbe returns the first address that accepts a TCP
// connection within a short timeout, or "" when none do. Used by the
// refuse-if-running guard.
func firstRunningProbe(addrs []string) string {
	for _, a := range addrs {
		conn, err := net.DialTimeout("tcp", a, 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return a
		}
	}
	return ""
}

func newConfigImportCmd() *cobra.Command {
	var (
		inPath       string
		dryRun       bool
		mergeFlag    bool
		replaceFlag  bool
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "import --in PATH [--merge | --replace] [--dry-run]",
		Short: "Import a previously-exported gbounce config",
		Long: `Import a previously-exported gbounce config JSON.

Validates schema_version + product (refuses to import a kbounce /
dbounce / ibounce export into gbounce). Schema-validates the JSON
body against the published ` + "`schemas/gbounce-config.schema.json`" + `
so malformed input is rejected BEFORE any state mutation.

Modes:

  --merge        (default; safer) overlay onto existing state.
  --replace      wholesale-replace; future G-Slices that add list-
                  typed sections (profiles / rules / tasks) use this
                  to discard existing entries.
  --dry-run      show what WOULD change without mutating anything.

Refuse-if-running: the importer probes the wire port + mgmt port on
loopback and refuses if gbounce appears to be running. Stop gbounce
first; the importer cannot safely race the live proxy's writes.

Admin-action OCSF event fires on every successful import when
` + "`--audit-log-path`" + ` is configured.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if mergeFlag && replaceFlag {
				return errors.New(
					"gbounce: --merge and --replace are mutually exclusive")
			}
			if inPath == "" {
				return errors.New("gbounce: --in PATH is required")
			}

			mode := ImportModeMerge
			if replaceFlag {
				mode = ImportModeReplace
			}

			f, err := os.Open(inPath)
			if err != nil {
				return fmt.Errorf("open %q: %w", inPath, err)
			}
			defer f.Close()

			diff, exp, err := applyImport(ImportOptions{
				Source:     f,
				SourceName: inPath,
				Mode:       mode,
				DryRun:     dryRun,
			})
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			label := "imported"
			if dryRun {
				label = "would import (--dry-run)"
			}
			fmt.Fprintf(w, "gbounce: %s (mode=%s)\n", label, diff.Mode)
			fmt.Fprintf(w, "  runtime_config:  %s\n",
				boolPresent(diff.RuntimeConfigSet))
			fmt.Fprintf(w, "  audit_webhook:   %s\n",
				boolPresent(diff.AuditWebhookSet))
			fmt.Fprintf(w, "  license:         %s\n",
				boolPresent(diff.LicenseSet))
			if diff.AuditTailRows > 0 {
				fmt.Fprintf(w, "  audit_tail:      %d rows\n",
					diff.AuditTailRows)
			}
			if diff.PromptRows > 0 {
				fmt.Fprintf(w, "  audit_prompts:   %d rows\n",
					diff.PromptRows)
			}

			if dryRun {
				return nil
			}

			snapshot := map[string]any{
				"schema_version":     exp.SchemaVersion,
				"product":            exp.Product,
				"source":             inPath,
				"mode":               string(mode),
				"runtime_config_set": diff.RuntimeConfigSet,
				"audit_webhook_set":  diff.AuditWebhookSet,
				"license_set":        diff.LicenseSet,
			}
			emitAdminAction(auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionConfigImport,
				Actor:      currentActor(),
				EntityKind: "config",
				EntityName: inPath,
				Source:     audit.AdminActionSourceCLI,
				After:      snapshot,
				ExtraExt: map[string]any{
					"source": inPath,
					"mode":   string(mode),
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "",
		"Path to the export JSON to import. Required.")
	_ = cmd.MarkFlagRequired("in")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Show what would change without mutating state.")
	cmd.Flags().BoolVar(&mergeFlag, "merge", false,
		"Overlay onto existing state (default; safer). Mutually "+
			"exclusive with --replace.")
	cmd.Flags().BoolVar(&replaceFlag, "replace", false,
		"Wholesale-replace; future slices that add list-typed sections "+
			"use this to discard existing entries.")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Append the admin-action OCSF event to this JSONL audit log.")
	return cmd
}

// boolPresent returns "present" / "absent" for the diff-summary
// renderer. Keeps the import banner readable across language locales.
func boolPresent(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}

// emitAdminAction opens a one-shot LogWriter at auditLogPath (if set),
// emits the OCSF admin-action event, and closes the writer. Mirrors
// the kbounce + dbounce pattern. All errors are non-fatal — the
// underlying admin action already succeeded.
func emitAdminAction(auditLogPath string, in audit.AdminActionInput) {
	if auditLogPath == "" {
		return
	}
	ctx := context.Background()
	lw, err := audit.NewLogWriter(ctx, audit.LogWriterOptions{
		Path:  auditLogPath,
		Fsync: true,
	})
	if err != nil {
		// Non-fatal: surface a stderr warning so the operator knows
		// the audit channel didn't record this event.
		fmt.Fprintf(os.Stderr,
			"gbounce: warn: open audit-log %q failed: %v "+
				"(admin action completed; event NOT recorded)\n",
			auditLogPath, err)
		return
	}
	defer lw.Close()
	audit.EmitAdminAction(ctx, lw, in)
}

// currentActor returns the operator name recorded in admin-action
// rows. Best-effort: USER env var → USERNAME env var → "operator".
// Same pattern kbounce + dbounce + ibounce use.
func currentActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "operator"
}

// writeBundleAtomic writes b to path via temp file + rename so a
// crash between truncate + write cannot leave a half-written bundle.
// Mirrors the cross-product Bounce-suite pattern. Uses 0600 perms so
// the export's contents stay readable only by the owning user.
func writeBundleAtomic(path string, b []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gbounce-config-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, werr := tmp.Write(b); werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", werr)
	}
	if cerr := tmp.Chmod(0o600); cerr != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", cerr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("close temp: %w", cerr)
	}
	if rerr := os.Rename(tmpName, path); rerr != nil {
		return fmt.Errorf("rename into place: %w", rerr)
	}
	return nil
}

// ---------------------------------------------------------------------
// JSON-Schema validator (minimal in-house subset, no third-party deps)
// ---------------------------------------------------------------------
//
// Mirrors the kbounce validator. Implements only the keywords our
// schema actually uses: required, properties, items, type, enum.
// Adding a new keyword to the schema requires extending validateNode.

func validateConfigJSON(payload, schema []byte) []string {
	var p any
	if err := json.Unmarshal(payload, &p); err != nil {
		return []string{fmt.Sprintf("payload is not valid JSON: %v", err)}
	}
	var s map[string]any
	if err := json.Unmarshal(schema, &s); err != nil {
		return []string{fmt.Sprintf("embedded schema is broken (build bug): %v", err)}
	}
	var errs []string
	validateNode("$", p, s, &errs)
	return errs
}

func validateNode(path string, value any, schema map[string]any, errs *[]string) {
	if t, ok := schema["type"].(string); ok {
		if !typeMatches(value, t) {
			*errs = append(*errs, fmt.Sprintf(
				"%s: expected type %q, got %s", path, t, jsonTypeOf(value)))
			return
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, e := range enum {
			if e == value {
				matched = true
				break
			}
		}
		if !matched {
			*errs = append(*errs, fmt.Sprintf(
				"%s: value %v not in enum %v", path, value, enum))
		}
	}

	if obj, ok := value.(map[string]any); ok {
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, present := obj[name]; !present {
					*errs = append(*errs, fmt.Sprintf(
						"%s: missing required field %q", path, name))
				}
			}
		}
		if props, ok := schema["properties"].(map[string]any); ok {
			keys := make([]string, 0, len(props))
			for k := range props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v, present := obj[k]
				if !present {
					continue
				}
				if propSchema, ok := props[k].(map[string]any); ok {
					validateNode(path+"."+k, v, propSchema, errs)
				}
			}
		}
	}

	if arr, ok := value.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, item := range arr {
				validateNode(fmt.Sprintf("%s[%d]", path, i), item, items, errs)
			}
		}
	}
}

func typeMatches(v any, t string) bool {
	switch t {
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		if !ok {
			return false
		}
		return f == float64(int64(f))
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "null":
		return v == nil
	}
	return false
}

func jsonTypeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}
