// `gbounce backup` + `gbounce restore` per #279 (SQLite backup/restore).
//
// The two commands are sibling top-level subcommands (NOT nested under
// `gbounce config`) because their semantics are wholesale-file rather
// than per-bundle-merge: a `gbounce config import` overlays runtime
// config + audit-webhook config onto an existing deployment; a
// `gbounce restore` REPLACES the deployment's state.db with a backup
// file. Distinct verbs, distinct command names.
//
// Cross-product alignment per [[cross-product-agent-parity]]: kbounce
// + dbounce + ibounce ship the same `<product> backup` + `<product>
// restore` CLI shape with the same flag names + the same
// refuse-without-force semantics + the same
// `{product}_backup_metadata` table format.
//
// What backup ships by default (per #279 spec):
//
//   - schema_version table                — for the restore gate
//   - gbounce_backup_metadata             — provenance row
//   - decisions table is SKIPPED by default — gbounce's decisions
//     table is the dominant volume (every forwarded request emits one
//     row + one OCSF event), so default inclusion would silently
//     produce multi-GB backups on a busy proxy. Opt in via
//     --include-audit. Most operators route long-term audit data via
//     the JSONL audit-log + log-rotation pipeline instead.
//
// What backup ships only on opt-in:
//
//   - decisions table (--include-audit)   — the audit-history
//   - prompts table (--include-prompts)   — G-Slice 1 NO-OP; the
//     prompts table doesn't exist yet. Flag accepted for
//     cross-product CLI parity; metadata always records
//     included_prompts=false in G-Slice 1.
//
// Admin-action audit emission: both subcommands emit an OCSF class
// 6003 admin-action event via the existing internal/audit LogWriter
// when --audit-log-path is configured. Same wire shape the existing
// `gbounce config export | import` events use; cross-product correlation
// rules keyed on activity_name="backup.create" / "backup.restore"
// catch the lifecycle event regardless of which product fired it.

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// newBackupCmd implements `gbounce backup`. Top-level subcommand (NOT
// nested under `gbounce config`) per the file's doc comment.
func newBackupCmd() *cobra.Command {
	var (
		dbPath         string
		outPath        string
		includeAudit   bool
		includePrompts bool
		actor          string
		noTimestamp    bool
		auditLogPath   string
	)
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write an online SQLite backup of gbounce state.db to a file",
		Long: `Creates an online backup of gbounce's SQLite state database
using SQLite's VACUUM INTO primitive. The source database is NOT
locked; concurrent writers continue uninterrupted. The destination is
a fresh SQLite file at --out (default: gbounce-backup-<timestamp>.db
in the current working directory).

Default contents:
  - schema_version (for the restore gate)
  - gbounce_backup_metadata (provenance row)
  - decisions table is SKIPPED by default; pass --include-audit to opt in
  - prompts table is accepted as a no-op via --include-prompts in
    G-Slice 1 (no prompts subsystem exists yet)

The decisions table is excluded by default because every forwarded
request emits one row + one OCSF audit event, so a busy proxy can
accumulate GB of audit data. The default backup stays small +
DR-focused; long-term audit preservation is the JSONL audit-log +
log-rotation pipeline's job.

The backup file embeds a gbounce_backup_metadata table carrying:
  - gbounce_version
  - created_at (RFC3339)
  - source_hostname_hash (sha256[:12] of the source host's hostname)
  - schema_version
  - included_audit / included_prompts flags

` + "`gbounce restore`" + ` reads this metadata to validate cross-version +
cross-schema restores.

Per [[creates-never-mutates]]: backup is READ-ONLY against the source
database. Per [[self-host-zero-billing-dependency]]: no network calls.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if outPath == "" {
				outPath = defaultBackupFilename(noTimestamp)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			hostname, _ := os.Hostname()
			meta, err := st.Backup(outPath, store.BackupOptions{
				IncludeAudit:   includeAudit,
				IncludePrompts: includePrompts,
				GbounceVersion: version,
				Hostname:       hostname,
			})
			if err != nil {
				return err
			}

			abs, _ := filepath.Abs(outPath)
			info, statErr := os.Stat(outPath)
			var size int64
			if statErr == nil {
				size = info.Size()
			}
			counts, _ := store.CountRowsByTable(outPath)
			sum, _ := store.FileSHA256(outPath)
			fmt.Fprintf(cmd.OutOrStdout(),
				"wrote gbounce backup to %s (%d bytes, sha256=%s)\n",
				abs, size, sum)
			fmt.Fprintf(cmd.OutOrStdout(),
				"  schema_version=%d  gbounce_version=%s  created_at=%s\n",
				meta.SchemaVersion, meta.GbounceVersion,
				meta.CreatedAt.Format(time.RFC3339))
			fmt.Fprintf(cmd.OutOrStdout(),
				"  source_hostname_hash=%s  included_audit=%t  included_prompts=%t\n",
				meta.SourceHostnameHash, meta.IncludedAudit, meta.IncludedPrompts)
			if includePrompts && !meta.IncludedPrompts {
				// Honest no-op surface so an agent / operator who passed
				// --include-prompts doesn't silently believe data shipped.
				fmt.Fprintln(cmd.ErrOrStderr(),
					"gbounce: note: --include-prompts is a no-op in G-Slice 1 "+
						"(no prompts subsystem yet; flag accepted for cross-product parity)")
			}
			if len(counts) > 0 {
				names, _ := store.SortedTableNames(outPath)
				fmt.Fprintln(cmd.OutOrStdout(), "  tables:")
				for _, n := range names {
					fmt.Fprintf(cmd.OutOrStdout(), "    %-32s %d rows\n", n, counts[n])
				}
			}

			// Admin-action OCSF event. The After snapshot captures the
			// backup file's shape (metadata + counts + size) so a SIEM
			// rule can pivot on the row without parsing per-field
			// payloads.
			snapshot := map[string]any{
				"path":                 abs,
				"size_bytes":           size,
				"sha256":               sum,
				"schema_version":       meta.SchemaVersion,
				"gbounce_version":      meta.GbounceVersion,
				"included_audit":       meta.IncludedAudit,
				"included_prompts":     meta.IncludedPrompts,
				"source_hostname_hash": meta.SourceHostnameHash,
			}
			emitAdminAction(auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionBackupCreate,
				Actor:      resolveActor(actor),
				EntityKind: "backup",
				EntityName: abs,
				Source:     audit.AdminActionSourceCLI,
				After:      snapshot,
				ExtraExt: map[string]any{
					"path":             abs,
					"size_bytes":       size,
					"sha256":           sum,
					"included_audit":   meta.IncludedAudit,
					"included_prompts": meta.IncludedPrompts,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite source DB path (default: ~/.gbounce/state.db, or GBOUNCE_DB env).")
	cmd.Flags().StringVar(&outPath, "out", "",
		"Output file path. Default: gbounce-backup-<RFC3339-timestamp>.db in cwd.")
	cmd.Flags().BoolVar(&includeAudit, "include-audit", false,
		"Include the decisions table in the backup (default: excluded). "+
			"WARNING: gbounce's decisions table is the dominant volume — "+
			"a busy proxy can accumulate GB of audit data. Default exclusion "+
			"keeps backup files small + DR-focused; use the JSONL audit-log + "+
			"log-rotation pipeline for long-term audit preservation.")
	cmd.Flags().BoolVar(&includePrompts, "include-prompts", false,
		"Documented no-op in G-Slice 1 (no prompts subsystem yet). "+
			"Flag accepted for cross-product CLI parity with kbounce + "+
			"dbounce + ibounce; ignored at the backup-content level.")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded on the admin-action audit event. "+
			"Defaults to $USER then 'operator'.")
	cmd.Flags().BoolVar(&noTimestamp, "no-timestamp", false,
		"Skip the RFC3339 timestamp in the default --out filename. "+
			"Use only when you're managing filenames yourself (e.g. a CI "+
			"job that uploads to S3 keyed on the job id).")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Append the admin-action OCSF event to this JSONL audit log. "+
			"When empty, the backup is performed but NOT recorded in the "+
			"audit-export channel. Point this at the same file the proxy "+
			"daemon's --audit-log-path uses so all events land in one stream.")
	return cmd
}

// newRestoreCmd implements `gbounce restore`. Top-level subcommand
// (NOT nested under `gbounce config`) per the file's doc comment.
func newRestoreCmd() *cobra.Command {
	var (
		dbPath       string
		inPath       string
		force        bool
		actor        string
		probeSkip    bool
		probePort    []int
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Replace gbounce state.db with a backup file (destructive; gated)",
		Long: `Restores a ` + "`gbounce backup`" + ` file by copying it onto the
running deployment's state.db path. The destination is REPLACED — this
is a DR action, not a merge. For per-bundle merge semantics use
` + "`gbounce config import`" + ` instead.

Validation gates (all checked BEFORE the destructive copy):

  1. Schema-version match (HARD; --force does NOT override).
     Cross-schema restore is the ` + "`gbounce migrate`" + ` story,
     out-of-scope for #279.
  2. gbounce-version match (soft; --force overrides with a warning).
     Cross-version restores within the same schema_version are supported.
  3. Destination database must be empty (no rows in any config-bearing
     user table) unless --force is passed. The decisions table is
     intentionally NOT considered config-bearing so a fresh install
     that's already served a request doesn't trip the gate.
  4. ` + "`gbounce run`" + ` must not be running (probe loopback ports
     8080 + 8769). Pass --probe-skip if the ports are held by an
     unrelated process and you've manually verified gbounce is down.

On success the command prints the per-table row counts of the restored
database + its sha256 fingerprint.

Per [[creates-never-mutates]]: restore is the one CLI surface that DOES
mutate an existing DB; the destructive verb is gated by the explicit
subcommand name + the --force semantics + the running-process probe.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if inPath == "" {
				return errors.New("--in is required (path to a `gbounce backup` file)")
			}
			if dbPath == "" {
				resolved, err := store.DefaultDBPath()
				if err != nil {
					return fmt.Errorf("resolve default DB path: %w", err)
				}
				dbPath = resolved
			}

			opts := store.RestoreOptions{
				Force:          force,
				GbounceVersion: version,
				ProbeTimeout:   200 * time.Millisecond,
			}
			if probeSkip {
				opts.ProbePorts = []store.HostPort{} // empty, not nil — skips
			} else if len(probePort) > 0 {
				targets := make([]store.HostPort, 0, len(probePort))
				for _, p := range probePort {
					targets = append(targets, store.HostPort{Host: "127.0.0.1", Port: p})
				}
				opts.ProbePorts = targets
			}

			result, warn, err := store.Restore(inPath, dbPath, opts)
			if warn != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), warn.String())
			}
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"restored gbounce state.db from %s\n", inPath)
			fmt.Fprintf(cmd.OutOrStdout(),
				"  destination: %s\n  sha256: %s\n",
				result.DstPath, result.SHA256)
			if len(result.TableNames) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "  row counts:")
				for _, n := range result.TableNames {
					fmt.Fprintf(cmd.OutOrStdout(),
						"    %-32s %d rows\n", n, result.RowCounts[n])
				}
			}

			// Admin-action OCSF event. Restore is a HIGH-severity action
			// (the audit helper picks the severity automatically from
			// the action constant); the After snapshot captures the
			// restored file's identity (path + sha256 + row totals) so a
			// SIEM dashboard can correlate the event to the backup file.
			emitAdminAction(auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionBackupRestore,
				Actor:      resolveActor(actor),
				EntityKind: "backup",
				EntityName: inPath,
				Source:     audit.AdminActionSourceCLI,
				After: map[string]any{
					"source_path":     inPath,
					"destination":     result.DstPath,
					"sha256":          result.SHA256,
					"force":           force,
					"probe_skipped":   probeSkip,
					"row_count_total": totalRowCount(result.RowCounts),
				},
				ExtraExt: map[string]any{
					"source_path":     inPath,
					"destination":     result.DstPath,
					"sha256":          result.SHA256,
					"force":           force,
					"probe_skipped":   probeSkip,
					"row_count_total": totalRowCount(result.RowCounts),
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "",
		"Path to the gbounce backup file to restore. Required.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"Destination SQLite DB path (default: ~/.gbounce/state.db, or GBOUNCE_DB env).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Override the non-empty-destination refusal + the gbounce_version-mismatch warning. "+
			"Does NOT override schema_version mismatch (cross-schema migration is `gbounce migrate` territory).")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded on the admin-action audit event. "+
			"Defaults to $USER then 'operator'.")
	cmd.Flags().BoolVar(&probeSkip, "probe-skip", false,
		"Skip the running-process probe. Use only when the probe ports are "+
			"held by an unrelated process and you've manually verified gbounce is down.")
	cmd.Flags().IntSliceVar(&probePort, "probe-port", nil,
		"Override the loopback ports the running-process probe dials "+
			"(default: 8080 + 8769). Repeatable: --probe-port 8080 --probe-port 8769.")
	_ = cmd.MarkFlagRequired("in")
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Append the admin-action OCSF event to this JSONL audit log.")
	return cmd
}

// defaultBackupFilename returns gbounce-backup-<RFC3339-timestamp>.db
// in the current working directory. When noTimestamp is true the
// filename is just gbounce-backup.db.
func defaultBackupFilename(noTimestamp bool) string {
	if noTimestamp {
		return "gbounce-backup.db"
	}
	// RFC3339 with `:` replaced by `-` so the filename is portable
	// across platforms that disallow `:` in filenames (Windows).
	ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	return "gbounce-backup-" + ts + ".db"
}

// totalRowCount sums every value in the per-table count map. Surfaced
// in the audit event payload as a single integer so a SIEM rule can
// alert on "an unusually small restore" without parsing per-table
// fields.
func totalRowCount(counts map[string]int64) int64 {
	var n int64
	for _, c := range counts {
		n += c
	}
	return n
}

// resolveActor picks the operator string for the admin-action audit
// row. Explicit --actor flag wins; otherwise fall back to the existing
// currentActor() helper (USER → USERNAME → "operator") so the audit
// row always carries a value.
func resolveActor(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return currentActor()
}
