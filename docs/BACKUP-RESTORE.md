# gbounce backup + restore (#279)

`gbounce backup` and `gbounce restore` ship an online SQLite backup +
gated structured restore so an operator can move gbounce state between
hosts, snapshot before a risky change, or recover from disaster.

Sibling commands `kbounce backup`/`restore` (kbouncer), `dbounce
backup`/`restore` (dbounce), and `ibounce backup`/`restore`
(iam-jit-bouncer) ship the same CLI shape + the same metadata-table
format. The product-namespaced metadata table inside each backup file
is `gbounce_backup_metadata` / `kbounce_backup_metadata` /
`dbounce_backup_metadata` / `iam_jit_backup_metadata` so a single
shared tooling layer can tell which product produced the file.

## Why

- **Migration.** Move a hand-tuned dev-laptop gbounce onto a CI runner
  or sibling deployment without losing the schema_version stamp or the
  audit-log baseline.
- **Disaster recovery.** Restore a deployment's state.db after a host
  loss, snapshot rotation, or accidental file deletion.
- **Audit-trail preservation.** The decisions table is excluded by
  default (see "What ships in a backup" below) but `--include-audit`
  ships it; the JSONL audit-log + log-rotation pipeline remains the
  canonical long-term audit channel.

For per-bundle MERGE semantics (apply runtime-config + audit-webhook
settings onto an existing deployment) use `gbounce config import`
instead — see `docs/CONFIG-EXPORT-IMPORT.md` for that surface.
`gbounce restore` REPLACES the destination database wholesale.

## Three distinct artifacts

gbounce ships three operator-facing portability tools — each with a
different intended audience:

| Artifact | Subcommand | Audience | Issue |
| --- | --- | --- | --- |
| Portable config bundle (JSON) | `gbounce config export | import` | Change-management review, cross-host config sync | #275 |
| Diagnostics support bundle (ZIP) | `gbounce diagnostics bundle` | Support tickets, agent-shared troubleshooting | #277 |
| SQLite backup (single `.db` file) | `gbounce backup | restore` | Disaster recovery, machine migration | #279 |

They overlap in spirit but serve distinct workflows: the JSON bundle
is human-readable + safe to commit to a repo; the diagnostics ZIP is
designed to share over a support channel with secrets redacted; the
SQLite backup is the on-disk store itself, optimized for DR + wholesale
replacement (no merge semantics, schema-version-gated, refuses while
the proxy is running).

## Backup is online; restore requires the proxy stopped

`gbounce backup` uses SQLite's `VACUUM INTO` primitive: the source
database is NOT locked, concurrent writers continue uninterrupted, and
the destination file is created atomically. You can back up a running
deployment.

`gbounce restore` REPLACES the destination database file. The command
probes the loopback wire + management ports (8080 + 8769 by default)
and refuses with an actionable error if `gbounce run` is alive. Stop
the running process before restoring:

```
pkill -f 'gbounce run'   # or your service manager's stop verb
gbounce restore --in gbounce-backup-2026-05-18T14-30-00Z.db
```

If the probe ports are held by an unrelated process, pass `--probe-skip`
after manually verifying gbounce is down. To override the probe
targets (non-default ports), use `--probe-port` repeatedly:

```
gbounce restore --in backup.db --probe-port 18080 --probe-port 18769
```

## Schema-version safety

Every backup file embeds the SchemaVersion the producing binary was
built against. `gbounce restore` refuses to restore a backup whose
`schema_version` does NOT match the running binary — even with
`--force`. Cross-schema restores require the (out-of-scope-for-#279)
`gbounce migrate` command.

gbounce-version mismatches WITHIN the same schema version are
supported as a soft gate: the restore prints a WARNING + requires
`--force` to proceed. Use this when restoring a v1.0.5 backup onto a
v1.1.0 binary.

## What ships in a backup

By default the backup file contains:

- `schema_version` — for `gbounce restore`'s schema-version gate
- `gbounce_backup_metadata` — provenance row (gbounce_version,
  created_at, source_hostname_hash, schema_version, included_audit,
  included_prompts)

Excluded by default + opt-in via flag:

- `decisions` — opt in via `--include-audit`. **High volume warning:**
  gbounce's `decisions` table is the dominant storage volume in a
  running deployment because every forwarded request emits one row +
  one OCSF audit event. A busy proxy can accumulate **GB of audit
  data** in this table; the default backup excludes it to keep the
  backup file small + DR-focused. For long-term audit preservation,
  point Fluent Bit / Vector / logrotate at the JSONL audit log
  (`--audit-log-path` on `gbounce run`) — that's the canonical
  audit-shipping channel and is independent of the SQLite store.

- `--include-prompts` is accepted as a **documented no-op in G-Slice
  1**: gbounce has no prompts subsystem yet. The flag exists for
  cross-product CLI parity with kbounce + dbounce + ibounce; passing
  it emits a stderr note + records `included_prompts=false` in the
  metadata table. A later G-Slice that adds a prompts table will wire
  the flag through without breaking the CLI shape.

## Sample session

```
$ gbounce backup --out gbounce-backup-prod.db
wrote gbounce backup to /home/op/gbounce-backup-prod.db (40960 bytes, sha256=a3f2...)
  schema_version=1  gbounce_version=v1.0.5  created_at=2026-05-18T14:30:00Z
  source_hostname_hash=8b3c5d1f9a02  included_audit=false  included_prompts=false
  tables:
    gbounce_backup_metadata          1 rows
    schema_version                   1 rows
```

Restore onto a fresh host (`gbounce` stopped first):

```
$ gbounce restore --in gbounce-backup-prod.db
restored gbounce state.db from gbounce-backup-prod.db
  destination: /home/op/.gbounce/state.db
  sha256: 4c8e91...
  row counts:
    gbounce_backup_metadata          1 rows
    schema_version                   1 rows
```

Include the audit history for a full DR snapshot:

```
$ gbounce backup --out gbounce-backup-prod-full.db --include-audit
wrote gbounce backup to /home/op/gbounce-backup-prod-full.db (847564800 bytes, sha256=...)
  schema_version=1  gbounce_version=v1.0.5  created_at=2026-05-18T14:30:00Z
  source_hostname_hash=8b3c5d1f9a02  included_audit=true  included_prompts=false
  tables:
    decisions                        12480152 rows
    gbounce_backup_metadata          1 rows
    schema_version                   1 rows
```

Cross-version restore (force required):

```
$ gbounce restore --in gbounce-backup-prod-v1.0.5.db --force
gbounce: restore: WARNING gbounce_version mismatch — backup was created
by gbounce "v1.0.5", running binary is "v1.1.0". Continuing under
--force; this is supported but you should verify the running binary can
read the backup's row shapes.
restored gbounce state.db from gbounce-backup-prod-v1.0.5.db
...
```

## Audit-event emission

Both subcommands emit an OCSF v1.1.0 class 6003 admin-action event
when `--audit-log-path PATH` is configured:

- `backup.create` — severity Informational; payload carries
  `{path, size_bytes, sha256, schema_version, gbounce_version,
  included_audit, included_prompts, source_hostname_hash}`.
- `backup.restore` — severity **High**; payload carries
  `{source_path, destination, sha256, force, probe_skipped,
  row_count_total}`. Restore wholesale-replaces the live store, so it
  warrants a higher signal level than backup (which is read-only).

A SIEM dashboard keyed on `activity_name="backup.restore"` catches the
DR-lifecycle event regardless of which Bounce product fired it; the
severity escalation on restore lets a SIEM rule trigger an alert
without parsing per-product payloads.

## Constraints

- Per [[creates-never-mutates]]: backup is read-only against the source
  database. Restore is the one CLI surface that DOES mutate an
  existing DB; the destructive verb is gated by the explicit
  subcommand name + the `--force` semantics + the running-process
  probe.
- Per [[self-host-zero-billing-dependency]]: no network calls. Both
  subcommands are pure file + SQLite operations.
- Per [[push-policy-public-repo]]: the metadata table records
  `source_hostname_hash` (sha256[:12] of the hostname) rather than the
  literal hostname so an operator can share a backup file for support
  purposes without leaking infra topology.

## Out of scope (for #279)

- Cross-schema-version restore (`gbounce migrate`). The
  schema_version-mismatch refusal is intentional — restoring across
  schema versions would leave the destination running against tables
  the binary doesn't know how to read.
- Encrypted backups. The destination file inherits 0o600 perms and the
  hostname hash is the only privacy primitive. Wrap in your own
  encryption layer (`gpg --symmetric` / `age` / `aws s3 cp --sse`) when
  shipping backups across trust boundaries.
- Incremental backups. Each `gbounce backup` invocation is a full
  snapshot. With the default (decisions excluded) the state.db is
  small enough that incrementals aren't worth the recovery complexity;
  with `--include-audit` the right answer is the JSONL audit-log +
  log-rotation pipeline, not incremental SQLite backups.

## See also

- `docs/CONFIG-EXPORT-IMPORT.md` — JSON config bundle (#275)
- `docs/DIAGNOSTICS.md` — support-bundle ZIP (#277)
- kbouncer `docs/BACKUP-RESTORE.md` — sibling cross-product reference
- dbounce `docs/BACKUP-RESTORE.md` — sibling cross-product reference
