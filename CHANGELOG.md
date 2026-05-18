# Changelog

All notable changes to gbounce will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `gbounce backup` + `gbounce restore` per #279: single-file SQLite
  backup + gated restore so operators can move gbounce state between
  hosts, snapshot before a risky change, or recover from disaster
  WITHOUT the historical "stop daemon and cp state.db" footgun. Online
  backup via SQLite's `VACUUM INTO` primitive (no shutdown needed;
  concurrent writers continue uninterrupted); restore validates a
  `gbounce_backup_metadata` table first, refuses cross-schema
  restores even with `--force`, and probes loopback ports (8080 +
  8769) to refuse when `gbounce run` is alive. The decisions table is
  EXCLUDED by default (it's the dominant volume in a busy proxy — a
  busy deployment can accumulate GB of audit data; the JSONL audit-log
  + log-rotation pipeline is the canonical long-term audit channel);
  opt in via `--include-audit`. `--include-prompts` is accepted as a
  documented no-op (no prompts subsystem in G-Slice 1; flag exists for
  cross-product CLI parity). Both subcommands emit OCSF v1.1.0 class
  6003 admin-action events (`backup.create` Informational + `backup.
  restore` High) so a SIEM dashboard catches the DR lifecycle.
  Cross-product parity with kbounce + dbounce + ibounce per
  [[cross-product-agent-parity]]: same CLI shape, same flag names,
  same refuse-without-force semantics, same metadata-table format
  (`gbounce_backup_metadata` / `kbounce_backup_metadata` / etc.).
  Docs: `docs/BACKUP-RESTORE.md` (why, online-vs-stop-required,
  schema-version safety, three-artifact comparison with #275 + #277,
  sample session, cross-links).

- `gbounce diagnostics bundle` (alias `gbounce diag bundle`) per #277:
  produces a single ZIP with the operator's redacted config + audit-
  log tail + `/healthz` snapshot + system info + listener status +
  optional panic-log tail + a sha256 manifest. The bundle is safe to
  share with support OR to paste to a Claude agent for analysis (per
  #273) — webhook tokens / URLs, license bytes, user identifiers,
  env-var values, hostnames-in-URLs, and the audit-log path itself
  are all redacted. Reuses the `BuildExport` pipeline from #275's
  `config export` so the config-section redaction has one canonical
  source. Read-only ([[creates-never-mutates]]); one network call
  only (local `/healthz` GET, loopback by default). Cross-product
  parity with `kbounce diagnostics bundle` + `dbounce diagnostics
  bundle` per [[cross-product-agent-parity]]: same subcommand shape,
  same flag names, same `sha256:<12hex>` user-id hash format, same
  deterministic ZIP modtime (Bounce-suite epoch 2026-05-17).
  Emits an OCSF v1.1.0 class 6003 admin-action event with
  `activity_name="diagnostics.bundle"` so a SIEM correlation rule
  catches the lifecycle event regardless of which Bounce product
  fired it.

### Docs

- New `docs/DIAGNOSTICS.md`: bundle layout, redaction contract, flag
  reference, sample `unzip -l`, and cross-links to the kbounce +
  dbounce equivalents.
- README now shows two concrete `gbounce run` examples for the two
  start-mode shapes (`--upstream` for single-target rewrite,
  `--allow-connect` for CONNECT-method tunnel) so the first command
  after `go install` always succeeds — gbounce refuses to start
  without one of the two flags and the README's first snippet must
  reflect a working invocation.

### Added — G-Slice 1 (initial scaffold)

- HTTP/HTTPS forward proxy core (TLS passthrough; no MITM)
- `--mode discovery`: observe + log every request; emit one OCSF v1.1.0
  class 6003 (API Activity) event per request/response pair
- `internal/audit`: OCSF v1.1.0 class 6003 emission matching the
  existing Bounce-suite products (ibounce / kbounce / dbounce)
- SQLite audit log (`~/.gbounce/state.db`) + opt-in JSONL export via
  `--audit-log-path`
- `gbounce run` / `gbounce audit tail` / `gbounce --version` /
  `gbounce version-check`
- `/healthz` JSON liveness endpoint on separate management port (8769)
- CONNECT-tunnel support behind `--allow-connect` (TLS passthrough;
  audit log records `host:port` + method)
- Distroless multi-arch Dockerfile (TARGETOS / TARGETARCH undefaulted
  per the kbouncer #246 fix)
- GHCR publish workflow
- `go vet ./...` + `go test ./... -race` validate workflow

### Not in G-Slice 1 (queued)

- Profile mode (G-Slice 2)
- Tap mode (G-Slice 3)
- Auto-recommender (G-Slice 4)
- MCP server (G-Slice 5)
- Webhook export (G-Slice 6 — port from the existing Bounce-suite
  pattern when ready)
- Community profile bundle (post G-Slice 6)
