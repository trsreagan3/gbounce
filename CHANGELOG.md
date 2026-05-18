# Changelog

All notable changes to gbounce will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- HTTP `GET /audit/events` endpoint per #271: headless sibling of
  `gbounce audit tail --export jsonl`. Lives on the existing mgmt
  port (default `8769`) alongside `/healthz`. Same filter language,
  same supported field catalog, same OCSF v1.1.0 wire shape. Query
  parameters: `since`/`until` (ISO 8601), `filter` (repeatable;
  `field=value` / `field~regex` / `field>=N` / `field<=N`), `limit`
  (default 100, max 1000), `format` (`jsonl` default | `ocsf-bundle`).
  Loopback bind requires no auth (matches the existing mgmt-port
  trust anchor); external bind requires a bearer token via the new
  `gbounce run --audit-events-token TOKEN` flag (refuses to start in
  external-bind mode without it). Powers the cross-bouncer `iam-jit
  audit query` CLI (#271 B) which queries every reachable bouncer in
  parallel + merges the results. Per [[cross-product-agent-parity]] +
  [[creates-never-mutates]] (read-only) + [[self-host-zero-billing-
  dependency]] (operator-controlled port; no phone-home).
- `gbounce investigate` per #273: one-shot Claude-ready evidence pack.
  Composes the existing `audit tail --export ocsf-bundle` (#268) and
  `diagnostics bundle` (#277) into a single command that writes two
  artifact files into `--out-dir` —
  `gbounce-investigation.ndjson` (OCSF v1.1.0 class 2004 Detection
  Finding wrapping filtered audit events + trailing
  investigate-metadata NDJSON line) and
  `gbounce-investigation-context.zip` (the standard diagnostics
  bundle with `--no-audit`). Operator drops both files into THEIR
  local Claude client (Claude Code, Cursor's Claude integration,
  desktop Claude, the Anthropic console — whichever they use) and
  asks an investigative prompt; gbounce never calls Anthropic.
  Flags: `--out-dir`, `--time-range` (e.g. `24h`/`7d`/`4w`),
  `--filter`, `--print-prompts` (lists the 10 starter prompts as a
  paste-able block without writing files), `--db`,
  `--audit-log-path`, `--healthz-url`. Cross-product alignment per
  `[[cross-product-agent-parity]]` — ibounce / kbounce / dbounce
  ship the same shape with product-specific prompt swaps. Per
  `[[self-host-zero-billing-dependency]]` the only network call is
  the loopback `/healthz` GET the diagnostics bundle already makes;
  per `[[creates-never-mutates]]` read-only against the store + the
  audit log. Docs: `docs/INVESTIGATE-WITH-CLAUDE.md`.
- `gbounce audit tail` per #268: live-tail + filter + summary + export
  surface around the existing audit-tail subcommand. New flags:
  `--follow` (500ms polling loop; exits on SIGINT), `--filter EXPR`
  (repeatable AND semantics; supports `field=value` /
  `field~regex` / `field>=N` / `field<=N` over the cross-product OCSF
  field set plus gbounce-specific `upstream_host` / `path` / `method` /
  `http_status`), `--summary` (count-summary keyed by event_type /
  severity_id / actor.user.name / api.operation + gbounce-specific
  upstream_host / method / http_status / composite
  `upstream_host+method+http_status`), and `--export FORMAT --out PATH`
  with three formats (`jsonl` one-per-line OCSF; `csv` tabular with
  `--csv-columns` override; `ocsf-bundle` one OCSF v1.1.0 Detection
  Finding wrapping the contained API Activity events). Every export
  format applies a URL-token redaction pass — query-string params named
  `token`, `api_key`, `password`, `secret`, `bearer`, `key`,
  `authorization` (and cousins) are replaced with `REDACTED` so a CSV
  pasted into a support ticket or an OCSF bundle shipped to a SIEM
  doesn't leak credentials. The live `audit tail` display leaves raw
  values in place per the spec — operators debugging an agent need to
  see what was actually called. Cross-product parity per
  [[cross-product-agent-parity]]: ibounce + kbounce + dbounce ship the
  identical flag set + grammar + supported-field allowlist. Docs:
  `docs/AUDIT.md` with the full reference + sample sessions for each
  new flag + the redaction denylist + cross-links to the sibling
  product commands.

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
