# Changelog

All notable changes to gbounce will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **#311 / §A10 — audit-log retention surface** (2026-05-22) —
  cross-product launch-blocker resolved on the CLI + primitives side.
  New `gbounce logs purge --older-than DURATION --yes` /
  `gbounce logs archive --out FILE` / `gbounce logs verify` subcommand
  surface (same flag names as ibounce / kbounce / dbounce per
  [[cross-product-agent-parity]]). New `gbounce doctor logs` health
  check: integrity + freshness + retention + disk; exits non-zero on
  any failure. New `internal/audit/rotation.go` ships
  `ShouldRotateBySize` / `ShouldRotateByAge` / `Rotate` /
  `RecoverPartialTail` / `PurgeLogsOlderThan` / `ArchiveLogs` /
  `VerifyIntegrity` / `GetDiskStatus` / `ParseLogDuration`. Crash
  recovery primitive: `RecoverPartialTail` truncates a partial
  trailing JSONL line. Cross-product runbook:
  `iam-roles/docs/LOG-RETENTION.md`. 11 new tests in
  `internal/audit/rotation_test.go`. **Gap**: LogWriter-level wiring
  (auto-rotation guard inside the worker goroutine) is deferred — a
  parallel agent's concurrent work on `internal/audit/log.go`
  conflicted with the wiring; the primitives + CLI + doctor surface
  all ship and the writer-level guard ports cleanly from
  `dbounce/internal/audit/log.go` once the parallel work settles.
  Status tracked in `iam-roles/docs/LOG-RETENTION.md` "Cross-product
  parity matrix" + the §A10 entry in `KNOWN-CAVEATS.md`.

- **Deny hosts: per-destination CONNECT blocking** (#314 / KNOWN-CAVEATS §A12)
  — gbounce can now refuse a CONNECT based on destination host without
  any MITM:
  - `--deny-host <entry>` CLI flag (repeatable; supplements any future
    profile-YAML `deny_hosts:` list).
  - `--deny-hosts-file PATH` flag for newline-delimited deny lists
    (also accepts the YAML-list shape the future profile-mode YAML
    will use: `deny_hosts:` key + `- entry` lines + inline
    `deny_hosts: [a, b]`). Comments (`#` prefix) + blank lines
    ignored. Designed so a profile-YAML file containing only
    `deny_hosts:` parses through unchanged when G-Slice 2 lands.
  - Match shapes:
    - **Exact** (`evil.example.com`) — case-insensitive literal match.
    - **Leading wildcard** (`*.openai.com`) — matches `api.openai.com`,
      `foo.bar.openai.com`, AND the bare `openai.com` (operator-friendly
      "this org and all its subs"). Documented choice per the
      file-header in `internal/proxy/deny_hosts.go`.
  - Rejected at parse time (NewServer refuses to start; clear error
    naming the offending entry):
    - Bare `*` (use a future `--default-policy deny` for that posture).
    - Multi-level wildcards (`*.foo.*.bar.com`, `foo.*`, `*.*`).
    - Entries with embedded scheme / path / port / whitespace.
  - On a match: gbounce returns `403 Forbidden` to the client and
    emits an OCSF event with `verdict=DENY`, `status_id=4 (Denied)`,
    `activity_id=6 (Connect)`, and
    `ext.deny_reason="matched deny_hosts: <rule>"` naming the
    operator-written rule (the SIEM can pivot on the EXACT string the
    operator deployed). `/healthz` surfaces `deny_hosts_count` +
    `total_deny_host_matches` so operators see deny-rule activity
    without grepping the audit log.
  - Order of evaluation: deny WINS over any future allow_hosts list
    (safer-by-default per `[[safety-mode-lean-permissive]]`). When
    an allow list lands in G-Slice 2, a host in both deny + allow is
    still denied.
  - Per `[[creates-never-mutates]]` this is additive — absent any
    `--deny-host` flags the CONNECT path is unchanged. Per
    `[[don't-tailor-to-lighthouse]]` the wildcard semantics are
    generic; no specific provider blocklist is hardcoded.
  - Regression tests: `TestDenyHosts_ExactMatch_Denied`,
    `TestDenyHosts_WildcardSubdomain_Denied`,
    `TestDenyHosts_WildcardMatchesBareDomain_Denied`,
    `TestDenyHosts_WildcardDoesNotMatchUnrelated`,
    `TestDenyHosts_NotInList_Allowed`,
    `TestDenyHosts_BareWildcardRejected`,
    `TestDenyHosts_MultiLevelWildcardRejected`,
    `TestDenyHosts_AuditEventEmitted`,
    `TestDenyHosts_DenyWinsOverAllow`,
    `TestDenyHosts_CLIAndProfileMerge`,
    `TestDenyHosts_HealthzCounter` in
    `internal/proxy/deny_hosts_test.go`.

- **Agent-identity attribution in audit events** (#308) — every OCSF
  event now carries a populated `unmapped.iam_jit.agent` block:
  - `agent.name` — value of the inbound `X-Agent-Name` header
    (validated alphanumeric + `.`/`_`/`-`, max 64 chars); `"anonymous"`
    when the header is absent or invalid.
  - `agent.session_id` — value of the inbound `X-Agent-Session-Id`
    header (validated alphanumeric + `_`/`-`, max 128 chars); omitted
    when absent or invalid.
  - `agent.detected_from` — `"http_header"` when either header fired;
    `"unknown"` on anonymous traffic. Filterable via `unmapped.iam_jit.agent.detected_from=...`.
  Closes the `[[agent-identity-in-audit]]` (#266) cross-bouncer parity
  gap — operators can now run `iam-jit audit query --filter
  unmapped.iam_jit.agent.session_id=...` across all four Bounce
  products and gbounce events join the result set. Validation rejects
  shell-injection payloads + control characters (the bad header is
  treated as absent and the rejection counter surfaces via
  `/healthz.total_agent_headers_rejected`). Per
  `[[security-team-positioning-safety-not-surveillance]]` gbounce
  never fabricates a name — anonymous events surface as
  `name=anonymous` so the operator can see the attribution gap.
  Regression tests: `TestProxy_AgentHeadersThreadedIntoOCSF` +
  `TestProxy_NoAgentHeadersGracefulFallback` +
  `TestProxy_InvalidAgentHeaders_Rejected` in
  `internal/proxy/proxy_test.go`; OCSF wire-shape coverage in
  `TestFromRequest_AgentBlockAlwaysPopulated` +
  `TestIsValidAgentName` in `internal/audit/event_test.go`.

- **`gbounce doctor caveats` + KNOWN-CAVEATS discoverability surfaces** (#304)
  — caveats are now surfaced at four sites instead of being buried in
  `docs/KNOWN-CAVEATS.md`:
  - `internal/caveats/` — new package centralizes the gbounce-relevant
    §B entries (B8 + B9 product-specific; B13 + B14 + B15 cross-product)
    + their canonical-doc anchors. `caveats.BannerLines(Trigger)` returns
    one banner line per runtime-triggered entry; `caveats.DoctorEntries()`
    returns the full applicable list for the `doctor` subcommand;
    `caveats.LinkSuffix(id)` produces an inline `(see KNOWN-CAVEATS §X:
    <URL>)` suffix for error responses.
  - **README "Known limitations" section** — top 3 gbounce-relevant §B
    entries (B9 / B8 / B14) linked to the canonical doc.
  - **Startup banner** — `gbounce run` emits one line per triggered
    caveat after the listener address. Discovery mode triggers §B9 (the
    only G-Slice 1 mode, so always emitted); `--allow-connect` triggers
    §B8. Quiet when no triggering config applies per the founder
    direction "the signal should be useful, not noise."
  - **`gbounce doctor caveats`** — new subcommand under a new `doctor`
    command group (matches the cross-product `*bounce doctor caveats`
    shape per `[[cross-product-agent-parity]]`). Prints every
    gbounce-applicable §B entry + its canonical-doc anchor.
  - **Error message links** — the 421 "non-CONNECT method on CONNECT-only
    listener" response body now appends `(see KNOWN-CAVEATS §B8: <URL>)`
    so an operator hitting the deny lands on the doc immediately. Per
    `[[security-team-positioning-safety-not-surveillance]]` the link is
    helpful framing ("here's where to read more"), not accusatory.
  - gbounce has no MCP server in v1.0 (queued for G-Slice 5); MCP tool
    descriptions land alongside that slice.

### Fixed

- **Failed-CONNECT + non-CONNECT requests now audited** (#303 + #305)
  — two related launch-blocking visibility gaps in `internal/proxy/`:
  - #303: unreachable-upstream CONNECT attempts (DNS failure,
    connection refused, host doesn't exist) used to fail silently with
    a 502 returned to the client but NO audit event recorded. SSRF
    probes against private IPs (`169.254.169.254` IMDS, RFC1918) were
    invisible in the audit log. Failed CONNECT events now emit:
    `activity_id=6 (Connect)`, `status_id=2 (Failure)`,
    `unmapped.iam_jit.verdict="ALLOW"` (the operator INTENDED to
    allow; the network refused), `unmapped.iam_jit.ext.connect_refused=true`,
    `unmapped.iam_jit.ext.connect_error=<dial error string>`. Same
    `host:port` extraction from the CONNECT request-target as the
    successful-CONNECT happy path so a SIEM pivot on
    `dst_endpoint.hostname=...` correlates failures with successes.
  - #305: plain-HTTP requests on a CONNECT-only listener (`--allow-
    connect` without `--upstream`) returned `421 Misdirected Request`
    + silently dropped with no audit event. IMDS attacks (which ride
    plain HTTP, not HTTPS) were invisible. Rejected non-CONNECT
    requests now emit: `activity_id` derived from HTTP method,
    `status_id=4 (Denied)`, `unmapped.iam_jit.verdict="DENY"`,
    `unmapped.iam_jit.ext.deny_reason="non-CONNECT method on CONNECT-
    only listener"`. Method + host + path captured pre-TLS so IMDS
    probes show their `/latest/meta-data/...` target in the audit row.
  - New OCSF constants in `internal/audit/event.go`: `ActivityConnect=6`
    (gbounce extension for CONNECT) + `StatusDenied=4` (gbounce
    extension for policy denials). `RequestInput` gains
    `Verdict / ActivityIDOverride / StatusIDOverride / ExtraExt`
    fields for these failure-path call sites without breaking the
    happy-path call sites.
  - The SQLite-backed `/audit/events` HTTP endpoint + the local
    `gbounce audit tail` CLI reconstruct the override fields from the
    persistent `(method, http_status, verdict)` triple via the new
    `audit.ReconstructOverridesFromRow` helper — so both surfaces
    show the same shape as the canonical JSONL audit log.
  - Three regression tests in `internal/proxy/proxy_test.go`:
    `TestProxy_UnreachableHostCONNECTLogged`,
    `TestProxy_NonCONNECTRequestLogged`,
    `TestProxy_DNSFailureCONNECTLogged`. Plus
    `TestReconstructOverridesFromRow` (6 sub-tests covering the
    reconstruction matrix) in `internal/audit/event_test.go`.

### Added

- **Per-session recording CLI wiring** (#290) — wires the #285
  recorder library into the gbounce proxy hot path + ships the
  cross-product `gbounce session list / show / export / purge`
  subcommand group. New surfaces:
  - `gbounce run --record-sessions-dir PATH` — tees every audit
    event into `{PATH}/{agent.session_id}.ndjson`. The proxy reads
    agent identity from inbound `X-Agent-Session-Id` + `X-Agent-Name`
    headers; events without a session id are NOT routed to a session
    file (raw curl / unknown caller). Default off; opt-in.
  - `gbounce session list` — list recorded sessions (table or `--json`)
  - `gbounce session show` — summary + event-count-by-type
  - `gbounce session export` — OCSF Detection Finding envelope to
    `--out`
  - `gbounce session purge` — remove recordings older than
    `--older-than` (`--dry-run` supported; explicit threshold
    required per `[[creates-never-mutates]]`)
  - `audit.RequestInput` gains `AgentSessionID` + `AgentName` fields;
    `audit.FromRequest` populates the matching Ext keys with
    defensive `IsValidSessionID` gating.
  - `proxy.Server` gains an optional `*audit.SessionRecorder` field;
    `proxy.NewServer` signature now takes `(cfg, store, log,
    recorder)`. `Serve` + `ServeListeners` call `Recorder.Stop` on
    shutdown (atomic-rename `.partial` → `.ndjson`).
  - Subcommand names + flag shape match ibounce + kbouncer + dbounce
    exactly per `[[cross-product-agent-parity]]`.
  - Per `[[self-host-zero-billing-dependency]]`: zero network calls.

- **Per-session recording library** (#285) — new
  `internal/audit/recorder.go` ships the per-session NDJSON recorder.
  Tees every audit event into `{dir}/{agent.session_id}.ndjson` with
  the same on-disk shape as ibounce / kbouncer / dbounce per
  `[[cross-product-agent-parity]]` so the cross-product
  `iam-jit session replay <FILE>` CLI (lives in iam-roles) consumes
  gbounce recordings unchanged. Files carry a `_meta` header
  (recording_schema_version, session_id, agent_name, bouncer_product,
  recording_started_at) followed by one OCSF event per line.
  `.partial` suffix while in-flight; atomic rename to `.ndjson` on
  clean shutdown or 5-minute heartbeat-idle finalisation tick. File
  mode 0o600. gbounce session_id detection rides on
  `unmapped.iam_jit.ext[agent_session_id]` until the sibling-to-
  kbouncer #266 agent-identity block lands; the recorder consumes
  via the `AgentSessionIDExtKey` constant so the migration is a
  one-symbol rename. See `docs/SESSION-REPLAY.md` in iam-roles.
- **`gbounce run --preset security-observe`** (#254) — single-flag
  shortcut for the canonical security-team observation deployment
  shape. Equivalent to `--mode discovery --audit-log-path
  ~/.gbounce/audit/gbounce.jsonl`. Designed for the "gather data
  first; author profile second" starting position per
  `[[bouncer-mode-selection-for-agents]]`. HARD override on
  `--mode` (the entire point of the preset is observation);
  passing `--preset security-observe --mode profile` errors fast
  with a clear "drop the preset OR drop the explicit flag" message.
  SOFT override on `--audit-log-path` (operators have different
  SIEM destinations).
- gbounce G-Slice 1 has fewer surfaces than the other Bounce
  products (no profile / rule engine / heartbeat / alert-rules);
  the startup banner annotates the cross-product canonical settings
  (`--default-policy`, `--alert-rules`, `--heartbeat-interval`) as
  "not applicable to this product (G-Slice 1 has no surface; queued
  for later slice)" so an operator running the same preset across
  all four Bounce products sees what's intentionally missing here.
- Same preset NAME + same override semantics ship across ibounce /
  kbounce / dbounce per `[[cross-product-agent-parity]]`. Framework
  documented at `docs/DEPLOYMENT-PRESETS.md` with the post-v1.0
  roadmap (`dev-loop`, `production-strict`, `compliance-audit`)
  explicitly NOT shipped in this slice per
  `[[deliberate-feature-completion]]`.
- Per `[[security-team-positioning-safety-not-surveillance]]`:
  preset description + banner use neutral language; no violation /
  infraction / unauthorized framing.
- Per `[[self-host-zero-billing-dependency]]`: the preset does NOT
  configure any webhook URL, so a self-hosted security-observe
  deployment phones home to nothing without an operator action.
- **`GET /schemas/config` HTTP endpoint** (#276) — gbounce's mgmt
  port now serves the embedded `gbounce-config.schema.json`
  byte-for-byte at `Content-Type: application/schema+json`. Agents
  that want to validate a proposed `gbounce config import` payload
  against the LIVE bouncer's accepted shape fetch this rather than
  relying on a stale GitHub URL. READ-only (PUT/POST/DELETE return
  405); no auth (matches `/healthz` — the schema is non-sensitive
  metadata). The served bytes are a build-time copy of
  `schemas/gbounce-config.schema.json`; a test asserts byte-equality
  so drift between the two fails the build. Per
  `[[cross-product-agent-parity]]`: ibounce + kbounce + dbounce
  ship the same endpoint shape with their own product schemas.
- Live audit-stream web UI at `GET /` per #272: minimal vanilla-JS
  page served on gbounce's mgmt port (default `8769`) alongside
  `/healthz` and `/audit/events`. Single self-contained
  HTML+CSS+JS file (no build step, no CDN, no Google Fonts, no
  analytics, no telemetry), under 500 lines. Long-polls
  `/audit/events?since=<cursor>` every two seconds and renders a
  colour-coded table with top-bar event counters, filter input
  (same syntax as `/audit/events?filter=`), pause + clear controls,
  mobile-responsive layout. Wire model: long-polling rather than
  SSE — the existing `auditEventsHandler` doesn't ship streaming
  response semantics today and the operator UX is identical at
  2 s tick; a future bump can swap to `EventSource` without
  touching the server contract. Same auth model as
  `/audit/events`: loopback no auth; external bind takes the
  bearer token through the URL `#token=...` fragment so the HTML
  body never embeds the secret. Strict `Content-Security-Policy`
  header. Cross-product-identical HTML shape with ibounce /
  kbounce / dbounce per `[[cross-product-agent-parity]]`. Per
  `[[creates-never-mutates]]` the UI is read-only — no button
  mutates gbounce state. Per `[[security-team-positioning-safety-
  not-surveillance]]` event labels use "deny" / "allow", never
  "violation" / "infraction" / "unauthorized". Per `[[self-host-
  zero-billing-dependency]]` no CDN dependencies; everything
  inline. New file: `internal/proxy/events_ui.go`. Tests:
  `internal/proxy/events_ui_test.go`. Doc section in
  `docs/AUDIT.md`. The cross-bouncer TUI sibling (`iam-jit audit
  stream`) merges live streams from every reachable bouncer into
  one terminal table; see `iam-roles/docs/AUDIT-STREAM-TUI.md`.
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
