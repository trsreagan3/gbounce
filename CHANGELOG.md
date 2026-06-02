# Changelog

All notable changes to gbounce will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **iam-jit #682 — purpose-driven monitoring UI at `/admin/ui`** (2026-06-02) —
  Per founder direction in `[[gbounce-ui-purpose-driven]]`, the gbounce
  mgmt-port now serves a 5-panel monitoring console that answers the
  five questions an operator actually has when watching an agent:
  (1) "what is my agent doing right now" — live SSE decision stream;
  (2) "is my agent stuck" — three quantified pattern detections
  (`upstream_retry_storm`, `error_repeat`, `deny_storm`) each carrying
  the EXACT threshold that fired ("5 in 30s") so the heuristic is
  auditable; (3) "what is gbounce blocking" — DENY-only filtered
  stream with rule + source + severity; (4) "which features are
  turned on" — explicit ON/OFF table for `mitm`, `deny_hosts`,
  `dynamic_deny`, `injection_scan`, `profile_enforcement`,
  `audit_log`, `session_recorder`, `object_storage`,
  `disk_pressure_circuit_breaker`; (5) "are the features actually
  doing their job" — per-feature last-fired timestamp, total + 24h
  fire counts, last error, and an amber
  `CONFIGURED / NEVER FIRED` pill that distinctly highlights
  silent-degradation per `[[ibounce-honest-positioning]]`. Page
  bundles every byte (HTML + CSS + JS) into the Go binary; no CDNs,
  no fonts, no analytics. Empty-state copy ships an actionable
  `HTTPS_PROXY=... curl` test command so an operator never sees a
  blank console without a way out. Three new JSON endpoints back the
  page: `GET /admin/features`, `GET /admin/stuck-signals`,
  `GET /admin/stream` (SSE). Auth mirrors `/audit/events`: loopback
  open, external bind requires bearer via header OR `#token=` URL
  fragment that the JS surfaces as `?_token=`. 14 new tests cover
  HTML structure, the 5 question labels, no-external-dependency
  guard, no-embedded-token guard, anti-surveillance copy guard, CSP
  headers, the feature snapshot wire shape, the
  `ConfiguredButNeverFired` honesty surface, the stuck-pattern
  threshold strings, deny-storm detection, retry-storm detection,
  and the initial SSE frame emission. Verified end-to-end with a
  real-bouncer probe: launched `gbounce run --port 18080 --mgmt-port
  18769 --allow-connect --deny-host bad.example.com --audit-log-path
  /tmp/audit.jsonl`, sent `HTTPS_PROXY=http://127.0.0.1:18080 curl`
  to both an allowed + a denied host, confirmed the SSE stream
  pushed `event: decision` frames with verdict ALLOW + DENY,
  confirmed `deny_hosts` and `audit_log` features showed
  `fire_count_total > 0` and `last_fired_unix_ms > 0`, and
  confirmed `dynamic_deny` showed `configured_but_never_fired:
  true` (the honest gap). Legacy `/` live-tail UI is unchanged for
  backcompat. Operator guide: `docs/UI-USAGE.md`.

### Docs

- **#367 / §A36 — Docker bind-mount UID 65532 + colima caveat documented in README** (2026-05-23) —
  The distroless `:nonroot` runtime runs as UID 65532 (non-root for
  security). Operators bind-mounting a host directory hit a cryptic
  `open store: unable to open database file` because the host dir
  wasn't writable by 65532, and the existing Docker section gave no
  fix-it hint. This slice adds a **"Bind-mounting volumes (UID 65532)"**
  subsection showing two remediation paths (`chown 65532:65532 <hostdir>`
  OR `--user $(id -u):$(id -g)`), a docker-compose example with
  matching `user:` setting + pre-up chown comment, a **macOS / colima
  caveat** about `/Users/*` paths being the only reliable bind-mount
  surface (mounts under `/tmp`, `/var`, `/private` silently diverge),
  and a **"Common errors"** table mapping the store-open error and
  three other usual-suspect symptoms back to the bind-mount section.
  Closes the gap an operator following docs-as-written would hit on
  their first `docker run` with persistence enabled.

### CI

- **#368 / §A37 — docker-publish smoke now boots proxy + asserts audit DB written** (2026-05-23) —
  Previously the smoke between local build and multi-arch push was
  `--version` + `--help` only. Per the auditor that smoke would NOT
  have caught the Helm-chart flag drift surfaced in §A33
  (`--active-profile` vs `--profile`) if the binary changed — running
  `--help` proves the binary starts, not that any `run`-time flag
  actually wires through. This slice adds a **Real-deploy smoke** step
  after the size report: boots `gbounce run` in discovery mode against
  a placeholder upstream with a chown'd bind-mounted host data dir
  (mirroring the bind-mount docs that just landed for §A36), waits up
  to 30s for the mgmt-port `/healthz` to answer (default 8769 —
  distinct from kbounce's 8766, dbounce's 8768, ibounce's 8767),
  asserts the response is HTTP 200, and asserts `state.db` exists on
  the host bind-mount (proving the binary actually opened the SQLite
  store under `run`). If `run` rejects a flag, fails to bind, or
  silently never opens persistence, the smoke fails before the
  multi-arch push fires. The step block is annotated with
  `RUN_LOCALLY:` comments so operators can copy-run the same smoke
  against `ghcr.io/trsreagan3/gbounce:latest` on a dev machine.
  Validated by yaml-parse smoke locally.

### Changed

- **#296 / §A22 — SQLite store concurrency hardening (CRITICAL audit-loss fix)** (2026-05-22) —
  gbounce's `internal/store/store.go` `Open()` now applies
  `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`,
  `foreign_keys=1` via DSN PRAGMA bindings so EVERY connection in the
  `sql.DB` pool inherits the settings. Pre-#296 gbounce passed ZERO
  PRAGMAs (modernc.org/sqlite defaults: rollback-journal +
  synchronous=FULL + no busy_timeout); a 20-session load probe lost
  **11,804 of 12,000 audit rows** to `SQLITE_BUSY` because two pool
  goroutines could simultaneously attempt `BEGIN IMMEDIATE` on
  different connections. After the DSN tuning: 12,000/12,000 committed
  at 20 writers, 0 errors, p99 = 8.18ms. The new posture matches
  dbounce + kbouncer's PRAGMA shape across the Go bouncer trio per
  `[[cross-product-agent-parity]]`. No schema change; no public API
  change; data on existing DBs is preserved verbatim. Verified by
  `internal/store/concurrency_load_test.go` (build-tagged `loadtest`
  so normal `go test ./...` skips it). Lifts the cross-product §B13
  "1-3 concurrent terminals in v1.0" caveat — the new measured ceiling
  at the audit-write layer is **30+ concurrent agent sessions on one
  machine** with zero dropped audit events.

### Added

- **#342 / §A23 — Formal Apache-2.0 LICENSE + NOTICE + README license attribution** (2026-05-23) —
  gbounce's `LICENSE` file had the canonical Apache-2.0 text but an
  unfilled `Copyright [yyyy] [name of copyright owner]` boilerplate
  line; this slice fills it with `Copyright 2026 trsreagan3` (founder
  direction) and adds a `NOTICE` file with the per-product attribution
  shape. The README `## License` section (previously a bare
  `Apache-2.0.` one-liner) now reads `Apache-2.0 — see [LICENSE](./LICENSE).
  Copyright 2026 trsreagan3.` Same change shipped in iam-roles +
  kbouncer + dbounce so the Bounce suite presents one coherent license
  posture per `[[cross-product-agent-parity]]`. Unblocks: Anthropic
  Cyber Verification Program application + iam-jit-vs-OneCLI
  competitive-matrix accuracy. Per-source-file SPDX-License-Identifier
  headers DEFERRED to v1.1 per `[[deliberate-feature-completion]]`.

- **#324d — dynamic-deny YAML watcher + matcher extension + mgmt-port reload endpoint** (2026-05-22) —
  gbounce now consumes the cross-product
  `~/.iam-jit/dynamic-denies.yaml` file. The on-disk shape + cross-bouncer
  resolver semantics live in the canonical design doc at
  `iam-roles/docs/DYNAMIC-DENY-RULES.md`; the JSON Schema lives at
  `iam-roles/docs/schemas/dynamic-denies-v1.json`. This slice ships the
  gbounce consumer (#324d only — sibling slices #324a-c cover ibounce
  + kbouncer + dbounce; #324e ships the unified CLI + MCP fan-out;
  #324f embeds the same denies into JIT-issued roles).

  Surface:

  - New package `internal/dynamicdeny` — loader + watcher. The loader
    validates the YAML against the v1.0 schema shape (rule-id pattern,
    duration grammar, applied-to bouncer enum, duplicate-id rejection,
    product-magic discriminator) + filters down to rules whose
    `applied_to` list includes `"gbounce"`. Per
    `[[ibounce-honest-positioning]]` the loader rejects malformed YAML
    rather than silently dropping rules.
  - fsnotify-driven watcher (`fsevents` on macOS, `inotify` on Linux).
    Watches the parent directory so atomic-rename writes (`write-tmp
    + rename onto live path`) are caught. Rapid sequential writes are
    coalesced with a 100ms debounce quiet-period; the final reload
    fires only after writes settle.
  - Parse errors on reload RETAIN the previous in-memory snapshot
    (fail-CLOSED per `[[ibounce-honest-positioning]]`) + emit a
    `dynamic_deny.parse_error` admin-action OCSF event so a SIEM
    surfaces the bad-file event without an operator having to grep.
  - The proxy's `/internal/proxy/deny_hosts.go` matcher unions static
    `--deny-host` entries with the watcher's dynamic entries. Each
    compiled rule carries a `Source` field (`"static"` or `"dynamic"`)
    + a `DynamicDenyRuleID` field; the deny audit event surfaces both
    under `unmapped.iam_jit.ext.deny_source` +
    `unmapped.iam_jit.ext.dynamic_deny_rule_id` so an analyst can
    pivot on either.
  - `/healthz` now reports `dynamic_denies_enabled`,
    `dynamic_denies_count`, `dynamic_denies_globs_count`,
    `dynamic_denies_path`, `total_dynamic_deny_matches`,
    `total_dynamic_deny_reloads`, and
    `total_dynamic_deny_parse_errors`. Counter naming mirrors the
    existing `total_deny_host_matches` shape.
  - New flag `gbounce run --dynamic-denies-path PATH` (default
    `~/.iam-jit/dynamic-denies.yaml`, also honors
    `$IAM_JIT_DYNAMIC_DENIES_PATH`). Companion flag
    `--disable-dynamic-denies` turns the channel off for operators who
    haven't installed the cross-product CLI yet.
  - Startup banner emits one line per `[[cross-product-agent-parity]]`:
    `dynamic-denies: N rules loaded from PATH (M applied to gbounce;
    watching for changes)`.
  - New endpoint `POST /admin/dynamic-denies/reload` on the mgmt port
    (8769 default). Triggers an immediate reload from disk + returns
    `{"reloaded":true,"rules_count":N,"rules_applied_to_gbounce":M,
    "path":"..."}`. Parse errors return 422 with the structured
    error. Useful for the cross-bouncer fan-out CLI (#324e), which
    will write the YAML then POST to each Bounce product's mgmt port
    to confirm the rules are live.
  - When matched, dynamic-deny rules emit the SAME OCSF wire shape as
    static deny_hosts matches — the verdict event carries the extra
    `deny_source` + `dynamic_deny_rule_id` fields per the canonical
    design doc's "emitted as part of the verdict OCSF event (NOT
    separately)" note.
  - New admin-action constants `audit.AdminActionDynamicDenyReloaded`
    + `audit.AdminActionDynamicDenyParseError`. The CLI wires an
    emit-callback on the watcher that tees a `dynamic_deny.reloaded`
    OR `dynamic_deny.parse_error` admin-action event with
    `unmapped.iam_jit.ext.dynamic_deny_reload_reason ∈ {file_created,
    file_modified, file_removed, reload_requested, parse_error}` per
    the canonical design doc.

  Tests:

  - `internal/dynamicdeny/loader_test.go` — 13 tests covering
    `LoadsValidYAML`, `LoadFile_MissingFileIsNotAnError`, schema
    violations (missing `schema_version`, bad rule id, bad duration,
    unknown bouncer name, duplicate rule id, wrong product magic),
    filter behavior (`FiltersNonGbounceTargets` — ARN-only + k8s-only
    rules skipped; URL + RDS-endpoint rules kept), expired-rule
    filter, and the JSON / YAML round-trip shape.
  - `internal/dynamicdeny/watcher_test.go` — 6 tests covering
    `DetectsFileCreation`, `DetectsFileModification`,
    `DebouncesRapidWrites`, `RetainsRulesOnParseError`, `ReloadNow`
    (mgmt-port reload semantics), and the empty-path no-op shape.
  - `internal/proxy/deny_hosts_test.go` — 5 new tests covering
    `StaticAndDynamicUnion` (both rule kinds fire),
    `DynamicMatchEmitsRuleId` (OCSF ext fields), `AuditDistinguishesSource`
    (static + dynamic land with distinct `deny_source`),
    `ReloadEndpointAddsRule` (POST /admin/dynamic-denies/reload
    end-to-end), and `HealthzSurfacesDynamicCounters` (every new
    /healthz field is populated).
  - 24 new tests total; existing #314 + #305 + #303 deny-hosts
    regression suite continues to pass unchanged.

  New runtime dependency: `github.com/fsnotify/fsnotify v1.7.0` (one
  module — already a transitive dep of common Go ecosystem packages;
  same library kbouncer + dbounce will adopt for their #324b + #324c
  slices per `[[cross-product-agent-parity]]`).

  Per `[[creates-never-mutates]]`: this slice is additive — when the
  watcher is disabled (no path configured, file absent, or
  `--disable-dynamic-denies` set) the proxy's matcher behavior is
  byte-identical to the pre-#324d shape. Existing static
  `--deny-host` + `--deny-hosts-file` operators see zero change.

  Per `[[scorer-is-ground-truth]]`: deny always wins; static and
  dynamic entries are evaluated against the same match grammar
  (`*.example.com` semantics match the existing #314 wildcard
  shape). Per `[[deliberate-feature-completion]]`: this slice
  complete = loader + watcher + matcher extension + tests +
  mgmt-port endpoint + CHANGELOG + README link.

  See `iam-roles/docs/DYNAMIC-DENY-RULES.md` for the cross-bouncer
  design + `iam-roles/docs/tasks/324-dynamic-deny-rules.md` for the
  per-slice tracking.

### Changed

- **§A21 / [[discovery-first-default]] — gbounce is the discovery-first reference; no code change** (2026-05-22) —
  Per the role-effectiveness eval at
  `iam-roles/tests/dogfood/role-effectiveness-grades.md`, gbounce hit
  **66.7%** vs the 50% launch bar — the only Bounce product above the
  bar in v1.0. The shape (default = discovery mode = observe + audit +
  pass-through; deny_hosts + MITM URL+method are operator-set OPT-IN
  primitives) became the canonical model the other 3 bouncers flipped
  to on 2026-05-22 (see iam-roles + kbouncer + dbounce CHANGELOGs).
  No gbounce code changes were required — `--mode discovery` was already
  the documented default; `deny_hosts` (#314) + MITM (#315) profile
  rules are already opt-in.

  Cross-product context: under the pivot all 4 bouncers report
  `default_mode=discovery|profile` on the headline startup banner per
  `[[cross-product-agent-parity]]`. gbounce surfaces the canonical
  shape directly (no `--profile` concept yet in G-Slice 1; G-Slice 2
  will add YAML profiles + the doctor catalog per #321).

  See iam-roles KNOWN-CAVEATS §A21 + `iam-roles/tests/dogfood/role-effectiveness-grades-post-pivot.md`.

### Fixed

- **§A20 R3-02 — `/audit/events` stripped the agent block from every event** (2026-05-22) —
  `store.DecisionRow` carried `AgentSessionID` + `AgentName` columns
  (per the #318 / #320 schema migration; persisted on `RecordDecision`;
  selected by `RecentDecisions`) — but `internal/proxy/audit_events.go:
  rowsToAuditEvents` constructed `audit.RequestInput` WITHOUT copying
  the two fields. Result: GET `/audit/events` returned
  `{"agent":{"name":"anonymous","detected_from":"unknown"}}` for
  EVERY event, even when the JSONL log + the in-memory exporter had
  the correct agent block. Cross-product `iam-jit audit query
  --filter agent.session_id=<id>` against gbounce missed every event.
  The CLI mirror `internal/cli/cli.go:rowsToEvents` had the same bug,
  breaking `gbounce audit tail --export jsonl` symmetrically.
  Surfaced by UAT round 3
  (`iam-roles/tests/dogfood/findings-2026-05-22-round-3.md`).
  Fix: both projection sites now copy `r.AgentSessionID` +
  `r.AgentName` into the `audit.RequestInput`. Per
  [[cross-product-agent-parity]]: matches the recipe dbounce +
  kbouncer already use. `audit.FromRequest` re-validates via
  `IsValidSessionID` + `IsValidAgentName` + builds the OCSF
  `unmapped.iam_jit.agent` block — populated when either field is
  present (with `detected_from="http_header"`), the anonymous
  fallback otherwise. New regression tests in
  `internal/proxy/audit_events_test.go`:
  `TestRowsToAuditEvents_ThreadsAgentFieldsR302` +
  `TestRowsToAuditEvents_AnonymousWhenNoAgentR302` +
  `TestAuditEvents_HTTPSurfaceShowsAgentR302` cover the unit-level
  threading + the HTTP wire-shape end-to-end. iam-roles
  KNOWN-CAVEATS §A20.

### Added

- **#321 / §A19 — `gbounce profile doctor` cross-product CLI parity** (2026-05-22) —
  Surfaces the `<product> profile doctor` subcommand on gbounce per
  [[cross-product-agent-parity]] so orchestrators can run it against
  any Bounce product uniformly. gbounce v1.0 doesn't ship a default
  profiles.yaml — profile rules are explicit-file via
  `--profile-rules-file` (JSON) or `--deny-host` / `--deny-hosts-file`
  (newline / YAML list) — so the doctor reports "current" + a Notes
  line explaining the architectural difference. G-Slice 2 will
  populate the catalog when gbounce gains a YAML profiles surface;
  this slice wires the SURFACE so older installs surface missing
  safety floors the same way dbounce / kbouncer / ibounce do today.
  New files: `internal/profile/doctor.go`, `internal/profile/doctor_test.go`,
  `internal/cli/profile.go`. Same `--apply` / `--acknowledge` /
  `--check` / `--json` / `--diff` flag shape as siblings — all no-op
  in v1.0 but contract-stable for v1.1. 5 regression tests cover the
  no-op posture + the architectural-honesty Notes line.

- **#320 / §A18 — `audit.BuildAgentHeaderRejectionBreadcrumb` helper + structured rejection breadcrumb test** (2026-05-22) —
  closes the build-gap left by the #319 / §A17 / F-308-1 commit
  (the proxy.go call sites referenced
  `audit.BuildAgentHeaderRejectionBreadcrumb` +
  `audit.AgentNameField` + `audit.AgentSessionIDField` +
  `audit.ClassifyAgentNameRejection` +
  `audit.ClassifyAgentSessionIDRejection` but the helper file was
  never committed). Lands `internal/audit/agent_header_rejection.go`
  with the cross-product bounded enum (`invalid_name_charset` /
  `invalid_name_length` / `invalid_session_id_format` /
  `invalid_session_id_length` / dbounce-only
  `application_name_unparseable`) + the breadcrumb-build helper.
  Per `[[cross-product-agent-parity]]` the constants + classifier
  match dbounce's + kbouncer's + ibounce's byte-for-byte. New
  regression test
  `TestAgentHeaderRejection_320_StructuredBreadcrumb` in
  `internal/proxy/proxy_test.go` exercises both-headers-rejected
  shape (list of breadcrumbs) + asserts the raw value never leaks.

- **#298 — Bounce-suite link page at `GET /suite`** (2026-05-22) —
  ships the cross-product deployment-status landing page hosted on
  `gbounce`'s mgmt port (8769 by default). Per
  `[[unified-ui-link-page]]` this is signage + status pills, NOT an
  aggregator: each card is just an anchor to that bouncer's own
  mgmt-port UI, with a pill computed from a client-side parallel
  `/healthz` fetch every 5 s.
  - No backend aggregator service; no CORS plumbing; vanilla JS
    (no React/Vue/Svelte) embedded as a Go string constant for
    auditability + bundle-freeness.
  - Default mgmt-port wiring (ibounce 8767, kbouncer 8766,
    dbounce 8768, gbounce 8769) baked into the page; operator
    overrides land in `localStorage` under the
    `bounce.suite.ports` key via a "configure ports" modal.
  - Footer carries the cross-bouncer investigation CLI
    (`iam-jit audit query --filter agent.session_id=<UUID>`) with
    a one-click copy button.
  - Honest positioning per `[[ibounce-honest-positioning]]`: copy
    says "navigate to your bouncers" — NEVER "single pane of
    glass." Title is "Bounce suite - deployment status" per
    `[[security-team-positioning-safety-not-surveillance]]`.
  - Bouncers stay autonomous per
    `[[four-products-one-brand]]`: the suite page works even when
    half the deployment is unreachable (those cards show gray
    "unreachable" pills; the page itself never depends on any
    bouncer being up).
  - New `internal/proxy/suite_handler.go` +
    `internal/proxy/suite_handler_test.go`; cross-repo integration
    test at iam-roles `tests/integration/test_suite_page.py`
    (Playwright-optional, skips gracefully).

- **#317 / §A15 — cloud-neutral S3-compatible NDJSON object-storage sink** (2026-05-22) —
  closes the headline cloud-neutrality gap surfaced by founder
  direction 2026-05-22: bouncers other than ibounce are
  cloud-neutral; the AWS-only Security Lake adapter (#258) alone
  doesn't serve operators on GCS / Azure Blob / MinIO / R2 / B2 /
  DigitalOcean Spaces. gbounce ships the new sink alongside the
  existing JSONL audit-log path per [[creates-never-mutates]]
  (additive composition).
  - `gbounce run --audit-object-storage-endpoint URL
    --audit-object-storage-bucket NAME
    --audit-object-storage-prefix PREFIX
    --audit-object-storage-region REGION
    --audit-object-storage-credentials-file PATH
    --audit-object-storage-rotation-minutes N
    --audit-object-storage-max-size-mb N
    --audit-object-storage-instance-id ID` — generic S3-compat
    sink. Per [[cross-product-agent-parity]] the flag shape is
    identical on ibounce + kbouncer + dbounce.
  - New package symbols: `audit.ObjectStorageWriter` +
    `audit.ObjectStorageCredentials` +
    `audit.LoadObjectStorageCredentials` +
    `audit.NewObjectStorageWriter` +
    `audit.ObjectStorageStatus` +
    `audit.ObjectStorageDefaultRotationMinutes` +
    `audit.ObjectStorageDefaultMaxSizeMB` +
    `audit.ObjectStorageDefaultRegion` +
    `audit.ErrObjectStorageNoCredentials` +
    `audit.ErrObjectStorageBucketUnreachable`.
  - Output layout: NDJSON (one OCSF event per line),
    gzip-compressed, Hive-partitioned at
    `{prefix}/year=YYYY/month=MM/day=DD/hour=HH/gbounce-{instance_id}-{timestamp}.jsonl.gz`.
    Athena / BigQuery / Spark / Trino auto-discover the partitions;
    SIEM collectors `LIST + GET` against the prefix.
  - Additive `proxy.Server.SetObjectStorageWriter()` method; the
    three audit-emit sites (`proxy.go:record`,
    `mitm_handler.go:recordMITMRequest`,
    `mitm_handler.go:recordMITMDeny`,
    `mitm_handler.go:recordMITMHandshakeFailure`) fan events to the
    writer alongside the existing `log` (JSONL) + `recorder` (NDJSON
    per-session) channels.
  - Per [[self-host-zero-billing-dependency]]: destination is
    operator-owned (operator creates the bucket; gbounce never
    creates buckets). Per [[don't-tailor-to-lighthouse]]: generic
    S3-compat (AWS S3 native + GCS interop + Azure Blob S3-compat
    layer + MinIO + R2 + B2 + DigitalOcean Spaces).
  - Adds the `github.com/aws/aws-sdk-go-v2` + `service/s3` +
    `config` + `credentials` + `aws` + `service/sts` packages to
    gbounce's dependency graph. Previously gbounce had no AWS SDK
    dependency; the new sink is the first AWS-SDK-dependent
    feature. Per [[deliberate-feature-completion]] kept narrow to
    just the four packages the writer needs.

  **Regression tests:** `internal/audit/object_storage_test.go` —
  19 tests cover defaults, credentials resolution (env + YAML +
  INI), partition path format, construction refusal, write/flush
  happy path, status surface, size-cap synchronous flush,
  drop-on-buffer-full, write-before-start no-op,
  close-flushes-pending, put_object failure -> writes_ok=false, and
  the rotation timer triggering a background flush.

  **Task:** #317 — completed 2026-05-22.

### Fixed

- **#319 / §A17 — UAT findings cluster: cross-product CLI parity + doc-truth-up gaps (gbounce slice)** (2026-05-22) —
  - **F-311-4 (HIGH)** — added `--audit-log-max-size-mb` + `--audit-log-max-age-days` + `--audit-db-retention-days` flags on `gbounce run` with matching `GBOUNCE_AUDIT_LOG_MAX_SIZE_MB` / `_MAX_AGE_DAYS` / `_DB_RETENTION_DAYS` env-var overrides. Sentinel -1 = "use audit-pkg default (LOG-RETENTION.md spec)"; 0 = "operator explicitly disabled trigger." Writer-level rotation hook deferred per the LOG-RETENTION.md parity-matrix gbounce-deferred row; the flags are accepted + surfaced via the resolved-value path so the cross-product CLI contract holds.
  - **F-311-1 (MED)** — `gbounce logs archive` now errors loudly when the target directory contains zero audit-shaped files (filenames matching `audit*` + suffix `.jsonl{,.gz}` / `.db{,.gz}`) instead of silently producing an empty ~50-byte tar.gz. Error message names the dir + the filename pattern so the operator can fix the misconfiguration in one step.
  - **F-311-2 (MED)** — `gbounce logs verify` now flips `OK=false` + returns a non-zero exit when `files_checked == 0`, with a stderr message naming the three likely root causes (writer never started / wrong dir / `--audit-log` pointed at a sibling path). JSON output also reflects the corrected `ok=false`. Previously a brand-new install with no audit files would report "OK" — a false positive operators would misread as "audit integrity verified."
  - **F-304-3 (MED)** — `gbounce doctor --help` Long help now lists both `caveats` AND `logs` subcommands (the `logs` subcommand was wired + functional but only `caveats` was documented in the help text). The `RunE` error message also names both subcommands.
  - **F-308-1 (MED)** — invalid `X-Agent-Name` / `X-Agent-Session-Id` headers now land in the audit event at `unmapped.iam_jit.ext.agent_rejected_reason` as bounded enum strings (`session_id:invalid_charset_or_length`, `agent_name:invalid_charset_or_length`, semicolon-joined when both fail). Raw header values are NEVER included — the truncated-stderr line emitted by `logAgentHeaderRejected` remains the only place the raw value surfaces, with control-char filtering. Closes the "anonymous rows on every UAT run" investigation gap.
  - **F-308-1 prerequisite** — added the missing `audit.IsValidAgentName(s string) bool` function in `internal/audit/recorder.go` (the call sites in `proxy.go` + `mitm_handler.go` + `event.go` referenced it but the function was never committed). Regex matches the cross-product canonical `^[A-Za-z0-9._-]{1,64}$` shape so the four Bounce products' agent-name validators stay in lockstep per [[cross-product-agent-parity]].
  - **#308 store-schema completion** — added `agent_session_id` + `agent_name` columns to the `decisions` table (schema v2, additive `ALTER TABLE ... ADD COLUMN ... DEFAULT ''` migration); plumbed through `DecisionRow` + `RecordDecision` + `scanDecisionRow`. The persisted attribution feeds the cross-bouncer `unmapped.iam_jit.agent.{name, session_id}` filter via `audit/event.go`. Required to unblock the build (the call sites referenced the columns but the schema migration was missing).
  Regression coverage: `TestLogsArchive_EmptyDir_ErrorsLoudly`, `TestLogsVerify_EmptyDir_ReportsFailure`, `TestDoctorHelp_ListsLogsSubcommand`, `TestRunCmd_RegistersRotationFlags` (new `internal/cli/logs_test.go`) + the `TestProxy_InvalidAgentHeaders_Rejected` regression in `internal/proxy/proxy_test.go` extended with `agent_rejected_reason` ext-key + raw-value-leak assertions.

### Added

- **#315 / §A13 — MITM mode + CA lifecycle subcommands (pre-launch, opt-in)** (2026-05-22) —
  gbounce now ships an opt-in TLS-interception mode that gives URL-level audit visibility (path, method, redacted body snapshot, status). Default behavior is unchanged — `--mode discovery` stays the friction-free CONNECT-tunnel shape per `[[creates-never-mutates]]`. New code surface:
  - `internal/mitm/` — local CA cert generation (ECDSA P-256, 10-year life, common name `iam-jit gbounce local CA` with no operator-identifying info), per-host leaf-cert minting + LRU cache (size 1024), platform-specific OS trust-store install + uninstall instructions, key-permissions invariant (0o600; refuses to load a group/world-readable key), credential-shape header + JSON-body + query-param redactor (the secret never lands in the audit log).
  - `internal/profile/` — compiled profile-deny rules with host (exact + leading-wildcard), port, method (exact or list), path (exact / prefix / RE2 regex), and query-param predicates. `Rule.RequiresMITM()` short-circuits CONNECT-only callers so MITM-required rules don't accidentally fire in discovery mode.
  - `internal/proxy/mitm_handler.go` — the CONNECT handler that runs under `--mode mitm`: hijacks the client TCP, performs a TLS handshake with a per-host minted cert, decodes the HTTP/1.1 conversation, applies profile rules + redacts before forwarding (the UPSTREAM sees the original body; only the LOGGED snapshot is redacted), and emits the audit event with the #315 ext keys (`url_path`, `url_query`, `request_method`, `request_body_redacted`, `response_status`, `request_body_truncated`, optional `request_body_snapshot`, `mitm_upstream_handshake_failed`). Cert-pinning SDKs land on a graceful 502 with a message that names CONNECT mode as the fallback.
  - `internal/cli/ca.go` — `gbounce ca install / uninstall / info / rotate` subcommands. Install prints the platform-specific OS trust-store command (macOS `security`, Debian/Ubuntu `update-ca-certificates`, RHEL/Fedora `update-ca-trust`, Firefox manual import); uninstall prints the matching removal command + cleans the on-disk cert + key.
  - `internal/cli/cli.go` — new `--mode mitm`, `--profile-rules-file PATH`, `--audit-log-include-bodies` flags. MITM mode validates the CA + key permissions before binding the listener; an expired CA or world-readable key file fails fast.
  - `internal/caveats/` — startup banner emits the MITM honest-positioning line (cert-pinning SDKs break; default-redaction policy; link to docs/MITM-MODE.md) only when `--mode mitm` is active.
  - `internal/proxy/proxy.go` — `Mode` extends with `ModeMITM`; `Config` adds `MITMCertMinter`, `MITMRules`, `MITMAuditIncludeBodies`. `/healthz` exposes `mitm_enabled`, `mitm_rules_count`, `mitm_audit_include_bodies`, `total_mitm_denies`, `total_mitm_upstream_handshake_failures`.
  - `docs/MITM-MODE.md` — the canonical honest-positioning doc covering when to opt INTO MITM, when to STAY in CONNECT mode, the body-redaction policy, the OCSF ext-key catalog, profile-rule shape, performance impact, and security considerations.
  Regression coverage (28 new tests across the new + adjacent packages): `TestCA_Generate_FreshCertHasCorrectShape`, `TestCA_GenerateRefusesToOverwrite`, `TestCA_Install_KeyPermissions_RejectsWorldReadable`, `TestCA_Info_ReturnsFingerprint`, `TestCA_Uninstall_Idempotent`, `TestCA_LoadCA_MissingFileGivesHelpfulError`, `TestMITM_CONNECTGeneratesPerHostCert`, `TestMITM_CertMinterLRUCachesAndEvicts`, `TestMITM_CertMinter_StripsPort`, `TestMITM_BodyRedactionMasksAuthorizationHeader`, `TestMITM_BodyRedactionMasksXAPIKey`, `TestMITM_BodyRedactionMasksJSONApiKeyField`, `TestRedactJSONBody_NonJSONUnchanged`, `TestRedactQueryParams_SecretsStripped`, `TestIsRedactedHeader_KnownNames`, `TestMITM_ProfileRuleMatchesByPath`, `TestMITM_ProfileRuleMatchesByMethod`, `TestProfileRule_HostWildcard`, `TestProfileRule_QueryParamMatch`, `TestProfileRule_PathPrefixAndRegex`, `TestProfileRule_RequiresMITM_DetectsPredicates`, `TestProfileRule_RejectsMultiLevelWildcard`, `TestFirstMatch_SkipsMITMOnlyRulesInDiscoveryMode`, `TestMITM_RefusesToStartWithoutCA`, `TestMITM_AuditEventIncludesURLPath`, `TestMITM_CertPinningSDKsFail_GracefulError`, `TestMITM_ProfileRule_EndToEndDeny`, `TestMITM_PerformanceOverhead_Under15PercentLatency`.

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
