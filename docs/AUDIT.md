# Audit log + `audit tail` reference

`gbounce` records every forwarded request in two places:

- A local **SQLite database** at `~/.gbounce/state.db` (canonical
  source of truth).
- An optional **JSONL audit log** at the path passed via
  `--audit-log-path` (designed for Fluent Bit / Vector / logrotate to
  ship to a SIEM).

Both stores share the same wire shape — **OCSF v1.1.0 class 6003 (API
Activity)** events. The cross-product `iam-jit` extension under
`unmapped.iam_jit` carries gbounce-specific decision context.

The `gbounce audit tail` subcommand lets you read, filter, summarize,
and export rows from the SQLite store.

## Quick reference

```text
gbounce audit tail [--follow] [--filter EXPR ...] [--summary] [--export FORMAT --out PATH]
```

| Flag             | Purpose                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `--db PATH`      | SQLite path (default `~/.gbounce/state.db`; honors `GBOUNCE_DB`).        |
| `--limit N`      | Max rows for the default view (1..1000; default 50).                     |
| `--follow`       | Live-tail; polls every 500ms; exit on Ctrl-C.                            |
| `--filter EXPR`  | Narrow rows (repeatable; AND semantics).                                 |
| `--summary`      | Print count-summary instead of individual rows.                          |
| `--export FORMAT`| Export to file (`jsonl`, `csv`, `ocsf-bundle`). Requires `--out`.        |
| `--out PATH`     | Output file for `--export`.                                              |
| `--csv-columns`  | Override default CSV column set.                                         |

## Live tail + filtering + summary + export

This section covers the four enhanced modes gbounce ships for audit
visibility. Each mode composes with `--filter` (except `--follow` +
`--summary`, which clash by design — one is a stream, the other is a
fixed-snapshot aggregation).

### Live tail (`--follow`)

```sh
gbounce audit tail --follow
# # gbounce audit tail --follow (poll=500ms; cursor=2381); Ctrl-C to exit
# 2026-05-18T14:22:31Z  GET    200  api.example.com        /v1/health
# 2026-05-18T14:22:32Z  POST   201  api.example.com        /v1/users
# ^C
```

The follow loop polls the SQLite DB every 500ms and prints new rows
oldest-first as they arrive. A starting watermark (the max decision_id
at startup) ensures only rows recorded AFTER `--follow` is invoked
appear; historical rows are skipped (use the default `audit tail` for
those).

`--follow` is **mutually exclusive** with `--summary` and `--export`.

### Filtering (`--filter EXPR`)

Repeatable; AND semantics. Four operators:

```text
field=value   string equality (case-sensitive)
field~regex   Go RE2 regex match
field>=N      numeric greater-or-equal
field<=N      numeric less-or-equal
```

#### Cross-product OCSF fields (also supported by ibounce / kbounce / dbounce)

- `severity_id`
- `activity_id`
- `status_id`
- `actor.user.name`
- `api.operation`
- `unmapped.iam_jit.agent.name`
- `unmapped.iam_jit.agent.session_id`
- `unmapped.iam_jit.event_type`

#### gbounce-specific fields

- `upstream_host` — the destination host (e.g. `api.example.com`)
- `path` — the URL path of the request
- `method` — the HTTP verb (`GET`, `POST`, ...)
- `http_status` — the upstream's HTTP response code

#### Examples

```sh
# All calls to api.example.com.
gbounce audit tail --filter upstream_host=api.example.com

# All 4xx + 5xx responses from a single host.
gbounce audit tail \
  --filter upstream_host=api.example.com \
  --filter http_status>=400

# All write methods (POST / PUT / PATCH / DELETE).
gbounce audit tail --filter 'method~^(POST|PUT|PATCH|DELETE)$'

# Calls to a specific API path-prefix.
gbounce audit tail --filter 'api.operation~^GET /v1/users/'

# Activity from a specific agent session (when the agent populates
# unmapped.iam_jit.agent.session_id).
gbounce audit tail \
  --filter unmapped.iam_jit.agent.name=claude-code \
  --filter unmapped.iam_jit.agent.session_id=sess-abc-123
```

### Summary (`--summary`)

Count-summary keyed by the cross-product groupings (event_type,
severity_id, actor.user.name, api.operation) PLUS the gbounce-specific
groupings (upstream_host, method, http_status, and the composite
`upstream_host+method+http_status` "request shape" key).

```sh
gbounce audit tail --summary --limit 1000
# Total events: 348
#
# By event_type:
#   delete                                    14
#   get                                       250
#   post                                      72
#   put                                       12
#
# ...
#
# By upstream_host+method+http_status:
#   api.example.com GET 200                   220
#   api.example.com POST 201                  64
#   api.example.com POST 500                  4
#   other.example GET 404                     8
```

Composes with `--filter` — first filter, then summarize:

```sh
# How did 4xx + 5xx responses break down for api.example.com?
gbounce audit tail \
  --filter upstream_host=api.example.com \
  --filter http_status>=400 \
  --summary
```

### Export (`--export FORMAT --out PATH`)

Three formats. Every format applies URL-token redaction (see
[Query-string token redaction](#query-string-token-redaction-always-applied-on-export)
below).

```sh
# OCSF events one-per-line (for jq / Vector / Fluent Bit pipelines).
gbounce audit tail --export jsonl --out audit.jsonl

# Tabular CSV (default columns).
gbounce audit tail --export csv --out audit.csv

# Custom CSV column set.
gbounce audit tail \
  --export csv --out audit.csv \
  --csv-columns timestamp,method,upstream_host,path,http_status

# OCSF v1.1.0 Detection Finding wrapping the contained events
# (one-artifact shape for SIEM ingest or sharing with an analyst).
gbounce audit tail --export ocsf-bundle --out bundle.json
```

Default CSV columns: `timestamp, severity, event_type, actor,
operation, verdict, agent.name, agent.session_id, upstream_host, path,
method, http_status`.

Composes with `--filter`:

```sh
# Export only the failed requests as a CSV for a support ticket.
gbounce audit tail \
  --filter http_status>=400 \
  --export csv --out failures.csv
```

## Query-string token redaction (always applied on export)

The gbounce audit log records the raw inbound URL path INCLUDING the
query string. That's intentional for the live `audit tail` display —
an operator debugging an agent needs to see exactly what was called.

**Exports are different.** A CSV pasted into a support ticket, an
`ocsf-bundle` shipped to a SIEM, or a JSONL file dropped into a Claude
analysis thread can leak tokens to anyone with access. So `--export`
**always** strips sensitive query-string values, replacing them with
the literal string `REDACTED`.

### Denylist (case-insensitive query-param names)

```
token, api_key, apikey, password, passwd, secret, bearer, key,
authorization, auth, access_token, refresh_token, id_token,
client_secret, sig, signature
```

The parameter name is preserved so an analyst can see WHICH sensitive
params were present; only the value is replaced. Example:

```text
# Live tail (raw):
2026-05-18T14:22:24Z  GET    200  api.example.com  /v1/secrets?token=abc&user=alice

# CSV export (redacted):
.../v1/secrets?token=REDACTED&user=alice
```

The redaction is load-bearing for the share-export-with-Claude story
(see the `investigate-with-claude` memo). The denylist is the same one
that `kbounce` + `dbounce` + `ibounce` apply on their equivalent
exports, per the cross-product agent-parity contract.

## Cross-product agent parity

`gbounce audit tail` ships the same flag set + grammar + supported
fields as the equivalent commands in the other Bounce products. An
agent or operator who learns one learns the rest:

- `ibounce audit tail` — local IAM-decision audit log
- `kbounce audit tail` — Kubernetes proxy decision log
- `dbounce audit tail` — database statement decision log

Cross-product fields (`severity_id`, `actor.user.name`, etc.) have the
same semantics across all four products. Product-specific fields
(`upstream_host` here; `cluster_name` / `dialect` / etc. on the
others) are documented per-product but follow the same `name=value` /
`name~regex` / `name>=N` / `name<=N` grammar.

## HTTP `/audit/events` endpoint (`#271`)

Every Bounce-suite proxy exposes a headless audit-query surface on its
management port. For gbounce that's port `8769` (mgmt-host `127.0.0.1`
by default).

```
GET /audit/events?since=ISO8601&until=ISO8601&filter=field=value&filter=...&limit=N&format=jsonl|ocsf-bundle
```

Same filter language as `gbounce audit tail --filter`, same supported
field catalog. The defaults are `limit=100` (max `1000`) + `format=jsonl`
(one OCSF event per line). Pass `format=ocsf-bundle` for a single
OCSF v1.1.0 class 2004 Detection Finding wrapping the matched events.

### Sample invocations

```bash
# Loopback bind (default): no auth required.
curl 'http://127.0.0.1:8769/audit/events?limit=10'

# Filter to one upstream host, last hour, NDJSON.
curl 'http://127.0.0.1:8769/audit/events?filter=upstream_host=api.example.com&since=2026-05-18T00:00:00Z'

# OCSF Detection Finding bundle for SIEM batch import.
curl 'http://127.0.0.1:8769/audit/events?format=ocsf-bundle&limit=100'
```

### Auth model

- **Loopback bind (default)**: the endpoint is reachable only on
  loopback; no `Authorization` header required. This matches gbounce's
  baseline trust anchor (the mgmt port refuses to bind off-loopback
  without `--i-know-this-binds-externally`).
- **External bind**: `gbounce run --i-know-this-binds-externally
  --mgmt-host 0.0.0.0 --audit-events-token <TOKEN>` is required.
  Requests must carry `Authorization: Bearer <TOKEN>`. Missing header
  → 401; wrong token → 403. gbounce refuses to start in external-bind
  mode without `--audit-events-token`.

### Cross-bouncer query

The `iam-jit audit query` CLI calls this endpoint on every reachable
bouncer (ibounce / kbounce / dbounce / gbounce) in parallel and merges
the results. See
[`iam-roles/docs/IAM-JIT-AUDIT-QUERY.md`](https://github.com/trsreagan3/iam-roles/blob/main/docs/IAM-JIT-AUDIT-QUERY.md)
for the cross-product correlation workflow.

## Live web UI at `GET /` (`#272`)

gbounce serves a minimal vanilla-JS web UI on its mgmt port
(`8769` by default) — the same port that hosts `/healthz` and
`/audit/events`. The page is a single self-contained HTML+CSS+JS
file (no build step, no CDN, no Google Fonts, no analytics, no
telemetry) that long-polls `/audit/events?since=<cursor>` every two
seconds and renders a live-updating colour-coded table.

### How to access

```bash
# Loopback default (no auth needed).
gbounce run
# Then open in a browser:
open http://127.0.0.1:8769/

# Quick smoke test from curl.
curl -s http://127.0.0.1:8769/ | head
```

External-bind operators pass the bearer token through the URL
fragment (the JS extracts it client-side; the page itself never
embeds it):

```
https://gbounce.example.com:8769/#token=YOUR_AUDIT_EVENTS_TOKEN
```

### Visual conventions

- **DENIED** rows tinted red; **ALLOWED** rows untinted with a
  green verdict pill; **ADMIN_*** rows tinted blue; **HEARTBEAT**
  rows greyed out. Matches the cross-bouncer TUI shipped alongside
  this UI (see below).
- Top bar shows total event count + per-class breakdown (allow /
  deny / admin / heartbeat).
- Filter input forwards to the same `/audit/events?filter=` server-
  side syntax documented above.
- Pause / clear buttons; mobile-responsive layout.

### Read-only

Per `[[creates-never-mutates]]` the web UI is a **viewer**, never a
controller. No buttons mutate gbounce state — no "kill session",
no "pause profile". Operators run the existing `gbounce` CLI for
actions. The HTML response carries a strict `Content-Security-
Policy` header (`default-src 'self'; frame-ancestors 'none'; ...`).

### Cross-bouncer TUI sibling

For a single merged view across ibounce / kbounce / dbounce /
gbounce, see
[`iam-roles/docs/AUDIT-STREAM-TUI.md`](https://github.com/trsreagan3/iam-roles/blob/main/docs/AUDIT-STREAM-TUI.md)
— `iam-jit audit stream` is the terminal-UI sibling of the per-
bouncer web pages.

## Per-session recordings (`--record-sessions-dir`, `#285` + `#290`)

`gbounce run --record-sessions-dir PATH` tees every audit event
into a per-session NDJSON file at
`{PATH}/{agent.session_id}.ndjson`. Files are portable across
ibounce / kbouncer / dbounce / gbounce — same on-disk shape per
`[[cross-product-agent-parity]]` — so the cross-product
`iam-jit session replay <FILE>` CLI walks any product's
recordings uniformly. File mode 0o600.

### Per-request agent context

For gbounce the session id arrives on the inbound request as the
HTTP header `X-Agent-Session-Id` (and optionally `X-Agent-Name`).
Agents wrapping their HTTP traffic through gbounce set these
headers so the recorder can route events into a per-session file.
Requests without a session header are NOT routed to a session
file (raw curl from a script has no session identity); they
still land in the JSONL log + the SQLite decision table.

```bash
# Run the proxy with per-session recording enabled.
gbounce run --upstream https://api.target.com \
  --record-sessions-dir ~/.gbounce/sessions

# Agent invokes through the proxy with the session header set:
#   curl -H 'X-Agent-Session-Id: 01956c44-c5c1-7c31-9bca-7c0aaa000001' \
#        -H 'X-Agent-Name: claude-code' \
#        http://127.0.0.1:8080/v1/dashboards

# List what got recorded.
gbounce session list
# SESSION_ID                              AGENT          EVENTS START                  END
# 01956c44-c5c1-7c31-9bca-7c0aaa000001    claude-code         42 2026-05-19T14:01:33Z   2026-05-19T14:08:12Z
# 01956c44-c5c1-7c31-9bca-7c0aaa000099    cursor              17 2026-05-19T15:22:01Z   2026-05-19T15:24:55Z

# Summary + event-count-by-type for one recording.
gbounce session show 01956c44-c5c1-7c31-9bca-7c0aaa000001

# OCSF Detection Finding envelope.
gbounce session export 01956c44-c5c1-7c31-9bca-7c0aaa000001 \
  --out /tmp/finding.json

# Retention sweep — explicit threshold required; --dry-run lists candidates.
gbounce session purge --older-than 30d --dry-run
gbounce session purge --older-than 30d
```

Cross-product documentation lives at
[`iam-roles/docs/SESSION-REPLAY.md`](https://github.com/trsreagan3/iam-roles/blob/main/docs/SESSION-REPLAY.md).

Per `[[creates-never-mutates]]` the recorder is additive (it tees
the existing event stream); the `session` subcommands are read-
only or destructive-only-via-explicit-`purge --older-than`.

Per `[[self-host-zero-billing-dependency]]`: zero network calls;
entirely local filesystem.

## See also

- [`docs/HARDENING-AGAINST-PROMPT-INJECTION.md`](HARDENING-AGAINST-PROMPT-INJECTION.md)
  — defense-in-depth against the audit log surface itself being
  injected.
- [`docs/DIAGNOSTICS.md`](DIAGNOSTICS.md) — `gbounce diagnostics
  bundle` redacts more aggressively than `audit tail --export`; use it
  when sharing the full operator state, not just audit rows.
