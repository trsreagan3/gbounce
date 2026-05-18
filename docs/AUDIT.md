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

## See also

- [`docs/HARDENING-AGAINST-PROMPT-INJECTION.md`](HARDENING-AGAINST-PROMPT-INJECTION.md)
  — defense-in-depth against the audit log surface itself being
  injected.
- [`docs/DIAGNOSTICS.md`](DIAGNOSTICS.md) — `gbounce diagnostics
  bundle` redacts more aggressively than `audit tail --export`; use it
  when sharing the full operator state, not just audit rows.
