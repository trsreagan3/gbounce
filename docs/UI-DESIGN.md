# gbounce UI design memo — purpose-driven monitoring console

iam-jit #682 — [[gbounce-ui-purpose-driven]]

## Scope

The legacy live-tail at `GET /` is a single table that streams audit
events. It answers ONE operator question: "what just happened?" The
founder direction for #682 widens the surface to FIVE questions:

1. What is my agent doing RIGHT NOW?
2. Is my agent stuck?
3. What is gbounce blocking that I should know about?
4. Which features are turned on?
5. Are the features actually doing their job?

This memo documents the wireframes + data shapes that ship under
`GET /admin/ui`. The legacy `/` is preserved for backcompat.

## Anti-patterns (DO NOT)

Per [[ibounce-honest-positioning]]:

- Never show a green "OK" pill on a feature that's enabled but never
  fired. Show `CONFIGURED / NEVER FIRED` distinctly.
- Never show a deny without WHY (rule + source + severity).
- Never claim "monitoring active" when `audit_log_total` isn't
  incrementing.
- Never take a hard dependency on external CDNs / fonts / JS. Bundle
  every byte into the Go binary.

## Wireframe

```
+----------------------------------------------------------+
| header: status dot + bouncer + monitoring-since          |
+----------------------------------------------------------+
| [optional] empty-state hint with HTTPS_PROXY test cmd    |
+----------------------------------------------------------+
| Q2  Is the agent stuck? (hidden when no signals)         |
|     - [Critical] upstream_retry_storm                    |
|       6 requests to GET api.x.com/v1 in 30s              |
|       threshold: >= 5 in 30s                             |
+----------------------------------------------------------+
| Q1  Live decisions          | Q4+5  Features              |
|   time | verdict | op | st  |   mitm           [off]      |
|   12:01 ALLOW GET /v1  200  |     last fired never        |
|   12:02 DENY  CON bad. 403  |     total 0 - 24h 0         |
|                             |   deny_hosts     [firing]   |
|                             |     last fired 3s ago       |
|                             |     total 1 - 24h 1         |
|                             |   dynamic_deny  [gap]       |
|                             |     never fired             |
|                             |     how to test: write ...  |
+-----------------------------+-----------------------------+
| Q3  Recent denies                                        |
|   time | op | upstream | status                           |
|   12:02 CONNECT bad.example.com 403                       |
+----------------------------------------------------------+
| footer: links + read-only label                          |
+----------------------------------------------------------+
```

At narrow widths (`< 960px`) the grid collapses to a single column:
stuck → live → features → denies → footer.

## Server endpoints

All four are on the gbounce mgmt-port. Auth model mirrors
`/audit/events`: loopback open, external bind requires bearer.

### `GET /admin/ui` → HTML

Returns the bundled single-page console. CSP is identical to the
legacy `/` page (default-src 'self'; no frames; no external).

### `GET /admin/features` → JSON

```json
{
  "process_started_unix_ms": 1780398071312,
  "now_unix_ms": 1780398072394,
  "features": [
    {
      "name": "deny_hosts",
      "enabled": true,
      "fire_count_total": 1,
      "fire_count_24h": 1,
      "last_fired_unix_ms": 1780398070000,
      "configured_but_never_fired": false,
      "detail_hint": "CONNECT to a host matching a deny_hosts rule"
    },
    ...
  ]
}
```

Feature names (alphabetical, stable):

| name                              | "enabled" semantic                                         |
| --------------------------------- | ---------------------------------------------------------- |
| `audit_log`                       | `s.log != nil`                                             |
| `deny_hosts`                      | `len(s.denyHosts) > 0`                                     |
| `disk_pressure_circuit_breaker`   | `s.cfg.DiskPressure != nil`                                |
| `dynamic_deny`                    | `s.dynamicDeny != nil`                                     |
| `injection_scan`                  | active profile has `InjectionScanResponseBodies.Enabled`   |
| `mitm`                            | `s.cfg.Mode == ModeMITM`                                   |
| `object_storage`                  | `s.objectStorage != nil`                                   |
| `profile_enforcement`             | active profile is set                                      |
| `session_recorder`                | `s.recorder != nil`                                        |

### `GET /admin/stuck-signals` → JSON

```json
{
  "now_unix_ms": 1780398072394,
  "signals": [
    {
      "kind": "upstream_retry_storm",
      "severity": "Medium",
      "summary": "6 requests to GET *://api.x.com/v1 in 30s",
      "threshold": ">= 5 in 30s",
      "count": 6,
      "upstream_host": "api.x.com",
      "method": "GET",
      "path": "/v1",
      "last_seen_ms": 1780398072394
    }
  ]
}
```

Three signal kinds:

| kind                    | threshold                          |
| ----------------------- | ---------------------------------- |
| `upstream_retry_storm`  | ≥ 5 same `(method,host,path)` in 30s |
| `error_repeat`          | ≥ 5 same HTTP error in 30s        |
| `deny_storm`            | ≥ 5 DENY verdicts in 30s          |

Severity is a monotone mapping on count: `< 20: Medium`, `< 50: High`,
`>= 50: Critical`.

### `GET /admin/stream` → Server-Sent Events

Three event types over one long-lived connection:

```
event: features
data: {<featureStatusSnapshot>}

event: stuck-signals
data: {<stuck-signals-snapshot>}

event: decision
data: {"id":1,"time_ms":...,"method":"GET","path":"/v1","upstream_host":"api.x.com","http_status":200,"verdict":"ALLOW","mode":"discovery","agent_name":""}
```

Cadence:

- Initial snapshots emitted synchronously on connect (no blank
  console).
- `event: decision` polled at 1s tick, emitted oldest-first since the
  last cursor.
- `event: features` re-emitted at 5s tick.
- `event: stuck-signals` re-emitted at 10s tick.
- `: keepalive` SSE comment every 15s so reverse proxies don't idle
  the connection.

Cursor (`lastID`) is per-connection in-memory; a reconnecting client
re-builds it via the initial features snapshot.

## Hot-path cost

Each fire records two atomic ops:
`lastFired.Store(now)` + `fireCount.Add(1)`. Both are lock-free.
Snapshot cost is one `Load()` per feature — read by `/admin/features`
+ the SSE handler on its 5s tick.

The Server struct gains `atomic.Int64` fields per feature; alignment
considerations are inherited from the prior counter pack — adding
fields at the end keeps existing counters' offsets stable.

## Empty-state UX

When `liveCount === 0` after 5 seconds the page reveals an amber
hint block:

> No traffic observed yet on this bouncer. To send a test request:
> `HTTPS_PROXY=http://127.0.0.1:8769 curl https://api.github.com/zen`

This closes the "I see nothing and don't know why" gap that the
legacy UI had.

## Test coverage

`internal/proxy/admin_ui_test.go` covers:

- HTML rendering
- All five question labels present
- SSE handler wiring (`EventSource`, `/admin/stream`, three event types)
- No external CDNs / fonts / analytics
- No embedded bearer token
- No surveillance copy (`violation`, `infraction`, `unauthorized`)
- CSP headers (`default-src 'self'`, `connect-src 'self'`,
  `frame-ancestors 'none'`)
- Empty-state copy contains a `HTTPS_PROXY` test command
- `/admin/features` returns the canonical 9-feature list
- `ConfiguredButNeverFired` honesty surface for an enabled-but-no-fire
  feature
- Disabled features are NOT flagged as `ConfiguredButNeverFired`
- `/admin/stuck-signals` empty-state is `signals: []` (no fake "OK")
- `upstream_retry_storm` detection with threshold string match
- `deny_storm` detection
- SSE initial frames (`event: features` + `event: stuck-signals`)
  emitted synchronously on connect
- Bearer-token gate rejects no-header + wrong-header + wrong-_token

## See also

- [UI-USAGE.md](UI-USAGE.md) — operator guide
- `internal/proxy/admin_ui.go` — page bundle
- `internal/proxy/admin_monitoring.go` — endpoints + SSE
- `internal/proxy/feature_status.go` — feature snapshot builder
