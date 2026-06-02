# gbounce monitoring UI — operator guide

gbounce ships two browser UIs on the management port (default `8769`):

| route        | purpose                                                                          |
| ------------ | -------------------------------------------------------------------------------- |
| `/`          | legacy live-tail audit table (long-poll; backcompat with v0.x)                  |
| `/admin/ui`  | **purpose-driven monitoring console** answering the 5 operator questions below   |
| `/suite`     | Bounce-suite link page (#298)                                                    |

Both UIs bundle their HTML / CSS / JS into the gbounce Go binary. **No CDN, no
external fonts, no analytics.** The page works on air-gapped operator machines.

This doc covers `/admin/ui` — the console shipped in iam-jit #682 per
[[gbounce-ui-purpose-driven]].

## The 5 questions the console answers

1. **"What is my agent doing RIGHT NOW?"** — live decision stream, newest at
   the top. Auto-updates via Server-Sent Events; no polling, no refresh.
2. **"Is my agent stuck?"** — quantified pattern detection. The panel only
   renders when at least one signal fired; signals carry the EXACT
   threshold ("5 requests in 30s") so you can audit the heuristic.
3. **"What is gbounce blocking that I should know about?"** — DENY events
   filtered into a dedicated panel.
4. **"Which features are turned on?"** — table of every monitoring feature
   gbounce supports, with an `ON` / `OFF` pill.
5. **"Are the features actually doing their job?"** — for each ON feature:
   last-fired timestamp, total fire count, 24h count, and last error.
   Features that are configured but have **never fired** get a distinct
   `CONFIGURED / NEVER FIRED` pill — that's the honesty surface per
   [[ibounce-honest-positioning]].

## Wire shape

The console drives entirely off two endpoints + one SSE stream:

```
GET /admin/ui              → the HTML page
GET /admin/features        → JSON snapshot of per-feature firing state
GET /admin/stuck-signals   → JSON snapshot of stuck-pattern detections
GET /admin/stream          → Server-Sent Events (event: decision /
                              event: features / event: stuck-signals)
```

All four endpoints are read-only. None mutate gbounce state — they only
report what they observe.

### Auth model

Mirrors `/audit/events`:

- **Loopback bind (default)**: no auth header required.
- **External bind**: requires a bearer token via either
  `Authorization: Bearer <token>` header, or for the SSE stream the JS
  page extracts the token from the URL `#token=...` fragment and appends
  it as `?_token=<token>`. The HTML body NEVER embeds the token.

The bind-time CLI gate refuses external binds without a token set.

## Quick-start probe

```bash
# Start gbounce on a non-default port with audit-log + deny enabled.
gbounce run \
  --port 18080 \
  --mgmt-port 18769 \
  --allow-connect \
  --audit-log-path /tmp/gbounce-audit.jsonl \
  --deny-host bad.example.com

# Open the console.
open http://127.0.0.1:18769/admin/ui

# Send some test traffic.
HTTPS_PROXY=http://127.0.0.1:18080 curl -s https://api.github.com/zen
HTTPS_PROXY=http://127.0.0.1:18080 curl -s https://bad.example.com  # denied

# The console will show:
#  - the ALLOW + DENY in the live stream
#  - the DENY in the deny panel
#  - deny_hosts feature: ON, "firing" pill, fire_count_total: 1
#  - audit_log feature: ON, "firing" pill, fire_count_total: 2
#  - dynamic_deny feature: ON, "configured / never fired" pill (if no
#    rules in ~/.iam-jit/dynamic-denies.yaml)
```

## Honesty surface

The console deliberately does NOT paint a green "OK" badge on
silent-degraded features. A feature that is enabled but has never fired
gets the amber `CONFIGURED / NEVER FIRED` pill — that's the honesty bar
per [[ibounce-honest-positioning]].

If you're seeing `CONFIGURED / NEVER FIRED` on a feature you expect to
be working, the `how to test` hint shows the exact one-liner that should
cause it to fire. Example:

> **deny_hosts** `configured / never fired`
> how to test: `CONNECT to a host matching a deny_hosts rule`

## Stuck-pattern thresholds

The "is my agent stuck" panel fires three quantified signals:

| kind                    | threshold                          |
| ----------------------- | ---------------------------------- |
| `upstream_retry_storm`  | ≥ 5 same `(method,host,path)` in 30s |
| `error_repeat`          | ≥ 5 same HTTP error in 30s        |
| `deny_storm`            | ≥ 5 DENY verdicts in 30s          |

Every signal carries the exact threshold string in its body so an operator
can audit the heuristic — never a vague "stuck" label.

## Cross-product parity

Other Bounce-suite bouncers (ibounce, kbouncer, dbounce) share the legacy
`/` live-tail HTML shape per [[cross-product-agent-parity]]. The new
`/admin/ui` console is gbounce-specific for now; expect parity in a
future cross-product slice.

## See also

- [HARDENING-AGAINST-PROMPT-INJECTION.md](HARDENING-AGAINST-PROMPT-INJECTION.md)
- [AUDIT.md](AUDIT.md)
- [DEPLOYMENT-PRESETS.md](DEPLOYMENT-PRESETS.md)
