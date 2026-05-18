# Investigate with Claude

`gbounce investigate` is a one-shot helper that lands a Claude-ready
evidence pack on disk. The operator drops both artifacts into THEIR
local Claude client (Claude Code / Cursor / desktop Claude / the
Anthropic console — whichever they use) and runs an investigative
prompt. **gbounce never calls Anthropic.** The audit data leaves
your host only if you choose to paste it.

The subcommand exists because the most useful thing a Claude agent
can do for a self-host operator is read their proxy audit data and
notice patterns a human would miss in a thousand-row SQLite scroll.

## What the subcommand does

```
gbounce investigate [--out-dir DIR]
                    [--time-range 24h | 7d | 4w]
                    [--filter EXPR ...]
                    [--print-prompts]
                    [--db PATH]
                    [--audit-log-path PATH]
                    [--healthz-url URL]
```

It writes two files into `--out-dir`:

- `gbounce-investigation.ndjson` — an OCSF v1.1.0 class 2004
  (Detection Finding) wrapping the filtered audit events, followed
  by a trailing NDJSON line carrying the investigation metadata
  (requested time window + audit-log-present flag + event count).
  A Claude analyst can read either line independently — the OCSF
  bundle stands alone for SIEM-style review; the metadata line
  surfaces the gap between "quiet window" and "wiped log".
- `gbounce-investigation-context.zip` — the standard `gbounce
  diagnostics bundle` output with `--no-audit` set (the evidence
  file already carries the audit content). Includes redacted
  config, `/healthz` snapshot, system metadata, and a sha256
  manifest.

Then it prints a "now what" block: three of the ten starter
prompts, a one-line privacy reminder, and a pointer to this doc.

## Step-by-step workflow

```
+------------------------------------------------------------+
|  1. Run: gbounce investigate --time-range 24h              |
|                                                             |
|     Output (truncated):                                     |
|       Artifacts written:                                    |
|         evidence  /tmp/.../gbounce-investigation.ndjson     |
|         context   /tmp/.../gbounce-investigation-context.zip|
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  2. Open YOUR local Claude client.                          |
|     (Claude Code, Cursor's Claude integration, the desktop  |
|      app, or the Anthropic console — operator's choice.)    |
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  3. Drop BOTH files into the conversation.                  |
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  4. Ask one of the starter prompts:                         |
|       "Review the past 24h of gbounce audit data.           |
|        Anything that looks off?"                            |
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  5. Iterate. The starter prompts are openers; once Claude   |
|     has the evidence + context in scope, follow up with     |
|     whatever the first answer suggests.                     |
+------------------------------------------------------------+
```

## The ten starter prompts

Run `gbounce investigate --print-prompts` to get a paste-able copy
without writing artifact files.

 1. Review the past 24h of gbounce audit data. Anything that looks
    off?
 2. Which agent generated the most denies? Was it consistent or a
    one-shot spike?
 3. Did the heartbeat gap ever exceed 60s? If yes, when + how
    often?
 4. Are there bursts of similar requests from one client in a short
    window? Identify actor + time range + path set.
 5. Did any admin-action audit event happen outside normal working
    hours? List them with timestamps.
 6. Cross-reference the rule-trigger times against the audit-export
    channel's failures (if any). Any correlation?
 7. Are any upstream hosts being contacted that don't match the
    normal traffic pattern? Group by upstream host + agent.
 8. Which URL paths appear in the most denies? Does that match the
    intended scope for this proxy?
 9. Did the same `agent.session_id` show up across multiple gbounce
    deployments or restarts? Was that expected?
10. Summarize the most common denial reasons and what they imply
    about the active rules / policy.

Per project guidance the prompts stay generic re: Claude client —
no specific surface is named.

## Privacy and operator-side responsibilities

`gbounce investigate` itself is strictly local:

- **No network calls** except a single LOCAL `/healthz` GET on the
  loopback port (same as `gbounce diagnostics bundle`).
- **No telemetry.** gbounce does not phone home in any way.
- **No Anthropic API call.** The subcommand never sends data to
  Anthropic. That decision is yours and happens inside YOUR Claude
  session.
- **Read-only.** The subcommand never writes to the store or the
  audit log. It only creates the two artifacts in `--out-dir`.

What the operator should think about BEFORE pasting:

- **Your Claude session is yours.** If you use a hosted Claude
  (claude.ai, the API, Claude Code with default settings), the
  audit data goes to Anthropic the moment you upload it. That may
  or may not be acceptable in your environment. Check your data-
  classification policy first.
- **Path values may carry tokens.** gbounce's exporter redacts
  query-string tokens but URL paths themselves are passed through.
  If your upstream encodes secrets in path components, watch for
  that before sharing.
- **The context bundle IS redacted** — webhook tokens masked, env
  var keys only without values. Safe to share more broadly than
  the evidence file.
- **For air-gapped environments**: use a local Claude (running
  through Ollama or similar) so no data leaves the host.

## Composability with other workflows

- The evidence NDJSON drops straight into a SIEM that indexes OCSF
  class 2004 (Splunk Enterprise Security, AWS Security Lake,
  Microsoft Sentinel).
- The context ZIP is the same artifact `gbounce diagnostics bundle`
  produces.
- For incident review: `gbounce investigate --time-range 7d
  --out-dir ./incident-2026-05-18` produces a stable, named
  directory you can attach to a post-mortem.

## Cross-product alignment

The same `investigate` subcommand ships in `ibounce` (AWS IAM
API), `kbounce` (Kubernetes API), and `dbounce` (database
connections) with identical flags and prompt structure. An
operator running multiple bouncers learns ONE muscle-memory
pattern:

```
ibounce investigate --time-range 24h --out-dir ./ibounce-out
kbounce investigate --time-range 24h --out-dir ./kbounce-out
dbounce investigate --time-range 24h --out-dir ./dbounce-out
gbounce investigate --time-range 24h --out-dir ./gbounce-out
```

Drop all four evidence packs into one Claude session and ask
prompt 9 ("Did the same `agent.session_id` show up across multiple
products?") for cross-bouncer correlation.
