# Diagnostics bundle (`gbounce diagnostics bundle`)

`gbounce diagnostics bundle` (alias: `gbounce diag bundle`) produces a
single ZIP file that contains everything a support engineer — or a
Claude agent acting as your debugging partner (per #273) — needs to
diagnose a gbounce deployment, with secrets redacted at the bundle's
write site.

The bundle is the operator's to share. Review the section list below
and `unzip -l` output before forwarding to a third party.

## When to use this

- **Sharing with support.** You hit a bug, the maintainer asks "send
  me your config + a recent audit-log tail + your `/healthz` output."
  Run `gbounce diag bundle --out ~/issue-123.zip`, attach the ZIP.
- **Sharing with a Claude agent.** Per #273, the cleanest way to ask
  Claude "what's wrong with my gbounce deployment?" is to feed it a
  bundle. The redactor strips tokens, webhook URLs, hostnames in URLs,
  user identifiers, and env-var values — so the bundle is safe to
  paste into a prompt without leaking your deployment topology.
- **Capturing a debug baseline.** Run the bundle command before a
  config change, again after, and `diff` the two — every section is
  deterministic on byte-identical inputs (ZIP modtimes are pinned to
  the Bounce-suite epoch, `2026-05-17`) so the diff is meaningful.

Sibling Bounce products ship the same subcommand shape (per
[[cross-product-agent-parity]]):

- [`kbounce diagnostics bundle`](https://github.com/trsreagan3/kbouncer/blob/main/docs/DIAGNOSTICS.md)
- [`dbounce diagnostics bundle`](https://github.com/trsreagan3/dbounce/blob/main/docs/DIAGNOSTICS.md)
- `ibounce diagnostics bundle`

One `{product} diag bundle --out ./bundle.zip` invocation works
identically across all four.

## What's in the bundle

Every entry is digit-prefixed so `unzip -p ... | less` shows them in
the order a reviewer would naturally read them (README first, manifest
last):

```
00-README.txt              top-level explainer ("what's in this bundle")
01-version.txt             gbounce build info (version + Go + OS/ARCH)
02-config-redacted.json    operator config (tokens + webhook URL MASKED)
03-active-mode.txt         current proxy mode (G-Slice 1: discovery)
04-audit-tail.jsonl        last N audit events (user IDs hashed)
05-healthz.json            /healthz snapshot
06-system.txt              OS / kernel / hostname-redacted / env keys
07-listener.json           bind ports + request counters
08-panics.txt              captured panics (if any)
09-manifest.json           file list + sha256 of each
```

Why `03-active-mode.txt` instead of `03-active-profile.json`? gbounce
genuinely lacks the profile / rule / task / alert-rule subsystems the
sibling products ship — per the #275 ship note, gbounce's
`config export` reports those as `*_supported: false`. The
diagnostics bundle's `03-active-mode.txt` carries the equivalent
"what is the proxy doing" info (current mode + future-mode roadmap
hints).

## Redaction contract

The bundle redactor covers (per #277):

| Surface | What's redacted |
| --- | --- |
| Audit-webhook URL + token | Replaced with `***REDACTED***` |
| HEC tokens / API keys / Bearer tokens | Replaced with `***REDACTED***` |
| User identifiers in audit events (`name`, `uid`, `email`, etc.) | Replaced with stable `sha256:<12hex>` hash (matches the dbounce convention so two events for the same actor produce the same redacted token) |
| Webhook URLs / alert-route destinations | Replaced with `***REDACTED***` (the URL identifies your SIEM endpoint) |
| Hostnames inside URLs | Scrubbed wholesale via the URL pattern |
| `audit_log_path` in the config section | Replaced with `***REDACTED***` (the path can carry a username or org-specific directory name) |
| `uname -a` hostname | Replaced with `<hostname-redacted>` |
| Env-var values | Only KEYS appear (e.g. `GBOUNCE_DB`); values never leave the host |
| Certs / private keys | Never collected in the first place |
| License bytes | Never emitted; only `license_id` + `expires_at` round-trip |

**Single source of truth.** The config-section redaction reuses the
`BuildExport` pipeline from `gbounce config export` (#275) — the
diagnostics bundle never gets to drift relative to `config export
--redact-secrets`.

**Belt-and-suspenders.** Even when an upstream surface is supposed to
be already-redacted, the bundle re-runs the regex sweep at its own
write site. Tokens / URLs / IPs / emails / `Bearer …` headers get
scrubbed defensively.

## Flags

```
gbounce diagnostics bundle \
  [--out PATH] \
  [--include-audit-tail N] \
  [--no-audit] \
  [--db PATH] \
  [--audit-log-path PATH] \
  [--healthz-url URL] \
  [--insecure-skip-verify] \
  [--panic-log PATH]
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--out PATH` | `./gbounce-diagnostics-{ISO8601-UTC}.zip` | Where to write the ZIP. Parent dirs are `0o700`; the file is `0o600`. |
| `--include-audit-tail N` | `200` | Last N audit-log lines to include (redacted). Pass `0` to use the default. |
| `--no-audit` | off | Skip the audit-log tail entirely. For paranoid operators / regulated environments where even user-ID-hashed events are considered sensitive. |
| `--db PATH` | `~/.gbounce/state.db` (honors `GBOUNCE_DB`) | SQLite path the config-export step reads. |
| `--audit-log-path PATH` | unset | Path to the proxy's JSONL audit log. Doubles as the destination for the admin-action `diagnostics.bundle` event so a security team has a witness for "who pulled diagnostics + when?" Point at the same file the proxy daemon's `--audit-log-path` uses. |
| `--healthz-url URL` | `http://127.0.0.1:8769/healthz` | Local management endpoint to probe. Bundle records `"unreachable"` + the error reason on failure — the command does NOT abort. |
| `--insecure-skip-verify` | off | Skip TLS verification on the `/healthz` GET. For self-signed cert deployments. |
| `--panic-log PATH` | unset | Path to a captured stderr / panic log to include (REDACTED). |

## Admin-action audit event

Every successful bundle creation emits one OCSF v1.1.0 class 6003 (API
Activity) event with `activity_name="diagnostics.bundle"` when
`--audit-log-path` is configured. Same wire shape as kbounce / dbounce
/ ibounce so a single SIEM correlation rule catches the lifecycle
event regardless of which Bounce product fired it.

The event records:

- the output ZIP path (in `entity` / `entity_name`)
- the operator (best-effort: `USER` → `USERNAME` → `operator`)
- counts only (file count, audit-line count, total bytes); never the
  bundle's contents
- the `no_audit` flag + the `healthz_ok` boolean so an analyst can
  pivot on "who pulled an audit-suppressed bundle?"

## Sample `unzip -l` output

```
$ gbounce diagnostics bundle --out /tmp/bundle.zip \
    --audit-log-path /var/log/gbounce/audit.jsonl
gbounce: diagnostics bundle written to /tmp/bundle.zip (10 files, 4216 bytes, 12 audit lines included)

$ unzip -l /tmp/bundle.zip
Archive:  /tmp/bundle.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     1024  2026-05-17 00:00   00-README.txt
      214  2026-05-17 00:00   01-version.txt
     1186  2026-05-17 00:00   02-config-redacted.json
      290  2026-05-17 00:00   03-active-mode.txt
     2412  2026-05-17 00:00   04-audit-tail.jsonl
      198  2026-05-17 00:00   05-healthz.json
      512  2026-05-17 00:00   06-system.txt
      328  2026-05-17 00:00   07-listener.json
       54  2026-05-17 00:00   08-panics.txt
     1842  2026-05-17 00:00   09-manifest.json
---------                     -------
     8060                     10 files
```

All entries carry the same `2026-05-17 00:00` modtime — that's the
Bounce-suite epoch (rename day), deliberately pinned so two bundles
built from byte-identical inputs hash the same.

## Privacy posture (what gbounce promises)

- **Read-only** ([[creates-never-mutates]]): the diagnostics command
  never modifies the SQLite store, config, or audit log. Open the file
  read-only, write a ZIP, exit.
- **No network calls beyond loopback** ([[self-host-zero-billing-dependency]]):
  the only outbound traffic is the local `GET /healthz` (configurable
  via `--healthz-url`; defaults to `http://127.0.0.1:8769/healthz`).
- **Manifest sha256s** let a downstream verifier confirm the ZIP
  hasn't been tampered with after generation.

## Threat model: what the bundle does NOT protect against

- An operator who deliberately puts secrets in the configured
  `--panic-log` PATH file is shipping those secrets if the regex
  sweep misses them. The redactor catches URLs, IPs, emails, `Bearer
  …` headers, and long base64-shaped strings — false positives are
  preferred over false negatives — but it's not a substitute for
  reviewing the file's intended contents.
- The bundle includes the OPERATOR's `GBOUNCE_*` env var KEYS (not
  values). If you've set `GBOUNCE_INTERNAL_PROJECT_NAME=acme-prod`,
  the KEY name itself carries information.
- A custom audit-log field your future code adds whose key doesn't
  match `userIDFields` / `sensitiveKeyFragments` will pass through
  the redactor's free-text scrub but won't get the user-ID-hash
  treatment. When you add new audit fields, extend the redactor in
  the same PR.

## Related

- [#277 cross-product diagnostics bundle](https://github.com/trsreagan3/iam-jit/issues/277)
- [#273 share-bundles-with-Claude pattern](https://github.com/trsreagan3/iam-jit/issues/273)
- [docs/CONFIG-EXPORT-IMPORT.md](./CONFIG-EXPORT-IMPORT.md) — the
  `config export` pipeline the bundle reuses for the config section
- [kbounce DIAGNOSTICS.md](https://github.com/trsreagan3/kbouncer/blob/main/docs/DIAGNOSTICS.md)
- [dbounce DIAGNOSTICS.md](https://github.com/trsreagan3/dbounce/blob/main/docs/DIAGNOSTICS.md)
