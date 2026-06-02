# gbounce

Generic HTTP/HTTPS forward proxy with audit-export. The 5th product in
the Bounce suite (alongside `ibounce`, `kbounce`, `dbounce`, and the
host `iam-jit-bouncer`).

`gbounce` sits between any HTTP/HTTPS client (an AI agent, a CLI tool,
an SDK, a browser) and any upstream HTTP service. It forwards every
request verbatim and emits an OCSF v1.1.0 class 6003 (API Activity)
audit event for each request/response pair. The audit log is the
product.

## What ships in G-Slice 1

**Discovery mode only.** Observation + audit, no filtering, no
enforcement.

- `gbounce run --upstream https://api.target.com --port 8080` starts a
  forward proxy on `:8080` that:
  - Accepts inbound HTTP/HTTPS requests
  - Forwards them to the upstream verbatim
  - Returns the upstream's actual response
  - Emits one OCSF audit event per request/response pair
- `gbounce audit tail` prints recent rows from the local SQLite audit
  DB. Supports `--follow` (live-tail), `--filter EXPR` (repeatable;
  AND semantics), `--summary` (count-summary by event_type /
  severity_id / upstream_host / method / http_status / composite
  request-shape), and `--export jsonl|csv|ocsf-bundle --out PATH`
  (URL-token redaction always applied on export). See
  [`docs/AUDIT.md`](docs/AUDIT.md) for the full reference.
- `gbounce config export | import` portable JSON bundle for backup +
  migration + change-management review (see
  [`docs/CONFIG-EXPORT-IMPORT.md`](docs/CONFIG-EXPORT-IMPORT.md))
- `gbounce diagnostics bundle` (alias `gbounce diag bundle`) produces
  a single redacted ZIP with config + audit-log tail + `/healthz`
  snapshot + system info, safe to share with support OR a Claude
  agent (see [`docs/DIAGNOSTICS.md`](docs/DIAGNOSTICS.md))
- `gbounce --version` reports build metadata
- `gbounce version-check` opt-in informational check against GitHub
  Releases (no telemetry; disable with `GBOUNCE_NO_VERSION_CHECK=1`)
- `/healthz` JSON liveness probe on a separate management port
  (default `:8769`)

## Known limitations

Read before you install — knowing the boundaries up-front saves debugging time. The canonical list lives at [`docs/KNOWN-CAVEATS.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md); the top three for gbounce are:

- **§B9 — G-Slice 1 = discovery only.** gbounce v1.0 observes + logs but does NOT block. Profile-mode gating ships in G-Slice 2 (v1.1). If you need to block traffic in v1.0, point gbounce at an egress firewall or a network policy upstream.
- **§B8 — `--allow-connect` only sees host:port.** HTTPS CONNECT tunnels show `CONNECT host:443` only; URL paths + bodies are NOT visible (TLS passthrough, no MITM). Deliberate per [[ibounce-honest-positioning]] — more privacy + deployability. For URL-level visibility on plain HTTP use `--upstream` rewrite mode.
- **§B14 — Bounce-suite is "complementary," not "unified."** gbounce is one of four products under one brand. Only ~10% of decisions show TRUE multi-layer composition per UAT. The honest framing per [[ibounce-honest-positioning]].

`gbounce doctor caveats` prints the full applicable list (including cross-product entries B13/B14/B15).

## Later G-Slices (queued, not in this release)

- **G-Slice 2** — profile mode (deny verdicts honored)
- **G-Slice 3** — tap mode (out-of-band copy of traffic to a SIEM
  collector)
- **G-Slice 4** — auto-recommender (suggest profiles from observed
  traffic)
- **G-Slice 5** — MCP server (let agents query their own decisions)
- **G-Slice 6** — webhook export (push audit events to a customer
  collector)
- Post G-6 — community profile bundle

## Honest positioning

`gbounce` is a **deterrent and audit trail, not a security boundary**.
An operator who controls the agent's network can route around the
proxy — set `HTTPS_PROXY=`, bind to a different DNS, etc. The product
value is:

- Visibility (what did the agent actually call?)
- Audit trail (one OCSF event per call, with timestamps + status +
  size + latency)
- Future profile-mode gating (G-Slice 2)

If you need a boundary an adversarial agent can't bypass, an egress
firewall or network policy at the host / cluster / VPC layer is the
right tool.

## TLS handling (G-Slice 1)

Two shapes:

- **Upstream HTTPS (default forward shape)** — `--upstream
  https://api.target.com`. Clients send plain HTTP to gbounce's
  listener; gbounce rewrites onto the upstream's scheme/host/port. URL
  path + method + status are visible to the audit log; bodies stream
  through unmodified. The listener can itself be HTTPS in a later
  slice (G-Slice 1 ships plain-HTTP listener).
- **CONNECT tunnel** — `--allow-connect`. gbounce accepts the HTTP
  `CONNECT` verb that browsers / SDKs use to tunnel HTTPS through a
  forward proxy. gbounce splices the two sockets blindly: **no MITM,
  no body inspection.** The audit log records the CONNECT
  destination (`host:port`), method, status, and tunnel-open time.

CONNECT is **off by default** because most operators forwarding to a
single upstream service don't want a wide-open tunnel.

## Trade-offs (per the gbounce-generic-proxy design memo)

- **Granularity** is URL path + HTTP method. gbounce does not parse
  request bodies, query parameters semantically, or model resources —
  G-Slice 1 mappings to OCSF `activity_id` use the safe / idempotent
  HTTP method classification (GET→Read, POST→Create, PUT/PATCH→Update,
  DELETE→Delete). HTTP semantics are inherently loose; downstream
  tooling can re-classify from the raw `method` + `path` fields.
- **TLS passthrough by default.** Optional MITM mode (`--mode mitm`)
  ships v1.0 with `gbounce ca install` + a local CA you add to your
  OS trust store. MITM gives URL paths, methods, and body-redacted
  audit visibility at the cost of breaking cert-pinning SDKs. See
  [docs/MITM-MODE.md](docs/MITM-MODE.md) for the honest trade-offs.
- **No request body inspection by default.** Bodies stream through;
  only metadata is recorded. In MITM mode bodies are run through the
  credential-shape redactor before any audit field is built.

## Install

Pick the lowest-friction path for your machine. The Homebrew / prebuilt
binary / Scoop / APT / RPM paths need **no Go toolchain** — install from
source (the bottom of this section) only if you want to build it
yourself.

### Homebrew (macOS / Linux)

```sh
brew install trsreagan3/tap/gbounce
gbounce --version
```

(`trsreagan3/tap` is the [trsreagan3/homebrew-tap](https://github.com/trsreagan3/homebrew-tap)
tap. `brew tap trsreagan3/tap` then `brew install gbounce` works too.)

### Prebuilt binary (no toolchain, any OS)

Download the archive for your OS/arch from the
[Releases page](https://github.com/trsreagan3/gbounce/releases) —
`gbounce_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) — unpack it,
and put the `gbounce` binary on your `PATH`:

```sh
# macOS arm64 example — substitute your version + os + arch.
curl -L -o gbounce.tar.gz \
  https://github.com/trsreagan3/gbounce/releases/latest/download/gbounce_<version>_darwin_arm64.tar.gz
tar -xzf gbounce.tar.gz gbounce
sudo mv gbounce /usr/local/bin/
gbounce --version
```

Verify the download against `checksums.txt` on the same release.

### Scoop (Windows)

```powershell
scoop bucket add trsreagan3 https://github.com/trsreagan3/scoop-bucket
scoop install trsreagan3/gbounce
gbounce --version
```

### APT / RPM (Debian / Ubuntu / Fedora / RHEL)

Each release attaches a `.deb` + `.rpm` to the
[Releases page](https://github.com/trsreagan3/gbounce/releases). gbounce
is **not** (yet) published to a hosted APT/RPM registry — install the
attached package directly:

```sh
# Debian / Ubuntu (.deb)
curl -L -o gbounce.deb \
  https://github.com/trsreagan3/gbounce/releases/latest/download/gbounce_<version>_linux_amd64.deb
sudo dpkg -i gbounce.deb

# Fedora / RHEL (.rpm)
curl -L -o gbounce.rpm \
  https://github.com/trsreagan3/gbounce/releases/latest/download/gbounce_<version>_linux_amd64.rpm
sudo rpm -i gbounce.rpm

gbounce --version
```

### Docker

```sh
docker pull ghcr.io/trsreagan3/gbounce:latest
docker run --rm -p 8080:8080 -p 8769:8769 \
  ghcr.io/trsreagan3/gbounce:latest \
  run --upstream https://api.target.com \
      --host 0.0.0.0 --mgmt-host 0.0.0.0 \
      --i-know-this-binds-externally
```

(The `--i-know-this-binds-externally` flag is required when binding
off loopback: gbounce forwards inbound bearer tokens long enough to
relay them, so off-loopback binds are an opt-in choice.)

#### Bind-mounting volumes (UID 65532)

The distroless `:nonroot` base runs as **UID 65532** (non-root for
security; no shell, no package manager). When you bind-mount a host
directory into the container so the SQLite audit DB persists across
restarts, that directory must be writable by UID 65532 — otherwise
gbounce's first attempt to open the store fails with a cryptic error
like:

```
open store: unable to open database file
```

Two ways to fix this:

```sh
# Option A — chown the host directory once (preferred for daemons).
mkdir -p ~/.gbounce
sudo chown -R 65532:65532 ~/.gbounce
docker run --rm \
  -v ~/.gbounce:/home/nonroot/.gbounce \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:8769:8769 \
  ghcr.io/trsreagan3/gbounce:latest \
  run --upstream https://api.target.com

# Option B — run as your host UID (preferred for short-lived dev runs
# where you don't want to leave a host directory owned by 65532).
mkdir -p ~/.gbounce
docker run --rm \
  --user $(id -u):$(id -g) \
  -v ~/.gbounce:/home/nonroot/.gbounce \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:8769:8769 \
  ghcr.io/trsreagan3/gbounce:latest \
  run --upstream https://api.target.com
```

**macOS / colima caveat**: colima only bind-mounts `/Users/*` paths
reliably. Mounts under `/tmp`, `/var`, or `/private` silently diverge
between the host and the colima VM — files written by the container
may not appear on the host, and vice versa. Always mount paths under
`/Users/<you>/` on Mac.

#### docker-compose example

```yaml
# compose.yaml — gbounce with host-owned audit dir.
services:
  gbounce:
    image: ghcr.io/trsreagan3/gbounce:latest
    user: "65532:65532"             # match the distroless :nonroot UID
    command:
      - run
      - --upstream
      - https://api.target.com
      - --host
      - 0.0.0.0
      - --mgmt-host
      - 0.0.0.0
      - --i-know-this-binds-externally
    ports:
      - "127.0.0.1:8080:8080"       # loopback-only on the host
      - "127.0.0.1:8769:8769"
    volumes:
      - ./gbounce-data:/home/nonroot/.gbounce
    # Before `docker compose up`, run once:
    #   mkdir -p ./gbounce-data && sudo chown 65532:65532 ./gbounce-data
```

#### Common errors

| Symptom | Cause | Fix |
| --- | --- | --- |
| `open store: unable to open database file` | Bind-mounted dir not writable by UID 65532 | See **Bind-mounting volumes** above |
| `permission denied` on `/home/nonroot/.gbounce/...` | Same UID-65532 ownership issue | `chown -R 65532:65532 <hostdir>` or `--user $(id -u):$(id -g)` |
| Files written in container don't appear on host (macOS) | Mount path under `/tmp` or `/var` on colima | Move mount under `/Users/<you>/` |
| `bind: address already in use` on `:8080` or `:8769` | Another process holding the port | `lsof -i :8080` then stop the conflicting process or remap `-p 18080:8080` |

### From source (`go install`, needs Go ≥1.26)

This is the highest-friction path — it requires a Go toolchain. Prefer
Homebrew / a prebuilt binary / Scoop / APT / RPM above unless you're
building from a checkout or want to pin a commit.

**Toolchain requirement:** `go.mod` specifies `go 1.26.0`. With a stock
Go 1.24 or earlier toolchain the download will fail. By default Go
resolves this automatically (`GOTOOLCHAIN=auto` downloads Go 1.26.x on
first use), but **air-gapped or corporate-managed machines that pin or
restrict the Go toolchain** must have Go 1.26+ pre-installed — set
`GOTOOLCHAIN=local` to enforce the locally-installed version is
sufficient, or install Go 1.26+ from <https://go.dev/dl/>.

```sh
go install github.com/trsreagan3/gbounce/cmd/gbounce@latest

# Verify the binary is on your PATH:
gbounce --version

# If you get "command not found": $(go env GOPATH)/bin is not on PATH.
# Stock Ubuntu (and most Linux distros) do NOT put ~/go/bin on PATH by
# default. Fix once per shell:
export PATH="$PATH:$(go env GOPATH)/bin"

# Persist across sessions (pick the right rc for your shell):
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc   # bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc    # zsh
```

Closes #549 from UAT L1 2026-05-24 — the unmodified `go install` succeeds
silently with the binary at `~/go/bin/gbounce` while the operator's shell
reports "command not found", which reads as "install broken" on a fresh
machine.

**Version stamp note:** `go install` fetches a pre-compiled module-proxy
binary, which carries no VCS metadata — `gbounce --version` will show
`commit none, built unknown`. Only a source-checkout build (or an
explicit `-ldflags` pass) carries a real stamp. For a stamped binary,
use Homebrew / a prebuilt release binary, or build from a git checkout
with `-ldflags`:

```sh
go install \
  -ldflags "-X github.com/trsreagan3/gbounce/internal/cli.version=v1.0.0 \
            -X github.com/trsreagan3/gbounce/internal/cli.commit=$(git rev-parse --short HEAD) \
            -X github.com/trsreagan3/gbounce/internal/cli.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  github.com/trsreagan3/gbounce/cmd/gbounce@latest
```

The repo's `Makefile` wraps that recipe — `make install` from a source
checkout does the same thing. The `Dockerfile` + `.github/workflows/docker-publish.yml`
pipeline applies identical ldflags so every supported install path
reports the same version shape.

### After upgrade: `gbounce profile doctor` (cross-product parity)

For cross-product CLI parity with ibounce / kbouncer / dbounce,
gbounce ships `gbounce profile doctor`. v1.0 reports "current"
(gbounce doesn't manage a profiles.yaml — rules are explicit-file
via `--profile-rules-file`); G-Slice 2 will populate the catalog
when gbounce gains a YAML profiles surface. Run it after any upgrade
to confirm the no-op posture:

```sh
gbounce profile doctor          # v1.0: reports current + Notes line
```

See [docs/PROFILE-UPGRADE.md](../iam-roles/docs/PROFILE-UPGRADE.md)
for the full cross-product runbook (task #321 / KNOWN-CAVEATS §A19).

## First run

`gbounce run` refuses to start unless you pick one of two modes; the
error message names the missing flag, but the choice between the two
shapes is yours and depends on how the client talks to gbounce.

### Mode A — rewrite onto a single upstream (`--upstream`)

Use when the client speaks plain HTTP to gbounce and you want gbounce
to forward every request to one upstream service. URL path + method +
status are visible to the audit log.

```sh
gbounce run --upstream https://api.target.com --port 8080
# point the client at http://127.0.0.1:8080
# (gbounce rewrites scheme/host/port onto https://api.target.com)
```

### Mode B — CONNECT-method forward proxy (`--allow-connect`)

Use when the client speaks the standard `HTTP_PROXY` / `HTTPS_PROXY`
protocol — browsers, the AWS SDK with `HTTP_PROXY` set, `curl -x`,
etc. gbounce accepts the HTTP `CONNECT` verb and splices the TCP
sockets blindly (no MITM; only the destination `host:port` + tunnel
metadata appear in the audit log).

```sh
gbounce run --allow-connect --port 8080
# export HTTPS_PROXY=http://127.0.0.1:8080
# (the client picks the upstream per request via the CONNECT verb)
```

### Picking between them

- One known upstream, plain-HTTP client → `--upstream`.
- Many upstreams, or a client that already knows how to use an
  `HTTPS_PROXY` env var → `--allow-connect`.
- Both can be combined; CONNECT requests use the tunnel, plain
  requests are rewritten onto `--upstream`.

(G-Slice 1 ships discovery mode only. Both shapes observe + audit; no
filtering / enforcement yet — that ships in G-Slice 2.)

### Mode C — MITM (`--mode mitm`) — #315 / §A13 (OPT-IN)

When compliance or incident-response needs URL-level visibility into
HTTPS traffic, gbounce can terminate the TLS tunnel using a locally-
generated CA + re-encrypt to the real upstream.

```sh
# One-time: generate the CA + add it to your OS trust store.
gbounce ca install

# Start the proxy in MITM mode.
gbounce run --mode mitm --port 8080 \
            --audit-log-path ~/.gbounce/audit.jsonl

# Point the agent at the proxy.
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=localhost,127.0.0.1
```

What you get in the audit log under `unmapped.iam_jit.ext`:

- `url_path` — the actual path the agent hit (e.g. `/v1/chat/completions`).
- `request_method` — the HTTP verb.
- `request_body_redacted` — true when the body was redacted
  (default-on). Body bytes are NOT stored unless you pass
  `--audit-log-include-bodies`; even then, credentials are
  redacted before storage.
- `url_query` — the query string, with credential-shape params
  (`secret`, `api_key`, `token`, …) replaced by the sentinel
  `***REDACTED-CREDENTIAL***`.
- `response_status` — the upstream's HTTP status.

Honest trade-offs (per `[[ibounce-honest-positioning]]`):

- Cert-pinning SDKs (most modern AWS SDKs, banking SDKs, some
  mobile SDKs) WILL break. Flip those clients back to
  `--mode discovery --allow-connect`.
- The CA install step adds friction. Locked-down corporate
  laptops may forbid adding a custom CA at all.
- Latency overhead: ~5-15% per call (cold cache); <1 ms on hot
  cache (per-host leaf certs are cached LRU-bounded at 1024).

Full reference: [docs/MITM-MODE.md](docs/MITM-MODE.md).

## Add to your agent

`gbounce` plugs into any AI agent two ways. Most agents want **both**: the
MCP server lets the agent introspect its own decisions + manage denies;
the transparent proxy actually audits (and, in G-Slice 2, gates) the
agent's outbound HTTP.

### MCP mode — let the agent query + scope itself

`gbounce mcp serve` is an MCP-over-stdio server exposing the `gbounce_*`
tool family. One-shot installers wire it into the common clients
(idempotent; they preserve any other `mcpServers` entries):

```sh
gbounce mcp install-claude-code   # Claude Code / Claude Desktop
gbounce mcp install-cursor        # Cursor
gbounce mcp install-codex         # Codex (prints a TOML snippet to paste)
gbounce mcp install-devin         # Devin (cloud agent — prints a wiring recipe)
```

`install-devin` differs from the rest: Devin runs in Cognition's cloud
sandbox, not on your machine, so there's no local config to write and a
`127.0.0.1` proxy is unreachable from the sandbox. The recipe wires Devin
to gbounce at its **host** address instead of loopback — pass
`--devin-host HOST:PORT` to bake in a concrete reachable address.

For any other MCP client, `gbounce mcp show-config` prints the canonical
JSON (or `--shape yaml`) snippet, and `gbounce mcp list-tools` shows the
exact tools the agent will see.

### Transparent-proxy mode — audit (and gate) the agent's HTTP

Point the agent's standard proxy env var at gbounce's CONNECT-mode
listener. Every outbound HTTP/HTTPS call is forwarded verbatim and
audited (no MITM — only `host:port` + metadata for HTTPS tunnels):

```sh
gbounce run --allow-connect --port 8080
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=localhost,127.0.0.1
```

For URL-level visibility into HTTPS (paths + redacted bodies) use
`--mode mitm` (see [TLS handling](#tls-handling-g-slice-1) above).

### Claude-in-a-container

Running Claude Code inside Docker? See the cross-product
[Claude-in-container recipe](https://github.com/trsreagan3/iam-roles/blob/main/docs/DOCKER-CLAUDE-INTEGRATION.md)
(Pattern A: gbounce in-container; Pattern B: gbounce as a sidecar) for
how to wire the proxy env vars across the container boundary.

## Audit log

Every request emits one OCSF v1.1.0 class 6003 event. To tee events
to a JSONL file for shipping to a SIEM:

```sh
gbounce run --upstream https://api.target.com \
            --audit-log-path /var/log/gbounce/audit.jsonl
```

Point Fluent Bit / Vector / logrotate at the file. gbounce does not
rotate the file itself.

For the full "where do my audit logs go in production" decision tree
(JSONL / webhook + presets / Security Lake / Lambda → S3 / GCP / Azure
/ CI runners / Enterprise fan-out) see the cross-product runbook in
the iam-roles repo:
[docs/PRODUCTION-LOG-STORAGE.md](https://github.com/trsreagan3/iam-roles/blob/main/docs/PRODUCTION-LOG-STORAGE.md).
gbounce's webhook + Security Lake export channels ship in G-Slice 6
(post-launch); in G-Slice 1 use JSONL + Vector / Fluent Bit as
described above.

### Deny hosts (block a destination through gbounce without MITM)

When you want to refuse a CONNECT to a specific host (e.g. block an
agent from reaching `api.openai.com` or the EC2 IMDS endpoint),
gbounce honors a `deny_hosts` list at the CONNECT layer — no MITM,
no TLS interception, just a 403 + an audit event before the dial.

`--deny-host` is repeatable, and `--deny-hosts-file PATH` accepts
either newline-delimited entries or the YAML-list shape the future
profile-mode YAML will use. Both flags union — entries from CLI flags
+ entries from the file all take effect.

```sh
gbounce run --allow-connect --port 8080 \
            --deny-host '*.openai.com' \
            --deny-host '169.254.169.254' \
            --deny-hosts-file ~/.gbounce/deny-hosts.yaml
```

A sample `deny-hosts.yaml` (forward-compatible with the G-Slice 2
profile-YAML surface):

```yaml
# ~/.gbounce/deny-hosts.yaml
deny_hosts:
  - evil.example.com          # exact match (all ports)
  - "*.openai.com"             # wildcard: api.openai.com, foo.bar.openai.com,
                                # AND the bare openai.com
  - "*.anthropic.com"
  - 169.254.169.254            # IPv4 literal: EC2 / GCE IMDS endpoint
  - "*.metadata.google.internal"
```

**Match semantics:**

- **Exact** (`evil.example.com`) — case-insensitive; blocks all ports.
- **Leading wildcard** (`*.openai.com`) — matches every subdomain of
  `openai.com` AND the bare `openai.com` itself. (Operators usually
  mean "this org and all subs" when they write the entry; if you need
  to block just the subdomains, use the explicit entries.)
- **Bare `*`** — rejected at startup. Use a future `--default-policy
  deny` for whole-Internet denials.
- **Multi-level wildcards** (`*.foo.*.bar.com`, `foo.*`) — rejected at
  startup with a clear error. The only supported wildcard shape is a
  single leading `*.<domain>`.

**On match:** gbounce returns `403 Forbidden` to the client + emits an
OCSF event with `verdict=DENY`, `status_id=4 (Denied)`,
`activity_id=6 (Connect)`, and `ext.deny_reason="matched deny_hosts:
<rule>"` (naming the exact operator-written entry that fired). The
upstream TCP connection is NEVER opened.

**Visibility:** `/healthz` surfaces `deny_hosts_count` (how many rules
are loaded) + `total_deny_host_matches` (how many CONNECTs the rule
list has denied since startup) so operators see deny-rule activity
without grepping the audit log.

**Order of evaluation:** deny WINS over any future `allow_hosts` list.
A host in both deny + allow is denied (safer-by-default; an operator
who wrote a deny rule meant it). G-Slice 2 ships the allow side.

### Dynamic deny rules (#324d — cross-product hot-reload)

Static `--deny-host` flags are great for stable operator-set rules.
For **incident-time deny ergonomics** ("Claude, make sure nothing
touches prod for 3h"), gbounce also consumes
`~/.iam-jit/dynamic-denies.yaml` — a cross-product file shared with
ibounce, kbouncer, and dbounce. Rules in the file are hot-reloaded on
disk change (fsevents on macOS, inotify on Linux); rules whose
`applied_to` list does NOT include `gbounce` are silently skipped, so
ONE file fans out across the Bounce suite without operators picking
which proxy to call.

```sh
# Optional override; default is ~/.iam-jit/dynamic-denies.yaml.
gbounce run --allow-connect --port 8080 \
            --dynamic-denies-path ~/.iam-jit/dynamic-denies.yaml
```

Startup banner reports the loaded count:

```
dynamic-denies: 2 rules loaded from ~/.iam-jit/dynamic-denies.yaml (2 applied to gbounce; watching for changes)
```

On match: the verdict OCSF event carries
`unmapped.iam_jit.ext.deny_source="dynamic"` +
`unmapped.iam_jit.ext.dynamic_deny_rule_id="dd_..."` so a SIEM
distinguishes static from dynamic + names the originating rule.

`POST /admin/dynamic-denies/reload` on the mgmt port triggers an
immediate reload from disk — useful for the cross-bouncer fan-out
CLI (#324e), which writes the YAML then POSTs each Bounce product's
mgmt port to confirm rules are live.

The canonical cross-product design lives at
[`iam-roles/docs/DYNAMIC-DENY-RULES.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/DYNAMIC-DENY-RULES.md);
the on-disk schema at
[`iam-roles/docs/schemas/dynamic-denies-v1.json`](https://github.com/trsreagan3/iam-jit/blob/main/docs/schemas/dynamic-denies-v1.json).
The headline operator-facing CLI (`iam-jit deny add | list | remove |
show`) lands in #324e; this slice (#324d) ships the gbounce
consumer + manual / agent-driven YAML editing works today.

Honest caveats:

- **The watcher is bypassable.** Per `[[ibounce-honest-positioning]]`:
  an operator who controls the agent's network can route around
  gbounce. The dynamic-deny rules add ergonomics + audit-trail
  visibility; the defense-in-depth half (recommender embedding the
  same denies as explicit `Deny` statements on JIT-issued roles)
  ships in #324f.
- **Fail-CLOSED on parse error.** A YAML typo retains the previous
  in-memory snapshot — gbounce does NOT silently fall back to "0
  rules applied" when an operator's file fails to validate. The
  failure surfaces in `/healthz` (`total_dynamic_deny_parse_errors`)
  + as a `dynamic_deny.parse_error` admin-action OCSF event.

### Security-team observation preset

```sh
gbounce run --upstream https://api.target.com --preset security-observe
```

is the one-flag shortcut for `--mode discovery --audit-log-path
~/.gbounce/audit/gbounce.jsonl`. Same preset name + same override
semantics ship across every Bounce product per
`[[cross-product-agent-parity]]`. See
[docs/DEPLOYMENT-PRESETS.md](docs/DEPLOYMENT-PRESETS.md) for the
framework + the cross-product preset roadmap.

### Reading + filtering + exporting

`gbounce audit tail` reads the local SQLite audit DB with live-tail,
filter expressions, count-summary, and CSV / JSONL / OCSF Detection
Finding bundle export:

```sh
# Live tail with a filter (Ctrl-C to exit).
gbounce audit tail --follow \
  --filter upstream_host=api.example.com \
  --filter http_status>=400

# Count-summary across event_type / upstream_host / method / status.
gbounce audit tail --summary --limit 1000

# Export a CSV for sharing (query-string tokens auto-redacted).
gbounce audit tail \
  --filter http_status>=500 \
  --export csv --out failures.csv
```

Full reference + the filter-field allowlist lives in
[`docs/AUDIT.md`](docs/AUDIT.md). Cross-product parity:
`ibounce audit tail`, `kbounce audit tail`, and `dbounce audit tail`
ship the same flag set + grammar.

### Event shape (abbreviated)

```json
{
  "metadata": {"version": "1.1.0", "product": {"name": "gbounce", "vendor_name": "iam-jit", "version": "v1.0.0"}},
  "class_uid": 6003,
  "class_name": "API Activity",
  "category_uid": 6,
  "category_name": "Application Activity",
  "activity_id": 2,
  "activity_name": "get",
  "type_uid": 600302,
  "type_name": "API Activity: Read",
  "severity_id": 1,
  "severity": "Informational",
  "status_id": 1,
  "status": "Success",
  "api": {
    "operation": "GET /v1/dashboards",
    "service": {"name": "api.target.com"},
    "request": {"uid": "42"}
  },
  "resources": [
    {"name": "/v1/dashboards", "uid": "https://api.target.com/v1/dashboards", "type": "http resource"}
  ],
  "src_endpoint": {"ip": "127.0.0.1", "port": 56000},
  "dst_endpoint": {"hostname": "api.target.com", "port": 443},
  "unmapped": {
    "iam_jit": {
      "mode": "discovery",
      "verdict": "ALLOW",
      "decision_id": 42,
      "enforced": false,
      "ext": {"http_status": 200, "response_size": 1024, "latency_ms": 37}
    }
  }
}
```

The same OCSF shape is emitted by every product in the Bounce suite,
so a SIEM ingest auto-categorizes the events without per-product glue.

## Suite dashboard

When you run more than one Bounce product on the same host, `gbounce`
serves a cross-product link page at `http://127.0.0.1:8769/suite`. It
shows a status pill per bouncer (healthy / degraded / critical /
unreachable) and an "open ui" anchor to each bouncer's own mgmt-port
UI.

The page is intentionally a **link page**, not a single-pane-of-glass
aggregator. Per [`[[unified-ui-link-page]]`](https://github.com/trsreagan3/iam-roles/blob/main/docs/DESIGN-DECISIONS.md):

- Each bouncer's own UI keeps the full operator experience (filters,
  live audit tail, modal config).
- Status pills are the only synthesis — generated client-side by
  parallel fetch of each bouncer's `/healthz` every 5 s.
- Bouncers stay autonomous; the suite page works even when half the
  deployment is unreachable (those cards just show gray pills).
- No backend aggregator service. No CORS plumbing. Vanilla JS, no
  framework, embedded as a Go string constant — auditable + bundle-
  free.

### Default port wiring

| Product   | Default mgmt port |
|-----------|-------------------|
| ibounce   | 8767              |
| kbouncer  | 8766              |
| dbounce   | 8768              |
| gbounce   | 8769              |

### Operator port overrides

If you ran a bouncer on a non-default port (e.g. behind a port
collision), click "configure ports" on the page and enter the
overrides. They land in `localStorage` under the key
`bounce.suite.ports` — no server-side state.

### Footer: cross-bouncer investigation

The footer carries the one-shot CLI for tracing an agent's session
across every bouncer it touched:

```sh
iam-jit audit query --filter agent.session_id=<UUID>
```

One-click copy ships with the page.

## API credits required?

**No** when an AI agent is in the loop. `gbounce` is pure
deterministic HTTP egress rules + audit + MCP server. Your agent
(Claude Code / Cursor / Codex / Devin / any MCP-compatible client)
uses its own LLM credentials (Max / Plus / Pro / API key / Ollama /
etc.). The bouncer never makes an LLM call in this mode — `gbounce`
ships with zero LLM credentials required for local-dev.

**Yes** for standalone deployments (CI/CD / cron / daemon mode with
no agent in the loop). Opt in via `--llm-backend
anthropic|openai|bedrock|ollama` + supply credentials. This is the
minority case.

See [[bouncer-zero-llm-when-agent-in-loop]] in the iam-roles memory
for the full architecture.

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 trsreagan3.
