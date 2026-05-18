# Hardening gbounce against prompt-injected agents

How to harden gbounce (and the rest of the Bounce suite) against a
prompt-injected agent that tries to disable the proxy before issuing
HTTP calls. This doc is for SecOps + platform engineers deploying
gbounce on engineer laptops, agent containers, or CI runners.

---

## The honest framing

gbounce is a **user-process on a user-machine.** A prompt-injected
agent that has shell access on the same machine — through a tool
primitive like `bash`/`exec`/`python -c`, or simply by writing a
shim script the user then runs — can `pkill gbounce`,
`unset HTTPS_PROXY` / `unset HTTP_PROXY`, point a fresh
`requests.Session(proxies={})` straight at the upstream, or just
open a raw socket to the upstream's IP. gbounce by itself cannot
stop any of those moves.

This is called out plainly in the gbounce README:

> gbounce is a deterrent and audit trail, not a security boundary.

What gbounce CAN do is make every disable-attempt **detectable** and
make the bypass **costly** when composed with the rest of an
operator's defense-in-depth stack:

- Heartbeat events emitted to the audit pipeline (queued for
  G-Slice 2; this doc anticipates the shape so the customer can plan
  Layer 6 ahead of time).
- Tamper-detection on the audit chain (hash-chained rows; a gap or
  rewrite shows up at `gbounce audit verify`).
- Admin-action audit events so attempts to mutate the rule set,
  install a malicious profile, or change modes are themselves
  audited (G-Slice 2 onward).

The rest of this doc walks through the **six-layer defense** that, in
combination, actually prevents (or at minimum reliably detects) the
disable-bouncer attack. gbounce is **one layer.** The other five are
the customer's OS, network, sandbox, and MDM tooling — not things
gbounce ships.

---

## The 6-layer defense

### Layer 1 — Don't give the agent shell access

**Strongest layer.** If the agent has no shell primitive, it can't
run `pkill`, can't `unset` an env var in the parent process, and
can't build a fresh HTTP client. Everything the agent does has to
go through its declared tools.

**How to ship this:**

- **MCP-only agent configuration.** Tools the agent can call are
  exhaustively listed in the MCP server manifest. No
  `bash` / `exec` / `shell` / `run_command` tool exposed. Specifically
  for HTTP-using agents: expose a constrained `http_get` /
  `http_post` tool whose implementation uses the
  `HTTPS_PROXY=http://127.0.0.1:8080` env var, rather than exposing
  `subprocess.run(["curl", ...])`.
- **Claude Code default config.** As of the current release, Claude
  Code does not give the agent a shell primitive by default; the user
  must opt in explicitly with `--dangerously-skip-permissions` or by
  approving each Bash invocation. Keep that default.
- **Cursor agent mode** without the "Run terminal commands"
  permission ticked.

**Tools that do NOT satisfy this layer out of the box:**

- Most LangChain ReAct agents bootstrapped with the standard
  `shell_tool` / `terminal_tool` — these expose `subprocess.run` to
  the LLM by design.
- Several open-source agent loops that ship with a shell tool as
  their primary capability (the "shell is the universal tool" school
  of thought). Treat any agent loop whose flagship example wires a
  shell tool as **not Layer-1 safe** without modification.

**What this layer does NOT cover:** an agent that asks the human to
paste a curl command into a terminal still wins — the
prompt-injection moves up a level into social engineering. Layers
2–6 cover the residual risk.

### Layer 2 — Sandbox the agent

**Very strong.** Run the agent inside a Docker container, microVM,
Firecracker VM, or browser sandbox where the laptop's shell is not
reachable.

Key properties:

- **Proxy env vars set immutably inside the sandbox.** The sandbox
  starts with `HTTPS_PROXY=http://host.docker.internal:8080` and
  `HTTP_PROXY=http://host.docker.internal:8080` baked into the
  container's `ENV`. Even if the agent runs `unset HTTPS_PROXY`
  inside the sandbox, that only unsets it in the sandbox's shell;
  the requests / urllib3 / Go-net/http process inherits the original
  env from container `ENV`.
- **Sandbox network namespace only routes egress through gbounce's
  outbound IP.** The sandbox is on its own Docker network whose
  iptables rules block direct 80/443 egress and only allow the
  gbounce port (8080 by default).
- **Agent can `pkill` inside the sandbox.** gbounce is on the HOST,
  outside the sandbox; the agent's `pkill gbounce` finds no matching
  PID inside its container.

**Concrete: Docker run with a constrained network + baked proxy
env.**

```sh
# On the host, create a dedicated Docker network whose outbound
# rules block direct HTTP/HTTPS.
docker network create \
  --driver bridge \
  --subnet 172.33.0.0/24 \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  bouncer-net

# iptables rules on the host: this network is blocked from talking
# directly to common HTTP/HTTPS ports; gbounce is the only escape.
sudo iptables -I OUTPUT -s 172.33.0.0/24 -p tcp \
  -m multiport --dports 80,443 \
  -j REJECT
sudo iptables -t nat -A PREROUTING -s 172.33.0.0/24 \
  -p tcp --dport 8080 -j DNAT --to-destination 127.0.0.1:8080

# Run the agent inside this network with the proxy env baked in.
docker run --rm -it \
  --network bouncer-net \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -e HTTP_PROXY=http://host.docker.internal:8080 \
  -e NO_PROXY=localhost,127.0.0.1 \
  my-agent:latest
```

Most HTTP client libraries (Python `requests`, Go `net/http`, Node
`undici`, Rust `reqwest`) honor the `HTTPS_PROXY` env var by default.
Libraries that DON'T (e.g. a custom raw-socket client) bypass the
proxy unless Layer 3 (network egress allowlist) catches them.

### Layer 3 — Network egress allowlist

**Strong.** Block the dev-machine's direct egress to ports 80 / 443
except via gbounce's outbound IP. This catches the case where the
agent (or a human under social engineering) tries to open a fresh
HTTP client that ignores `HTTPS_PROXY`.

**macOS — pf (packet filter):**

`/etc/pf.anchors/com.bouncer`:

```
# Allow loopback (gbounce listens on 127.0.0.1:8080)
pass quick on lo0

# Allow gbounce's own process (uid 501 is the operator account) to
# reach upstream HTTP/HTTPS
pass out proto tcp from any to any port { 80, 443 } user 501 keep state

# Block every OTHER user process from reaching external HTTP/HTTPS
block out quick proto tcp from any to any port { 80, 443 }
```

Load with:

```sh
sudo pfctl -a com.bouncer -f /etc/pf.anchors/com.bouncer
sudo pfctl -e
```

**Linux — nftables:**

```
table inet bouncer {
  chain output {
    type filter hook output priority 0; policy accept;

    # Allow loopback
    oifname "lo" accept

    # Allow gbounce's process (matched by cgroup or uid) to reach
    # external HTTP/HTTPS
    meta skuid 1000 tcp dport { 80, 443 } accept

    # Block everyone else from external HTTP/HTTPS
    tcp dport { 80, 443 } reject with tcp reset
  }
}
```

**Corporate / VPN exit:** push the same allowlist as a VPN egress
ACL. Every laptop's HTTP/HTTPS traffic must exit through a corporate
proxy whose upstream is gbounce.

**Cloud dev workspaces (Codespaces, Gitpod, etc.):** VPC route tables
+ a NAT instance running gbounce. Same shape.

### Layer 4 — MDM-enforced signed binary + managed env vars

**Strong for managed fleets.** Use Jamf / Kandji / Intune /
equivalent to lock down:

- **Which processes can run.** Only the signed `gbounce` binary, with
  a known SHA-256, can listen on the loopback port. Modified binaries
  refuse to launch.
- **Managed env vars that the user (or agent) cannot modify.**
  `HTTPS_PROXY=http://127.0.0.1:8080` and `HTTP_PROXY=http://127.0.0.1:8080`
  are shipped as managed preferences and re-applied on every login.
  `unset HTTPS_PROXY` in a shell unsets it for that shell session,
  but the next-launched process inherits the managed value again.
- **Prevent `pkill` of managed services.** macOS Endpoint Security
  framework profiles can block signal-delivery to processes in a
  managed list.

**macOS Configuration Profile** (illustrative `.mobileconfig` payload
keys — full XML omitted for brevity; consult Apple's `profiles`
reference):

```
PayloadType: com.apple.systempolicy.kernelextensionpolicy
  AllowedTeamIdentifiers: [ <gbounce-signing-team-id> ]

PayloadType: com.apple.ManagedClient.preferences
  ManagedPreferences:
    HTTPS_PROXY: "http://127.0.0.1:8080"
    HTTP_PROXY:  "http://127.0.0.1:8080"
    NO_PROXY:    "localhost,127.0.0.1"

PayloadType: com.apple.TCC.configuration-profile-policy
  Services.SystemPolicyAllFiles:
    - Identifier: <gbounce-bundle-id>
      Authorization: Allow
```

**Linux — systemd hardening:**

```
[Service]
ExecStart=/usr/local/bin/gbounce run --upstream https://api.target.com --port 8080
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

Combined with **AppArmor** (`/etc/apparmor.d/usr.local.bin.gbounce`):

```
/usr/local/bin/gbounce {
  capability net_bind_service,
  network inet stream,
  /home/*/.gbounce/state.db rwk,
  /home/*/.gbounce/state.db-journal rwk,
  /etc/bouncer/** r,
  deny /home/*/.ssh/** rwx,
  deny /home/*/.aws/credentials rwx,
  deny /home/*/.netrc rwx,
}
```

**Windows — Group Policy + WDAC (Windows Defender Application
Control):** ship a WDAC policy whose `Allowed Publishers` list
includes only the gbounce signing certificate; set the `HTTPS_PROXY`
and `HTTP_PROXY` environment variables via a Group Policy Preference
(Computer Configuration → Preferences → Environment) so they reapply
on every user-login refresh.

### Layer 5 — launchd / systemd KeepAlive watchdog

**Medium.** If the agent does manage to kill gbounce, the OS-level
process supervisor restarts it within seconds. Combined with Layer 6,
the security team sees both the kill event AND the restart event in
the audit stream — a strong signal for incident response.

**macOS launchd plist** —
`/Library/LaunchDaemons/com.bouncer.gbounce.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bouncer.gbounce</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/gbounce</string>
    <string>run</string>
    <string>--upstream</string>
    <string>https://api.target.com</string>
    <string>--port</string>
    <string>8080</string>
    <string>--mgmt-port</string>
    <string>8769</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>/var/log/gbounce.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/gbounce.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/operator</string>
  </dict>
</dict>
</plist>
```

Install:

```sh
sudo cp com.bouncer.gbounce.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bouncer.gbounce.plist
```

**Linux systemd unit** — `/etc/systemd/system/gbounce.service`:

```ini
[Unit]
Description=gbounce — generic HTTP/HTTPS forward proxy with audit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gbounce run --upstream https://api.target.com --port 8080 --mgmt-port 8769
Restart=always
RestartSec=5
User=gbounce
Group=gbounce

# Hardening (see Layer 4)
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Install:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now gbounce.service
```

Each restart emits a gbounce startup audit event (one row per process
start; see `gbounce audit tail`). Pair with Layer 6 so the SIEM sees
the kill/restart cycle.

### Layer 6 — Heartbeat + admin-action audit (what gbounce ships)

**Detection, not prevention.** This is the layer gbounce itself
provides; the other five layers are customer-owned infrastructure.

What gbounce emits today (G-Slice 1):

- **OCSF v1.1.0 class 6003 API Activity** events for every
  request/response pair. The audit log IS the product at this slice.
- `/healthz` liveness probe on the management port (`:8769` by
  default).

What's queued (G-Slice 2 onward):

- **HEARTBEAT** events every N seconds (default 30s) to the audit
  pipeline. Configurable via `GBOUNCE_HEARTBEAT_INTERVAL`.
- **Slice-2 alert rule `heartbeat_gap`** fires when the SIEM-side
  view of the audit stream sees a gap larger than 2× the configured
  interval. Routes to whichever sink the operator configures
  (webhook, OCSF/Splunk HEC).
- **Admin-action OCSF events** for rule-mutation, profile-install,
  mode-change, and pause-override attempts.

Plan Layer 6 ahead of G-Slice 2 by wiring `/healthz` polling into the
SIEM today; the heartbeat event will replace the polling check once
shipped.

**Cross-correlation signal:** the audit pipeline can correlate
gbounce events against the upstream service's own access log (the
target API's request log, CloudFront / CDN logs, etc.). Any
upstream-side log row attributed to the operator's machine /
API-key for which there is NO matching gbounce audit row in the same
window = the proxy was bypassed. That correlation is the canonical
bypass detector.

**What the operator must do:**

1. Route gbounce audit to a SIEM (Splunk, Sumo, Datadog,
   Elasticsearch, etc.).
2. Enable the `heartbeat_gap` alert rule on that SIEM (once
   G-Slice 2 ships; until then, poll `/healthz` from the SIEM).
3. Subscribe the security team to the alert channel.

---

## Worked example: combining layers 1 + 3 + 5 + 6

A common deployment for an engineer laptop running Claude Code as
the agent against a third-party HTTP API:

- **Layer 1 (partial):** Claude Code in its default config, with
  `Bash` tool approval prompts left on (don't
  `--dangerously-skip-permissions`).
- **Layer 3:** macOS pf rules blocking direct outbound 443 traffic
  except from the gbounce process.
- **Layer 5:** launchd plist with `KeepAlive: true` so any
  `pkill gbounce` triggers an automatic restart within ~5 seconds.
- **Layer 6:** gbounce OCSF API-Activity events routed to Splunk via
  the audit-export pipeline + (post-G-Slice-2) `heartbeat_gap` alert
  wired to the SecOps Slack channel.

**Combined behavior on a prompt-injection disable attempt:**

1. Injected prompt arrives via a poisoned tool response or upstream
   API response.
2. Agent attempts `pkill gbounce` — Claude Code surfaces the Bash
   approval prompt; the user (hopefully) denies.
3. If the user approves (or the deployment skipped Layer 1), gbounce
   dies → launchd restarts it within ~5s.
4. During the gap, the agent attempts a direct
   `requests.get('https://api.target.com/...', proxies={})` call —
   pf blocks the connection at the TCP layer.
5. `heartbeat_gap` alert fires in Splunk; security team is paged.
6. Audit chain shows the kill event, the restart event, and the
   blocked direct-egress attempt — full forensic picture.

The bypass attempt is **detected within seconds**, **can't reach the
upstream directly**, and **gbounce keeps coming back**. No single
layer provides this on its own; the combination does.

---

## What gbounce CAN'T do

Explicit, honest list of what is **not** in gbounce's lane:

- **We don't prevent the disable itself.** A user-process can be
  killed by the user. That's how operating systems work. gbounce
  can only make the kill visible.
- **We don't ship MDM.** Jamf, Kandji, Intune, and equivalent are
  the customer's IT-management tooling. gbounce can be packaged for
  managed deployment, but the policy enforcement is the MDM's.
- **We don't ship the sandbox.** Docker, Firecracker, gVisor,
  browser sandboxes — pick the one that fits your agent's runtime.
  gbounce runs on the host; the sandbox is the customer's container
  layer.
- **We don't ship the firewall rules.** pf, nftables, VPN ACLs, VPC
  route tables — these are network-team responsibilities. gbounce
  provides the loopback target; the routing decision is upstream.
- **We don't enforce file-system policy.** Whether the agent can
  read credential files directly (and then use the credentials
  against the upstream without going through the proxy) is an
  AppArmor / SELinux / macOS TCC concern. See Layer 4.
- **G-Slice 1 doesn't yet ship the heartbeat / admin-action events
  the ibounce / kbounce / dbounce siblings ship.** That's a
  G-Slice 2 deliverable. Until then, treat `/healthz` polling +
  per-request OCSF audit as the Layer-6 signal.

**What gbounce ships:** the per-request OCSF audit signal, the
`/healthz` liveness probe, and (G-Slice 2+) the heartbeat + alert
rule + admin-action event stream, and this doc explaining how to
compose all six layers.

---

## FAQ

**Q: What stops a prompt-injected agent from running `pkill gbounce`
as its first command?**

**A:** Nothing in gbounce itself. The full answer is "Layer 1
prevents the agent from having a shell, Layer 5 restarts gbounce if
it does get killed, Layer 6 alerts the SecOps team within seconds,
and Layer 3 blocks the direct-egress attempt during the restart
window." That combination is what stops the attack — not any single
layer.

This is the same shape as host-IDS or endpoint detection: a
prompt-injected agent can `rm -rf` a CrowdStrike agent's files too,
which is why CrowdStrike pairs detection with kernel-level
tamper-protection and a network-level egress block. gbounce uses
the same playbook, but the kernel-level tamper-protection is the
customer's MDM (Layer 4), not anything gbounce can ship as a
user-space binary.

**Q: Can gbounce be run as root to prevent the user (or agent) from
killing it?**

**A:** Running gbounce as root makes `pkill` require root, which
helps against an agent running as the unprivileged user — but it
introduces its own risks (a vulnerability in gbounce becomes a root
vulnerability) and it doesn't help against an agent that has sudo
(many dev-laptop setups give the engineer NOPASSWD sudo).

The Bounce-suite recommendation is: run gbounce as the engineer's
own user account, NOT as root. Use **Layer 5 (launchd / systemd
KeepAlive)** for the "always-restart-on-kill" property. Use
**Layer 4 (MDM-managed process protection)** for the "user can't
kill it at all" property — that one belongs to the OS, not gbounce.

If you have a hard requirement to run gbounce as a privileged
daemon, you can — `Restart=always` + `User=root` in the systemd
unit works — but the hardening team should review the resulting
threat model carefully. The default-recommended deployment is
user-process with launchd/systemd supervision.

---

## Related docs

- The cross-suite hardening doc is replicated in the `ibounce`,
  `kbounce`, and `dbounce` repos with their respective env-var and
  upstream-protocol specifics — the threat model and layer model are
  identical across the Bounce suite.
