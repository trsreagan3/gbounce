# Deployment Presets

A **deployment preset** is a named bundle of `gbounce run`-command
flag values that activates a common deployment shape with one flag
instead of several. Presets are SHORTCUTS — every preset value can
be set explicitly; the preset just makes the canonical combinations
discoverable + one-flag for the operator.

Per `[[cross-product-agent-parity]]` the same preset NAMES + same
HARD-vs-SOFT override semantics ship across **ibounce / kbounce /
dbounce / gbounce**. gbounce in G-Slice 1 has fewer surfaces than
the other Bounce products — the banner annotates cross-product
canonical settings (`--default-policy`, `--alert-rules`,
`--heartbeat-interval`) as "not applicable to this product
(G-Slice 1 has no surface; queued for later slice)" so an operator
running the same preset across all four products sees what's
intentionally missing here.

## The mechanism

A preset is a `(name, description, values)` record. Each value entry
carries an override policy:

- **HARD** — operator passing the flag with a DIFFERENT value
  errors. The preset's whole point depends on the setting.
- **SOFT** — operator's value wins; the preset value is the default
  the operator gets when they leave the flag unset.

The preset resolution runs BEFORE mode validation so the resolved
mode flows through everything that follows.

The startup banner names the active preset + lists every derived
setting (with hard/soft annotation) so the operator sees exactly
what changed. Format is identical across all four Bounce products.

## Available presets (v1.0)

### `security-observe`

```sh
gbounce run --upstream https://api.target.com --preset security-observe
```

is equivalent to:

```sh
gbounce run \
  --upstream https://api.target.com \
  --mode discovery \
  --audit-log-path ~/.gbounce/audit/gbounce.jsonl
```

| Setting | Why |
|---|---|
| `--mode discovery` | gbounce G-Slice 1's only mode — observe + audit; no enforcement. The gbounce equivalent of the other products' "transparent + audit-only" shape. |
| `--audit-log-path <default>` | Per-product JSONL stream the security team can ship to a SIEM. |

**Override semantics**:

- HARD: `--mode` (the entire point of the preset is observation;
  passing `--mode profile` or `--mode tap` with `--preset
  security-observe` is a deployment-intent mismatch).
- SOFT: `--audit-log-path` (operators have different SIEM
  destinations).

**Banner**: gbounce's banner annotates the cross-product canonical
settings that have no G-Slice 1 surface as
`not applicable to this product (G-Slice 1 has no surface; queued
for later slice)`. The annotated settings:

- `--default-policy` (gbounce G-Slice 1 only ships discovery; no
  enforce mode means no default-policy decision)
- `--alert-rules` (no alert-rules engine in G-Slice 1; queued)
- `--heartbeat-interval` (no heartbeat in G-Slice 1; queued)

When G-Slice 2 + later lands these surfaces, the preset grows + the
annotations go away. The cross-product preset NAME is stable across
slices.

**What the preset does NOT set** (operator wires explicitly):

- The upstream URL (`--upstream` or `--allow-connect`) is always
  operator-supplied — there's no sensible default.

## Roadmap (post-v1.0)

Queued (NOT shipped in v1.0):

| Preset | Planned shape | Use case |
|---|---|---|
| `dev-loop` | (post G-Slice 2) profile mode + `--prompt-on-deny` | Solo-dev iteration with advisory denies |
| `production-strict` | (post G-Slice 2) profile + strict + no overrides + JSONL only | Locked-down production deployments |
| `compliance-audit` | (post G-Slice 3) discovery + tap recording + all-alerts | Compliance evidence-gathering |

Per `[[deliberate-feature-completion]]` we ship the framework with
one preset; the next presets ship when a concrete operator asks +
the required gbounce surfaces (profile mode, tap mode) land.

## Cross-product alignment

A single command runs the SAME preset across every Bounce product:

```sh
ibounce  run --preset security-observe
kbounce  run --preset security-observe
dbounce  run --preset security-observe
gbounce  run --upstream https://api.target.com --preset security-observe
```

per `[[cross-product-agent-parity]]`: an SRE runbook that says
"spin up the Bounce suite in observation mode" maps to one flag
name regardless of which proxy is in scope.
