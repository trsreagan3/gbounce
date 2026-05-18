# gbounce config export / import

Portable JSON bundle for backup, restore, migration, and change-management
review. Cross-product parity with the sibling Bounce-suite products:
[kbounce], [dbounce], [ibounce] all ship the same shape.

[kbounce]: https://github.com/trsreagan3/kbouncer/blob/main/internal/cli/config.go
[dbounce]: https://github.com/trsreagan3/dbounce/blob/main/internal/cli/config.go
[ibounce]: https://github.com/trsreagan3/iam-jit/blob/main/internal/cli/config.go

## Why

Until this slice landed, the answer to "I'm moving gbounce to a new host /
want to back up before an upgrade / want to mirror the same config across
CI runners" was "manually recreate from scratch". This subcommand closes
the gap.

A few use cases:

- Snapshot a deployment's runtime config before a risky change.
- Move a hand-tuned forward-proxy config from one VM to another.
- Feed a diff into a change-management review so the security reviewer
  sees exactly what's about to land.
- Ship a starter config to a teammate alongside the install instructions.

## CLI shape

```
gbounce config export --out PATH [--redact-secrets] [--include-audit] [--include-prompts]
gbounce config import --in  PATH [--merge | --replace] [--dry-run]
```

The flag names match the sibling Bounce products verbatim.

## Wire shape

JSON document conforming to
[`schemas/gbounce-config.schema.json`](../schemas/gbounce-config.schema.json).
Top-level fields:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | `"1.0"`; mismatch refused at import |
| `product` | string | `"gbounce"`; mismatch refused at import |
| `gbounce_version` | string | binary version that produced the export |
| `exported_at` | RFC3339 string | UTC |
| `source_hostname_hash` | string | first 12 hex chars of `sha256(hostname)` |
| `profiles_supported` | bool | `false` in G-Slice 1; see "What does not ship" |
| `rules_supported` | bool | `false` in G-Slice 1 |
| `tasks_supported` | bool | `false` in G-Slice 1 |
| `alert_rules_supported` | bool | `false` in G-Slice 1 |
| `mcp_install_history_supported` | bool | `false` in G-Slice 1 |
| `runtime_config` | object | mode + bind defaults + audit-log path |
| `audit_webhook` | object | URL + token MASKED unless `--redact-secrets=false` |
| `license` | object (opt) | `license_id` + `expires_at`; bytes NEVER emitted |
| `audit_tail` | array (opt) | up to 50 recent decision rows (only with `--include-audit`) |
| `audit_prompts` | array (opt) | reserved for a future slice |

Per the task spec: gbounce genuinely doesn't yet have profiles / rules /
tasks / alert-rules / MCP-install-history subsystems. Rather than omitting
those sections silently, the export reports them with `*_supported: false`
booleans so cross-product re-import logic stays simple — later G-Slices add
the subsystem AND set the boolean to `true` in lockstep.

## Redaction

`--redact-secrets` is the **default**. The webhook URL + token are masked
to `"***REDACTED***"` and the `redacted: true` flag is stamped into the
`audit_webhook` block.

License bytes are NEVER emitted. Only `license_id` + `expires_at` round-trip;
the signed bytes stay on disk where they belong.

The redaction grep test
([`config_test.go`](../internal/cli/config_test.go) `TestRedactionGrep_NoLeaksInExport`)
catches regressions by asserting the secret strings do not survive the
serialization.

## Refuse-if-running

`gbounce config import` probes the configured wire port and management
port on loopback before mutating anything. If either responds, the import
refuses with:

```
refusing to import: gbounce appears to be running on 127.0.0.1:8080.
Stop gbounce first (e.g. `pkill gbounce` or stop the systemd unit),
then re-run `gbounce config import`.
```

This avoids the failure mode where the importer interleaves writes with
the live proxy and leaves state half-mutated.

## Cross-product refusal

A `kbounce` / `dbounce` / `ibounce` export will be refused at import time:

```
$ gbounce config import --in kbounce-export.json
Error: schema validation failed:
  - $.product: value kbounce not in enum [gbounce]
```

This is load-bearing — the different products have different config
surfaces and a silent cross-product import would silently drop fields.

## Admin-action audit event

Both `config export` and `config import` emit an OCSF v1.1.0 class 6003
(API Activity) event to the JSONL audit log when `--audit-log-path` is
configured. Sample (config.import):

```json
{
  "metadata": {"version": "1.1.0", "product": {"name": "gbounce", ...}},
  "class_uid": 6003,
  "class_name": "API Activity",
  "activity_id": 1,
  "activity_name": "config.import",
  "status": "Success",
  "unmapped": {
    "iam_jit": {
      "mode": "admin",
      "verdict": "ALLOW",
      "ext": {
        "admin_action": "config.import",
        "config_change": {
          "type": "config.import",
          "source": "cli",
          "after_hash": "<sha256-of-snapshot>",
          "entity": "/path/to/bundle.json",
          "entity_kind": "config",
          "actor": "alice",
          "ext": {"source": "/path/to/bundle.json", "mode": "merge"}
        }
      }
    }
  }
}
```

A SIEM correlation rule keyed on `activity_name="config.import"` catches
the lifecycle event regardless of which Bounce product fired it (per
[[cross-product-agent-parity]]).

## Sample session

```console
$ gbounce config export --out /tmp/gbounce-config.json \
    --audit-log-path /var/log/gbounce/audit.jsonl
gbounce: config export written to /tmp/gbounce-config.json (812 bytes)

$ gbounce config import --in /tmp/gbounce-config.json --dry-run
gbounce: would import (--dry-run) (mode=merge)
  runtime_config:  present
  audit_webhook:   absent
  license:         absent

$ gbounce config import --in /tmp/gbounce-config.json \
    --audit-log-path /var/log/gbounce/audit.jsonl
gbounce: imported (mode=merge)
  runtime_config:  present
  audit_webhook:   absent
  license:         absent
```

Sample export (redacted, defaults):

```json
{
  "schema_version": "1.0",
  "product": "gbounce",
  "gbounce_version": "1.0.0",
  "exported_at": "2026-05-18T03:42:11Z",
  "source_hostname_hash": "a1b2c3d4e5f6",
  "profiles_supported": false,
  "rules_supported": false,
  "tasks_supported": false,
  "alert_rules_supported": false,
  "mcp_install_history_supported": false,
  "runtime_config": {
    "mode": "discovery"
  },
  "audit_webhook": {
    "redacted": true
  }
}
```

## Constraints honored

- [[cross-product-agent-parity]] — CLI shape + schema_version handling +
  redaction defaults + refuse-cross-product-import semantic all match the
  sibling products.
- [[security-team-positioning-safety-not-surveillance]] — no
  "violation" / "infraction" / "unauthorized" strings in any user-facing
  message.
- [[creates-never-mutates]] — `export` is read-only; `import` is the only
  destructive path, and `--dry-run` shows what it would do first.
- [[self-host-zero-billing-dependency]] — no network calls. Both
  subcommands are fully self-contained.
- [[deliberate-feature-completion]] — tests + docs land in the same
  commit as the implementation.
