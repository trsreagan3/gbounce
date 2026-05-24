# Contributing to gbounce

`gbounce` is the HTTP egress gating bouncer in the iam-jit Bounce
suite. Same agent-friendly UX surface as `ibounce` per
`[[cross-product-agent-parity]]`, with HTTP method + host + path
verbs underneath. Catches data-exfil and off-task egress attempts
from AI agents.

## Development setup

```bash
make build          # ./bin/gbounce with -ldflags version stamping
make install        # go install with the same -ldflags
make test           # go test ./...
```

`make install` writes to `$(go env GOPATH)/bin` (defaults to `~/go/bin`).
If `gbounce --version` reports "command not found", that directory is not
on your PATH — `export PATH="$PATH:$(go env GOPATH)/bin"` once, and
persist it in `~/.bashrc` or `~/.zshrc` (closes #549 from UAT L1
2026-05-24).

`make build` / `make install` stamp `version` / `commit` / `buildTime`
via `-ldflags` so `gbounce --version` reports a real commit SHA. The
binary also auto-populates these from Go's `runtime/debug.ReadBuildInfo`
VCS settings when ldflags are unset (e.g. plain `go install ./...`),
so `iam-jit canary update`'s version-check step works from every
supported install path. See `internal/cli/cli.go::resolveBuildInfo` +
the `Dockerfile` for the canonical shape.

Local-test infrastructure (httpbin upstream + audit DB) lives
alongside the test suite. Driven by `Makefile` targets.

## Adding a deny rule

Deny rules use the cross-product YAML shape (per
`[[cross-product-agent-parity]]`). HTTP-specific shape:

```yaml
- host: example.com           # exact match or glob
  methods: [POST, PUT, DELETE]  # optional; default [*]
  path_prefix: /api/v1/admin    # optional
  reason: "agents shouldn't admin third-party APIs"
```

Submit profile contributions to the shared profile repo at
[`trsreagan3/bounce-profiles`](https://github.com/trsreagan3/bounce-profiles).

## Adding a preset

Curated preset packs ship with the binary. Each preset targets an
HTTP egress narrative (e.g. `block-data-exfil-targets`,
`read-only-third-party-apis`, `internal-network-only`). Add a
test in `internal/...` exercising the preset against a
representative request stream.

## Calibration corpus contributions

`gbounce` is the cross-protocol companion for ibounce / kbouncer /
dbounce — catching the HTTP egress that doesn't go through the
other protocol-specific bouncers. See
[`iam-roles/docs/CONTRIBUTING.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/CONTRIBUTING.md)
for the calibration discipline + corpus contribution path.

## TLS handling

G-Slice 1 ships CONNECT-mode (see destination, not body). MITM
mode is BETA per `[[mitm-beta-pii-pci-concern]]` — additional
contributor caveats live in [`docs/MITM-MODE.md`](./docs/MITM-MODE.md).

## Code style

```bash
gofmt -s -w .
go vet ./...
```

Before committing.

## Cross-product parity

Per `[[cross-product-agent-parity]]`, the gbounce MCP surface
mirrors ibounce's (only the tool prefix changes). When adding a
new MCP tool, add the equivalent surface to the other bouncers
(or file an issue noting the gap). Symmetry is the cross-product
wedge.
