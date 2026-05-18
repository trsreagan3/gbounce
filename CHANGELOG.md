# Changelog

All notable changes to gbounce will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — G-Slice 1 (initial scaffold)

- HTTP/HTTPS forward proxy core (TLS passthrough; no MITM)
- `--mode discovery`: observe + log every request; emit one OCSF v1.1.0
  class 6003 (API Activity) event per request/response pair
- `internal/audit`: OCSF v1.1.0 class 6003 emission matching the
  existing Bounce-suite products (ibounce / kbounce / dbounce)
- SQLite audit log (`~/.gbounce/state.db`) + opt-in JSONL export via
  `--audit-log-path`
- `gbounce run` / `gbounce audit tail` / `gbounce --version` /
  `gbounce version-check`
- `/healthz` JSON liveness endpoint on separate management port (8769)
- CONNECT-tunnel support behind `--allow-connect` (TLS passthrough;
  audit log records `host:port` + method)
- Distroless multi-arch Dockerfile (TARGETOS / TARGETARCH undefaulted
  per the kbouncer #246 fix)
- GHCR publish workflow
- `go vet ./...` + `go test ./... -race` validate workflow

### Not in G-Slice 1 (queued)

- Profile mode (G-Slice 2)
- Tap mode (G-Slice 3)
- Auto-recommender (G-Slice 4)
- MCP server (G-Slice 5)
- Webhook export (G-Slice 6 — port from the existing Bounce-suite
  pattern when ready)
- Community profile bundle (post G-Slice 6)
