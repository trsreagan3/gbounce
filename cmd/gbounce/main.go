// Command gbounce is the generic HTTP/HTTPS forward proxy in the Bounce
// product suite.
//
// G-Slice 1 ships discovery mode only: gbounce accepts inbound HTTP or
// HTTPS requests, forwards them verbatim to a configured upstream, and
// emits an OCSF v1.1.0 class 6003 (API Activity) event per request/
// response pair. No filtering, no enforcement — the audit log is the
// product.
//
// Future slices add profile mode (G-Slice 2), tap mode (G-Slice 3),
// auto-recommender (G-Slice 4), MCP server (G-Slice 5), and webhook
// export (G-Slice 6).
//
// All command wiring lives in internal/cli so the single source of
// truth for flags + subcommands stays in one place.
package main

import "github.com/trsreagan3/gbounce/internal/cli"

func main() { cli.Main() }
