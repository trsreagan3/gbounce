// Package proxy implements gbounce's HTTP/HTTPS forward proxy.
//
// G-Slice 1 ships discovery mode only: every inbound request is
// forwarded verbatim to the configured upstream and the request /
// response pair is recorded in the audit log. No filtering, no
// enforcement.
//
// TLS approach (G-Slice 1):
//
//   - "Upstream HTTPS" mode (DEFAULT): the operator points gbounce at
//     a single upstream URL (e.g. https://api.target.com). Clients
//     send their HTTP/1.1 request to gbounce's listener; gbounce
//     rewrites the request onto the upstream's scheme/host/port and
//     forwards. URL path + method + status + size + latency are
//     visible to gbounce's audit log; request/response bodies stream
//     through unmodified. Listener can itself be HTTPS by passing
//     --tls-cert + --tls-key (a future slice will document the
//     cert-pinning story).
//
//   - "CONNECT tunnel" mode (when --allow-connect is passed): gbounce
//     accepts the HTTP CONNECT verb that browsers / SDKs use to
//     tunnel HTTPS through a forward proxy. gbounce splices the two
//     sockets blindly (no MITM, no body inspection) and records the
//     CONNECT decision in the audit log with method=CONNECT + path=
//     host:port. Granularity per [[ibounce-honest-positioning]] +
//     [[gbounce-generic-proxy]]: this is a deterrent + audit trail,
//     not a payload-inspection boundary.
//
// gbounce NEVER mutates upstream state — it's a passthrough proxy
// per [[creates-never-mutates]]. The proxy holds inbound bearer
// tokens long enough to forward them; it does not log token bodies.
//
// Per [[ibounce-honest-positioning]]: an operator who controls the
// agent's network can route around the proxy. The product value is
// audit trail + visibility + future profile-mode gating, not a
// boundary the agent can't bypass.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/dynamicdeny"
	"github.com/trsreagan3/gbounce/internal/mitm"
	"github.com/trsreagan3/gbounce/internal/profile"
	"github.com/trsreagan3/gbounce/internal/store"
	"github.com/trsreagan3/gbounce/internal/structureddeny"
)

// Mode is the proxy's operating mode. G-Slice 1 ships ModeDiscovery
// (default); #315 / §A13 adds ModeMITM (opt-in TLS interception).
type Mode string

const (
	// ModeDiscovery parses + forwards + logs every call. No filtering.
	// FREE-tier, no license gate.
	ModeDiscovery Mode = "discovery"
	// ModeMITM (#315 / §A13) terminates TLS using a CA loaded from
	// disk + re-encrypts to the upstream. DEFAULT-OFF; operator opts
	// in via `--mode mitm` after `gbounce ca install`. Per
	// [[creates-never-mutates]] MITM is additive — CONNECT-mode is
	// unchanged.
	ModeMITM Mode = "mitm"
)

// IsValid returns true if m is one of the known modes.
func (m Mode) IsValid() bool { return m == ModeDiscovery || m == ModeMITM }

// caveatLinkSuffixB8 is the inline help-link appended to the 421
// "non-CONNECT on CONNECT-only listener" error body so an operator
// hitting the deny sees the canonical KNOWN-CAVEATS §B8 explanation
// without grepping. Hand-coded here (not via internal/caveats) to
// avoid an internal/caveats import + the lint cost of one more
// inter-package edge for a single constant. Per #304 + per
// [[security-team-positioning-safety-not-surveillance]]: language is
// helpful ("here's the doc") not accusatory.
const caveatLinkSuffixB8 = " (see KNOWN-CAVEATS §B8: " +
	"https://github.com/trsreagan3/iam-jit/blob/main/docs/" +
	"KNOWN-CAVEATS.md#b8-gbounce---allow-connect-only-sees-hostport-design)"

// hopByHopHeaders are stripped before forwarding. Lowercase for the
// case-insensitive comparison. Lifted from RFC 7230 §6.1.
//
// Content-Length is included because the Go transport recomputes it
// from the body bytes.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-length":      {},
}

// Config holds the proxy's runtime configuration. Built from CLI
// flags in the cli package.
type Config struct {
	// Host/Port: where the proxy listens for inbound requests.
	Host string
	Port int
	// MgmtHost/MgmtPort: where /healthz lives. SEPARATE from the proxy
	// port so the proxy port can be HTTPS-only without conflating
	// liveness probes with the data path.
	MgmtHost string
	MgmtPort int
	// UpstreamURL is the single upstream gbounce forwards to. Required
	// in upstream-mode; ignored in CONNECT-tunnel mode (the tunnel
	// target comes from the client's CONNECT host:port).
	UpstreamURL string
	// AllowConnect lets gbounce accept HTTP CONNECT verbs and splice
	// the two sockets blindly (TLS passthrough; no MITM). Default
	// false — most operators forwarding to a single upstream service
	// don't want a wide-open tunnel.
	AllowConnect bool
	// ForwardTimeoutSeconds bounds how long a single forwarded request
	// can take end-to-end. 0 → 60s default.
	ForwardTimeoutSeconds int
	// AuditLogPath: when non-empty, every decision is also written to
	// this JSONL file. Opt-in.
	AuditLogPath  string
	AuditLogFsync bool
	// AuditEventsToken is the bearer token clients must present on
	// GET /audit/events when the mgmt server is bound off-loopback.
	// Empty + loopback-bound: no auth required (the loopback bind is
	// itself a trust anchor). Empty + external-bound: the constructor
	// refuses to start.
	AuditEventsToken string
	// Mode: G-Slice 1 only supports ModeDiscovery.
	Mode Mode
	// DenyHosts — #314 / §A12. Operator-written deny-list entries
	// (exact + wildcard). Compiled at NewServer time; a parse error
	// fails the constructor with a clear message naming the offending
	// entry. A non-empty list is checked on every CONNECT before the
	// upstream is dialed; a match emits a verdict=DENY OCSF event
	// (status_id=4 Denied + ext.deny_reason="matched deny_hosts: <rule>")
	// and returns 403 to the client. See deny_hosts.go for the
	// wildcard semantics + the order-of-evaluation rule.
	DenyHosts []string

	// #324d — Dynamic-deny watcher. When non-nil, the proxy unions
	// entries from `~/.iam-jit/dynamic-denies.yaml` with the static
	// DenyHosts list above. Source attribution (`ext.deny_source` +
	// `ext.dynamic_deny_rule_id`) lands on every deny audit event so
	// a SIEM analyst sees which surface fired. Nil = pre-#324d shape
	// (static rules only).
	DynamicDenyWatcher *dynamicdeny.Watcher

	// #388 / §A25 Phase 2 — active profile bridge for the POST
	// /admin/profile/reload endpoint. The proxy hot-path doesn't
	// consult ActiveProfile directly (gbounce translates the profile
	// into denyHosts + mitmRules at start); the reload endpoint uses
	// these fields as the bridge so a `gbounce profile allow`
	// mutation re-translates without a restart.
	ActiveProfile     *profile.Profile
	ActiveProfileName string
	ProfilesPath      string

	// #315 / §A13 — MITM-mode wiring.
	//
	// MITMCertMinter is set when Mode==ModeMITM. NewServer rejects
	// MITM mode with a nil minter; the CLI layer constructs it after
	// loading the CA + running the LoadCA permission check.
	MITMCertMinter *mitm.CertMinter
	// MITMRules is the compiled profile-rule list (host + method +
	// path + query-param matching). Empty list = MITM mode with only
	// URL-level audit visibility.
	MITMRules []profile.Rule
	// MITMAuditIncludeBodies opts INTO storing redacted request +
	// response bodies in the audit log. Default false — only the
	// redaction MARK + the bool surface so a SIEM can find which
	// rows had a redacted body.
	MITMAuditIncludeBodies bool

	// DiskPressure (#461 / §A63c) is the optional disk-pressure
	// circuit-breaker state. When non-nil the proxy:
	//   - surfaces an audit_log block on /healthz with disk usage +
	//     mode + refuse_requests flag,
	//   - returns 503 with the #459 structured-deny shape on every
	//     request when state.RefuseRequests() reports true
	//     (pause-requests mode at critical / emergency),
	//   - starts a background periodic goroutine in Serve() that
	//     ticks every DiskPressureCheckInterval to re-evaluate state
	//     + emit admin-action disk_pressure.transition OCSF events
	//     on status changes.
	// When nil the proxy behavior is byte-identical to the pre-#461
	// shape per [[creates-never-mutates]].
	DiskPressure *audit.DiskPressureState
}

// Normalize fills sensible defaults + returns the normalized Config.
func (c Config) Normalize() Config {
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		c.Port = 8080
	}
	if c.MgmtHost == "" {
		c.MgmtHost = "127.0.0.1"
	}
	if c.MgmtPort == 0 {
		// 8769 picked to not collide with kbounce (8766), ibounce (8767),
		// or dbounce (8768). The Bounce-suite mgmt-port lineage in one
		// sequence.
		c.MgmtPort = 8769
	}
	if c.ForwardTimeoutSeconds == 0 {
		c.ForwardTimeoutSeconds = 60
	}
	if c.Mode == "" {
		c.Mode = ModeDiscovery
	}
	return c
}

// Server is the gbounce proxy server. Wraps the inbound HTTP listener
// + the management HTTP listener + the audit sinks.
type Server struct {
	cfg     Config
	store   *store.Store
	log     *audit.LogWriter
	// #285 — optional per-session NDJSON recorder. Nil disables the
	// channel. When wired, every audit event is teed to
	// {dir}/{agent.session_id}.ndjson via Recorder.Record. Fail-soft
	// inside Record so disk failures never propagate the proxy hot
	// path; same shape as the kbouncer + dbounce wiring.
	recorder *audit.SessionRecorder
	// #317 — optional cloud-neutral S3-compat NDJSON object-storage
	// writer. Nil disables the channel. When wired, every audit
	// event is also buffered + finalized into the operator-owned
	// bucket per the Hive-partitioned NDJSON.gz layout. Per
	// [[self-host-zero-billing-dependency]] the destination is
	// operator-owned; iam-jit-the-company never receives the data.
	objectStorage *audit.ObjectStorageWriter
	httpSrv       *http.Server
	mgmtSrv  *http.Server
	// upstreamURL is the parsed cfg.UpstreamURL, kept as *url.URL so
	// each request avoids re-parsing.
	upstreamURL *url.URL
	// client is the pooled http.Client used to forward upstream
	// requests. Single shared client per Server so connection pooling
	// works.
	client *http.Client
	// counters
	totalRequests atomic.Int64
	totalErrors   atomic.Int64
	// #308 — bumped each time an inbound X-Agent-Session-Id or
	// X-Agent-Name header fails validation. Surfaces via /healthz so
	// an operator can spot agent-config drift (e.g. somebody set the
	// header to a shell-injection payload).
	totalAgentHeadersRejected atomic.Int64
	// #314 — compiled deny_hosts rules. Built at NewServer time from
	// cfg.DenyHosts. Empty slice when no deny entries were configured;
	// MatchDenyHosts returns nil cheaply in that case so the CONNECT
	// hot path stays the same shape it had pre-#314.
	denyHosts []DenyHostRule
	// #314 — bumped each time a CONNECT is denied by a deny_hosts
	// rule. Surfaces via /healthz so an operator can see deny-rule
	// activity without grepping the audit log.
	totalDenyHostMatches atomic.Int64

	// #324d — dynamic-deny watcher. Pulls hot-reloadable entries from
	// the cross-product YAML; the matcher unions these with the static
	// list above. Nil disables the channel.
	dynamicDeny *dynamicdeny.Watcher
	// #324d — bumped each time a dynamic-deny rule fires. Surfaces via
	// /healthz so an operator sees activity. Independent counter from
	// the static-deny counter so a SIEM dashboard can split the two.
	totalDynamicDenyMatches atomic.Int64
	// #324d — bumped each time the dynamic-deny YAML file reloads
	// (either via the watcher or the mgmt-port reload endpoint).
	totalDynamicDenyReloads atomic.Int64
	// #324d — bumped each time a dynamic-deny reload attempt failed
	// parse / schema validation. Surfaces via /healthz.
	totalDynamicDenyParseErrors atomic.Int64

	// #315 / §A13 — MITM-mode state. nil minter = MITM disabled.
	mitmMinter             *mitm.CertMinter
	mitmRules              []profile.Rule
	mitmAuditIncludeBodies bool

	// #388 / §A25 Phase 2 — hot-swap-aware active profile state. The
	// proxy hot-path doesn't consult these directly (gbounce
	// translates profile fields into denyHosts + mitmRules at start);
	// the POST /admin/profile/reload endpoint uses them as the bridge
	// so a `gbounce profile allow` mutation re-translates without a
	// restart. profileMu guards activeProfile + activeProfileName.
	profileMu         sync.RWMutex
	activeProfile     *profile.Profile
	activeProfileName string
	// #315 — bumped each time a MITM-intercepted request was denied
	// by a profile rule.
	totalMITMDenies atomic.Int64
	// #315 — bumped each time an upstream TLS handshake fails inside
	// MITM mode (most commonly = upstream pins certs).
	totalMITMUpstreamHandshakeFailures atomic.Int64
}

// NewServer builds a Server from the given Config + Store. Caller
// must call Serve to start listening. Audit log writer is OPTIONAL —
// pass a *audit.LogWriter to also tee decisions into JSONL; nil to
// skip. Session recorder is also OPTIONAL — pass a non-nil
// *audit.SessionRecorder to also tee events into per-session NDJSON
// files; pass nil to skip (the #285 default).
func NewServer(cfg Config, st *store.Store, lw *audit.LogWriter, sr *audit.SessionRecorder) (*Server, error) {
	cfg = cfg.Normalize()
	if cfg.UpstreamURL == "" && !cfg.AllowConnect {
		return nil, fmt.Errorf("gbounce: --upstream is required (or pass --allow-connect for CONNECT-tunnel mode)")
	}
	var up *url.URL
	if cfg.UpstreamURL != "" {
		u, err := url.Parse(cfg.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("gbounce: parse upstream URL %q: %w", cfg.UpstreamURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("gbounce: upstream URL scheme must be http or https; got %q", u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("gbounce: upstream URL must include a host; got %q", cfg.UpstreamURL)
		}
		up = u
	}
	if !cfg.Mode.IsValid() {
		return nil, fmt.Errorf("gbounce: invalid mode %q (supported: %q, %q)", cfg.Mode, ModeDiscovery, ModeMITM)
	}
	// #315 / §A13 — MITM mode requires a loaded CA + the LoadCA
	// permission check (see internal/mitm) to have already passed.
	// NewServer refuses MITM mode with a nil minter so programmatic
	// callers can't bypass the CA gate.
	if cfg.Mode == ModeMITM && cfg.MITMCertMinter == nil {
		return nil, fmt.Errorf("gbounce: --mode mitm requires a CA — run `gbounce ca install` first")
	}

	// #314 — compile deny_hosts rules up-front so any parse error fails
	// the constructor with a clear message naming the offending entry.
	// Empty cfg.DenyHosts produces a nil rules slice + the CONNECT hot
	// path's MatchDenyHosts returns nil cheaply.
	denyRules, err := ParseDenyHosts(cfg.DenyHosts)
	if err != nil {
		return nil, fmt.Errorf("gbounce: %w", err)
	}

	timeout := time.Duration(cfg.ForwardTimeoutSeconds) * time.Second

	s := &Server{
		cfg:                    cfg,
		store:                  st,
		log:                    lw,
		recorder:               sr,
		upstreamURL:            up,
		denyHosts:              denyRules,
		dynamicDeny:            cfg.DynamicDenyWatcher,
		mitmMinter:             cfg.MITMCertMinter,
		mitmRules:              cfg.MITMRules,
		mitmAuditIncludeBodies: cfg.MITMAuditIncludeBodies,
		activeProfile:          cfg.ActiveProfile,
		activeProfileName:      cfg.ActiveProfileName,
		client: &http.Client{
			Timeout: timeout,
			// Don't follow redirects — surface the upstream's
			// 3xx response verbatim so audit semantics match what the
			// agent sees.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	// Proxy listener uses a bare HandlerFunc (NOT a ServeMux) because
	// the HTTP CONNECT verb has a request-target of "host:port" not a
	// URL path; ServeMux's path-based routing rejects it as 404. The
	// management server (below) DOES use a mux since /healthz is a
	// normal path route.
	s.httpSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}

	mgmtMux := http.NewServeMux()
	mgmtMux.HandleFunc("/healthz", s.healthz)
	// #276 — GET /schemas/config serves the embedded
	// gbounce-config.schema.json byte-for-byte. Agents that want to
	// validate a proposed `gbounce config import` payload against
	// the LIVE bouncer's accepted shape fetch this rather than
	// relying on a stale GitHub URL. Per [[cross-product-agent-
	// parity]]: ibounce + kbounce + dbounce ship the same endpoint
	// shape with their own product schema. READ-ONLY; no auth
	// (matches /healthz — the schema is non-sensitive metadata).
	mgmtMux.HandleFunc("/schemas/config", schemasConfigHandler)
	// #271 — GET /audit/events ships the headless audit-tail query
	// surface. Same filter language as `gbounce audit tail --filter`;
	// the cross-bouncer `iam-jit audit query` CLI calls this endpoint
	// in parallel against each reachable bouncer to produce a single
	// merged stream.
	mgmtMux.HandleFunc("/audit/events", auditEventsHandler(st, cfg.AuditEventsToken))
	// #324d — POST /admin/dynamic-denies/reload triggers an immediate
	// reload of the dynamic-deny YAML from disk. Useful for the
	// cross-bouncer fan-out CLI (#324e), which will write the YAML
	// + then call POST on each Bounce product's mgmt port so the
	// operator gets a confirmed "rules are live on bouncer X" reply.
	// 200 with a small JSON payload on success; 4xx with a structured
	// error on parse / schema failure. Reuses the same loopback /
	// bearer-token gating as /audit/events since the endpoint
	// indirectly exposes a manifest-shape view of the active rules.
	// #524 BB-3 — defense-in-depth middleware on /admin/* that closes
	// the residual gap when a future code path bypasses the CLI's
	// bind-time --audit-events-token requirement (config-file loader,
	// programmatic embed, test harness). The handler-internal bearer
	// check below ALSO fires (belt-and-suspenders); requireMgmtAuth
	// adds the "external bind without token → 503" failure case the
	// handler-internal check can't enforce because it has no view of
	// the bind host.
	mgmtMux.HandleFunc("/admin/dynamic-denies/reload",
		requireMgmtAuth(s.dynamicDenyReloadHandler(cfg.AuditEventsToken),
			cfg.AuditEventsToken, cfg.MgmtHost))
	// #388 / §A25 Phase 2 — POST /admin/profile/reload re-reads
	// profiles.yaml + re-translates the active profile into the
	// proxy's denyHosts + mitmRules so a `gbounce profile allow`
	// mutation takes effect without a restart. Same auth model as
	// /audit/events. Response shape mirrors ibounce + kbouncer +
	// dbounce per [[cross-product-agent-parity]].
	mgmtMux.HandleFunc("/admin/profile/reload",
		requireMgmtAuth(s.profileReloadHandler(cfg.AuditEventsToken, cfg.ProfilesPath),
			cfg.AuditEventsToken, cfg.MgmtHost))

	// #298 — GET /suite serves the cross-product Bounce-suite link
	// page. Per [[unified-ui-link-page]] this is signage + status
	// pills, not an aggregator. Each card is just an anchor to the
	// matching bouncer's own mgmt-port UI; client-side JS does
	// parallel /healthz polling for the pills. No backend coupling.
	// Registered BEFORE the "/" catch-all so ServeMux's longest-prefix
	// match routes /suite here instead of the live audit UI's
	// 404-on-non-root path.
	mgmtMux.HandleFunc("/suite", suiteUIHandler())
	// #272 — GET / serves the minimal live audit-stream web UI on
	// the same mgmt port as /healthz + /audit/events. The page polls
	// /audit/events every 2 s. Same auth model as /audit/events:
	// loopback no header; external bind takes the bearer token
	// through the URL `#token=...` fragment so the rendered HTML
	// body never embeds the secret. Cross-product-identical HTML
	// shape with ibounce / kbounce / dbounce.
	mgmtMux.HandleFunc("/", auditEventsUIHandler(cfg.AuditEventsToken))
	s.mgmtSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.MgmtHost, strconv.Itoa(cfg.MgmtPort)),
		Handler:           mgmtMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s, nil
}

// Addr returns the proxy's bind address.
// SetObjectStorageWriter installs the #317 cloud-neutral S3-compat
// NDJSON object-storage writer. Pass nil to clear. The writer must
// already be Start()-ed before installation so the first event's
// buffer doesn't no-op. Goes through this method instead of being
// a constructor arg to keep NewServer's signature stable across
// product slices.
func (s *Server) SetObjectStorageWriter(w *audit.ObjectStorageWriter) {
	s.objectStorage = w
}

// ActiveProfile returns the hot-swap-aware active profile pointer.
// May be nil when no profile was selected at proxy start. #388 /
// §A25 Phase 2.
func (s *Server) ActiveProfile() *profile.Profile {
	if s == nil {
		return nil
	}
	s.profileMu.RLock()
	defer s.profileMu.RUnlock()
	return s.activeProfile
}

// ActiveProfileName returns the configured active profile name. May
// be empty when no profile was selected at proxy start.
func (s *Server) ActiveProfileName() string {
	if s == nil {
		return ""
	}
	s.profileMu.RLock()
	defer s.profileMu.RUnlock()
	return s.activeProfileName
}

// SetActiveProfile hot-swaps the active profile pointer + re-
// translates the profile's DenyHosts + DenyRules into the proxy's
// active denyHosts + mitmRules. The next inbound CONNECT / forward
// reads the new compiled state via the proxy's existing accessors.
// Per [[creates-never-mutates]]: this swaps in a new slice that the
// proxy owns; we never mutate the prior slice in-place.
//
// Returns an error when the translation fails (e.g., a profile
// deny_rule has an invalid host pattern); on error the prior state
// is unchanged + the caller surfaces the parse error.
func (s *Server) SetActiveProfile(p *profile.Profile) error {
	if s == nil {
		return nil
	}
	if p == nil {
		s.profileMu.Lock()
		s.activeProfile = nil
		s.activeProfileName = ""
		s.profileMu.Unlock()
		return nil
	}

	// Translate DenyHosts → DenyHostRule list. Mirrors the CLI's
	// run-cmd plumbing — union onto a fresh slice (we deliberately
	// don't merge with the prior compiled list since the reload
	// represents the new authoritative state).
	newDenyHosts, err := ParseDenyHosts(p.DenyHosts)
	if err != nil {
		return fmt.Errorf("gbounce: profile %q: deny_hosts: %w", p.Name, err)
	}

	// Translate DenyRules → MITM []profile.Rule. Mirrors the CLI's
	// `for _, spec := range ap.DenyRules { profile.ParseRule(spec) }`
	// step.
	newMITMRules := make([]profile.Rule, 0, len(p.DenyRules))
	for _, spec := range p.DenyRules {
		r, rerr := profile.ParseRule(spec)
		if rerr != nil {
			return fmt.Errorf("gbounce: profile %q: deny_rules: %w", p.Name, rerr)
		}
		newMITMRules = append(newMITMRules, r)
	}

	s.profileMu.Lock()
	s.activeProfile = p
	s.activeProfileName = p.Name
	s.denyHosts = newDenyHosts
	s.mitmRules = newMITMRules
	s.profileMu.Unlock()
	return nil
}

func (s *Server) Addr() string { return s.httpSrv.Addr }

// MgmtAddr returns the management server's bind address.
func (s *Server) MgmtAddr() string { return s.mgmtSrv.Addr }

// SetAddrs overrides the bind addresses (test helper for port 0).
func (s *Server) SetAddrs(proxyAddr, mgmtAddr string) {
	s.httpSrv.Addr = proxyAddr
	s.mgmtSrv.Addr = mgmtAddr
}

// Serve starts BOTH listeners. Blocks until ctx is cancelled or
// either listener errors. The management listener runs in a
// goroutine.
func (s *Server) Serve(ctx context.Context) error {
	mgmtErr := make(chan error, 1)
	go func() {
		err := s.mgmtSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			mgmtErr <- err
		}
		close(mgmtErr)
	}()

	proxyErr := make(chan error, 1)
	go func() {
		err := s.httpSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			proxyErr <- err
		}
		close(proxyErr)
	}()

	// #461 / §A63c — start disk-pressure check loop. Goroutine exits
	// when the Serve context is cancelled.
	diskStop := s.startDiskPressureLoop(ctx)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
		_ = s.mgmtSrv.Shutdown(shutdownCtx)
		// #285 — finalise every still-open recording (.partial →
		// .ndjson) before the server exits. SIGKILL-leftover .partial
		// files are recovered by the next Start().
		if s.recorder != nil {
			s.recorder.Stop()
		}
		if diskStop != nil {
			close(diskStop)
		}
		return nil
	case err := <-proxyErr:
		if diskStop != nil {
			close(diskStop)
		}
		return err
	case err := <-mgmtErr:
		if diskStop != nil {
			close(diskStop)
		}
		return err
	}
}

// startDiskPressureLoop launches the periodic check goroutine when
// cfg.DiskPressure is set. Returns the stop channel for cleanup; nil
// when the subsystem is disabled (so the caller's close path can
// nil-check uniformly).
func (s *Server) startDiskPressureLoop(ctx context.Context) chan struct{} {
	if s == nil || s.cfg.DiskPressure == nil {
		return nil
	}
	stop := make(chan struct{})
	go audit.RunDiskPressureLoop(ctx, s.cfg.DiskPressure, s.log, stop)
	return stop
}

// ServeListeners is a test helper that serves on caller-provided
// listeners (avoids racing to bind ephemeral ports across test
// processes).
func (s *Server) ServeListeners(ctx context.Context, proxyL, mgmtL net.Listener) error {
	mgmtErr := make(chan error, 1)
	go func() {
		err := s.mgmtSrv.Serve(mgmtL)
		if err != nil && err != http.ErrServerClosed {
			mgmtErr <- err
		}
		close(mgmtErr)
	}()
	proxyErr := make(chan error, 1)
	go func() {
		err := s.httpSrv.Serve(proxyL)
		if err != nil && err != http.ErrServerClosed {
			proxyErr <- err
		}
		close(proxyErr)
	}()
	diskStop := s.startDiskPressureLoop(ctx)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
		_ = s.mgmtSrv.Shutdown(shutdownCtx)
		// #285 — finalise every still-open recording (.partial →
		// .ndjson) before the server exits. Same shape as the Serve
		// path above (the test-only ServeListeners helper must honor
		// the same lifecycle).
		if s.recorder != nil {
			s.recorder.Stop()
		}
		if diskStop != nil {
			close(diskStop)
		}
		return nil
	case err := <-proxyErr:
		if diskStop != nil {
			close(diskStop)
		}
		return err
	case err := <-mgmtErr:
		if diskStop != nil {
			close(diskStop)
		}
		return err
	}
}

// handle is the proxy's catch-all HTTP handler. Routes CONNECT to
// the tunnel handler (when enabled) and everything else to the
// forward handler.
//
// #315 — when the proxy runs in ModeMITM, CONNECT verbs route to
// handleMITMConnect (TLS terminate + decrypt + audit + re-encrypt).
// The default ModeDiscovery shape is unchanged.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// #461 / §A63c — disk-pressure circuit breaker. In pause-requests
	// mode at critical / emergency the proxy refuses every inbound
	// request with 503 + the #459 structured-deny body BEFORE
	// running the forward / connect dispatch. Refusing pre-evaluation
	// avoids the audit-write race when the disk is already at the
	// wall. Other modes (rotate-aggressively / archive-and-purge)
	// never flip refuse_requests so this is a no-op for them.
	if s.cfg.DiskPressure != nil && s.cfg.DiskPressure.RefuseRequests() {
		writeDiskPressurePause(w, s.cfg.DiskPressure.Snapshot())
		return
	}
	if r.Method == http.MethodConnect {
		if s.cfg.Mode == ModeMITM {
			s.handleMITMConnect(w, r)
			return
		}
		s.handleConnect(w, r)
		return
	}
	s.handleForward(w, r)
}

// writeDiskPressurePause emits the 503 refusal body when the
// disk-pressure subsystem is in pause-requests mode at critical /
// emergency. Wire shape mirrors the #459 structured-deny payload so
// agents grep the same fields they'd see from a routine policy deny.
func writeDiskPressurePause(w http.ResponseWriter, snap audit.DiskPressureSnapshot) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-gbounce-refusal", "disk-pressure-pause")
	usedPct := 0.0
	if snap.UsedPct != nil {
		usedPct = *snap.UsedPct
	}
	reason := fmt.Sprintf(audit.PauseRequestsRefusalReasonTemplate, usedPct, snap.CritPct)
	sd := structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:    "gbounce",
		Action:     "disk_pressure.pause",
		DenyReason: reason,
		DenySource: "disk_pressure",
	})
	body := map[string]any{
		"status":        "Failure",
		"message":       reason,
		"reason":        "ServiceUnavailable",
		"code":          http.StatusServiceUnavailable,
		"disk_pressure": snap,
	}
	for k, v := range sd.AsMap() {
		body[k] = v
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(body)
}

// handleForward forwards a non-CONNECT request to the configured
// upstream. Streams the response body back to the client.
func (s *Server) handleForward(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)
	startedAt := time.Now()

	if s.upstreamURL == nil {
		// #305 — CONNECT-only mode: a non-CONNECT verb on the proxy port
		// is a configuration mismatch + a useful attack signal (IMDS
		// probes ride plain HTTP, not HTTPS). 421 Misdirected Request is
		// the closest RFC code. Audit the rejection BEFORE writing the
		// response so the SIEM sees it even when the client gives up on
		// the 421.
		//
		// #685 — this is a PROTOCOL/CONFIG reject, NOT a policy decision:
		// record it as a Failure (status_id=2), not a Denial
		// (status_id=4). A discovery-mode bouncer with zero deny rules
		// must never emit "Denied" events ([[ibounce-honest-positioning]]).
		// The IMDS-probe visibility #305 added is preserved — the request
		// is still audited with its path + reject_reason; an operator who
		// wants it DENIED adds a --deny-host (→ recordDenyWithSource).
		s.recordReject(r, startedAt, http.StatusMisdirectedRequest,
			"non-CONNECT method on CONNECT-only listener")
		http.Error(w, "gbounce: --upstream not configured; only CONNECT is accepted", http.StatusMisdirectedRequest)
		s.totalErrors.Add(1)
		return
	}

	// #353 / §A28 — deny_hosts evaluation in reverse-proxy mode. Mirrors
	// handleConnect's pre-dial check shape so a denied host never causes
	// an outbound upstream request. Match against BOTH the inbound Host
	// header (what the client targeted) AND the configured upstream host
	// (what we'd actually dial). This catches:
	//
	//   - operators who deny by the requested vhost (`--deny-host evil.com`
	//     + `curl -H "Host: evil.com" http://proxy/...`)
	//   - operators who deny by the proxy's upstream destination
	//     (`--deny-host 169.254.169.254` + `--upstream http://169.254.169.254`)
	//
	// Both shapes appeared in the dogfood repro. Port is stripped before
	// the match — the matcher is port-agnostic per deny_hosts.go.
	effective, _ := s.effectiveDenyRules()
	if len(effective) > 0 {
		// Check the inbound Host header first (the client's intent).
		candidates := make([]string, 0, 2)
		if r.Host != "" {
			h, _ := splitHostPortStr(r.Host)
			if h == "" {
				h = r.Host
			}
			candidates = append(candidates, h)
		}
		// Then the upstream the proxy would dial.
		if s.upstreamURL.Host != "" {
			h, _ := splitHostPortStr(s.upstreamURL.Host)
			if h == "" {
				h = s.upstreamURL.Host
			}
			candidates = append(candidates, h)
		}
		for _, denyHost := range candidates {
			rule := MatchDenyHosts(effective, denyHost)
			if rule == nil {
				continue
			}
			if rule.Source == DenySourceDynamic {
				s.totalDynamicDenyMatches.Add(1)
			} else {
				s.totalDenyHostMatches.Add(1)
			}
			reason := fmt.Sprintf("matched deny_hosts: %s", rule.Raw)
			if rule.Source == DenySourceDynamic && rule.DynamicDenyRuleID != "" {
				reason = fmt.Sprintf("matched dynamic-deny rule %s (%s)",
					rule.DynamicDenyRuleID, rule.Raw)
			}
			s.recordDenyWithSource(r, startedAt, http.StatusForbidden, reason, rule)
			// #459 / §A57b — structured-deny wire shape per
			// [[cross-product-agent-parity]]. Legacy `error` field
			// preserved for old clients per [[creates-never-mutates]].
			legacyMsg := "gbounce: request denied by deny_hosts rule: " + rule.Raw
			writeStructuredDeny403(w, r, rule, legacyMsg, classifyGbounceDenySource(rule))
			s.totalErrors.Add(1)
			return
		}
	}

	// Rewrite onto the upstream scheme/host. The inbound request's
	// path + query are preserved verbatim.
	target := *s.upstreamURL
	target.Path = singleJoiningSlash(s.upstreamURL.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "gbounce: build upstream request: "+err.Error(), http.StatusBadGateway)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusBadGateway, 0)
		return
	}
	// Copy headers minus hop-by-hop.
	for k, vv := range r.Header {
		if _, hop := hopByHopHeaders[strings.ToLower(k)]; hop {
			continue
		}
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	// Set Host header to the upstream's host so the upstream's TLS
	// SNI / virtual-host routing works.
	outReq.Host = s.upstreamURL.Host

	resp, err := s.client.Do(outReq)
	if err != nil {
		http.Error(w, "gbounce: upstream request failed: "+err.Error(), http.StatusBadGateway)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusBadGateway, 0)
		return
	}
	defer resp.Body.Close()

	// Copy response headers (strip hop-by-hop) before writing status.
	for k, vv := range resp.Header {
		if _, hop := hopByHopHeaders[strings.ToLower(k)]; hop {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, resp.Body)

	s.record(r, startedAt, resp.StatusCode, written)
}

// handleConnect splices the client TCP connection through to the
// upstream host:port the client requested via the CONNECT verb.
// Honest TLS passthrough: gbounce sees the host:port but not the
// inner request URL or body — per [[gbounce-generic-proxy]] G-Slice 1.
//
// Refuses CONNECT when --allow-connect was not passed.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)
	startedAt := time.Now()

	if !s.cfg.AllowConnect {
		http.Error(w, "gbounce: CONNECT not enabled (start with --allow-connect)", http.StatusMethodNotAllowed)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusMethodNotAllowed, 0)
		return
	}
	target := r.Host // CONNECT host:port lives in Request.Host
	if target == "" {
		http.Error(w, "gbounce: CONNECT missing host:port", http.StatusBadRequest)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusBadRequest, 0)
		return
	}
	// #314 + #324d — deny_hosts evaluation runs BEFORE the dial so a
	// matched host never causes an outbound TCP connection. Union the
	// static rule list with any dynamic entries pulled from the
	// hot-reloadable YAML file. Match against the host portion only
	// (port-agnostic; operators write `evil.example.com` and expect
	// every port to be denied). Per the docstring on deny_hosts.go:
	// deny_hosts WINS over any future allow_hosts list.
	effective, _ := s.effectiveDenyRules()
	if len(effective) > 0 {
		denyHost, _ := splitHostPortStr(target)
		if denyHost == "" {
			denyHost = target
		}
		if rule := MatchDenyHosts(effective, denyHost); rule != nil {
			if rule.Source == DenySourceDynamic {
				s.totalDynamicDenyMatches.Add(1)
			} else {
				s.totalDenyHostMatches.Add(1)
			}
			reason := fmt.Sprintf("matched deny_hosts: %s", rule.Raw)
			if rule.Source == DenySourceDynamic && rule.DynamicDenyRuleID != "" {
				// Surface the rule id verbatim in the operator-facing
				// reason so a 403 body alone names the rule. Audit-
				// event has the structured field; this is the human-
				// readable echo.
				reason = fmt.Sprintf("matched dynamic-deny rule %s (%s)",
					rule.DynamicDenyRuleID, rule.Raw)
			}
			// 403 Forbidden so the verdict word matches the audit event
			// + ReconstructOverridesFromRow can distinguish deny_hosts
			// (403) from "non-CONNECT on CONNECT-only listener" (421).
			s.recordDenyWithSource(r, startedAt, http.StatusForbidden, reason, rule)
			// #459 / §A57b — structured-deny wire shape per
			// [[cross-product-agent-parity]]. The CONNECT path returns
			// the JSON body BEFORE the tunnel handshake; the client
			// sees the structured deny exactly like the non-CONNECT
			// path. Legacy `error` field preserved per
			// [[creates-never-mutates]].
			legacyMsg := "gbounce: CONNECT denied by deny_hosts rule: " + rule.Raw
			writeStructuredDeny403(w, r, rule, legacyMsg, classifyGbounceDenySource(rule))
			s.totalErrors.Add(1)
			return
		}
	}
	upstream, err := net.DialTimeout("tcp", target,
		time.Duration(s.cfg.ForwardTimeoutSeconds)*time.Second)
	if err != nil {
		// #303 — unreachable upstream (DNS failure, connection refused,
		// host doesn't exist) used to be invisible: the proxy returned
		// the 502 to the client but never audited the attempt. SSRF
		// probes against private IPs (169.254.169.254 IMDS, RFC1918) hid
		// in that gap. Audit the failed CONNECT attempt with
		// verdict=ALLOW (we INTENDED to allow; the connect failed at
		// the network layer) + a Failure status + connect_refused/
		// connect_error ext keys so a SIEM filter on
		// `activity_id=6 AND status_id=2` finds every failed tunnel.
		s.recordFailedConnect(r, startedAt, err)
		http.Error(w, "gbounce: dial upstream: "+err.Error(), http.StatusBadGateway)
		s.totalErrors.Add(1)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "gbounce: server does not support hijacking", http.StatusInternalServerError)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusInternalServerError, 0)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		http.Error(w, "gbounce: hijack: "+err.Error(), http.StatusInternalServerError)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusInternalServerError, 0)
		return
	}
	// Send the 200 OK that signals the tunnel is established.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusBadGateway, 0)
		return
	}
	// Audit the CONNECT decision *before* the blind splice begins —
	// after the splice we have no record of what flowed.
	s.record(r, startedAt, http.StatusOK, 0)

	// Splice bidirectionally. Best-effort cleanup; the splice
	// terminates when either side closes.
	go func() {
		defer clientConn.Close()
		defer upstream.Close()
		_, _ = io.Copy(upstream, clientConn)
	}()
	_, _ = io.Copy(clientConn, upstream)
}

// healthz responds 200 with a small JSON liveness payload. Lives on
// the SEPARATE management port so liveness probes never touch the
// proxy data path (and never pollute the audit log).
//
// #524 BB-4 — field scoping for unauthenticated external callers.
// When the caller is on loopback OR carries a valid Authorization
// bearer (matching --audit-events-token), the FULL payload returns
// (preserves the [[cross-product-agent-parity]] composite-monitor
// key set). When the caller is unauthenticated AND off-loopback, the
// response is scoped to the minimal liveness surface (status, product,
// version-ish keys) — upstream URL, per-counter operational signal,
// audit-log path, and disk-pressure detail are withheld so an
// externally-bound /healthz the operator forgot to put behind a
// reverse proxy doesn't hand attackers reconnaissance on the
// upstream target + operational tempo.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	authed := requestAuthenticatedOrLoopback(r,
		s.cfg.AuditEventsToken, s.cfg.MgmtHost)

	// Minimal liveness surface always returned. Mirrors the
	// [[ibounce-honest-positioning]] floor: a probe gets a truthful
	// status without exposing infrastructure detail.
	body := map[string]any{
		"status":  "ok",
		"product": "gbounce",
	}
	if !authed {
		// Unauth + external: still surface chain_initialized +
		// llm_budget so the cross-bouncer composite monitor's REQUIRED
		// key set stays present (it's a parity contract per
		// [[cross-product-agent-parity]]); a missing key would break
		// the monitor's JSON decode. The VALUES are still safe — a
		// bool + a small map with {"enabled": false}.
		body["chain_initialized"] = s.log != nil
		body["llm_budget"] = map[string]any{"enabled": false}
		// Mirror the disk-pressure 503 flip below WITHOUT surfacing
		// the detailed snapshot — operators on unauth probes still
		// need the degraded signal.
		statusCode := http.StatusOK
		if s.cfg.DiskPressure != nil {
			snap := s.cfg.DiskPressure.Snapshot()
			if snap.RefuseRequests {
				body["status"] = "degraded"
				statusCode = http.StatusServiceUnavailable
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(body)
		return
	}

	// Authenticated (or loopback) — full payload.
	body["mode"] = string(s.cfg.Mode)
	body["upstream"] = s.cfg.UpstreamURL
	body["allow_connect"] = s.cfg.AllowConnect
	body["total_requests"] = s.totalRequests.Load()
	body["total_errors"] = s.totalErrors.Load()
	// #308 — invalid X-Agent-* header counter so operators see
	// agent-config drift in liveness probes.
	body["total_agent_headers_rejected"] = s.totalAgentHeadersRejected.Load()
	// #314 — deny_hosts match counter so operators see deny-rule
	// activity from /healthz without grepping the audit log.
	body["total_deny_host_matches"] = s.totalDenyHostMatches.Load()
	body["deny_hosts_count"] = len(s.denyHosts)
	// #324d — dynamic-deny counters. Independent of the static-
	// deny pair above so a SIEM dashboard can split the two. When
	// the watcher is disabled all of these stay zero; pre-existing
	// /healthz consumers see the new keys as "0" rather than
	// "missing field" so a JSON-decode against an older schema
	// doesn't break.
	body["dynamic_denies_enabled"] = s.dynamicDeny != nil
	body["dynamic_denies_count"] = s.dynamicDenyActiveCount()
	body["dynamic_denies_globs_count"] = s.dynamicDenyGlobCount()
	body["dynamic_denies_path"] = s.dynamicDenyPath()
	body["total_dynamic_deny_matches"] = s.totalDynamicDenyMatches.Load()
	body["total_dynamic_deny_reloads"] = s.totalDynamicDenyReloads.Load()
	body["total_dynamic_deny_parse_errors"] = s.totalDynamicDenyParseErrors.Load()
	// #315 / §A13 — MITM-mode counters.
	body["mitm_enabled"] = s.cfg.Mode == ModeMITM
	body["mitm_rules_count"] = len(s.mitmRules)
	body["mitm_audit_include_bodies"] = s.mitmAuditIncludeBodies
	body["total_mitm_denies"] = s.totalMITMDenies.Load()
	body["total_mitm_upstream_handshake_failures"] = s.totalMITMUpstreamHandshakeFailures.Load()
	if s.log != nil {
		body["audit_log_path"] = s.log.Path()
		body["audit_log_total"] = s.log.Total()
		body["audit_log_dropped"] = s.log.Dropped()
		if e := s.log.LastError(); e != "" {
			body["audit_log_last_error"] = e
		}
	}
	// #544 / MRR-5 M2 — cross-bouncer parity with ibounce's
	// /healthz.chain_initialized field. True iff the audit log writer
	// is configured + ready to stamp events; False when --audit-log is
	// off OR the writer construction failed (in which case s.log is
	// nil per NewLogWriter's contract). Closes the cold-start audit-
	// init-failure gap noted in MRR-5-MONITORING-RUNBOOK.md §6 M2
	// (failure surfaced in the bouncer log but NOT on /healthz until
	// the first event tried to write). Per [[cross-product-agent-parity]]
	// every Bounce surfaces the same field for SRE composite monitors.
	body["chain_initialized"] = s.log != nil
	// #544 / MRR-5 M3 — cross-bouncer parity with ibounce's
	// /healthz.llm_budget block. Go bouncers don't run LLM per
	// [[bouncer-zero-llm-when-agent-in-loop]] (they're deterministic
	// by default), so the field is a constant {"enabled": false}. This
	// is honest per [[ibounce-honest-positioning]] — NOT a stubbed
	// TODO. If a Go bouncer later adds optional LLM features, expand
	// to match ibounce's full shape (used_today_usd, cap_per_day_usd,
	// remaining_usd, percent_consumed, approaching_limit). Returned
	// unconditionally so a composite monitor scraping all four
	// /healthz endpoints sees the same key set.
	body["llm_budget"] = map[string]any{"enabled": false}
	// #461 / §A63c — disk-pressure subsystem snapshot + 503 status
	// flip in pause-requests at critical / emergency. Per
	// [[ibounce-honest-positioning]] every state crossing surfaces
	// here so external monitors (liveness probes, monit) see the
	// same paused-bouncer signal the request hot path uses.
	statusCode := http.StatusOK
	if s.cfg.DiskPressure != nil {
		snap := s.cfg.DiskPressure.Snapshot()
		body["audit_log"] = snap
		if snap.RefuseRequests {
			body["status"] = "degraded"
			statusCode = http.StatusServiceUnavailable
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(body)
}

// recordOverrides bundles the per-call audit-event overrides #303 and
// #305 need without changing the (now stable across the rest of the
// codebase) record() signature. Zero-value fields fall back to the
// default behavior — record() with no overrides matches the
// pre-#303/#305 shape verbatim.
type recordOverrides struct {
	// Verdict overrides the default "ALLOW". Used by #305 to emit
	// "DENY" for explicit policy rejects.
	Verdict string
	// ActivityID pins a specific OCSF activity_id; zero falls back to
	// method-derived. Used by #303 to pin ActivityConnect on a failed
	// CONNECT (so SIEM filter `activity_id=6` finds it alongside the
	// happy-path CONNECT entries).
	ActivityID int
	// StatusID pins a specific OCSF status_id; zero falls back to
	// HTTPStatus-derived. Used by #303 (StatusFailure for CONNECT dial
	// errors) and #305 (StatusDenied for policy rejects).
	StatusID int
	// ExtraExt merges into unmapped.iam_jit.ext. Used by #303
	// (connect_refused, connect_error) and #305 (deny_reason).
	ExtraExt map[string]any
}

// recordFailedConnect is the #303 entrypoint: audit a CONNECT attempt
// whose TCP dial failed. We never sent any HTTP status to the client
// at this point (the 502 below is the http.Error response; the audit
// event captures the gbounce-internal decision). The host:port is
// extracted from r.Host the same way the happy-path CONNECT does so a
// SIEM pivot on dst_endpoint correlates failures with successes for
// the same target.
func (s *Server) recordFailedConnect(r *http.Request, startedAt time.Time, dialErr error) {
	errStr := ""
	if dialErr != nil {
		errStr = dialErr.Error()
	}
	// Persist http_status=502 (matches the BadGateway the proxy returned
	// to the client) so the SQLite-backed reconstruction in
	// audit.ReconstructOverridesFromRow recognises this row as the
	// #303 dial-failure shape.
	s.recordWith(r, startedAt, http.StatusBadGateway, 0, recordOverrides{
		// We INTENDED to allow this CONNECT — the upstream was simply
		// unreachable. Verdict stays ALLOW per the spec.
		Verdict:    "ALLOW",
		ActivityID: audit.ActivityConnect,
		StatusID:   audit.StatusFailure,
		ExtraExt: map[string]any{
			"connect_refused": true,
			"connect_error":   errStr,
		},
	})
}

// recordDeny audits a request the proxy refused as a POLICY decision
// (a deny_hosts / dynamic-deny match — see recordDenyWithSource for the
// rule-attributed variant). status_id is pinned to StatusDenied so a
// SIEM filter on `status_id=4` isolates real deny outcomes — and ONLY
// real deny outcomes: protocol/config rejects (e.g. a non-CONNECT verb
// on a CONNECT-only listener) go through recordReject (#685) as a
// Failure, never here. The path is captured from r.URL.Path so a denied
// host's request target stays visible in the audit row.
func (s *Server) recordDeny(r *http.Request, startedAt time.Time, httpStatus int, reason string) {
	ov := recordOverrides{
		Verdict:  "DENY",
		StatusID: audit.StatusDenied,
		ExtraExt: map[string]any{
			"deny_reason": reason,
		},
	}
	// #314 — pin ActivityConnect on a denied CONNECT so a SIEM filter
	// on `activity_id=6` finds every tunnel-establishment outcome
	// regardless of verdict (success / failure / denied). The pre-#314
	// recordDeny call site (#305's non-CONNECT-on-CONNECT-only path)
	// keeps the default method-derived activity since the rejected
	// verb is NOT CONNECT.
	if strings.EqualFold(r.Method, http.MethodConnect) {
		ov.ActivityID = audit.ActivityConnect
	}
	s.recordWith(r, startedAt, httpStatus, 0, ov)
}

// recordReject (#685) audits a request the proxy refused for a
// PROTOCOL or CONFIG reason — e.g. a non-CONNECT verb on a
// CONNECT-only listener (#305) — as distinct from a POLICY deny
// (recordDeny / recordDenyWithSource). The distinction matters for
// honesty: a protocol reject is NOT a security decision, so it must
// NOT read as status_id=4 "Denied". It lands as status_id=2
// "Failure" with verdict="ERROR" + ext.reject_reason, mirroring
// recordFailedConnect's treatment of an unreachable upstream (#303,
// "we made no deny decision; the request just couldn't proceed").
// This preserves the invariant that a discovery-mode bouncer with
// zero deny rules emits zero "Denied" events, while keeping the audit
// visibility (path, host, reason) #305 was built for. Because the
// verdict is "ERROR" (not "DENY"), the reject also stays out of the
// profile-allow "recent denies" list (denies.go filters Verdict=="DENY").
func (s *Server) recordReject(r *http.Request, startedAt time.Time, httpStatus int, reason string) {
	ov := recordOverrides{
		Verdict:  "ERROR",
		StatusID: audit.StatusFailure,
		ExtraExt: map[string]any{
			"reject_reason": reason,
		},
	}
	if strings.EqualFold(r.Method, http.MethodConnect) {
		ov.ActivityID = audit.ActivityConnect
	}
	s.recordWith(r, startedAt, httpStatus, 0, ov)
}

// recordDenyWithSource is the #324d entrypoint: same as recordDeny but
// also threads the matched rule's Source + DynamicDenyRuleID into the
// audit ext map so a SIEM analyst can answer "static or dynamic?" +
// "which dynamic rule?" without grepping the config files. Static
// matches land with `ext.deny_source="static"` + no rule id; dynamic
// matches land with `ext.deny_source="dynamic"` +
// `ext.dynamic_deny_rule_id="dd_..."`.
//
// Same shape as the cross-product design doc's
// `dynamic_deny.rule_fired` event — except it's NOT a separate event,
// it's an EXTRA FIELD on the verdict event, per the design doc's
// "emitted as part of the verdict OCSF event (NOT separately)" note.
func (s *Server) recordDenyWithSource(r *http.Request, startedAt time.Time, httpStatus int, reason string, rule *DenyHostRule) {
	extra := map[string]any{
		"deny_reason": reason,
	}
	if rule != nil {
		// Default to "static" when the matched rule pre-dates #324d's
		// Source field (defensive; ParseDenyHosts now pins Source for
		// every produced rule, but a third-party constructor might
		// pass a bare DenyHostRule literal).
		src := rule.Source
		if src == "" {
			src = DenySourceStatic
		}
		extra["deny_source"] = src
		if rule.DynamicDenyRuleID != "" {
			extra["dynamic_deny_rule_id"] = rule.DynamicDenyRuleID
		}
	}
	ov := recordOverrides{
		Verdict:  "DENY",
		StatusID: audit.StatusDenied,
		ExtraExt: extra,
	}
	if strings.EqualFold(r.Method, http.MethodConnect) {
		ov.ActivityID = audit.ActivityConnect
	}
	s.recordWith(r, startedAt, httpStatus, 0, ov)
}

// dynamicDenyActiveCount returns the number of rules currently in the
// dynamic-deny watcher's snapshot (post-filter, gbounce-applicable
// rules only). Used by /healthz + the mgmt-port reload endpoint.
func (s *Server) dynamicDenyActiveCount() int {
	if s.dynamicDeny == nil {
		return 0
	}
	snap := s.dynamicDeny.Snapshot()
	if snap == nil {
		return 0
	}
	return len(snap.Rules)
}

// dynamicDenyGlobCount returns the number of compiled deny globs the
// dynamic-deny snapshot contributes to the matcher (sum over each
// rule's Targets list).
func (s *Server) dynamicDenyGlobCount() int {
	if s.dynamicDeny == nil {
		return 0
	}
	snap := s.dynamicDeny.Snapshot()
	if snap == nil {
		return 0
	}
	n := 0
	for _, r := range snap.Rules {
		n += len(r.Targets)
	}
	return n
}

// dynamicDenyPath returns the on-disk path the watcher consults, or
// "" when the watcher is disabled.
func (s *Server) dynamicDenyPath() string {
	if s.dynamicDeny == nil {
		return ""
	}
	return s.dynamicDeny.Path()
}

// BumpDynamicDenyReload + BumpDynamicDenyParseError are exposed for
// the CLI layer's emit-func wiring. The CLI installs an emit callback
// on the watcher that bumps these counters + tees the OCSF admin-action
// event into the audit-log sink. Methods (not direct atomic access)
// so the counters can move out of Server in a future refactor without
// breaking the call site.
func (s *Server) BumpDynamicDenyReload()     { s.totalDynamicDenyReloads.Add(1) }
func (s *Server) BumpDynamicDenyParseError() { s.totalDynamicDenyParseErrors.Add(1) }

// effectiveDenyRules returns the union of static + dynamic deny rules
// the matcher should evaluate against on each CONNECT. Returns the
// dynamic-only rule count as the second value so callers (e.g.
// /healthz) can surface "dynamic count" separately from "total
// effective." Empty when no rules of either kind are configured.
//
// Dynamic-side parse errors are surfaced through the watcher's
// fail-CLOSED retain-previous semantic (see internal/dynamicdeny);
// this method never re-parses, just consumes the watcher's already-
// validated snapshot.
func (s *Server) effectiveDenyRules() ([]DenyHostRule, int) {
	if s.dynamicDeny == nil {
		return s.denyHosts, 0
	}
	snap := s.dynamicDeny.Snapshot()
	if snap == nil || len(snap.Rules) == 0 {
		return s.denyHosts, 0
	}
	// Build dynamic rules from the snapshot. Bad globs are skipped (a
	// future hardening pass could route these into the parse_error
	// admin-action channel; for #324d the loader already validates
	// the YAML shape — bad globs at the matcher layer would surface
	// only if an operator wrote `*.foo.*.bar` and the loader chose
	// not to reject it. Today the loader is shape-only; reject the
	// rule here so a single bad glob doesn't take down the proxy.
	out := make([]DenyHostRule, 0, len(s.denyHosts)+len(snap.Rules))
	out = append(out, s.denyHosts...)
	dynCount := 0
	for _, rule := range snap.Rules {
		for _, glob := range rule.Targets {
			compiled, err := ParseDynamicDenyHost(glob, rule.ID)
			if err != nil {
				continue
			}
			out = append(out, compiled)
			dynCount++
		}
	}
	return out, dynCount
}

// record builds + persists an OCSF event for the request/response
// pair. Best-effort: SQLite or JSONL failure logs nothing here (the
// proxy must keep serving), but they're surfaced via /healthz.
//
// Thin wrapper over recordWith with zero-value overrides so the existing
// happy-path call sites stay unchanged (see #303/#305 commentary above).
func (s *Server) record(r *http.Request, startedAt time.Time, status int, respSize int64) {
	s.recordWith(r, startedAt, status, respSize, recordOverrides{})
}

// recordWith is the shared implementation behind record /
// recordFailedConnect / recordDeny. Adds the recordOverrides parameter
// without growing the original record() signature.
func (s *Server) recordWith(r *http.Request, startedAt time.Time, status int, respSize int64, ov recordOverrides) {
	clientHost, clientPort := splitHostPort(r.RemoteAddr)
	var (
		upHost   string
		upPort   int
		upScheme string
	)
	if r.Method == http.MethodConnect {
		// CONNECT path: target host:port comes from r.Host. We don't
		// have a scheme — TLS passthrough means we never see the inner
		// request. Record what we know.
		h, ps := splitHostPortStr(r.Host)
		upHost = h
		if p, err := strconv.Atoi(ps); err == nil {
			upPort = p
		}
		upScheme = "" // unknown
	} else if s.upstreamURL != nil {
		upHost = s.upstreamURL.Hostname()
		upScheme = s.upstreamURL.Scheme
		if p := s.upstreamURL.Port(); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				upPort = n
			}
		} else if upScheme == "https" {
			upPort = 443
		} else if upScheme == "http" {
			upPort = 80
		}
	} else {
		// #305 — non-CONNECT request on a CONNECT-only listener. The
		// upstreamURL is unset (--upstream not configured) so the branch
		// above doesn't fire, BUT a plain-HTTP proxy request still
		// carries the intended target in r.URL.Host (or r.Host as
		// fallback) + the scheme in r.URL.Scheme. Capture both so an
		// IMDS probe (`GET http://169.254.169.254/latest/meta-data/`)
		// shows the dst_endpoint host in the audit row, not a blank
		// field.
		host := ""
		portStr := ""
		if r.URL != nil && r.URL.Host != "" {
			host, portStr = splitHostPortStr(r.URL.Host)
		}
		if host == "" {
			host, portStr = splitHostPortStr(r.Host)
		}
		upHost = host
		if p, err := strconv.Atoi(portStr); err == nil {
			upPort = p
		}
		if r.URL != nil {
			upScheme = r.URL.Scheme
		}
		// Default ports when the proxy URL omitted them.
		if upPort == 0 {
			if upScheme == "https" {
				upPort = 443
			} else if upScheme == "http" {
				upPort = 80
			}
		}
	}

	// #303 + #305 — verdict can be overridden by the caller. Default
	// remains "ALLOW" so happy-path call sites are unchanged.
	verdict := "ALLOW"
	if ov.Verdict != "" {
		verdict = ov.Verdict
	}
	// #308 — agent identity captured from the inbound headers BEFORE
	// the persistent row is built so the SQLite-backed reconstruction
	// (HTTP /audit/events + `gbounce audit tail`) carries the same
	// agent.name / agent.session_id as the JSONL log. Validation
	// happens here (rejects shell-injection chars + over-length
	// inputs); an invalid header is treated as if it were absent and a
	// stderr line surfaces the rejection so an operator debugging
	// "why is my session id missing?" sees it. Per
	// [[security-team-positioning-safety-not-surveillance]] we never
	// fabricate values — when detection fails the event surfaces as
	// anonymous so the operator knows attribution is missing.
	rawSessionID := r.Header.Get("X-Agent-Session-Id")
	rawAgentName := r.Header.Get("X-Agent-Name")
	agentSessionIDValidated := ""
	agentNameValidated := ""
	// #319 / §A17 (F-308-1) — record which header tripped validation so
	// the audit event surfaces an `unmapped.iam_jit.agent.rejected_reason`
	// breadcrumb. Without this an operator who sees "anonymous" rows can't
	// tell whether the client never sent a header or sent an invalid one;
	// the /healthz counter `total_agent_headers_rejected` was the only
	// existing signal, which is too coarse for "which agent's collector is
	// misconfigured?" investigation. Reasons are bounded enum strings
	// (NEVER include the raw header value here — that lives only in the
	// truncated-stderr line emitted by logAgentHeaderRejected so a
	// malicious agent can't fill the audit log with junk).
	//
	// #320 / §A18 ADDITIVE upgrade: the §A17 string lumped charset +
	// length failures together — SOC analysts couldn't distinguish
	// "agent SDK sending shell-injection-shaped payloads" from
	// "agent picked an overly-verbose canonical name." The new
	// `agent_header_rejection` breadcrumb splits these into a bounded
	// enum (invalid_name_charset / invalid_name_length /
	// invalid_session_id_format / invalid_session_id_length) AND
	// records the rejected value's LENGTH (never the value itself)
	// for safe forensics. Same shape across all four Bounce products
	// per [[cross-product-agent-parity]]. The §A17 string stays for
	// backward compat — additive per [[creates-never-mutates]].
	var agentRejectedReasons []string
	var agentRejectionBreadcrumbs []map[string]any
	if rawSessionID != "" {
		if audit.IsValidSessionID(rawSessionID) {
			agentSessionIDValidated = rawSessionID
		} else {
			s.logAgentHeaderRejected("X-Agent-Session-Id", rawSessionID)
			agentRejectedReasons = append(agentRejectedReasons, "session_id:invalid_charset_or_length")
			agentRejectionBreadcrumbs = append(agentRejectionBreadcrumbs,
				audit.BuildAgentHeaderRejectionBreadcrumb(
					audit.AgentSessionIDField,
					audit.ClassifyAgentSessionIDRejection(rawSessionID),
					len(rawSessionID),
				))
		}
	}
	if rawAgentName != "" {
		if audit.IsValidAgentName(rawAgentName) {
			agentNameValidated = rawAgentName
		} else {
			s.logAgentHeaderRejected("X-Agent-Name", rawAgentName)
			agentRejectedReasons = append(agentRejectedReasons, "agent_name:invalid_charset_or_length")
			agentRejectionBreadcrumbs = append(agentRejectionBreadcrumbs,
				audit.BuildAgentHeaderRejectionBreadcrumb(
					audit.AgentNameField,
					audit.ClassifyAgentNameRejection(rawAgentName),
					len(rawAgentName),
				))
		}
	}
	row := store.DecisionRow{
		At:             startedAt.UTC(),
		Method:         r.Method,
		Path:           r.URL.Path,
		UpstreamHost:   upHost,
		UpstreamPort:   upPort,
		UpstreamScheme: upScheme,
		ClientHost:     clientHost,
		ClientPort:     clientPort,
		HTTPStatus:     status,
		ResponseSize:   respSize,
		LatencyMS:      time.Since(startedAt).Milliseconds(),
		Verdict:        verdict,
		Mode:           string(s.cfg.Mode),
		Enforced:       false,
		// #308 — persisted agent identity feeds the cross-bouncer
		// audit-query filter; reconstruction in audit_events.go +
		// cli.go reads these columns back into the OCSF builder.
		AgentName:      agentNameValidated,
		AgentSessionID: agentSessionIDValidated,
	}
	if r.Method == http.MethodConnect {
		// For CONNECT, the path field carries the tunnel target so the
		// audit log answers "what did the client tunnel to?".
		row.Path = r.Host
	}

	var decisionID int64
	if s.store != nil {
		id, err := s.store.RecordDecision(row)
		if err == nil {
			decisionID = id
		}
	}
	if s.log != nil || s.recorder != nil {
		// #285 — agent session context from inbound headers. Empty is
		// fine; the recorder drops events without a session_id (raw
		// curl / unknown caller). When a client (Claude Code, Cursor,
		// custom agent) sets these headers, the event routes into the
		// matching per-session NDJSON file.
		// #308 — use the VALIDATED agent fields so the OCSF builder
		// emits the canonical `unmapped.iam_jit.agent.{name,session_id,
		// detected_from}` block + the legacy flat ext keys the
		// SessionRecorder reads stay correct.
		// #319 / §A17 (F-308-1) — merge agent-header rejection reasons
		// into the OCSF ExtraExt map so they land at
		// `unmapped.iam_jit.agent.rejected_reason` for SIEM query.
		extraExt := ov.ExtraExt
		if len(agentRejectedReasons) > 0 {
			if extraExt == nil {
				extraExt = map[string]any{}
			}
			// Reuse the existing reason if the caller already set one
			// (defensive — no current caller does, but keep additive
			// behavior so a future caller can attach extra context).
			if existing, ok := extraExt["agent_rejected_reason"]; ok {
				extraExt["agent_rejected_reason"] = fmt.Sprintf(
					"%v;%s", existing, strings.Join(agentRejectedReasons, ";"))
			} else {
				extraExt["agent_rejected_reason"] = strings.Join(agentRejectedReasons, ";")
			}
		}
		// #320 / §A18: structured rejection breadcrumb under the same
		// ExtraExt map. Lands at `unmapped.iam_jit.ext.agent_header_rejection`
		// — single map when one header failed, list of maps when both
		// failed. Per [[cross-product-agent-parity]] the shape is the
		// same in ibounce / kbouncer / dbounce.
		if len(agentRejectionBreadcrumbs) > 0 {
			if extraExt == nil {
				extraExt = map[string]any{}
			}
			if len(agentRejectionBreadcrumbs) == 1 {
				extraExt["agent_header_rejection"] = agentRejectionBreadcrumbs[0]
			} else {
				// Convert to []any for the OCSF wire shape (the Ext map's
				// type is map[string]any; nested untyped slices serialize
				// cleanly to JSON arrays).
				bs := make([]any, 0, len(agentRejectionBreadcrumbs))
				for _, b := range agentRejectionBreadcrumbs {
					bs = append(bs, b)
				}
				extraExt["agent_header_rejection"] = bs
			}
		}
		ev := audit.FromRequest(audit.RequestInput{
			At:                 row.At,
			DecisionID:         decisionID,
			Mode:               row.Mode,
			Method:             row.Method,
			Path:               row.Path,
			UpstreamHost:       row.UpstreamHost,
			UpstreamPort:       row.UpstreamPort,
			UpstreamScheme:     row.UpstreamScheme,
			ClientHost:         row.ClientHost,
			ClientPort:         row.ClientPort,
			HTTPStatus:         row.HTTPStatus,
			ResponseSize:       row.ResponseSize,
			LatencyMS:          row.LatencyMS,
			AgentSessionID:     agentSessionIDValidated,
			AgentName:          agentNameValidated,
			Verdict:            row.Verdict,
			ActivityIDOverride: ov.ActivityID,
			StatusIDOverride:   ov.StatusID,
			ExtraExt:           extraExt,
		})
		if s.log != nil {
			_ = s.log.Write(r.Context(), ev)
		}
		// #285 — per-session NDJSON tee. Record is fail-soft (disk
		// errors land on the recorder's lastErr counter + surface via
		// Status; never propagated into the proxy hot path so a busted
		// recording dir can't stall the proxy).
		if s.recorder != nil {
			s.recorder.Record(ev)
		}
		// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
		// Synchronous in-memory append; the background rotator handles
		// finalize uploads. Fail-soft so an unreachable bucket never
		// blocks the proxy hot path.
		if s.objectStorage != nil {
			s.objectStorage.Write(r.Context(), ev)
		}
	}
}

// logAgentHeaderRejected emits one stderr line + bumps the rejected-
// header counter when an inbound X-Agent-* header fails validation
// (#308). Bounded log shape: header name + truncated raw value (first
// 32 chars, single-quoted) — prevents a malicious agent from filling
// the operator's terminal with junk. The decision still gets audited
// (under name="anonymous") so the rejection isn't invisible; this log
// line is the side-channel debug aid.
//
// Per [[security-team-positioning-safety-not-surveillance]]: surfacing
// the rejection is SAFETY (operator sees attribution gap); the
// truncation is privacy-shaped (we don't echo arbitrary unbounded
// header bodies into the log). Control characters are replaced with
// '?' so an attacker who embeds an escape sequence can't reposition
// the cursor in an attached terminal.
func (s *Server) logAgentHeaderRejected(headerName, rawValue string) {
	s.totalAgentHeadersRejected.Add(1)
	truncated := rawValue
	if len(truncated) > 32 {
		truncated = truncated[:32] + "..."
	}
	clean := make([]byte, 0, len(truncated))
	for i := 0; i < len(truncated); i++ {
		c := truncated[i]
		if c < 0x20 || c > 0x7e {
			clean = append(clean, '?')
		} else {
			clean = append(clean, c)
		}
	}
	fmt.Fprintf(os.Stderr,
		"gbounce: rejected invalid %s header (value=%q) — request will be audited as anonymous\n",
		headerName, string(clean),
	)
}

// singleJoiningSlash joins a + b ensuring exactly one slash sits
// between them. Lifted from httputil.NewSingleHostReverseProxy.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// splitHostPort splits "host:port" into a host string + int port.
// Returns ("", 0) for empty input. Tolerates IPv6-literal forms.
func splitHostPort(s string) (string, int) {
	host, portStr := splitHostPortStr(s)
	p, _ := strconv.Atoi(portStr)
	return host, p
}

// splitHostPortStr is the string-only variant. Used for the CONNECT
// target which arrives as "host:port" with no other parsing context.
func splitHostPortStr(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return s, ""
	}
	return h, p
}

// LicensedForGbounce is the placeholder license-gate stub for future
// G-Slices that introduce paid-tier modes (profile, tap). G-Slice 1
// ships discovery mode only, which is FREE — this function is never
// called. Mirror of kbounce/dbounce license-gate stubs per
// [[cross-product-agent-parity]] + the #235 license-file plumbing
// queue.
//
// Returning an error here is the safe default once a paid mode is
// wired in: the caller falls back to ModeDiscovery + emits a notice
// pointing the operator at the licensing docs.
func LicensedForGbounce(mode Mode) error {
	if mode == ModeDiscovery {
		return nil
	}
	return fmt.Errorf("gbounce: mode %q requires a paid-tier license (see #235 license-file plumbing); falling back to discovery", mode)
}

// writeStructuredDeny403 emits the gbounce 403 wire body shaped per
// the canonical structured-deny schema (#459 / §A57b). Mirrors Python
// ibounce's 403 emit at iam_jit.bouncer.proxy.py:~3060 so an agent
// receives identical field names regardless of which bouncer caught
// the request — per [[cross-product-agent-parity]].
//
// Per [[creates-never-mutates]] the legacy `error` field is preserved
// so old grep-on-`error` clients keep working. The structured-deny
// fields are ADDITIVE.
//
// Per [[ambient-value-prop-and-friction-framing]] the wire shape
// leads with caught_by_bouncer (never "ERROR" / "DENIED" / "BLOCKED").
//
// Per [[ibounce-honest-positioning]] the classifier_hook field is set
// to "go-heuristic-only" so an operator can tell at a glance that
// this 403 was not classified by the LLM (which Python ibounce can
// call).
func writeStructuredDeny403(w http.ResponseWriter, r *http.Request, rule *DenyHostRule, legacyMsg, denySource string) {
	host := r.Host
	if r.URL != nil && r.URL.Host != "" {
		host = r.URL.Host
	}
	if host == "" && rule != nil {
		host = rule.Raw
	}
	hostOnly, _ := splitHostPortStr(host)
	if hostOnly == "" {
		hostOnly = host
	}

	action := gbounceStructuredDenyAction(r)
	resource := hostOnly
	ruleID := ""
	if rule != nil {
		ruleID = rule.DynamicDenyRuleID
	}
	deny := structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:               "gbounce",
		Action:                action,
		Resource:              resource,
		DenyReason:            legacyMsg,
		DenySource:            denySource,
		RuleIDIfDynamic:       ruleID,
		SuggestedAllowCommand: gbounceSuggestedAllowCommand(rule, resource, action, denySource),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	body := map[string]any{
		// Legacy keys (preserved per [[creates-never-mutates]] so old
		// SDK clients + scripts grepping on `error` keep working).
		"error":           legacyMsg,
		"decision_verdict": "deny",
		"decision_reason":  legacyMsg,
		// #459 — structured-deny additive fields.
		"caught_by_bouncer":                  deny.CaughtByBouncer,
		"is_likely_injection_classification": deny.IsLikelyInjectionClassification,
		"suggested_allow_command":            deny.SuggestedAllowCommand,
		"recommended_action":                 deny.RecommendedAction,
		"deny_event_id":                      deny.DenyEventID,
		"classifier_hook":                    deny.ClassifierHook,
		"deny_source_classified":             deny.DenySourceClassified,
		"structured_deny_schema_version":     deny.StructuredDenySchemaVersion,
	}
	_ = json.NewEncoder(w).Encode(body)
}

// gbounceStructuredDenyAction builds the gbounce-shaped action
// "METHOD:/path-prefix" used by the structureddeny heuristic. The
// path is left intact (not truncated) so destructive-verb path
// segments like "/users/delete" trip the heuristic.
func gbounceStructuredDenyAction(r *http.Request) string {
	method := r.Method
	if method == "" {
		method = "GET"
	}
	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}
	if path == "" {
		path = "/"
	}
	return method + ":" + path
}

// gbounceSuggestedAllowCommand synthesizes a one-line `gbounce profile
// allow ...` command for the agent to surface to an operator. When the
// deny is a dynamic-deny rule the command starts with `#` so
// DeriveRecommendedAction routes to rephrase+retry — dynamic-deny
// rules aren't allow-able from the CLI; the operator has to edit the
// YAML.
func gbounceSuggestedAllowCommand(rule *DenyHostRule, host, action, denySource string) string {
	if denySource == "dynamic_deny" {
		ruleID := ""
		if rule != nil {
			ruleID = rule.DynamicDenyRuleID
		}
		return "# dynamic-deny rule " + ruleID +
			" — edit the dynamic-deny YAML to allow this; rephrase+retry"
	}
	if host == "" {
		host = "*"
	}
	if action == "" {
		action = "*"
	}
	return "gbounce profile allow --target " + host +
		" --action " + action +
		" --reason '<why is this safe?>'"
}

// classifyGbounceDenySource maps a DenyHostRule onto the canonical
// deny_source enum the structureddeny package understands.
func classifyGbounceDenySource(rule *DenyHostRule) string {
	if rule == nil {
		return "unknown"
	}
	if rule.Source == DenySourceDynamic {
		return "dynamic_deny"
	}
	return "deny_hosts"
}
