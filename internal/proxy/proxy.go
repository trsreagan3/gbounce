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
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// Mode is the proxy's operating mode. G-Slice 1 ships only
// ModeDiscovery; ModeProfile + ModeTap are reserved for G-Slices 2-3.
type Mode string

const (
	// ModeDiscovery parses + forwards + logs every call. No filtering.
	// FREE-tier, no license gate.
	ModeDiscovery Mode = "discovery"
)

// IsValid returns true if m is one of the known modes.
func (m Mode) IsValid() bool { return m == ModeDiscovery }

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
	httpSrv *http.Server
	mgmtSrv *http.Server
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
}

// NewServer builds a Server from the given Config + Store. Caller
// must call Serve to start listening. Audit log writer is OPTIONAL —
// pass a *audit.LogWriter to also tee decisions into JSONL; nil to
// skip.
func NewServer(cfg Config, st *store.Store, lw *audit.LogWriter) (*Server, error) {
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
		return nil, fmt.Errorf("gbounce: invalid mode %q (G-Slice 1 supports only %q)", cfg.Mode, ModeDiscovery)
	}

	timeout := time.Duration(cfg.ForwardTimeoutSeconds) * time.Second

	s := &Server{
		cfg:         cfg,
		store:       st,
		log:         lw,
		upstreamURL: up,
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

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
		_ = s.mgmtSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-proxyErr:
		return err
	case err := <-mgmtErr:
		return err
	}
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
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
		_ = s.mgmtSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-proxyErr:
		return err
	case err := <-mgmtErr:
		return err
	}
}

// handle is the proxy's catch-all HTTP handler. Routes CONNECT to
// the tunnel handler (when enabled) and everything else to the
// forward handler.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleForward(w, r)
}

// handleForward forwards a non-CONNECT request to the configured
// upstream. Streams the response body back to the client.
func (s *Server) handleForward(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)
	startedAt := time.Now()

	if s.upstreamURL == nil {
		// CONNECT-only mode: a non-CONNECT verb on the proxy port is a
		// configuration mismatch. 421 Misdirected Request is the
		// closest RFC code.
		http.Error(w, "gbounce: --upstream not configured; only CONNECT is accepted", http.StatusMisdirectedRequest)
		s.totalErrors.Add(1)
		return
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
	upstream, err := net.DialTimeout("tcp", target,
		time.Duration(s.cfg.ForwardTimeoutSeconds)*time.Second)
	if err != nil {
		http.Error(w, "gbounce: dial upstream: "+err.Error(), http.StatusBadGateway)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusBadGateway, 0)
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
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	body := map[string]any{
		"status":         "ok",
		"product":        "gbounce",
		"mode":           string(s.cfg.Mode),
		"upstream":       s.cfg.UpstreamURL,
		"allow_connect":  s.cfg.AllowConnect,
		"total_requests": s.totalRequests.Load(),
		"total_errors":   s.totalErrors.Load(),
	}
	if s.log != nil {
		body["audit_log_path"] = s.log.Path()
		body["audit_log_total"] = s.log.Total()
		body["audit_log_dropped"] = s.log.Dropped()
		if e := s.log.LastError(); e != "" {
			body["audit_log_last_error"] = e
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// record builds + persists an OCSF event for the request/response
// pair. Best-effort: SQLite or JSONL failure logs nothing here (the
// proxy must keep serving), but they're surfaced via /healthz.
func (s *Server) record(r *http.Request, startedAt time.Time, status int, respSize int64) {
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
		Verdict:        "ALLOW",
		Mode:           string(s.cfg.Mode),
		Enforced:       false,
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
	if s.log != nil {
		ev := audit.FromRequest(audit.RequestInput{
			At:             row.At,
			DecisionID:     decisionID,
			Mode:           row.Mode,
			Method:         row.Method,
			Path:           row.Path,
			UpstreamHost:   row.UpstreamHost,
			UpstreamPort:   row.UpstreamPort,
			UpstreamScheme: row.UpstreamScheme,
			ClientHost:     row.ClientHost,
			ClientPort:     row.ClientPort,
			HTTPStatus:     row.HTTPStatus,
			ResponseSize:   row.ResponseSize,
			LatencyMS:      row.LatencyMS,
		})
		_ = s.log.Write(r.Context(), ev)
	}
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
