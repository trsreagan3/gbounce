// mitm_handler.go — #315 / §A13. The CONNECT handler that runs when
// the proxy is started with `--mode mitm`. Terminates TLS on the
// client side using a CA-signed per-host leaf cert + re-encrypts to
// the real upstream. Body capture is run through the mitm redactor
// before any audit event is built.
//
// Per [[ibounce-honest-positioning]]: cert-pinning SDKs (most
// modern AWS SDKs, some banking SDKs, some mobile SDKs) will break
// here. The proxy returns a graceful 502 with a clear error message
// so the operator can flip the affected client back to CONNECT mode.
//
// Per [[creates-never-mutates]]: MITM is opt-in. The plain
// CONNECT-tunnel path (handleConnect) is preserved verbatim for
// `--mode discovery` runs.
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/mitm"
	"github.com/trsreagan3/gbounce/internal/profile"
	"github.com/trsreagan3/gbounce/internal/store"
)

// maxBodySnapshotBytes caps the in-memory request/response body
// snapshot we hold for audit purposes. Bodies larger than this are
// streamed past with request_body_truncated=true marked in the
// audit row.
const maxBodySnapshotBytes = 1 << 20

// mitmAllowInsecureUpstreamForTest is a TEST-ONLY toggle that bypasses
// upstream TLS verification when MITM mode dials the real upstream.
// Production code MUST leave this false — the upstream's real cert
// is verified against the system pool so a separately-MITM'd
// upstream still surfaces as a handshake error. Tests flip this to
// true to exercise the MITM hot path against an httptest.NewTLSServer
// (which produces a self-signed cert the system pool doesn't trust).
var mitmAllowInsecureUpstreamForTest = false

// handleMITMConnect is the MITM-mode CONNECT entry. Lifecycle:
//
//  1. Validate target host:port + deny_hosts check (same as
//     plain CONNECT)
//  2. Hijack the client TCP connection
//  3. Send 200 Connection established to the client
//  4. Wrap the client conn in a tls.Server using a per-host cert
//     minted from the loaded CA
//  5. Read HTTP/1.1 requests off the decrypted client stream + for
//     each one:
//     - Apply profile rules; deny -> emit audit + write 403
//     - Open a TLS conn to the real upstream
//     - Read body (bounded), redact, audit, forward (upstream sees
//     the ORIGINAL body; only the LOGGED snapshot is redacted)
//     - Stream the response back to the client
//  6. Loop until either side closes
func (s *Server) handleMITMConnect(w http.ResponseWriter, r *http.Request) {
	s.totalRequests.Add(1)
	startedAt := time.Now()
	target := r.Host
	if target == "" {
		http.Error(w, "gbounce: CONNECT missing host:port", http.StatusBadRequest)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusBadRequest, 0)
		return
	}

	// deny_hosts check — same shape as plain CONNECT + handleForward.
	// Runs BEFORE the hijack so a denied target never gets a 200
	// Connection established (the agent sees a clean 403).
	//
	// §A28b (#358) — use s.effectiveDenyRules() so dynamic-deny entries
	// (#324d) fire in MITM mode too. Pre-fix this called MatchDenyHosts
	// against s.denyHosts directly, which meant dynamic-deny rules
	// silently never evaluated for MITM CONNECT requests — only static
	// `--deny-host` entries did. The audit-event shape matches the other
	// two handlers (recordDenyWithSource sets ext.deny_source +
	// ext.dynamic_deny_rule_id when applicable).
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
				reason = fmt.Sprintf("matched dynamic-deny rule %s (%s)",
					rule.DynamicDenyRuleID, rule.Raw)
			}
			s.recordDenyWithSource(r, startedAt, http.StatusForbidden, reason, rule)
			http.Error(w, "gbounce: CONNECT denied by deny_hosts rule: "+rule.Raw,
				http.StatusForbidden)
			s.totalErrors.Add(1)
			return
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "gbounce: server does not support hijacking", http.StatusInternalServerError)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusInternalServerError, 0)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "gbounce: hijack: "+err.Error(), http.StatusInternalServerError)
		s.totalErrors.Add(1)
		s.record(r, startedAt, http.StatusInternalServerError, 0)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		s.totalErrors.Add(1)
		return
	}

	// Record the CONNECT itself so a SIEM filter on activity_id=6
	// sees the tunnel-establishment. The per-request audit events
	// (below) come additionally as activity_id=read/create/etc.
	s.record(r, startedAt, http.StatusOK, 0)

	host, portStr := splitHostPortStr(target)
	if host == "" {
		host = target
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	// TLS-terminate the client side using a per-host minted cert.
	tlsServerCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				sni = host
			}
			return s.mitmMinter.CertFor(sni)
		},
		MinVersion: tls.VersionTLS12,
	}
	tlsClient := tls.Server(clientConn, tlsServerCfg)
	if err := tlsClient.Handshake(); err != nil {
		_ = tlsClient.Close()
		s.totalMITMUpstreamHandshakeFailures.Add(1)
		return
	}
	defer tlsClient.Close()

	// HTTP/1.1 conversation over the now-decrypted client stream.
	reader := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = target
		}
		if req.Host == "" {
			req.Host = host
		}
		if req.RemoteAddr == "" {
			req.RemoteAddr = clientConn.RemoteAddr().String()
		}
		s.serveMITMRequest(req, tlsClient, host, port, target)
		_ = req.Body.Close()
	}
}

// serveMITMRequest is the per-decrypted-request handler called by
// handleMITMConnect's read loop.
func (s *Server) serveMITMRequest(req *http.Request, clientConn io.Writer, host string, port int, target string) {
	s.totalRequests.Add(1)
	startedAt := time.Now()

	if rule := profile.FirstMatch(s.mitmRules, true, host, port, req.Method, req.URL.Path, req.URL.RawQuery); rule != nil {
		s.totalMITMDenies.Add(1)
		s.recordMITMDeny(req, host, port, startedAt, rule)
		body := "gbounce: request denied by profile rule"
		if rule.Reason != "" {
			body += ": " + rule.Reason
		}
		writeRawHTTPResponse(clientConn, req, http.StatusForbidden, body)
		return
	}

	requestBodyBytes, bodyTruncated, err := readBounded(req.Body, maxBodySnapshotBytes)
	if err != nil {
		s.totalErrors.Add(1)
		writeRawHTTPResponse(clientConn, req, http.StatusBadGateway, "gbounce: read request body: "+err.Error())
		s.recordMITMRequest(req, host, port, startedAt, http.StatusBadGateway, 0, nil, false, false)
		return
	}
	redactedReqBody, reqRedacted := mitm.RedactJSONBody(requestBodyBytes)

	upstreamConn, err := tls.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: mitmAllowInsecureUpstreamForTest,
	})
	if err != nil {
		s.totalMITMUpstreamHandshakeFailures.Add(1)
		msg := buildMITMHandshakeFailureMessage(host, err)
		writeRawHTTPResponse(clientConn, req, http.StatusBadGateway, msg)
		s.recordMITMHandshakeFailure(req, host, port, startedAt, err)
		return
	}
	defer upstreamConn.Close()

	req.Body = io.NopCloser(strings.NewReader(string(requestBodyBytes)))
	if err := req.Write(upstreamConn); err != nil {
		s.totalErrors.Add(1)
		writeRawHTTPResponse(clientConn, req, http.StatusBadGateway, "gbounce: write upstream request: "+err.Error())
		s.recordMITMRequest(req, host, port, startedAt, http.StatusBadGateway, 0, redactedReqBody, reqRedacted, bodyTruncated)
		return
	}
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		s.totalErrors.Add(1)
		writeRawHTTPResponse(clientConn, req, http.StatusBadGateway, "gbounce: read upstream response: "+err.Error())
		s.recordMITMRequest(req, host, port, startedAt, http.StatusBadGateway, 0, redactedReqBody, reqRedacted, bodyTruncated)
		return
	}
	defer resp.Body.Close()

	respBodyBytes, _, err := readBounded(resp.Body, maxBodySnapshotBytes)
	if err != nil {
		s.totalErrors.Add(1)
		writeRawHTTPResponse(clientConn, req, http.StatusBadGateway, "gbounce: read upstream body: "+err.Error())
		s.recordMITMRequest(req, host, port, startedAt, http.StatusBadGateway, 0, redactedReqBody, reqRedacted, bodyTruncated)
		return
	}

	resp.Body = io.NopCloser(strings.NewReader(string(respBodyBytes)))
	_ = resp.Write(clientConn)

	s.recordMITMRequest(req, host, port, startedAt, resp.StatusCode, int64(len(respBodyBytes)), redactedReqBody, reqRedacted, bodyTruncated)
}

// readBounded copies up to maxBytes from r + returns the captured
// slice + a bool reporting whether truncation happened.
func readBounded(r io.Reader, maxBytes int) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	limited := io.LimitReader(r, int64(maxBytes)+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if len(buf) > maxBytes {
		buf = buf[:maxBytes]
		_, _ = io.Copy(io.Discard, r)
		return buf, true, nil
	}
	return buf, false, nil
}

// writeRawHTTPResponse builds + writes a minimal HTTP/1.1 response
// to the given Writer (the TLS-terminated client conn).
func writeRawHTTPResponse(w io.Writer, req *http.Request, status int, body string) {
	if w == nil {
		return
	}
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = "Status"
	}
	resp := &http.Response{
		Status:        fmt.Sprintf("%d %s", status, statusText),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(strings.NewReader(body)),
		Request:       req,
	}
	_ = resp.Write(w)
}

// recordMITMRequest emits the OCSF event for one MITM-intercepted
// request/response pair, with the #315-extended ext keys (url_path,
// url_query, request_method, request_body_redacted, response_status).
func (s *Server) recordMITMRequest(req *http.Request, host string, port int, startedAt time.Time, status int, respSize int64, redactedReqBody []byte, reqRedacted, truncated bool) {
	clientHost, clientPort := splitHostPort(req.RemoteAddr)
	redactedQuery, _ := mitm.RedactQueryParams(req.URL.RawQuery)
	extras := map[string]any{
		"url_path":              req.URL.Path,
		"url_query":             redactedQuery,
		"request_method":        req.Method,
		"request_body_redacted": reqRedacted,
		"response_status":       status,
	}
	if truncated {
		extras["request_body_truncated"] = true
	}
	if s.mitmAuditIncludeBodies && len(redactedReqBody) > 0 {
		extras["request_body_snapshot"] = string(redactedReqBody)
	}

	row := store.DecisionRow{
		At:             startedAt.UTC(),
		Method:         req.Method,
		Path:           buildPathWithQuery(req.URL.Path, redactedQuery),
		UpstreamHost:   host,
		UpstreamPort:   port,
		UpstreamScheme: "https",
		ClientHost:     clientHost,
		ClientPort:     clientPort,
		HTTPStatus:     status,
		ResponseSize:   respSize,
		LatencyMS:      time.Since(startedAt).Milliseconds(),
		Verdict:        "ALLOW",
		Mode:           string(ModeMITM),
		Enforced:       false,
	}
	rawSessionID := req.Header.Get("X-Agent-Session-Id")
	rawAgentName := req.Header.Get("X-Agent-Name")
	if rawSessionID != "" && audit.IsValidSessionID(rawSessionID) {
		row.AgentSessionID = rawSessionID
	}
	if rawAgentName != "" && audit.IsValidAgentName(rawAgentName) {
		row.AgentName = rawAgentName
	}
	var decisionID int64
	if s.store != nil {
		if id, err := s.store.RecordDecision(row); err == nil {
			decisionID = id
		}
	}
	if s.log != nil || s.recorder != nil {
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
			AgentSessionID: row.AgentSessionID,
			AgentName:      row.AgentName,
			Verdict:        row.Verdict,
			ExtraExt:       extras,
		})
		if s.log != nil {
			_ = s.log.Write(req.Context(), ev)
		}
		if s.recorder != nil {
			s.recorder.Record(ev)
		}
		// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
		if s.objectStorage != nil {
			s.objectStorage.Write(req.Context(), ev)
		}
	}
}

// recordMITMDeny emits a DENY audit event when a profile rule
// matched the intercepted MITM request.
func (s *Server) recordMITMDeny(req *http.Request, host string, port int, startedAt time.Time, rule *profile.Rule) {
	clientHost, clientPort := splitHostPort(req.RemoteAddr)
	redactedQuery, _ := mitm.RedactQueryParams(req.URL.RawQuery)
	reason := rule.Reason
	if reason == "" {
		reason = "matched profile rule: " + rule.Source
	}
	extras := map[string]any{
		"url_path":              req.URL.Path,
		"url_query":             redactedQuery,
		"request_method":        req.Method,
		"request_body_redacted": false,
		"response_status":       http.StatusForbidden,
		"deny_reason":           reason,
	}
	row := store.DecisionRow{
		At:             startedAt.UTC(),
		Method:         req.Method,
		Path:           buildPathWithQuery(req.URL.Path, redactedQuery),
		UpstreamHost:   host,
		UpstreamPort:   port,
		UpstreamScheme: "https",
		ClientHost:     clientHost,
		ClientPort:     clientPort,
		HTTPStatus:     http.StatusForbidden,
		LatencyMS:      time.Since(startedAt).Milliseconds(),
		Verdict:        "DENY",
		Mode:           string(ModeMITM),
		Enforced:       true,
	}
	rawSessionID := req.Header.Get("X-Agent-Session-Id")
	rawAgentName := req.Header.Get("X-Agent-Name")
	if rawSessionID != "" && audit.IsValidSessionID(rawSessionID) {
		row.AgentSessionID = rawSessionID
	}
	if rawAgentName != "" && audit.IsValidAgentName(rawAgentName) {
		row.AgentName = rawAgentName
	}
	var decisionID int64
	if s.store != nil {
		if id, err := s.store.RecordDecision(row); err == nil {
			decisionID = id
		}
	}
	if s.log != nil || s.recorder != nil {
		ev := audit.FromRequest(audit.RequestInput{
			At:               row.At,
			DecisionID:       decisionID,
			Mode:             row.Mode,
			Method:           row.Method,
			Path:             row.Path,
			UpstreamHost:     row.UpstreamHost,
			UpstreamPort:     row.UpstreamPort,
			UpstreamScheme:   row.UpstreamScheme,
			ClientHost:       row.ClientHost,
			ClientPort:       row.ClientPort,
			HTTPStatus:       row.HTTPStatus,
			LatencyMS:        row.LatencyMS,
			AgentSessionID:   row.AgentSessionID,
			AgentName:        row.AgentName,
			Verdict:          "DENY",
			StatusIDOverride: audit.StatusDenied,
			ExtraExt:         extras,
		})
		if s.log != nil {
			_ = s.log.Write(req.Context(), ev)
		}
		if s.recorder != nil {
			s.recorder.Record(ev)
		}
		// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
		if s.objectStorage != nil {
			s.objectStorage.Write(req.Context(), ev)
		}
	}
}

// recordMITMHandshakeFailure emits an audit event when the upstream
// TLS handshake fails inside MITM mode. Cert-pinning shape lands here.
func (s *Server) recordMITMHandshakeFailure(req *http.Request, host string, port int, startedAt time.Time, handshakeErr error) {
	clientHost, clientPort := splitHostPort(req.RemoteAddr)
	extras := map[string]any{
		"url_path":                       req.URL.Path,
		"request_method":                 req.Method,
		"response_status":                http.StatusBadGateway,
		"mitm_upstream_handshake_failed": true,
		"mitm_upstream_handshake_error":  truncErr(handshakeErr),
	}
	row := store.DecisionRow{
		At:             startedAt.UTC(),
		Method:         req.Method,
		Path:           req.URL.Path,
		UpstreamHost:   host,
		UpstreamPort:   port,
		UpstreamScheme: "https",
		ClientHost:     clientHost,
		ClientPort:     clientPort,
		HTTPStatus:     http.StatusBadGateway,
		LatencyMS:      time.Since(startedAt).Milliseconds(),
		Verdict:        "ALLOW",
		Mode:           string(ModeMITM),
		Enforced:       false,
	}
	var decisionID int64
	if s.store != nil {
		if id, err := s.store.RecordDecision(row); err == nil {
			decisionID = id
		}
	}
	if s.log != nil {
		ev := audit.FromRequest(audit.RequestInput{
			At:               row.At,
			DecisionID:       decisionID,
			Mode:             row.Mode,
			Method:           row.Method,
			Path:             row.Path,
			UpstreamHost:     row.UpstreamHost,
			UpstreamPort:     row.UpstreamPort,
			UpstreamScheme:   row.UpstreamScheme,
			ClientHost:       row.ClientHost,
			ClientPort:       row.ClientPort,
			HTTPStatus:       row.HTTPStatus,
			LatencyMS:        row.LatencyMS,
			Verdict:          row.Verdict,
			StatusIDOverride: audit.StatusFailure,
			ExtraExt:         extras,
		})
		_ = s.log.Write(req.Context(), ev)
		// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
		if s.objectStorage != nil {
			s.objectStorage.Write(req.Context(), ev)
		}
	}
}

// buildMITMHandshakeFailureMessage builds the helpful error string
// returned to the client when an upstream TLS handshake fails in
// MITM mode. Most callers landing here are cert-pinning SDKs.
func buildMITMHandshakeFailureMessage(host string, err error) string {
	return fmt.Sprintf(
		"gbounce: upstream TLS handshake failed for %s in MITM mode (%v). "+
			"This usually means the upstream SDK pins certs (e.g. some AWS SDKs, banking SDKs, mobile SDKs). "+
			"Switch this client to CONNECT-only mode (`--mode discovery --allow-connect`) — MITM cannot proxy cert-pinning callers.",
		host, err)
}

// buildPathWithQuery rebuilds "path?query" while preserving an empty
// query (i.e. just "path").
func buildPathWithQuery(path, query string) string {
	if query == "" {
		return path
	}
	return path + "?" + query
}

// truncErr converts an error to a string + caps it at 256 chars so a
// pathological error message doesn't bloat the audit row.
func truncErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}
