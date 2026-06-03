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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/injectionscan"
	"github.com/trsreagan3/gbounce/internal/mitm"
	"github.com/trsreagan3/gbounce/internal/profile"
	"github.com/trsreagan3/gbounce/internal/store"
	"github.com/trsreagan3/gbounce/internal/structureddeny"
	"github.com/trsreagan3/gbounce/internal/toolcallvalidator"
)

// maxBodySnapshotBytes caps the in-memory request/response body
// snapshot we hold for audit purposes. Bodies larger than this are
// streamed past with request_body_truncated=true marked in the
// audit row.
const maxBodySnapshotBytes = 1 << 20

// sourceProfileAllow is the decision_source value recorded when a
// profile allow_rule explicitly allowed the intercepted request.
// Mirrors dbounce's profile.SourceProfileAllow ("profile.allow") so
// the suite's audit attribution lines up across bouncers.
const sourceProfileAllow = "profile.allow"

// allowRuleCtxKey is the request-context key under which
// serveMITMRequest stashes the *profile.Rule that fired the allow,
// so the downstream recordMITMRequest can attribute the ALLOW to
// source=profile.allow without a wider signature change. Private
// zero-size type so it can't collide with another package's key.
type allowRuleCtxKey struct{}

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
				s.dynamicDenyLastFiredUnixMs.Store(time.Now().UnixMilli())
			} else {
				s.totalDenyHostMatches.Add(1)
				s.denyHostsLastFiredUnixMs.Store(time.Now().UnixMilli())
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
		// #682 — record so /admin/features surfaces the most-recent
		// MITM error (typically upstream cert pinning) instead of a
		// silent zero.
		recordFeatureError(&s.mitmLastError, "client TLS handshake failed: "+err.Error())
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
	// #682 — record the MITM "fire" (one decrypted request observed)
	// so /admin/features can answer "is MITM actually intercepting
	// anything" honestly. Distinct from totalMITMDenies which only
	// counts profile-rule denies.
	s.totalMITMIntercepted.Add(1)
	s.mitmLastFiredUnixMs.Store(time.Now().UnixMilli())
	startedAt := time.Now()

	// iam-jit #377 — profile allow_rules layer. Mirrors dbounce's
	// Profile.Evaluate Order 4 (matchAnyAllowRule): an explicit
	// allow_rule that matches the intercepted request OVERRIDES a
	// would-be deny_rule deny. We consult it BEFORE the deny_rules
	// FirstMatch below so the allow short-circuits the deny layer.
	//
	// PRECEDENCE (matches dbounce exactly): allow_rules sit ABOVE the
	// finer-grained deny_rules but BELOW the deny_hosts hard floor.
	// deny_hosts is enforced at the CONNECT pre-dial gate (see
	// handleMITMConnect, before the hijack), so a deny_hosts-blocked
	// destination never reaches serveMITMRequest — an allow_rule
	// structurally CANNOT resurrect it. That is the documented
	// deny_hosts.go posture ("deny_hosts WINS over any allow list")
	// and dbounce's "hard floor denies run before allow_rules" order.
	//
	// On match we stash the rule on the request context so the eventual
	// recordMITMRequest emits decision_source=profile.allow honestly,
	// then fall through to the normal proxy path (the deny FirstMatch
	// is skipped). The orthogonal opt-in safety scanners (tool-call
	// validator, response-injection scan) still run — an allow_rule
	// overrides the profile DENY decision, not the independent BETA
	// safety features.
	var matchedAllow *profile.Rule
	if matchedAllow = profile.FirstAllowMatch(s.mitmAllowRules, true, host, port, req.Method, req.URL.Path, req.URL.RawQuery); matchedAllow != nil {
		s.totalMITMAllows.Add(1)
		s.profileEnforcementLastFiredUnixMs.Store(time.Now().UnixMilli())
		req = req.WithContext(context.WithValue(req.Context(), allowRuleCtxKey{}, matchedAllow))
	} else if rule := profile.FirstMatch(s.mitmRules, true, host, port, req.Method, req.URL.Path, req.URL.RawQuery); rule != nil {
		s.totalMITMDenies.Add(1)
		s.profileEnforcementLastFiredUnixMs.Store(time.Now().UnixMilli())
		s.recordMITMDeny(req, host, port, startedAt, rule)
		legacyMsg := "gbounce: request denied by profile rule"
		if rule.Reason != "" {
			legacyMsg += ": " + rule.Reason
		}
		// #459 / §A57b — emit the structured-deny JSON body on the
		// MITM path so the agent sees the same caught_by_bouncer
		// framing it gets from the non-MITM and CONNECT paths. Per
		// [[cross-product-agent-parity]].
		writeRawHTTPStructuredDenyResponse(clientConn, req, host, legacyMsg, "static_profile")
		return
	}

	requestBodyBytes, bodyTruncated, err := readBounded(req.Body, maxBodySnapshotBytes)
	if err != nil {
		s.totalErrors.Add(1)
		writeRawHTTPResponse(clientConn, req, http.StatusBadGateway, "gbounce: read request body: "+err.Error())
		s.recordMITMRequest(req, host, port, startedAt, http.StatusBadGateway, 0, nil, false, false)
		return
	}
	redactedReqBody, reqRedacted := mitm.RedactBody(req.Header.Get("Content-Type"), requestBodyBytes)

	// #729 / BUILD-8 — hallucinated tool-call validator. Only runs on
	// POST-like bodies (the wire shapes we recognize all live in JSON
	// request bodies). Default OFF; only active when the profile opts
	// in via `validate_tool_calls.enabled: true`.
	tcResult, tcDecision := s.runToolCallValidator(req, requestBodyBytes)
	switch tcDecision {
	case toolcallvalidator.ActionDeny:
		s.totalToolCallValidatorDenies.Add(1)
		s.toolCallValidatorLastFiredUnixMs.Store(time.Now().UnixMilli())
		writeToolCallValidatorDenyResponse(clientConn, req, host, tcResult)
		s.recordMITMResponseWithToolCallFinding(req, host, port, startedAt, http.StatusUnprocessableEntity, 0, redactedReqBody, reqRedacted, bodyTruncated, tcResult, "deny")
		return
	case toolcallvalidator.ActionStrip:
		// Replace the request body with the stripped version BEFORE
		// the upstream dial; the upstream sees a sanitized body.
		newBody := toolcallvalidator.ApplyStrip(requestBodyBytes, tcResult)
		if len(newBody) > 0 {
			requestBodyBytes = newBody
			req.ContentLength = int64(len(newBody))
			req.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		}
		req.Header.Set("X-IAM-JIT-Hallucinated-Tool-Call", toolCallValidatorWarningHeader(tcResult))
		s.totalToolCallValidatorStrips.Add(1)
		s.toolCallValidatorLastFiredUnixMs.Store(time.Now().UnixMilli())
	case toolcallvalidator.ActionWarn:
		req.Header.Set("X-IAM-JIT-Hallucinated-Tool-Call", toolCallValidatorWarningHeader(tcResult))
		s.totalToolCallValidatorWarns.Add(1)
		s.toolCallValidatorLastFiredUnixMs.Store(time.Now().UnixMilli())
	}

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

	// #730 / BUILD-9 — indirect-prompt-injection response-body scan.
	// Only runs when MITM mode is active (we're here, so it is) AND
	// the active profile opts in. Default OFF per
	// [[mitm-beta-pii-pci-concern]] + [[ibounce-honest-positioning]].
	finalRespBody := respBodyBytes
	scanResult, scanDecision := s.runResponseInjectionScan(resp, respBodyBytes)
	switch scanDecision {
	case injectionscan.ActionDeny:
		// Block the response from reaching the agent. Emit a
		// structured caught_by_bouncer-shaped 403 with the indicator
		// list so the harness can surface why.
		s.totalInjectionScanDenies.Add(1)
		s.injectionScanLastFiredUnixMs.Store(time.Now().UnixMilli())
		writeInjectionScanDenyResponse(clientConn, req, host, scanResult)
		s.recordMITMResponseWithInjectionFinding(req, host, port, startedAt, http.StatusForbidden, 0, redactedReqBody, reqRedacted, bodyTruncated, scanResult, "deny")
		return
	case injectionscan.ActionStrip:
		finalRespBody = injectionscan.ApplyStrip(respBodyBytes, scanResult)
		// The body changed, so Content-Length on `resp` is stale.
		resp.Header.Set("Content-Length", strconv.Itoa(len(finalRespBody)))
		resp.ContentLength = int64(len(finalRespBody))
		resp.Header.Set("X-IAM-JIT-Injection-Warning", injectionWarningHeader(scanResult))
		s.totalInjectionScanStrips.Add(1)
		s.injectionScanLastFiredUnixMs.Store(time.Now().UnixMilli())
	case injectionscan.ActionWarn:
		resp.Header.Set("X-IAM-JIT-Injection-Warning", injectionWarningHeader(scanResult))
		s.totalInjectionScanWarns.Add(1)
		s.injectionScanLastFiredUnixMs.Store(time.Now().UnixMilli())
	}

	resp.Body = io.NopCloser(strings.NewReader(string(finalRespBody)))
	_ = resp.Write(clientConn)

	// For warn/strip/allow paths, record one event with the finding
	// fields merged into extras when detected.
	//
	// Precedence on the recording variant:
	//   1. BUILD-9 (response-side injection) — if detected, takes the
	//      injection variant (its indicators are response-shaped).
	//   2. BUILD-8 (request-side tool-call validator) — if detected
	//      but BUILD-9 didn't, record via the tool-call variant.
	//   3. Otherwise — plain recordMITMRequest.
	if scanResult.Detected && (scanDecision == injectionscan.ActionWarn || scanDecision == injectionscan.ActionStrip) {
		s.recordMITMResponseWithInjectionFinding(req, host, port, startedAt, resp.StatusCode, int64(len(finalRespBody)), redactedReqBody, reqRedacted, bodyTruncated, scanResult, string(scanDecision))
	} else if tcResult.Detected && (tcDecision == toolcallvalidator.ActionWarn || tcDecision == toolcallvalidator.ActionStrip) {
		s.recordMITMResponseWithToolCallFinding(req, host, port, startedAt, resp.StatusCode, int64(len(finalRespBody)), redactedReqBody, reqRedacted, bodyTruncated, tcResult, string(tcDecision))
	} else {
		s.recordMITMRequest(req, host, port, startedAt, resp.StatusCode, int64(len(finalRespBody)), redactedReqBody, reqRedacted, bodyTruncated)
	}
}

// recordMITMResponseWithInjectionFinding is the variant of recordMITMRequest
// that merges injection-scanner indicator fields into the OCSF event's
// `unmapped.iam_jit.ext` extras. Keeps the existing 6003 (API Activity)
// shape; the finding details ride alongside as ext fields so
// log-shipping pipelines pick them up automatically (no new class_uid
// required for v1.0).
func (s *Server) recordMITMResponseWithInjectionFinding(
	req *http.Request, host string, port int, startedAt time.Time,
	status int, respSize int64, redactedReqBody []byte, reqRedacted, truncated bool,
	r injectionscan.ScanResult, decidedAction string,
) {
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
	// Injection finding fields — present iff detected.
	if r.Detected {
		indicatorList := make([]map[string]any, 0, len(r.Indicators))
		for _, ind := range r.Indicators {
			indicatorList = append(indicatorList, map[string]any{
				"rule":     ind.Rule,
				"layer":    string(ind.Layer),
				"severity": string(ind.Severity),
				"source":   ind.Source,
				"snippet":  ind.Snippet,
			})
		}
		extras["injection_scan_detected"] = true
		extras["injection_scan_confidence"] = r.Confidence
		extras["injection_scan_action"] = decidedAction
		extras["injection_scan_indicators"] = indicatorList
		// MITRE ATLAS T0051 — LLM Prompt Injection. Citing the
		// taxonomy gives downstream OCSF consumers a stable join key.
		extras["injection_scan_mitre_attack_id"] = "T0051"
		if r.LowConfidenceExplanation != "" {
			extras["injection_scan_low_confidence_explanation"] = r.LowConfidenceExplanation
		}
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
		Enforced:       decidedAction == "deny" || decidedAction == "strip",
	}
	if decidedAction == "deny" {
		row.Verdict = "DENY"
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
			s.auditLogLastFiredUnixMs.Store(time.Now().UnixMilli())
		}
		if s.recorder != nil {
			s.recorder.Record(ev)
			s.sessionRecorderFireCount.Add(1)
			s.sessionRecorderLastFiredUnixMs.Store(time.Now().UnixMilli())
		}
		if s.objectStorage != nil {
			s.objectStorage.Write(req.Context(), ev)
			s.objectStorageFireCount.Add(1)
			s.objectStorageLastFiredUnixMs.Store(time.Now().UnixMilli())
		}
	}
}

// runResponseInjectionScan inspects the upstream response body for
// indirect-prompt-injection indicators per #730. Returns the verdict
// + the decided action (post-profile-config reconciliation). Returns
// ActionAllow when the scanner is disabled on the active profile or
// not configured — caller treats Allow as no-op.
func (s *Server) runResponseInjectionScan(resp *http.Response, body []byte) (injectionscan.ScanResult, injectionscan.Action) {
	prof := s.ActiveProfile()
	if prof == nil {
		return injectionscan.ScanResult{}, injectionscan.ActionAllow
	}
	pcfg := prof.InjectionScanResponseBodies
	if !pcfg.Enabled {
		return injectionscan.ScanResult{}, injectionscan.ActionAllow
	}
	cfg := injectionscan.DefaultConfig()
	cfg.Enabled = true
	if pcfg.Action != "" {
		cfg.Action = injectionscan.Action(pcfg.Action)
	}
	if len(pcfg.AllowlistPatterns) > 0 {
		cfg.AllowlistPatterns = pcfg.AllowlistPatterns
	}
	if pcfg.MaxBodyBytes > 0 {
		cfg.MaxBodyBytes = pcfg.MaxBodyBytes
	}
	if pcfg.MinConfidenceForDeny > 0 {
		cfg.MinConfidenceForDeny = pcfg.MinConfidenceForDeny
	}
	ct := ""
	if resp != nil {
		ct = resp.Header.Get("Content-Type")
	}
	result := injectionscan.ScanResponseBody(body, ct, cfg)
	return result, injectionscan.DecideAction(result, cfg)
}

// injectionWarningHeader serializes scanner indicators into a single
// HTTP header value. Format:
//
//	detected; rules=<csv>; confidence=<float>
//
// Kept short (≤ 256 bytes) so it survives downstream proxies that
// trim long header values.
func injectionWarningHeader(r injectionscan.ScanResult) string {
	names := make([]string, 0, len(r.Indicators))
	for _, ind := range r.Indicators {
		names = append(names, ind.Rule)
	}
	csv := strings.Join(names, ",")
	if len(csv) > 200 {
		csv = csv[:200]
	}
	return fmt.Sprintf("detected; rules=%s; confidence=%.2f", csv, r.Confidence)
}

// writeInjectionScanDenyResponse emits a 403 to the client with a
// structured caught_by_bouncer-shaped JSON body. The agent's harness
// sees the same `caught_by_bouncer` framing it gets from request-side
// denies (#459 / §A57b parity).
func writeInjectionScanDenyResponse(w io.Writer, req *http.Request, host string, r injectionscan.ScanResult) {
	if w == nil {
		return
	}
	indicators := make([]map[string]any, 0, len(r.Indicators))
	for _, ind := range r.Indicators {
		indicators = append(indicators, map[string]any{
			"rule":     ind.Rule,
			"layer":    string(ind.Layer),
			"severity": string(ind.Severity),
			"source":   ind.Source,
			"snippet":  ind.Snippet,
		})
	}
	payload := map[string]any{
		"caught_by_bouncer": "gbounce",
		"reason":            "indirect_prompt_injection_in_response_body",
		"host":              host,
		"confidence":        r.Confidence,
		"indicators":        indicators,
		"deny_source":       "injection_scanner",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		// Fall back to plain message rather than leaking a 500.
		writeRawHTTPResponse(w, req, http.StatusForbidden,
			"gbounce: indirect prompt injection detected in upstream response body")
		return
	}
	statusText := http.StatusText(http.StatusForbidden)
	if statusText == "" {
		statusText = "Forbidden"
	}
	headers := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		http.StatusForbidden, statusText, len(body),
	)
	_, _ = w.Write([]byte(headers))
	_, _ = w.Write(body)
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
	// iam-jit #377 — when an allow_rule fired (stashed on the context
	// by serveMITMRequest), attribute the ALLOW honestly so the audit
	// log shows the request was explicitly allowed by the profile
	// (source=profile.allow) rather than merely "not denied". Mirrors
	// dbounce's SourceProfileAllow attribution.
	if ar, ok := req.Context().Value(allowRuleCtxKey{}).(*profile.Rule); ok && ar != nil {
		extras["decision_source"] = sourceProfileAllow
		if ar.Source != "" {
			extras["allow_rule"] = ar.Source
		}
		if ar.Reason != "" {
			extras["allow_reason"] = ar.Reason
		}
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
		s.auditLogLastFiredUnixMs.Store(time.Now().UnixMilli())
		// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
		if s.objectStorage != nil {
			s.objectStorage.Write(req.Context(), ev)
			s.objectStorageFireCount.Add(1)
			s.objectStorageLastFiredUnixMs.Store(time.Now().UnixMilli())
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

// writeRawHTTPStructuredDenyResponse is the MITM-path equivalent of
// proxy.go's writeStructuredDeny403 — produces a structured-deny JSON
// body on the TLS-terminated client conn so the agent sees the same
// caught_by_bouncer wire shape it gets from the non-MITM and CONNECT
// paths (#459 / §A57b, [[cross-product-agent-parity]]).
//
// Per [[creates-never-mutates]] the legacy `error` field is preserved.
// Per [[ibounce-honest-positioning]] the classifier_hook field is set
// to "go-heuristic-only".
func writeRawHTTPStructuredDenyResponse(w io.Writer, req *http.Request, host, legacyMsg, denySource string) {
	if w == nil {
		return
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	path := "/"
	if req.URL != nil && req.URL.Path != "" {
		path = req.URL.Path
	}
	action := method + ":" + path
	suggested := "gbounce profile allow --target " + host +
		" --action " + action + " --reason '<why is this safe?>'"
	deny := structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:               "gbounce",
		Action:                action,
		Resource:              host,
		DenyReason:            legacyMsg,
		DenySource:            denySource,
		SuggestedAllowCommand: suggested,
	})
	body := map[string]any{
		"error":                              legacyMsg,
		"decision_verdict":                   "deny",
		"decision_reason":                    legacyMsg,
		"caught_by_bouncer":                  deny.CaughtByBouncer,
		"is_likely_injection_classification": deny.IsLikelyInjectionClassification,
		"suggested_allow_command":            deny.SuggestedAllowCommand,
		"recommended_action":                 deny.RecommendedAction,
		"deny_event_id":                      deny.DenyEventID,
		"classifier_hook":                    deny.ClassifierHook,
		"deny_source_classified":             deny.DenySourceClassified,
		"structured_deny_schema_version":     deny.StructuredDenySchemaVersion,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		// Fallback to the plain text path so we never silently drop
		// the deny on the wire.
		writeRawHTTPResponse(w, req, http.StatusForbidden, legacyMsg)
		return
	}
	resp := &http.Response{
		Status:        fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)),
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		ContentLength: int64(len(bodyBytes)),
		Body:          io.NopCloser(strings.NewReader(string(bodyBytes))),
		Request:       req,
	}
	_ = resp.Write(w)
}

// --------------------------------------------------------------------
// Hallucinated-tool-call validator wire-up (#729 / BUILD-8).
//
// Parallel to runResponseInjectionScan but inspecting the REQUEST body
// instead of the upstream response. The validator runs only when the
// active profile opts in. Default OFF — same posture as the response
// scanner per [[ibounce-honest-positioning]].
// --------------------------------------------------------------------

// runToolCallValidator inspects the request body for hallucinated tool-
// call shapes per #729. Returns the verdict + the decided action (post-
// profile-config reconciliation). Returns ActionAllow when the
// validator is disabled on the active profile.
func (s *Server) runToolCallValidator(req *http.Request, body []byte) (toolcallvalidator.ValidationResult, toolcallvalidator.Action) {
	prof := s.ActiveProfile()
	if prof == nil {
		return toolcallvalidator.ValidationResult{}, toolcallvalidator.ActionAllow
	}
	pcfg := prof.ValidateToolCalls
	if !pcfg.Enabled {
		return toolcallvalidator.ValidationResult{}, toolcallvalidator.ActionAllow
	}
	cfg := toolcallvalidator.DefaultConfig()
	cfg.Enabled = true
	if pcfg.Action != "" {
		cfg.Action = toolcallvalidator.Action(pcfg.Action)
	}
	if len(pcfg.AllowlistPatterns) > 0 {
		cfg.AllowlistPatterns = pcfg.AllowlistPatterns
	}
	if pcfg.MaxBodyBytes > 0 {
		cfg.MaxBodyBytes = pcfg.MaxBodyBytes
	}
	if pcfg.MinConfidenceForDeny > 0 {
		cfg.MinConfidenceForDeny = pcfg.MinConfidenceForDeny
	}
	// Operator corpus override path is recognized in the YAML; the
	// runtime loader for it is a follow-up — the file-system read
	// would need to be cached so we don't re-parse per-request. For
	// v1.0 the baked-in corpus is the active set; operators with
	// custom tools should add the names to allowlist_patterns until
	// the corpus loader lands.
	result := toolcallvalidator.Validate(body, cfg)
	return result, toolcallvalidator.DecideAction(result, cfg)
}

// toolCallValidatorWarningHeader serializes validator indicators into a
// single HTTP header value. Same shape as injectionWarningHeader.
//
//	detected; rules=<csv>; confidence=<float>
func toolCallValidatorWarningHeader(r toolcallvalidator.ValidationResult) string {
	names := make([]string, 0, len(r.Indicators))
	for _, ind := range r.Indicators {
		names = append(names, ind.Rule)
	}
	csv := strings.Join(names, ",")
	if len(csv) > 200 {
		csv = csv[:200]
	}
	return fmt.Sprintf("detected; rules=%s; confidence=%.2f", csv, r.Confidence)
}

// writeToolCallValidatorDenyResponse emits a 422 Unprocessable Entity
// with a structured caught_by_bouncer-shaped JSON body. 422 is
// semantically correct: the request body is syntactically valid but
// fails validation (vs. 403 which is for authz failures + injection).
//
// The harness sees the same `caught_by_bouncer` framing it gets from
// request-side denies (#459 / §A57b parity), with reason=
// hallucinated_tool_call_shape.
func writeToolCallValidatorDenyResponse(w io.Writer, req *http.Request, host string, r toolcallvalidator.ValidationResult) {
	if w == nil {
		return
	}
	indicators := make([]map[string]any, 0, len(r.Indicators))
	for _, ind := range r.Indicators {
		indicators = append(indicators, map[string]any{
			"rule":      ind.Rule,
			"shape":     ind.Shape,
			"tool_name": ind.ToolName,
			"severity":  string(ind.Severity),
			"source":    ind.Source,
			"reason":    ind.Reason,
		})
	}
	extracted := make([]map[string]string, 0, len(r.ExtractedCalls))
	for _, ec := range r.ExtractedCalls {
		extracted = append(extracted, map[string]string{
			"shape": ec.Shape,
			"name":  ec.Name,
		})
	}
	payload := map[string]any{
		"caught_by_bouncer": "gbounce",
		"reason":            "hallucinated_tool_call_shape",
		"host":              host,
		"confidence":        r.Confidence,
		"indicators":        indicators,
		"extracted_calls":   extracted,
		"deny_source":       "tool_call_validator",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		writeRawHTTPResponse(w, req, http.StatusUnprocessableEntity,
			"gbounce: hallucinated tool call shape detected in request body")
		return
	}
	statusText := http.StatusText(http.StatusUnprocessableEntity)
	if statusText == "" {
		statusText = "Unprocessable Entity"
	}
	headers := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		http.StatusUnprocessableEntity, statusText, len(body),
	)
	_, _ = w.Write([]byte(headers))
	_, _ = w.Write(body)
}

// recordMITMResponseWithToolCallFinding is the variant of
// recordMITMRequest that merges tool-call-validator indicator fields
// into the OCSF event's ext extras. Same shape as
// recordMITMResponseWithInjectionFinding (#730) — fields prefixed
// `tool_call_validator_` so log pipelines can disambiguate.
func (s *Server) recordMITMResponseWithToolCallFinding(
	req *http.Request, host string, port int, startedAt time.Time,
	status int, respSize int64, redactedReqBody []byte, reqRedacted, truncated bool,
	r toolcallvalidator.ValidationResult, decidedAction string,
) {
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
	if r.Detected {
		indicatorList := make([]map[string]any, 0, len(r.Indicators))
		for _, ind := range r.Indicators {
			indicatorList = append(indicatorList, map[string]any{
				"rule":      ind.Rule,
				"shape":     ind.Shape,
				"tool_name": ind.ToolName,
				"severity":  string(ind.Severity),
				"source":    ind.Source,
				"reason":    ind.Reason,
			})
		}
		extracted := make([]map[string]string, 0, len(r.ExtractedCalls))
		for _, ec := range r.ExtractedCalls {
			extracted = append(extracted, map[string]string{
				"shape": ec.Shape,
				"name":  ec.Name,
			})
		}
		extras["tool_call_validator_detected"] = true
		extras["tool_call_validator_confidence"] = r.Confidence
		extras["tool_call_validator_action"] = decidedAction
		extras["tool_call_validator_indicators"] = indicatorList
		extras["tool_call_validator_extracted_calls"] = extracted
		if r.LowConfidenceExplanation != "" {
			extras["tool_call_validator_low_confidence_explanation"] = r.LowConfidenceExplanation
		}
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
		Enforced:       decidedAction == "deny" || decidedAction == "strip",
	}
	if decidedAction == "deny" {
		row.Verdict = "DENY"
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
			s.auditLogLastFiredUnixMs.Store(time.Now().UnixMilli())
		}
		if s.recorder != nil {
			s.recorder.Record(ev)
			s.sessionRecorderFireCount.Add(1)
			s.sessionRecorderLastFiredUnixMs.Store(time.Now().UnixMilli())
		}
		if s.objectStorage != nil {
			s.objectStorage.Write(req.Context(), ev)
			s.objectStorageFireCount.Add(1)
			s.objectStorageLastFiredUnixMs.Store(time.Now().UnixMilli())
		}
	}
}
