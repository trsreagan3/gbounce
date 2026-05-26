// admin_auth.go — #524 BB-3 / #484 security-audit closure.
//
// Defense-in-depth middleware for the mgmt-port admin endpoints
// (POST /admin/dynamic-denies/reload, POST /admin/profile/reload, and
// any future POST /admin/*). The bind-time CLI gate already refuses
// to start when --mgmt-host is non-loopback without an
// --audit-events-token; this middleware closes the residual gap when
// a loopback-bound mgmt port is exposed externally via a port-forward,
// reverse proxy, or container-network bridge AND a future code path
// reaches NewServer without going through the CLI gate (config-file
// loaders, programmatic embeds, test harnesses).
//
// Threat model: an unauthenticated POST to /admin/dynamic-denies/reload
// or /admin/profile/reload could re-read attacker-controlled YAML the
// attacker dropped via a parallel filesystem write (or, in container
// shapes, via a shared volume). Even though the reload doesn't write
// new policy, it can SWAP the active rule set under the operator's
// feet — turning a fail-closed deployment into fail-open in the
// window between the attacker's write + the operator's next probe.
//
// Policy enforced here:
//   - mgmtHost is loopback:
//       - token unset: pass-through (preserves existing UX — operators
//         on loopback never had to set a token + we don't break that
//         contract). The loopback bind is itself a trust anchor.
//       - token set: require Authorization: Bearer <token> with a
//         constant-time compare (mirrors /audit/events § A99).
//   - mgmtHost is NOT loopback:
//       - token unset: 503 with operator hint pointing at
//         --audit-events-token. This SHOULD be unreachable (CLI gate
//         already refuses startup) — present here as defense-in-depth
//         for future code paths that bypass the CLI gate.
//       - token set: require Authorization: Bearer <token> with a
//         constant-time compare.
//
// Per [[cross-product-agent-parity]] the same middleware ships
// byte-identical in kbouncer + dbounce (function names + behavior +
// error-message shape).
//
// Per [[ibounce-honest-positioning]] the error messages are explicit
// about WHY the request was rejected so operators can fix the
// misconfig instead of guessing.

package proxy

import (
	"crypto/subtle"
	"net/http"
)

// isLoopbackMgmtHost mirrors internal/cli/cli.go's loopbackHosts
// allowlist so the runtime middleware uses the SAME definition the
// startup gate uses. Diverging definitions would create a window
// where the startup gate accepts a host the middleware then rejects.
func isLoopbackMgmtHost(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "[::1]", "localhost",
		"ip6-localhost", "ip6-loopback":
		return true
	}
	return false
}

// requireMgmtAuth is the runtime defense-in-depth gate for the
// mgmt-port admin endpoints. See the file header for the policy
// matrix.
//
// next is the unprotected handler this middleware wraps. token is
// cfg.AuditEventsToken (the same secret the bind-time gate validates
// against). mgmtHost is cfg.MgmtHost (the configured bind host, not
// the resolved listener address — the cli layer normalizes both into
// MgmtHost before NewServer runs).
//
// Returns an http.HandlerFunc with the same signature as next so the
// wiring in NewServer reads cleanly:
//
//	mgmtMux.HandleFunc("/admin/profile/reload",
//	    requireMgmtAuth(s.profileReloadHandler(...), cfg.AuditEventsToken, cfg.MgmtHost))
func requireMgmtAuth(next http.HandlerFunc, token, mgmtHost string) http.HandlerFunc {
	loopback := isLoopbackMgmtHost(mgmtHost)
	return func(w http.ResponseWriter, r *http.Request) {
		// External bind + no token configured: fail closed with an
		// operator-actionable hint. The CLI gate already refuses this
		// shape at startup; reaching here means a code path bypassed
		// the gate (e.g. test harness, programmatic embed). Surface
		// the misconfig instead of silently allowing the request.
		if !loopback && token == "" {
			http.Error(w,
				"mgmt port bound externally without --audit-events-token; "+
					"refuse /admin/* per #524 BB-3. Set --audit-events-token "+
					"or bind --mgmt-host to loopback.",
				http.StatusServiceUnavailable)
			return
		}
		// Token configured (loopback or external): always enforce.
		if token != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				http.Error(w,
					"Authorization: Bearer <token> required",
					http.StatusUnauthorized)
				return
			}
			tok, ok := parseBearer(ah)
			// §A99 — constant-time compare; a wall-clock-string
			// compare leaks the configured token byte-by-byte over
			// enough requests.
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(token)) != 1 {
				http.Error(w,
					"bearer token rejected",
					http.StatusUnauthorized)
				return
			}
		}
		// Loopback + no token: legacy pass-through. The loopback bind
		// is itself a trust anchor; operators who haven't set a token
		// rely on the kernel + the bind-time gate for protection.
		next.ServeHTTP(w, r)
	}
}

// requestAuthenticatedOrLoopback is the BB-4 helper for /healthz field
// scoping on gbounce. Returns true when the caller is on loopback OR
// the request carries a valid bearer token. Used to gate the
// upstream_url + per-counter operational fields so an externally-bound
// /healthz that the operator forgot to put behind a reverse proxy
// doesn't leak the upstream target + operational signal to unauth
// scanners.
//
// Returns true under any of:
//   - mgmtHost is loopback (existing trust anchor)
//   - r.RemoteAddr resolves to a loopback IP (defense-in-depth — even
//     if mgmtHost is somehow non-loopback at config time, a request
//     that ARRIVED over loopback gets the full payload)
//   - token is set AND the request carries a valid Authorization
//     header with a constant-time match
//
// Returns false otherwise (unauth external request → scoped payload).
func requestAuthenticatedOrLoopback(r *http.Request, token, mgmtHost string) bool {
	if isLoopbackMgmtHost(mgmtHost) {
		return true
	}
	if remoteAddrIsLoopback(r.RemoteAddr) {
		return true
	}
	if token == "" {
		return false
	}
	ah := r.Header.Get("Authorization")
	if ah == "" {
		return false
	}
	tok, ok := parseBearer(ah)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(token)) == 1
}

// remoteAddrIsLoopback returns true if the http.Request.RemoteAddr
// (which is host:port) resolves to a loopback IP. Defensive parsing —
// a malformed RemoteAddr returns false (fail-closed for the
// authenticated-or-loopback gate).
func remoteAddrIsLoopback(remoteAddr string) bool {
	// Strip the port (RemoteAddr is always host:port for HTTP).
	// Walk backwards to the last ':' to handle "[::1]:1234" correctly.
	host := remoteAddr
	for i := len(remoteAddr) - 1; i >= 0; i-- {
		if remoteAddr[i] == ':' {
			host = remoteAddr[:i]
			break
		}
	}
	// Strip brackets from IPv6 literal.
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	switch host {
	case "127.0.0.1", "::1":
		return true
	}
	// IPv4-mapped IPv6 loopback.
	if host == "::ffff:127.0.0.1" {
		return true
	}
	return false
}
