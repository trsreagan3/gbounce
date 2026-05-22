// dynamic_deny_reload.go — #324d POST /admin/dynamic-denies/reload
// handler on the mgmt port (default 8769).
//
// The handler triggers an immediate reload of the dynamic-deny YAML
// from disk + returns a structured JSON payload describing the result.
// Useful for the cross-bouncer fan-out CLI (#324e), which will write
// the YAML on the operator's host + call this endpoint on each Bounce
// product's mgmt port to confirm "rules are live."
//
// Success shape:
//
//	HTTP 200 application/json
//	{
//	  "reloaded": true,
//	  "rules_count": N,
//	  "rules_applied_to_gbounce": M,
//	  "path": "/home/.../dynamic-denies.yaml"
//	}
//
// Error shape (parse / schema failure on the file):
//
//	HTTP 422 application/json
//	{
//	  "reloaded": false,
//	  "error": "<structured error>",
//	  "previous_rules_count": N  // pre-reload snapshot retained
//	}
//
// Other error shapes:
//
//	HTTP 405: non-POST verb
//	HTTP 401 / 403: bearer-token gate (mirrors /audit/events)
//	HTTP 503: watcher not configured (the operator didn't pass
//	          --dynamic-denies-path)
//
// Per [[cross-product-agent-parity]] the shape ships identically in
// the other Bounce products (#324a/b/c); the cross-bouncer CLI keys
// on the same JSON shape regardless of which product replied.

package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/trsreagan3/gbounce/internal/dynamicdeny"
)

// dynamicDenyReloadHandler builds the POST /admin/dynamic-denies/reload
// handler. Pass requireBearer="" to allow unauthenticated requests
// (loopback-only deploys); a non-empty token gates external binds.
func (s *Server) dynamicDenyReloadHandler(requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeReloadError(w, http.StatusMethodNotAllowed, "only POST is supported")
			return
		}
		// Auth gate mirrors /audit/events.
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeReloadError(w, http.StatusUnauthorized, "Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearer(ah)
			if !ok || tok != requireBearer {
				writeReloadError(w, http.StatusForbidden, "bearer token rejected")
				return
			}
		}
		if s.dynamicDeny == nil {
			writeReloadError(w, http.StatusServiceUnavailable,
				"dynamic-deny watcher not configured (gbounce was started without --dynamic-denies-path)")
			return
		}
		rs, err := s.dynamicDeny.ReloadNow(dynamicdeny.ReasonReloadRequested)
		if err != nil {
			// Parse / schema error → retain previous snapshot (the
			// watcher already did this). Surface enough detail for the
			// operator to fix the file; the OCSF audit event has the
			// full reason for SIEM ingest.
			prev := 0
			if rs != nil {
				prev = len(rs.Rules)
			}
			body := map[string]any{
				"reloaded":             false,
				"error":                err.Error(),
				"previous_rules_count": prev,
				"path":                 s.dynamicDeny.Path(),
			}
			writeJSON(w, http.StatusUnprocessableEntity, body)
			return
		}
		// On a successful reload bump the reload counter so /healthz +
		// the operator-side `gbounce` instrumentation reflects the
		// activity.
		s.BumpDynamicDenyReload()
		body := map[string]any{
			"reloaded":                  true,
			"rules_count":               s.dynamicDenyAllRulesCount(),
			"rules_applied_to_gbounce":  len(rs.Rules),
			"path":                      s.dynamicDeny.Path(),
		}
		writeJSON(w, http.StatusOK, body)
	}
}

// dynamicDenyAllRulesCount returns the TOTAL active rule count loaded
// from the YAML file (pre-filter). At #324d gbounce only sees its own
// applicable slice (filtering happens inside the loader), so this is
// the same as the gbounce-applicable count. Surfaces as a separate
// field on the reload response so the cross-bouncer CLI can present
// "M of N rules applied to this bouncer" without inferring it from
// missing fields.
func (s *Server) dynamicDenyAllRulesCount() int {
	return s.dynamicDenyActiveCount()
}

// writeReloadError emits a structured-error JSON body with the given
// status code. Mirrors writeAuditError from audit_events.go so the
// cross-product fan-out CLI parses both endpoints identically.
func writeReloadError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"reloaded": false,
		"error":    msg,
	})
}

// writeJSON writes an arbitrary JSON body with the given status code.
// Local helper so the reload handler doesn't pull on the audit_events
// helpers (which are scoped to the audit-events response shape).
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
