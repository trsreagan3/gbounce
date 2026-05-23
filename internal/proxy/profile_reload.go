// profile_reload.go — #388 / §A25 Phase 2 POST /admin/profile/reload
// handler on the gbounce mgmt port.
//
// Re-reads profiles.yaml from disk + re-translates the active
// profile's deny_hosts + deny_rules into the proxy's compiled
// denyHosts + mitmRules so a `gbounce profile allow` (or any
// profile edit) takes effect on the next request without a restart.
//
// Response shape mirrors ibounce + kbouncer + dbounce per
// [[cross-product-agent-parity]]:
//
//	HTTP 200 application/json
//	{ "reloaded": true, "active_profile": "<name>",
//	  "rules_in_active_profile": N }
//
// Error shapes: 405 (non-POST), 401/403 (bearer-token gate),
// 400 (parse error), 409 (active profile missing from file).

package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/trsreagan3/gbounce/internal/profile"
)

func (s *Server) profileReloadHandler(requireBearer string, profilesPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProfileReloadJSON(w, http.StatusMethodNotAllowed,
				map[string]any{"reloaded": false, "error": "only POST is supported"})
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeProfileReloadJSON(w, http.StatusUnauthorized,
					map[string]any{"reloaded": false, "error": "Authorization: Bearer <token> required"})
				return
			}
			tok, ok := parseBearer(ah)
			// §A99 — constant-time compare; see audit_events.go
			// for the threat-model context.
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(requireBearer)) != 1 {
				writeProfileReloadJSON(w, http.StatusForbidden,
					map[string]any{"reloaded": false, "error": "bearer token rejected"})
				return
			}
		}

		currentName := s.ActiveProfileName()
		if currentName == "" {
			// No profile selected at startup. Successful no-op per
			// [[ibounce-honest-positioning]].
			writeProfileReloadJSON(w, http.StatusOK, map[string]any{
				"reloaded":                true,
				"no_active_profile":       true,
				"active_profile":          "",
				"rules_in_active_profile": 0,
			})
			return
		}

		resolvedPath := profilesPath
		if resolvedPath == "" {
			rp, perr := profile.DefaultProfilesPath()
			if perr != nil {
				writeProfileReloadJSON(w, http.StatusInternalServerError, map[string]any{
					"reloaded": false,
					"error":    "resolve_path_failed",
					"detail":   perr.Error(),
				})
				return
			}
			resolvedPath = rp
		}

		fresh, lerr := profile.LoadProfiles(resolvedPath)
		if lerr != nil {
			writeProfileReloadJSON(w, http.StatusBadRequest, map[string]any{
				"reloaded":       false,
				"error":          "parse_error",
				"detail":         lerr.Error(),
				"active_profile": currentName,
			})
			return
		}

		resolved, aerr := fresh.Active(currentName)
		if aerr != nil {
			writeProfileReloadJSON(w, http.StatusConflict, map[string]any{
				"reloaded": false,
				"error":    "active_profile_missing_from_file",
				"detail": "active profile " + currentName +
					" no longer present in profiles.yaml; refusing to silently swap",
				"active_profile": currentName,
			})
			return
		}

		if err := s.SetActiveProfile(resolved); err != nil {
			writeProfileReloadJSON(w, http.StatusBadRequest, map[string]any{
				"reloaded":       false,
				"error":          "translate_error",
				"detail":         err.Error(),
				"active_profile": currentName,
			})
			return
		}

		writeProfileReloadJSON(w, http.StatusOK, map[string]any{
			"reloaded":                  true,
			"active_profile":            resolved.Name,
			"rules_in_active_profile":   len(resolved.AllowRules),
			"deny_hosts_in_active_profile": len(resolved.DenyHosts),
			"deny_rules_in_active_profile": len(resolved.DenyRules),
		})
	}
}

func writeProfileReloadJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
