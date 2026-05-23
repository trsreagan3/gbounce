// profile_reload_test.go — #388 / §A25 Phase 2 admin endpoint tests.

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/gbounce/internal/profile"
	"github.com/trsreagan3/gbounce/internal/store"
)

func newReloadTestServer(t *testing.T, active *profile.Profile) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Host:                  "127.0.0.1",
		Port:                  0,
		MgmtHost:              "127.0.0.1",
		MgmtPort:              0,
		ForwardTimeoutSeconds: 5,
		AllowConnect:          true,
	}
	if active != nil {
		cfg.ActiveProfile = active
		cfg.ActiveProfileName = active.Name
	}
	srv, err := NewServer(cfg, st, nil, nil)
	require.NoError(t, err)
	return srv
}

func writeReloadProfilesYAML(t *testing.T, dir, name string, denyHosts int) string {
	t.Helper()
	body := "profiles:\n  " + name + ":\n    description: test\n"
	if denyHosts > 0 {
		body += "    deny_hosts:\n"
		for i := 0; i < denyHosts; i++ {
			body += "    - bad.example.com\n"
		}
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdminProfileReload_HotSwapsActiveProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GBOUNCE_PROFILES_PATH", filepath.Join(dir, "profiles.yaml"))
	path := writeReloadProfilesYAML(t, dir, "work", 0)
	ps, err := profile.LoadProfiles(path)
	require.NoError(t, err)
	active, _ := ps.Active("work")
	srv := newReloadTestServer(t, active)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.Equal(t, float64(0), body["deny_hosts_in_active_profile"])

	// Mutate the file (simulate `gbounce profile allow` adding rules
	// or the operator hand-editing) — add 2 deny_hosts to verify
	// re-translation kicked in.
	_ = writeReloadProfilesYAML(t, dir, "work", 2)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, float64(2), body["deny_hosts_in_active_profile"])

	// Hot-swap should be visible via ActiveProfile.
	got := srv.ActiveProfile()
	require.NotNil(t, got)
	require.Equal(t, 2, len(got.DenyHosts))
}

func TestAdminProfileReload_RejectsNonPOST(t *testing.T) {
	srv := newReloadTestServer(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", "")(rec, req)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminProfileReload_NoActiveProfileNoOp(t *testing.T) {
	srv := newReloadTestServer(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", "")(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.True(t, body["no_active_profile"].(bool))
}
