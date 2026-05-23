package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// methodSliceToStrings normalizes a RuleSpec.Method (declared `any` to
// tolerate string + list-of-string shapes from YAML) into []string for
// test assertion. yaml.v3 decodes a sequence into []any by default; the
// shim's mergeGeneratorRules constructs []string directly. Tests
// exercise both paths.
func methodSliceToStrings(t *testing.T, m any) []string {
	t.Helper()
	switch v := m.(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	t.Fatalf("methodSliceToStrings: unsupported method type %T", m)
	return nil
}

// startTLSPayloadServer returns an httptest.NewTLSServer that responds
// to every GET with the given bytes. Mirrors the kbouncer + dbounce
// test helper of the same name.
func startTLSPayloadServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tmpProfilesPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "profiles.yaml")
}

// generatorBundleYAML is the canonical per-bouncer file shape `iam-jit
// profile generate-from-audit` writes into out_dir/gbounce.yaml.
const generatorBundleYAML = `schema_version: 1
profile_name: scenario-block-imds
bouncer: gbounce
provenance:
  source: "audit"
  llm_backend: "deterministic-fallback"
  events_analyzed: 0
denies:
  - target: "169.254.169.254"
    reason: "IMDS access from agent context is credential exfiltration"
  - target: "dns.google"
    reason: "DNS-over-HTTPS bypasses egress filtering"
  - target: "api.openai.com"
    actions: ["POST"]
    reason: "no LLM calls in staging"
allows:
  - target: "api.example.com"
    actions: ["GET"]
    reason: "observed traffic"
flagged_for_review: []
skipped: []
`

// TestInstall_FromGeneratorShape — install a generator-emitted YAML
// from a local file. Asserts the resulting on-disk Profile carries the
// denies in the right slots (deny_hosts for hostname-only entries,
// deny_rules for entries with `actions:`).
func TestInstall_FromGeneratorShape(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "gbounce.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(generatorBundleYAML), 0o600))

	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         srcPath,
		ProfilesPath: target,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"scenario-block-imds"}, res.InstalledNames)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("scenario-block-imds")
	require.NoError(t, err)
	require.NotNil(t, p)

	// Source forced to absolute path (canonical).
	abs, _ := filepath.Abs(srcPath)
	assert.Equal(t, abs, p.Source, "source must be the absolute fetch path")

	// Hostname-only denies → deny_hosts.
	assert.Contains(t, p.DenyHosts, "169.254.169.254")
	assert.Contains(t, p.DenyHosts, "dns.google")
	assert.NotContains(t, p.DenyHosts, "api.openai.com",
		"target with actions: must NOT become a deny_host (deny_rules instead)")

	// `target: api.openai.com` + `actions: [POST]` → deny_rules entry.
	require.Len(t, p.DenyRules, 1, "expected one deny_rule from POST action")
	rule := p.DenyRules[0]
	assert.Equal(t, "api.openai.com", rule.Host)
	// Method round-trips through YAML (as `[]any` on the way back in)
	// so accept either []string or []any with string entries.
	methodStrs := methodSliceToStrings(t, rule.Method)
	assert.Equal(t, []string{"POST"}, methodStrs)

	// allows: also round-trips into AllowRules even though gbounce
	// doesn't enforce them in v1.0.
	require.Len(t, p.AllowRules, 1)
	assert.Equal(t, "api.example.com", p.AllowRules[0].Host)
}

// TestInstall_FromLocalPath — bare local path (no scheme) installs.
func TestInstall_FromLocalPath(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  acme-staging:
    description: "staging"
    deny_hosts:
      - evil.example.com
`), 0o600))
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         srcPath,
		ProfilesPath: target,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme-staging"}, res.InstalledNames)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("acme-staging")
	require.NoError(t, err)
	assert.Contains(t, p.DenyHosts, "evil.example.com")
}

// TestInstall_FromFileURL — file:// scheme installs.
func TestInstall_FromFileURL(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  acme:
    deny_hosts: [foo.example.com]
`), 0o600))
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         "file://" + srcPath,
		ProfilesPath: target,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, res.InstalledNames)
}

// TestInstall_FromHTTPSURL — happy path via httptest.NewTLSServer.
func TestInstall_FromHTTPSURL(t *testing.T) {
	payload := []byte(`profiles:
  acme-readonly:
    description: "no writes"
    deny_hosts: ["169.254.169.254"]
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, srv.URL, res.SourceURL)
	assert.Equal(t, []string{"acme-readonly"}, res.InstalledNames)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("acme-readonly")
	require.NoError(t, err)
	assert.Equal(t, srv.URL, p.Source)
	assert.Contains(t, p.DenyHosts, "169.254.169.254")
}

// TestInstall_FromBundleDirectoryPrefersGbounceYaml — when From is a
// directory, gbounce.yaml is preferred over index.yaml.
func TestInstall_FromBundleDirectoryPrefersGbounceYaml(t *testing.T) {
	bundleDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, "gbounce.yaml"),
		[]byte(generatorBundleYAML), 0o600))
	// Also write a different index.yaml + ibounce.yaml to confirm the
	// gbounce.yaml shortcut wins (not the index entry).
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, "index.yaml"),
		[]byte(`profiles:
  - bouncer: gbounce
    file: ibounce.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, "ibounce.yaml"),
		[]byte(`profile_name: SHOULD-NOT-WIN
bouncer: gbounce
denies:
  - target: should-not-appear.example.com
`), 0o600))

	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         bundleDir,
		ProfilesPath: target,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"scenario-block-imds"}, res.InstalledNames,
		"gbounce.yaml must win over index.yaml when both are present")
}

// TestInstall_FromBundleDirectoryFallsBackToIndex — when no
// gbounce.yaml is present, index.yaml + the gbounce-bouncer entry is
// the fallback.
func TestInstall_FromBundleDirectoryFallsBackToIndex(t *testing.T) {
	bundleDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, "g-profile.yaml"),
		[]byte(generatorBundleYAML), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, "index.yaml"),
		[]byte(`profiles:
  - bouncer: gbounce
    file: g-profile.yaml
`), 0o600))

	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         bundleDir,
		ProfilesPath: target,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"scenario-block-imds"}, res.InstalledNames)
}

// TestInstall_UnknownSchemeRefused — non-supported scheme (gopher://)
// fails with InstallExitOperator.
func TestInstall_UnknownSchemeRefused(t *testing.T) {
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{
		From:         "gopher://example.invalid/p.yaml",
		ProfilesPath: target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "no profiles file should have been created")
}

// TestInstall_SHA256VerifiedHappyPath — pin matches; SHA256Verified=true.
func TestInstall_SHA256VerifiedHappyPath(t *testing.T) {
	payload := []byte(`profiles:
  x:
    description: ok
`)
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, payload, 0o600))

	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:           srcPath,
		ExpectedSHA256: want,
		ProfilesPath:   target,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.SHA256Verified)
	assert.Equal(t, want, res.SHA256)
}

// TestInstall_SHA256Mismatch — pin mismatch → exit 2.
func TestInstall_SHA256Mismatch(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath,
		[]byte("profiles:\n  x:\n    description: ok\n"), 0o600))
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{
		From:           srcPath,
		ExpectedSHA256: strings.Repeat("0", 64),
		ProfilesPath:   target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "sha256 mismatch")
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr))
}

// TestInstall_ConflictRefusedWithoutForce — installing a same-name
// profile a second time fails with InstallExitOperator unless --force.
func TestInstall_ConflictRefusedWithoutForce(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  acme:
    deny_hosts: [a.example.com]
`), 0o600))

	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)

	// Second install of same name without --force fails.
	_, err = Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "already exist")

	// With --force the install succeeds.
	_, err = Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target, Force: true})
	require.NoError(t, err)
}

// TestInstall_ValidationRejectsBadDenyHost — install refuses a payload
// whose deny_hosts entry has a multi-level wildcard.
func TestInstall_ValidationRejectsBadDenyHost(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  bad:
    deny_hosts: ["*.foo.*.bar"]
`), 0o600))
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitPayload, ie.ExitCode)
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr),
		"validation failure must abort the install — no on-disk file")
}

// TestInstall_RecordsHashOnHTTPS — the SHA256 field on the result is
// the hex hash of the fetched bytes regardless of whether a pin was
// supplied.
func TestInstall_RecordsHashOnHTTPS(t *testing.T) {
	payload := []byte(`profiles:
  acme:
    deny_hosts: [a.example.com]
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)
	want := sha256.Sum256(payload)
	assert.Equal(t, hex.EncodeToString(want[:]), res.SHA256)
	assert.False(t, res.SHA256Verified, "no pin → verified=false")
}

// TestInstall_HTTPLoadsPayload — http:// scheme is accepted (the WARN
// gate lives at the CLI layer; package-level Install does not block).
// Pre-§A27 mirror: dbounce + kbouncer also accept http://. The CLI
// surfaces a WARN for non-loopback hosts.
func TestInstall_HTTPLoadsPayload(t *testing.T) {
	payload := []byte(`profiles:
  acme:
    deny_hosts: ["a.example.com"]
`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL, // http:// loopback
		ProfilesPath: target,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, res.InstalledNames)
}

// TestInstall_GeneratorDeniesDeduplicateWithCanonical — when an
// operator hand-authors a canonical `deny_hosts` list AND a generator
// addendum names the same host, the merge step must not produce
// duplicate entries.
func TestInstall_GeneratorDeniesDeduplicateWithCanonical(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  hybrid:
    description: "canonical + generator shape merged"
    deny_hosts:
      - 169.254.169.254
    denies:
      - target: 169.254.169.254
      - target: dns.google
`), 0o600))
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)
	require.Equal(t, []string{"hybrid"}, res.InstalledNames)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("hybrid")
	require.NoError(t, err)

	count := 0
	for _, h := range p.DenyHosts {
		if h == "169.254.169.254" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate 169.254.169.254 must be deduped")
	assert.Contains(t, p.DenyHosts, "dns.google")
}

// TestInstall_TargetWithPathBecomesDenyRule — a generator deny whose
// `target` includes a `/` is split into host+path and lands as a
// PathPrefix rule.
func TestInstall_TargetWithPathBecomesDenyRule(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profile_name: with-paths
bouncer: gbounce
denies:
  - target: api.openai.com/v1/chat
    actions: [POST]
`), 0o600))
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active(res.InstalledNames[0])
	require.NoError(t, err)
	require.Len(t, p.DenyRules, 1)
	rule := p.DenyRules[0]
	assert.Equal(t, "api.openai.com", rule.Host)
	assert.Equal(t, "/v1/chat", rule.PathPrefix)
}

// TestInstall_AdversarialDenied_PostInstall — the round-trip:
// install a generator-shape profile, exercise the deny via the
// compiled []Rule pipeline, assert the matcher fires.
//
// This is the load-bearing assertion that the install path actually
// produces enforceable state (vs. just landing bytes on disk).
func TestInstall_AdversarialDenied_PostInstall(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "g.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(generatorBundleYAML), 0o600))

	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("scenario-block-imds")
	require.NoError(t, err)

	// Validate the deny_hosts entries are well-formed (parse without error).
	for _, h := range p.DenyHosts {
		_, perr := ParseDenyHostEntry(h)
		require.NoError(t, perr, "deny_host %q must parse: %v", h, perr)
	}

	// Compile the deny_rules so we can exercise FirstMatch against
	// the adversarial input. This is the same compile step the CLI
	// layer runs.
	rules, err := ParseRules(p.DenyRules)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// Adversarial: POST api.openai.com/anything → must be denied by
	// the host+method rule.
	hit := FirstMatch(rules, true, "api.openai.com", 443, "POST", "/v1/chat", "")
	require.NotNil(t, hit, "POST api.openai.com must match the deny_rule")

	// GET to the same host MUST pass (method predicate constrains).
	miss := FirstMatch(rules, true, "api.openai.com", 443, "GET", "/v1/models", "")
	require.Nil(t, miss, "GET must not match POST-only deny_rule")
}

// TestInstall_SourceForcedRegardlessOfUpstreamClaim — a malicious
// payload that names `source: local` cannot escape the read-only
// invariant; Install forces source = canonical fetch source.
func TestInstall_SourceForcedRegardlessOfUpstreamClaim(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  malicious:
    source: local
    deny_hosts: [evil.example.com]
`), 0o600))
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)
	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("malicious")
	require.NoError(t, err)
	abs, _ := filepath.Abs(srcPath)
	assert.Equal(t, abs, p.Source,
		"upstream source: local claim must be overridden by canonical fetch path")
	assert.False(t, p.IsLocalSource(),
		"installed profile must NOT be treated as local-editable")
}

// TestInstall_UpsertProfileRefusesNonLocalOverwrite — the canonical
// write entry point refuses to clobber an installed profile.
func TestInstall_UpsertProfileRefusesNonLocalOverwrite(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(srcPath, []byte(`profiles:
  acme:
    deny_hosts: [a.example.com]
`), 0o600))
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)

	// Try to overwrite via UpsertProfile (the recommender / save path).
	err = UpsertProfile(&Profile{Name: "acme", DenyHosts: []string{"different.example.com"}}, target)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")
}

// TestInstall_AdminActionFieldsCarryAuditData — confirm the result
// fields the CLI uses to populate the admin-action OCSF event are
// populated (the CLI passes them into emitAdminAction).
//
// We exercise the result-field shape rather than re-emitting the
// OCSF row because admin_action_test.go already covers the OCSF
// shape and we don't want to assert OCSF schema in two layers.
func TestInstall_AdminActionFieldsCarryAuditData(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "p.yaml")
	payload := []byte(`profiles:
  acme:
    deny_hosts: [a.example.com]
`)
	require.NoError(t, os.WriteFile(srcPath, payload, 0o600))
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{From: srcPath, ProfilesPath: target})
	require.NoError(t, err)

	// The CLI uses these fields verbatim for the admin-action event.
	require.NotEmpty(t, res.SHA256)
	require.NotEmpty(t, res.SourceURL)
	require.Equal(t, target, res.ProfilesPath)
	require.Equal(t, []string{"acme"}, res.InstalledNames)

	// SHA256 must match the actual file bytes.
	sum := sha256.Sum256(payload)
	assert.Equal(t, hex.EncodeToString(sum[:]), res.SHA256)
}

// jsonRoundtripResult ensures the result struct serializes cleanly
// (the CLI banner re-marshals these for the --json flag in some
// sibling tools; keep gbounce's shape symmetric).
func TestInstallResult_JSONRoundtrip(t *testing.T) {
	res := InstallResult{
		SourceURL:      "https://example/p.yaml",
		ProfilesPath:   "/tmp/p.yaml",
		InstalledNames: []string{"a", "b"},
		SHA256:         strings.Repeat("f", 64),
		SHA256Verified: true,
	}
	b, err := json.Marshal(res)
	require.NoError(t, err)
	var back InstallResult
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, res, back)
}
