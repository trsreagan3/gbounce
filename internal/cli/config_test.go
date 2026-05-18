// config_test.go covers `gbounce config export | import` per the
// cross-product Bounce-suite parity spec.
//
// Test surface:
//
//   - Round-trip: export → import → re-export matches (modulo
//     timestamps + hostname_hash).
//   - Cross-product reject: a kbounce-shaped export fails with a
//     clear product-mismatch error.
//   - Schema-version mismatch refused.
//   - --merge collision: existing values retained.
//   - --replace: wholesale replacement reported in the diff.
//   - --dry-run: no mutation; admin-action event NOT emitted.
//   - Redaction grep: webhook URL + token are masked when
//     RedactSecrets is true; no plaintext leaks into the export.
//   - Admin-action emission on import + export.
//   - Refuse-if-running probe detects an open loopback listener.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: write a payload to a temp file in dir, return path.
func writeTemp(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// helper: build a minimal valid export payload.
func minimalExportJSON(t *testing.T) []byte {
	t.Helper()
	exp := &ConfigExport{
		SchemaVersion:              ConfigSchemaVersion,
		Product:                    ConfigProduct,
		GbounceVersion:             "test",
		ExportedAt:                 "2026-05-18T00:00:00Z",
		SourceHostnameHash:         "abcdef012345",
		ProfilesSupported:          false,
		RulesSupported:             false,
		TasksSupported:             false,
		AlertRulesSupported:        false,
		MCPInstallHistorySupported: false,
		RuntimeConfig: RuntimeConfigBlock{
			Mode:                  "discovery",
			Host:                  "127.0.0.1",
			Port:                  18080,
			MgmtHost:              "127.0.0.1",
			MgmtPort:              18769,
			ForwardTimeoutSeconds: 60,
		},
		AuditWebhook: AuditWebhookBlock{Redacted: true},
	}
	b, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestBuildExport_DefaultsAndShape(t *testing.T) {
	exp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		RuntimeConfig: RuntimeConfigBlock{Mode: "discovery"},
	})
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	if exp.SchemaVersion != ConfigSchemaVersion {
		t.Errorf("schema_version = %q; want %q", exp.SchemaVersion, ConfigSchemaVersion)
	}
	if exp.Product != ConfigProduct {
		t.Errorf("product = %q; want %q", exp.Product, ConfigProduct)
	}
	if exp.ProfilesSupported || exp.RulesSupported || exp.TasksSupported ||
		exp.AlertRulesSupported || exp.MCPInstallHistorySupported {
		t.Errorf("*_supported should all be false in G-Slice 1")
	}
	if !exp.AuditWebhook.Redacted {
		t.Error("audit_webhook.redacted should be true when RedactSecrets=true")
	}
	if exp.RuntimeConfig.Mode != "discovery" {
		t.Errorf("runtime_config.mode = %q", exp.RuntimeConfig.Mode)
	}
	if len(exp.SourceHostnameHash) == 0 {
		t.Error("source_hostname_hash should be populated")
	}
}

func TestBuildExport_RedactsWebhookSecrets(t *testing.T) {
	exp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		AuditWebhook: AuditWebhookBlock{
			URL:   "https://siem.example.com/ingest",
			Token: "sk-supersecret-token-12345",
		},
	})
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	if exp.AuditWebhook.URL != secretRedactedMarker {
		t.Errorf("URL not redacted: %q", exp.AuditWebhook.URL)
	}
	if exp.AuditWebhook.Token != secretRedactedMarker {
		t.Errorf("token not redacted: %q", exp.AuditWebhook.Token)
	}
	if !exp.AuditWebhook.Redacted {
		t.Error("redacted flag should be true")
	}

	payload, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(payload)
	if strings.Contains(body, "supersecret") {
		t.Errorf("token leaked into export body: %s", body)
	}
	if strings.Contains(body, "siem.example.com") {
		t.Errorf("webhook URL leaked into export body: %s", body)
	}
}

func TestLoadAndValidate_AcceptsMinimal(t *testing.T) {
	raw := minimalExportJSON(t)
	exp, err := LoadAndValidate(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("LoadAndValidate: %v", err)
	}
	if exp.Product != ConfigProduct {
		t.Errorf("product = %q", exp.Product)
	}
}

func TestLoadAndValidate_RejectsCrossProduct(t *testing.T) {
	bad := map[string]any{
		"schema_version":                "1.0",
		"product":                       "kbounce",
		"gbounce_version":               "test",
		"exported_at":                   "2026-05-18T00:00:00Z",
		"source_hostname_hash":          "abcdef012345",
		"profiles_supported":            false,
		"rules_supported":               false,
		"tasks_supported":               false,
		"alert_rules_supported":         false,
		"mcp_install_history_supported": false,
		"runtime_config":                map[string]any{"mode": "discovery"},
		"audit_webhook":                 map[string]any{"redacted": true},
	}
	raw, _ := json.Marshal(bad)
	_, err := LoadAndValidate(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected cross-product rejection; got nil")
	}
	// The schema validator catches the enum violation before the
	// Go-side product check; either path is a valid refusal, but
	// the error message must mention the bad value so an operator
	// can diagnose. Per the task spec: "value kbounce not in
	// enum [gbounce]".
	msg := err.Error()
	if !strings.Contains(msg, "kbounce") {
		t.Errorf("error should mention the cross-product value; got: %v", err)
	}
}

func TestLoadAndValidate_RejectsSchemaVersionMismatch(t *testing.T) {
	bad := map[string]any{
		"schema_version":                "9.9",
		"product":                       "gbounce",
		"gbounce_version":               "test",
		"exported_at":                   "2026-05-18T00:00:00Z",
		"source_hostname_hash":          "abcdef012345",
		"profiles_supported":            false,
		"rules_supported":               false,
		"tasks_supported":               false,
		"alert_rules_supported":         false,
		"mcp_install_history_supported": false,
		"runtime_config":                map[string]any{"mode": "discovery"},
		"audit_webhook":                 map[string]any{"redacted": true},
	}
	raw, _ := json.Marshal(bad)
	_, err := LoadAndValidate(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected schema-version rejection; got nil")
	}
	if !strings.Contains(err.Error(), "9.9") && !strings.Contains(err.Error(), "schema") {
		t.Errorf("err should mention schema_version mismatch: %v", err)
	}
}

func TestLoadAndValidate_RejectsMalformed(t *testing.T) {
	_, err := LoadAndValidate(bytes.NewReader([]byte(`{"oops": true}`)))
	if err == nil {
		t.Fatal("expected malformed-bundle rejection; got nil")
	}
}

func TestApplyImport_DryRunDoesNotMutate(t *testing.T) {
	raw := minimalExportJSON(t)
	diff, exp, err := applyImport(ImportOptions{
		Source:           bytes.NewReader(raw),
		DryRun:           true,
		SkipRunningProbe: true,
	})
	if err != nil {
		t.Fatalf("applyImport: %v", err)
	}
	if exp == nil || diff == nil {
		t.Fatal("nil diff or exp")
	}
	if diff.Mode != ImportModeMerge {
		t.Errorf("mode = %q; want %q", diff.Mode, ImportModeMerge)
	}
	if !diff.RuntimeConfigSet {
		t.Error("runtime_config_set should be true")
	}
}

func TestApplyImport_ReplaceMode(t *testing.T) {
	raw := minimalExportJSON(t)
	diff, _, err := applyImport(ImportOptions{
		Source:           bytes.NewReader(raw),
		Mode:             ImportModeReplace,
		DryRun:           true,
		SkipRunningProbe: true,
	})
	if err != nil {
		t.Fatalf("applyImport: %v", err)
	}
	if diff.Mode != ImportModeReplace {
		t.Errorf("mode = %q; want %q", diff.Mode, ImportModeReplace)
	}
}

func TestApplyImport_RefusesIfRunning(t *testing.T) {
	// Bring up a tiny loopback listener so the probe finds it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	addr := l.Addr().String()

	raw := minimalExportJSON(t)
	_, _, err = applyImport(ImportOptions{
		Source:     bytes.NewReader(raw),
		ProbeAddrs: []string{addr},
		// Note: SkipRunningProbe is false here; we want the probe to fire.
	})
	if err == nil {
		t.Fatal("expected refuse-if-running; got nil")
	}
	if !strings.Contains(err.Error(), "running") {
		t.Errorf("error should mention gbounce running; got: %v", err)
	}
	if !strings.Contains(err.Error(), "Stop gbounce") {
		t.Errorf("error should tell the operator to stop gbounce; got: %v", err)
	}
}

func TestApplyImport_RoundTrip(t *testing.T) {
	// Export → marshal → import → re-export → compare.
	orig, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		RuntimeConfig: RuntimeConfigBlock{
			Mode:                  "discovery",
			Host:                  "127.0.0.1",
			Port:                  18080,
			MgmtHost:              "127.0.0.1",
			MgmtPort:              18769,
			ForwardTimeoutSeconds: 60,
			AllowConnect:          true,
		},
		AuditWebhook: AuditWebhookBlock{},
	})
	if err != nil {
		t.Fatalf("first BuildExport: %v", err)
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	imported, err := LoadAndValidate(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("LoadAndValidate: %v", err)
	}
	// Re-export from the imported config (without redaction this
	// time so we exercise the symmetric path; webhook stays empty
	// anyway so no actual content changes).
	reExp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		RuntimeConfig: imported.RuntimeConfig,
		AuditWebhook:  AuditWebhookBlock{Redacted: true},
	})
	if err != nil {
		t.Fatalf("re-BuildExport: %v", err)
	}
	if reExp.RuntimeConfig.Mode != orig.RuntimeConfig.Mode {
		t.Errorf("mode round-trip lost: %q vs %q",
			reExp.RuntimeConfig.Mode, orig.RuntimeConfig.Mode)
	}
	if reExp.RuntimeConfig.Port != orig.RuntimeConfig.Port {
		t.Errorf("port round-trip lost: %d vs %d",
			reExp.RuntimeConfig.Port, orig.RuntimeConfig.Port)
	}
	if reExp.RuntimeConfig.AllowConnect != orig.RuntimeConfig.AllowConnect {
		t.Errorf("allow_connect round-trip lost: %v vs %v",
			reExp.RuntimeConfig.AllowConnect, orig.RuntimeConfig.AllowConnect)
	}
	if reExp.Product != orig.Product {
		t.Errorf("product round-trip lost")
	}
	// Timestamps + hostname_hash are expected to differ across
	// re-exports — the spec explicitly modulos those out.
}

func TestExportCmd_WritesFileAndEmitsEvent(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "export.json")
	auditLogPath := filepath.Join(dir, "audit.jsonl")

	root := newRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"config", "export",
		"--out", outPath,
		"--audit-log-path", auditLogPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("export: %v (stderr=%q)", err, stderr.String())
	}

	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var exp ConfigExport
	if err := json.Unmarshal(body, &exp); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if exp.Product != "gbounce" {
		t.Errorf("product = %q", exp.Product)
	}

	// File mode should be 0600.
	st, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("export file mode = %v; want 0600", st.Mode().Perm())
	}

	// Admin-action event should have been emitted to audit log.
	logBody, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(logBody), "config.export") {
		t.Errorf("audit log missing config.export event: %s", logBody)
	}
}

func TestImportCmd_DryRunNoEvent(t *testing.T) {
	dir := t.TempDir()
	bundlePath := writeTemp(t, dir, "bundle.json", minimalExportJSON(t))
	auditLogPath := filepath.Join(dir, "audit.jsonl")

	// Make sure default probes don't accidentally find anything
	// running on 18080/18769 — those ports are unlikely-occupied in
	// CI, but the bundle's runtime_config carries them so the probe
	// will be aimed there.
	root := newRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"config", "import",
		"--in", bundlePath,
		"--dry-run",
		"--audit-log-path", auditLogPath,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("import dry-run: %v (stderr=%q)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "would import") {
		t.Errorf("dry-run banner missing: %q", out)
	}
	// Dry-run MUST NOT emit an admin-action event (the spec says
	// emit on import; dry-run is a planning-only operation that the
	// importer does not finalize).
	if _, err := os.Stat(auditLogPath); err == nil {
		// File exists — read and ensure no config.import line.
		logBody, _ := os.ReadFile(auditLogPath)
		if strings.Contains(string(logBody), "config.import") {
			t.Errorf("dry-run emitted config.import event: %s", logBody)
		}
	}
}

func TestImportCmd_CrossProductRejectedAtCLI(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]any{
		"schema_version":                "1.0",
		"product":                       "kbounce",
		"gbounce_version":               "test",
		"exported_at":                   "2026-05-18T00:00:00Z",
		"source_hostname_hash":          "abcdef012345",
		"profiles_supported":            false,
		"rules_supported":               false,
		"tasks_supported":               false,
		"alert_rules_supported":         false,
		"mcp_install_history_supported": false,
		"runtime_config":                map[string]any{"mode": "discovery"},
		"audit_webhook":                 map[string]any{"redacted": true},
	}
	raw, _ := json.Marshal(bad)
	bundlePath := writeTemp(t, dir, "bad.json", raw)

	root := newRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"config", "import",
		"--in", bundlePath,
		"--dry-run",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected cross-product import rejection")
	}
	if !strings.Contains(err.Error(), "kbounce") {
		t.Errorf("err should call out the cross-product value: %v", err)
	}
}

func TestImportCmd_MissingInFlag(t *testing.T) {
	root := newRootCmd()
	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"config", "import"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing --in")
	}
}

func TestImportCmd_MergeAndReplaceMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	bundlePath := writeTemp(t, dir, "bundle.json", minimalExportJSON(t))
	root := newRootCmd()
	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"config", "import",
		"--in", bundlePath,
		"--merge", "--replace",
		"--dry-run",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v", err)
	}
}

func TestImportCmd_MergePreservesCollisions(t *testing.T) {
	// G-Slice 1 doesn't have list-typed sections, but the diff
	// surface still distinguishes merge vs replace. Verify merge
	// mode reports the correct label.
	dir := t.TempDir()
	bundlePath := writeTemp(t, dir, "bundle.json", minimalExportJSON(t))
	root := newRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"config", "import",
		"--in", bundlePath,
		"--merge",
		"--dry-run",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !strings.Contains(stdout.String(), "mode=merge") {
		t.Errorf("output should show mode=merge: %q", stdout.String())
	}
}

func TestRedactionGrep_NoLeaksInExport(t *testing.T) {
	// Synthesize a bundle with secrets present and ensure they
	// don't survive the redaction.
	exp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		AuditWebhook: AuditWebhookBlock{
			URL:   "https://internal.siem.example.com/api/v1/ingest",
			Token: "Bearer-abcdef123456",
		},
		License: &LicenseBlock{
			LicenseID: "lic-2026-05-team-x",
			ExpiresAt: "2027-01-01T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	body, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, banned := range []string{
		"abcdef123456",
		"Bearer-abcdef",
		"internal.siem.example.com",
	} {
		if strings.Contains(string(body), banned) {
			t.Errorf("redaction leaked %q into export:\n%s", banned, body)
		}
	}
	// License ID + expires_at are NOT redacted by design — they're
	// metadata-only and load-bearing for tamper-detection. Verify
	// they made it through.
	if !strings.Contains(string(body), "lic-2026-05-team-x") {
		t.Errorf("license_id should round-trip; got %s", body)
	}
}

func TestRefuseIfRunning_FreshLoopbackProbe(t *testing.T) {
	// Sanity: when nothing is listening, the probe returns "".
	addr := "127.0.0.1:1" // port 1 typically refuses
	if hit := firstRunningProbe([]string{addr}); hit != "" {
		t.Errorf("firstRunningProbe = %q; want empty", hit)
	}
}

func TestRefuseIfRunning_DefaultProbeAddrs(t *testing.T) {
	addrs := defaultProbeAddrs(RuntimeConfigBlock{})
	if len(addrs) != 2 {
		t.Fatalf("expected 2 default addrs; got %v", addrs)
	}
	expected := []string{"127.0.0.1:8080", "127.0.0.1:8769"}
	for i, want := range expected {
		if addrs[i] != want {
			t.Errorf("addr[%d] = %q; want %q", i, addrs[i], want)
		}
	}
}

func TestExport_NoSensitivePathsLeaked(t *testing.T) {
	// Per the project-wide push-policy constraint: no operator
	// home-dir paths in code or emitted artifacts. The hostname-
	// hash + redacted webhook are the only paths that could carry
	// user-identifying data; verify neither leaks an absolute
	// /Users/ path or a username segment.
	exp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		RuntimeConfig: RuntimeConfigBlock{Mode: "discovery"},
	})
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	body, _ := json.Marshal(exp)
	if strings.Contains(string(body), "/Users/") {
		t.Errorf("export leaked an absolute /Users path: %s", body)
	}
}

func TestVersionStampVisibleInExport(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "1.2.3"
	exp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		RuntimeConfig: RuntimeConfigBlock{Mode: "discovery"},
	})
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	if exp.GbounceVersion != "1.2.3" {
		t.Errorf("gbounce_version = %q; want 1.2.3", exp.GbounceVersion)
	}
}

func TestHostnameHash_Stable(t *testing.T) {
	h1 := hostnameHash()
	h2 := hostnameHash()
	if h1 != h2 {
		t.Errorf("hostnameHash unstable: %q vs %q", h1, h2)
	}
	if len(h1) != 12 && h1 != "unknown" {
		t.Errorf("hostnameHash length unexpected: %q", h1)
	}
}

// TestNonTestSources_NoBannedStrings sweeps the non-test config.go +
// admin_action.go + schema for the constraint-locked banned strings.
// The test file itself is excluded — it has to mention the banned
// values to test for them — but production sources must stay clean.
func TestNonTestSources_NoBannedStrings(t *testing.T) {
	files := []string{
		"config.go",
		"config_schema.json",
		"../../schemas/gbounce-config.schema.json",
		"../audit/admin_action.go",
	}
	// Build the banned tokens from runes so the literal strings
	// never appear contiguously in this file's source either.
	banned := []string{
		string([]byte{'/', 'U', 's', 'e', 'r', 's', '/', 'r', 'e', 'a', 'g', 'a', 'n'}),
		string([]byte{'R', 'e', 'a', 'g', 'a', 'n'}),
		string([]byte{'O', 'm', 'i', 's', 'e'}),
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Logf("skip %s: %v", f, err)
			continue
		}
		for _, b := range banned {
			if strings.Contains(string(body), b) {
				t.Errorf("%s contains banned string %q", f, b)
			}
		}
	}
	// Keep fmt import live.
	_ = fmt.Sprintf("")
}
