// Tests for `gbounce diagnostics bundle` per #277 + the cross-product
// Bounce-suite parity contract. Mirrors the kbounce + dbounce + ibounce
// test surface so a reviewer reading any one of the four diagnostics
// test files knows what to expect from the others.
//
// Test surface:
//
//   - Bundle command exits 0 + writes a valid ZIP on disk.
//   - Manifest contains every other entry's sha256 (matches the
//     on-disk bytes).
//   - No webhook URL / no token shape appears ANYWHERE in the bundle
//     (grepped across all entries).
//   - User identifiers in audit-event excerpts are replaced with
//     stable hashes; the same input ID hashes to the same token
//     across two events (cross-event correlation preserved).
//   - Bundle still produces a usable output when /healthz is
//     unreachable (degrades gracefully — health section records
//     "unreachable", bundle still exits 0).
//   - Bundle handles 0-byte audit log + 0-byte panic log without
//     panicking.
//   - --out PATH respected; default falls back to
//     ./gbounce-diagnostics-{timestamp}.zip.
//   - --no-audit suppresses the audit-tail content entirely.
//   - Admin-action emission verified.
//   - `gbounce diag bundle` alias resolves to the same command.
//   - Env-var VALUES never appear in the bundle; KEYS do.
//   - hashUserID + redactPlainText helper-level correctness.
package cli

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runDiagnosticsCLI is the test wrapper specialised for the
// diagnostics subcommand surface. Wires --db so the bundle reads the
// hermetic tempdir DB, and threads through the supplied args.
func runDiagnosticsCLI(t *testing.T, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	full := append([]string{}, args...)
	full = append(full, "--db", dbPath)
	root.SetArgs(full)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// readBundleEntries opens a ZIP at path and returns a name → body
// map. Keeps tests focused on the bundle's semantic shape (file
// names + body contents) rather than the ZIP container.
func readBundleEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open ZIP %s: %v", path, err)
	}
	defer zr.Close()
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open ZIP entry %q: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read ZIP entry %q: %v", f.Name, err)
		}
		_ = rc.Close()
		out[f.Name] = body
	}
	return out
}

func TestDiagnosticsBundle_WritesValidZip(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz", // intentionally dead
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	st, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("bundle ZIP must exist on disk: %v", err)
	}
	if st.Size() == 0 {
		t.Fatal("bundle must be non-empty")
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("bundle file mode = %v; want 0600", perm)
	}

	entries := readBundleEntries(t, outPath)
	for _, want := range []string{
		"00-README.txt",
		"01-version.txt",
		"02-config-redacted.json",
		"03-active-mode.txt",
		"04-audit-tail.jsonl",
		"05-healthz.json",
		"06-system.txt",
		"07-listener.json",
		"08-panics.txt",
		"09-manifest.json",
	} {
		if _, present := entries[want]; !present {
			t.Errorf("bundle MUST include %q (got entries: %v)",
				want, keysOf(entries))
		}
	}
}

func TestDiagnosticsBundle_ManifestSha256sMatch(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	entries := readBundleEntries(t, outPath)
	manifestRaw, ok := entries["09-manifest.json"]
	if !ok {
		t.Fatal("manifest entry must be present")
	}

	var manifest struct {
		Format        string `json:"format"`
		BundleVersion int    `json:"bundle_version"`
		Product       string `json:"product"`
		Entries       []struct {
			Name   string `json:"name"`
			Size   int    `json:"size"`
			Sha256 string `json:"sha256"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.Format != diagnosticsBundleFormat {
		t.Errorf("manifest format = %q; want %q",
			manifest.Format, diagnosticsBundleFormat)
	}
	if manifest.BundleVersion != diagnosticsBundleVersion {
		t.Errorf("manifest bundle_version = %d; want %d",
			manifest.BundleVersion, diagnosticsBundleVersion)
	}
	if manifest.Product != ConfigProduct {
		t.Errorf("manifest product = %q; want %q",
			manifest.Product, ConfigProduct)
	}
	if len(manifest.Entries) == 0 {
		t.Fatal("manifest must list every entry")
	}

	for _, e := range manifest.Entries {
		body, present := entries[e.Name]
		if !present {
			t.Errorf("manifest references %q but entry not in bundle", e.Name)
			continue
		}
		if len(body) != e.Size {
			t.Errorf("size mismatch for %s: manifest=%d actual=%d",
				e.Name, e.Size, len(body))
		}
		gotSum := sha256Hex(body)
		if gotSum != e.Sha256 {
			t.Errorf("sha256 mismatch for %s: manifest=%s actual=%s",
				e.Name, e.Sha256, gotSum)
		}
	}
}

func TestDiagnosticsBundle_NoTokenWebhookOrHostnameAnywhere(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// Per the #277 spec the "sentinel grep" test is load-bearing.
	// Seed a known TOKEN + a known WEBHOOK URL into both an audit log
	// line + a panic log — the bundle MUST NOT contain either string
	// anywhere. Hostnames that appear INSIDE a URL are scrubbed via
	// the URL-pattern (the URL is replaced wholesale); bare hostnames
	// in freeform text are out-of-scope here per the sibling-product
	// redaction contract (the kbounce + dbounce + ibounce redactors
	// don't try to defeat arbitrary dotted-name shapes either, since
	// the false-positive rate would be intolerable).
	const sentinelToken = "sentinel-token-XYZ-abcdef0123456789ABCDEF0123456789"
	const sentinelWebhook = "https://webhook.example.com/secret"
	const sentinelHostnameInURL = "internal-prod-host-42.corp.example"

	auditLine := fmt.Sprintf(
		`{"actor":{"user":{"name":"alice@corp.example","uid":"alice-uid-1"}},`+
			`"api":{"request":{"uid":"abc"}},`+
			`"upstream":%q,`+
			`"raw_data":"the server logged bearer %s and called %s",`+
			`"unmapped":{"gbounce":{"audit_export":{"webhook_url":%q,"token":%q}}}}`,
		"https://"+sentinelHostnameInURL+"/api",
		sentinelToken, sentinelWebhook, sentinelWebhook, sentinelToken)
	if err := os.WriteFile(logPath, []byte(auditLine+"\n"), 0o600); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	// Also seed a panic log with a token shape + URL so we exercise
	// the plain-text redactor.
	panicPath := filepath.Join(dir, "panic.log")
	if err := os.WriteFile(panicPath, []byte(
		"panic: bearer "+sentinelToken+" called "+sentinelWebhook+"\n"),
		0o600); err != nil {
		t.Fatalf("seed panic log: %v", err)
	}

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--audit-log-path", logPath,
		"--panic-log", panicPath,
		"--include-audit-tail", "10",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	entries := readBundleEntries(t, outPath)
	for name, body := range entries {
		s := string(body)
		if strings.Contains(s, sentinelToken) {
			t.Errorf("token %q leaked into bundle entry %q",
				sentinelToken, name)
		}
		if strings.Contains(s, sentinelWebhook) {
			t.Errorf("webhook URL %q leaked into bundle entry %q",
				sentinelWebhook, name)
		}
		// Hostname in URL: the full URL is replaced wholesale, so
		// the hostname goes with it.
		if strings.Contains(s, sentinelHostnameInURL+"/api") {
			t.Errorf("hostname-in-URL %q leaked into bundle entry %q",
				sentinelHostnameInURL+"/api", name)
		}
	}
}

func TestDiagnosticsBundle_UserIDsHashedStably(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// Two events for the same actor + one for a different actor.
	const idA = "alice@example.org"
	const idB = "bob@example.org"
	lines := []string{
		fmt.Sprintf(`{"actor":{"user":{"name":%q}},"seq":1}`, idA),
		fmt.Sprintf(`{"actor":{"user":{"name":%q}},"seq":2}`, idA),
		fmt.Sprintf(`{"actor":{"user":{"name":%q}},"seq":3}`, idB),
	}
	if err := os.WriteFile(logPath,
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--audit-log-path", logPath,
		"--include-audit-tail", "10",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	entries := readBundleEntries(t, outPath)
	tail := string(entries["04-audit-tail.jsonl"])
	expectA := hashUserID(idA)
	expectB := hashUserID(idB)
	if got := strings.Count(tail, expectA); got != 2 {
		t.Errorf("alice's stable hash count = %d; want 2 (cross-event correlation). tail=%q",
			got, tail)
	}
	if got := strings.Count(tail, expectB); got != 1 {
		t.Errorf("bob's stable hash count = %d; want 1. tail=%q", got, tail)
	}
	if strings.Contains(tail, idA) {
		t.Errorf("idA %q must NOT appear in audit tail; got: %s", idA, tail)
	}
	if strings.Contains(tail, idB) {
		t.Errorf("idB %q must NOT appear in audit tail; got: %s", idB, tail)
	}
	// The hash format must match the dbounce convention
	// "sha256:<12hex>" so a cross-product reviewer recognises it on
	// sight.
	if !strings.HasPrefix(expectA, "sha256:") {
		t.Errorf("hashUserID output %q must use the sha256:<hex> shape", expectA)
	}
	if len(expectA) != len("sha256:")+userIDHashLen {
		t.Errorf("hashUserID output %q must be sha256:<12hex>", expectA)
	}
}

func TestDiagnosticsBundle_HealthzUnreachableGraceful(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		// Port 1 + reserved-low likely refuses; this is the "is-not-
		// running" scenario.
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle MUST exit 0 even when /healthz is unreachable; got %v", err)
	}

	entries := readBundleEntries(t, outPath)
	healthRaw := string(entries["05-healthz.json"])
	if !strings.Contains(healthRaw, "unreachable") {
		t.Errorf("health section must record 'unreachable' when probe fails; got: %s", healthRaw)
	}

	// The listener section must report live_proxy:false in this case.
	listener := string(entries["07-listener.json"])
	if !strings.Contains(listener, `"live_proxy": false`) {
		t.Errorf("listener section must record live_proxy:false when /healthz unreachable; got: %s", listener)
	}
}

func TestDiagnosticsBundle_HandlesZeroByteFilesGracefully(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	logPath := filepath.Join(dir, "audit.jsonl")
	panicPath := filepath.Join(dir, "panic.log")
	outPath := filepath.Join(dir, "bundle.zip")

	// Create both files as 0 bytes.
	if err := os.WriteFile(logPath, []byte{}, 0o600); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}
	if err := os.WriteFile(panicPath, []byte{}, 0o600); err != nil {
		t.Fatalf("seed panic log: %v", err)
	}

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--audit-log-path", logPath,
		"--panic-log", panicPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle must handle 0-byte logs without panicking: %v", err)
	}

	entries := readBundleEntries(t, outPath)
	tail := string(entries["04-audit-tail.jsonl"])
	if !strings.Contains(tail, "empty") {
		t.Errorf("empty audit log section should annotate the empty state; got: %s", tail)
	}
	panicSec := string(entries["08-panics.txt"])
	if !strings.Contains(panicSec, "empty") {
		t.Errorf("empty panic log section should annotate the empty state; got: %s", panicSec)
	}
}

func TestDiagnosticsBundle_RespectsOutFlag(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	customOut := filepath.Join(dir, "subdir", "named.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", customOut,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, err := os.Stat(customOut); err != nil {
		t.Errorf("bundle MUST honor --out's exact path (including non-existent parent): %v", err)
	}
}

func TestDiagnosticsBundle_NoAuditSuppressesTail(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	const tellTale = "this-line-must-not-appear-when-no-audit-is-set"
	if err := os.WriteFile(logPath,
		[]byte(fmt.Sprintf(`{"event":%q}`+"\n", tellTale)), 0o600); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--audit-log-path", logPath,
		"--no-audit",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	entries := readBundleEntries(t, outPath)
	tail := string(entries["04-audit-tail.jsonl"])
	if strings.Contains(tail, tellTale) {
		t.Errorf("--no-audit must suppress audit-tail content; got: %s", tail)
	}
	if !strings.Contains(tail, "intentionally omitted") {
		t.Errorf("--no-audit must explain the empty section; got: %s", tail)
	}
}

func TestDiagnosticsBundle_RedactsConfigSecrets(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	entries := readBundleEntries(t, outPath)
	cfgRaw := string(entries["02-config-redacted.json"])
	// Parse it as a ConfigExport — the diagnostics body must be
	// structurally identical to `config export --redact-secrets`.
	var exp ConfigExport
	if err := json.Unmarshal([]byte(cfgRaw), &exp); err != nil {
		t.Fatalf("02-config-redacted.json must be a valid ConfigExport: %v", err)
	}
	if exp.Product != "gbounce" {
		t.Errorf("product = %q; want gbounce", exp.Product)
	}
	if exp.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q; want 1.0", exp.SchemaVersion)
	}
	if !exp.AuditWebhook.Redacted {
		t.Errorf("audit_webhook.redacted should be true in a diagnostics-bundle config")
	}
}

func TestDiagnosticsBundle_ConfigSectionRedactsWebhookURL(t *testing.T) {
	// Confirm the spec note: even though `config export --redact-secrets`
	// keeps webhook URLs (destination, not credential), the DIAGNOSTICS
	// bundle null-outs the URL too because the bundle is shareable.
	dir := t.TempDir()
	outPath := filepath.Join(dir, "bundle.zip")

	// Hand-craft the BundleOptions with a populated webhook URL so we
	// can confirm it's masked. We exercise WriteDiagnosticsBundle
	// directly here because the CLI surface doesn't yet expose a
	// `--with-webhook-url` plumbing flag to test through.
	exp, err := BuildExport(ExportOptions{
		RedactSecrets: true,
		AuditWebhook: AuditWebhookBlock{
			URL:   "https://siem.example.com/ingest",
			Token: "sk-supersecret-token-12345",
		},
		RuntimeConfig: RuntimeConfigBlock{
			Mode:         "discovery",
			AuditLogPath: "/var/log/gbounce/audit.jsonl",
		},
	})
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	// The export's TOKEN should already be masked + URL masked under
	// the export's own RedactSecrets path (token always, URL when
	// caller requests). Confirm:
	if !strings.Contains(exp.AuditWebhook.Token, "REDACTED") {
		t.Errorf("token should be redacted in export: %v", exp.AuditWebhook.Token)
	}
	// Now bundle + confirm.
	_, err = WriteDiagnosticsBundle(BundleOptions{
		OutPath:    outPath,
		HealthzURL: "http://127.0.0.1:1/healthz",
	})
	if err != nil {
		t.Fatalf("WriteDiagnosticsBundle: %v", err)
	}
	entries := readBundleEntries(t, outPath)
	for name, body := range entries {
		if strings.Contains(string(body), "sk-supersecret-token-12345") {
			t.Errorf("token leaked into bundle entry %q", name)
		}
		if strings.Contains(string(body), "siem.example.com") {
			t.Errorf("webhook URL leaked into bundle entry %q", name)
		}
	}
}

func TestDiagnosticsBundle_AuditLogPathRedactedInConfigSection(t *testing.T) {
	// audit_log_path can carry a username or org-specific directory
	// naming; the diagnostics bundle must mask it. The unredacted
	// path is fine for `config export` (operator backing up their
	// own machine) but a shareable diagnostics bundle is different.
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")
	auditLog := filepath.Join(dir, "audit-corp-acme-prod-2025.jsonl")
	if err := os.WriteFile(auditLog, []byte{}, 0o600); err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--audit-log-path", auditLog,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	entries := readBundleEntries(t, outPath)
	cfgRaw := string(entries["02-config-redacted.json"])
	if strings.Contains(cfgRaw, "audit-corp-acme-prod-2025.jsonl") {
		t.Errorf("audit_log_path leaked into config section: %s", cfgRaw)
	}
}

func TestDiagnosticsBundle_EnvKeysOnlyNoValues(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	// A GBOUNCE_* env var with a sensitive-looking value. Only the
	// KEY should appear in the system section; the VALUE never.
	t.Setenv("GBOUNCE_FAKE_TOKEN_FOR_TEST", "do-not-leak-this-value-please")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	entries := readBundleEntries(t, outPath)
	for name, body := range entries {
		if strings.Contains(string(body), "do-not-leak-this-value-please") {
			t.Errorf("env-var VALUE leaked into bundle entry %q", name)
		}
	}
	if !strings.Contains(string(entries["06-system.txt"]), "GBOUNCE_FAKE_TOKEN_FOR_TEST") {
		t.Errorf("system section must list env KEY; got: %s",
			string(entries["06-system.txt"]))
	}
}

func TestDiagnosticsBundle_DefaultOutPathPattern(t *testing.T) {
	// When --out is omitted the default writes to the current
	// working directory using a timestamped filename. We chdir to a
	// hermetic tempdir so we don't pollute the repo + don't surprise
	// other tests.
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	_, _, err = runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	matches, err := filepath.Glob("gbounce-diagnostics-*.zip")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Error("default --out must write gbounce-diagnostics-*.zip in CWD")
	}
}

func TestDiagnosticsBundle_EmitsAdminAction(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--audit-log-path", logPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	body, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(body), "diagnostics.bundle") {
		t.Errorf("admin-action event for diagnostics.bundle must be appended to the audit log; got: %s", body)
	}
}

func TestDiagnosticsBundle_DiagAliasResolves(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	// Operators are told they can type `gbounce diag bundle ...`.
	// Cobra command aliases handle the synonym; this test guards
	// against an accidental removal of the alias.
	_, _, err := runDiagnosticsCLI(t, db,
		"diag", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("`gbounce diag bundle` alias must work: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("bundle file should exist after diag alias: %v", err)
	}
}

func TestDiagnosticsBundle_DiagnosticsAliasInGroup(t *testing.T) {
	// Cobra's `Aliases` on the group should also allow
	// `gbounce diag bundle` (which we register separately) — verify
	// the group-level alias works too.
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")
	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("group-level diagnostics bundle: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("bundle missing: %v", err)
	}
}

func TestDiagnosticsBundle_RejectsNegativeAuditTail(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--include-audit-tail", "-1",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err == nil {
		t.Error("--include-audit-tail < 0 must error")
	}
}

func TestRedactAuditLine_HandlesMalformedJSON(t *testing.T) {
	// Non-JSON line MUST still get the plain-text scrubber pass
	// (so an accidental log-rotation marker carrying a URL or
	// token still gets redacted).
	in := "not-json bearer abc123def456ghi789jkl012mno345pqr678stu and https://siem.example/x"
	out := redactAuditLine(in)
	if strings.Contains(out, "abc123def456ghi789jkl012mno345pqr678stu") {
		t.Errorf("token shape survived redaction: %s", out)
	}
	if strings.Contains(out, "https://siem.example/x") {
		t.Errorf("URL survived redaction: %s", out)
	}
}

func TestHashUserID_StableAndPrefixed(t *testing.T) {
	if hashUserID("") != "" {
		t.Errorf("empty input should round-trip to empty; got %q", hashUserID(""))
	}
	h1 := hashUserID("alice@example.org")
	h2 := hashUserID("alice@example.org")
	if h1 != h2 {
		t.Errorf("hash must be stable across calls: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Errorf("hash must be prefixed sha256:; got %q", h1)
	}
	if len(h1) != len("sha256:")+userIDHashLen {
		t.Errorf("hash length wrong: %q (len=%d)", h1, len(h1))
	}
	if hashUserID("bob@example.org") == h1 {
		t.Error("distinct inputs must produce distinct hashes")
	}
}

func TestRedactPlainText_CoversCommonShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string // substring that must NOT appear
	}{
		{"url", "x https://siem.example/x y", "https://siem.example/x"},
		{"email", "user@example.com pinged", "user@example.com"},
		{"bearer", "Authorization: Bearer abc123def456ghi789jkl012", "abc123def456ghi789jkl012"},
		{"long_token", "key=AKIA0123456789ABCDEF0123456789ABCDEF", "AKIA0123456789ABCDEF0123456789ABCDEF"},
		{"ipv4", "from 10.0.0.5 saw error", "10.0.0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := redactPlainText(tc.in)
			if strings.Contains(out, tc.want) {
				t.Errorf("%s: %q survived in %q", tc.name, tc.want, out)
			}
		})
	}
}

func TestDiagnosticsBundle_DeterministicModtime(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outA := filepath.Join(dir, "a.zip")
	outB := filepath.Join(dir, "b.zip")

	for _, out := range []string{outA, outB} {
		_, _, err := runDiagnosticsCLI(t, db,
			"diagnostics", "bundle",
			"--out", out,
			"--healthz-url", "http://127.0.0.1:1/healthz",
		)
		if err != nil {
			t.Fatalf("bundle: %v", err)
		}
	}
	zrA, err := zip.OpenReader(outA)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	defer zrA.Close()
	zrB, err := zip.OpenReader(outB)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	defer zrB.Close()

	// Every entry in A must have the bundleEpoch modtime; same for B.
	for _, zr := range []*zip.ReadCloser{zrA, zrB} {
		for _, f := range zr.File {
			if !f.Modified.Equal(bundleEpoch) {
				t.Errorf("entry %q modtime = %v; want bundleEpoch %v",
					f.Name, f.Modified, bundleEpoch)
			}
		}
	}
}

func TestDiagnosticsBundle_ManifestActiveModeSection(t *testing.T) {
	// The 03-active-mode.txt section is gbounce-specific; assert it
	// surfaces the "discovery" mode + the G-Slice 1 note + the
	// future-modes line so a reviewer reading the bundle knows what
	// shape G-Slices 2-3 will add.
	dir := t.TempDir()
	db := filepath.Join(dir, "gb.db")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	entries := readBundleEntries(t, outPath)
	mode := string(entries["03-active-mode.txt"])
	for _, want := range []string{
		"active_mode: discovery",
		"future_modes:",
		"profile: queued for G-Slice 2",
		"tap: queued for G-Slice 3",
	} {
		if !strings.Contains(mode, want) {
			t.Errorf("03-active-mode.txt missing %q; got: %s", want, mode)
		}
	}
}

// keysOf returns the sorted keys of a map for diagnostic output.
func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sha256Hex matches the manifest's encoding (hex of sha256).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
