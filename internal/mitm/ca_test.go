package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCA_Generate_FreshCertHasCorrectShape (spec test): newly minted
// CA must carry the documented CN, be marked IsCA, have a 10-year
// lifetime, and write the key with 0o600.
func TestCA_Generate_FreshCertHasCorrectShape(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	cert, key, err := GenerateCA(paths, false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if !cert.IsCA {
		t.Errorf("expected IsCA=true; got false")
	}
	if cert.Subject.CommonName != caCommonName {
		t.Errorf("CN = %q; want %q", cert.Subject.CommonName, caCommonName)
	}
	if got := cert.NotAfter.Year() - cert.NotBefore.Year(); got != caValidYears {
		t.Errorf("lifetime years = %d; want %d", got, caValidYears)
	}
	if key == nil {
		t.Fatal("private key is nil")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(paths.KeyFile)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("key permissions = %#o; want 0o600", info.Mode().Perm())
		}
	}
	// Cert file is readable.
	certPEM, err := os.ReadFile(paths.CertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("cert PEM type %q; want CERTIFICATE", block.Type)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !strings.Contains(parsed.Issuer.String(), caCommonName) {
		t.Errorf("issuer %q does not contain %q", parsed.Issuer.String(), caCommonName)
	}
}

// TestCA_GenerateRefusesToOverwrite confirms install is idempotent-
// failure: running ca install twice without --overwrite must error.
func TestCA_GenerateRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	if _, _, err := GenerateCA(paths, false); err != nil {
		t.Fatalf("first GenerateCA: %v", err)
	}
	_, _, err := GenerateCA(paths, false)
	if err == nil {
		t.Fatalf("expected error on second install without overwrite")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error %q; want 'already exists'", err)
	}
	// Overwrite=true should succeed (the rotate path).
	if _, _, err := GenerateCA(paths, true); err != nil {
		t.Fatalf("rotate (overwrite=true): %v", err)
	}
}

// TestCA_Install_KeyPermissions_RejectsWorldReadable (spec test):
// when the operator chmod's the CA key to 0o644, LoadCA must refuse
// to proceed with a clear error.
func TestCA_Install_KeyPermissions_RejectsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not enforced on Windows")
	}
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	if _, _, err := GenerateCA(paths, false); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.Chmod(paths.KeyFile, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, _, err := LoadCA(paths)
	if err == nil {
		t.Fatalf("expected LoadCA to refuse a world-readable key")
	}
	if !strings.Contains(err.Error(), "permissions") {
		t.Errorf("error %q does not mention permissions", err)
	}
}

// TestCA_Info_ReturnsFingerprint ensures the info command emits a
// non-empty fingerprint + the matching subject.
func TestCA_Info_ReturnsFingerprint(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	if _, _, err := GenerateCA(paths, false); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	info, err := Info(paths)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Fingerprint == "" || !strings.Contains(info.Fingerprint, ":") {
		t.Errorf("fingerprint %q malformed", info.Fingerprint)
	}
	if info.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Errorf("NotAfter %v should be ~10y out", info.NotAfter)
	}
}

// TestCA_Uninstall_Idempotent removes the files cleanly; running it
// twice should not error.
func TestCA_Uninstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	if _, _, err := GenerateCA(paths, false); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := Uninstall(paths); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(paths.CertFile); err == nil {
		t.Errorf("cert file still exists after uninstall")
	}
	if err := Uninstall(paths); err != nil {
		t.Errorf("Uninstall idempotency failed: %v", err)
	}
}

// TestCA_LoadCA_MissingFileGivesHelpfulError covers the empty-disk
// case — LoadCA should point the operator at `ca install`.
func TestCA_LoadCA_MissingFileGivesHelpfulError(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	_, _, err := LoadCA(paths)
	if err == nil {
		t.Fatalf("expected error for missing CA")
	}
	if !strings.Contains(err.Error(), "ca install") {
		t.Errorf("error %q does not mention `ca install`", err)
	}
}
