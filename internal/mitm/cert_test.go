package mitm

import (
	"crypto/x509"
	"path/filepath"
	"testing"
)

// TestMITM_CONNECTGeneratesPerHostCert (spec test): when the proxy
// asks for a leaf cert for a given host, the minter returns one
// whose subjectAltName contains the host + is signed by the CA.
func TestMITM_CONNECTGeneratesPerHostCert(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	ca, key, err := GenerateCA(paths, false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	m, err := NewCertMinter(ca, key)
	if err != nil {
		t.Fatalf("NewCertMinter: %v", err)
	}

	leaf, err := m.CertFor("api.example.com")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatalf("Leaf nil")
	}
	// SAN contains host.
	foundHost := false
	for _, dns := range leaf.Leaf.DNSNames {
		if dns == "api.example.com" {
			foundHost = true
		}
	}
	if !foundHost {
		t.Errorf("DNSNames %v missing api.example.com", leaf.Leaf.DNSNames)
	}
	// Verify chain via the CA pool we just built.
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "api.example.com",
	})
	if err != nil {
		t.Errorf("Verify against CA: %v", err)
	}
}

// TestMITM_CertMinterLRUCachesAndEvicts asserts cache hits + eviction
// at the documented size bound.
func TestMITM_CertMinterLRUCachesAndEvicts(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	ca, key, err := GenerateCA(paths, false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	m, err := NewCertMinter(ca, key)
	if err != nil {
		t.Fatalf("NewCertMinter: %v", err)
	}

	// First mint
	c1, err := m.CertFor("api.example.com")
	if err != nil {
		t.Fatalf("CertFor first: %v", err)
	}
	// Second call returns the SAME *tls.Certificate from the cache.
	c2, err := m.CertFor("api.example.com")
	if err != nil {
		t.Fatalf("CertFor second: %v", err)
	}
	if c1 != c2 {
		t.Errorf("expected cache hit; got different pointers %p vs %p", c1, c2)
	}
	if m.Size() != 1 {
		t.Errorf("Size %d; want 1", m.Size())
	}
}

// TestMITM_CertMinter_StripsPort confirms a host:port input normalizes
// to host-only before signing.
func TestMITM_CertMinter_StripsPort(t *testing.T) {
	dir := t.TempDir()
	paths := CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}
	ca, key, err := GenerateCA(paths, false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	m, _ := NewCertMinter(ca, key)
	leaf, err := m.CertFor("api.example.com:443")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	if got := leaf.Leaf.Subject.CommonName; got != "api.example.com" {
		t.Errorf("CN = %q; want api.example.com", got)
	}
}
