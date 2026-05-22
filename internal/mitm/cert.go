// cert.go — per-host leaf cert generation + the in-memory LRU cache.
//
// On every CONNECT in MITM mode, the proxy looks up the host in the
// cache. Cache miss → mint a leaf cert signed by the loaded CA with
// `subjectAltName: DNS:<host>` (or `IP:<addr>` for IP-literal hosts)
// + insert into the cache. Cache hit → reuse. The LRU is bounded at
// 1024 entries; cold-host churn is acceptable since cert minting is
// ~milliseconds for ECDSA P-256.
package mitm

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// hostCertCacheSize is the maximum number of leaf certs we hold in
// memory. Matches the spec's "LRU size 1024". Past this, the
// least-recently-used entry is evicted.
const hostCertCacheSize = 1024

// CertMinter mints per-host leaf certs signed by a loaded CA + caches
// them with LRU eviction. Goroutine-safe.
type CertMinter struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	mu     sync.Mutex
	cache  map[string]*list.Element
	lru    *list.List // newest at front
	leafKey *ecdsa.PrivateKey // single shared key for all leaves
}

// cacheEntry is one LRU node. The key is the leaf cert's host (used
// for cache lookup); the value is the assembled tls.Certificate ready
// to be returned from a tls.Config.GetCertificate hook.
type cacheEntry struct {
	host    string
	tlsCert *tls.Certificate
}

// NewCertMinter builds a CertMinter from a loaded CA cert + key. The
// leaf-signing keypair is generated once and reused across all hosts
// — leaf certs share a public key, but each carries the unique host
// in subjectAltName. Sharing the key keeps minting fast (no per-host
// keygen on the hot path).
func NewCertMinter(ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*CertMinter, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	return &CertMinter{
		ca:      ca,
		caKey:   caKey,
		cache:   make(map[string]*list.Element, hostCertCacheSize),
		lru:     list.New(),
		leafKey: leafKey,
	}, nil
}

// CertFor returns a TLS cert for the given host. Cache-first; mints
// on miss. The host should be a bare hostname (no port) — strip the
// port before calling. Safe to call concurrently.
func (m *CertMinter) CertFor(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("CertFor: empty host")
	}

	m.mu.Lock()
	if elem, ok := m.cache[host]; ok {
		m.lru.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		m.mu.Unlock()
		return entry.tlsCert, nil
	}
	m.mu.Unlock()

	// Cache miss — mint outside the lock so concurrent misses for
	// different hosts don't serialize. Two callers minting the same
	// host produces a benign double-mint; second insert wins.
	tlsCert, err := m.mintLeaf(host)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if elem, ok := m.cache[host]; ok {
		// Lost the race. Use the existing entry + drop our mint.
		m.lru.MoveToFront(elem)
		return elem.Value.(*cacheEntry).tlsCert, nil
	}
	entry := &cacheEntry{host: host, tlsCert: tlsCert}
	elem := m.lru.PushFront(entry)
	m.cache[host] = elem
	if m.lru.Len() > hostCertCacheSize {
		oldest := m.lru.Back()
		if oldest != nil {
			m.lru.Remove(oldest)
			delete(m.cache, oldest.Value.(*cacheEntry).host)
		}
	}
	return tlsCert, nil
}

// Size returns the current LRU population. Test helper.
func (m *CertMinter) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cache)
}

// mintLeaf builds + signs a leaf cert for the given host.
func (m *CertMinter) mintLeaf(host string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.AddDate(0, 0, hostCertValidDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, &m.leafKey.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert for %q: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, m.ca.Raw},
		PrivateKey:  m.leafKey,
		Leaf:        leaf,
	}, nil
}

// normalizeHost lowercases + strips any trailing port. Empty input
// returns empty.
func normalizeHost(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// --- PEM-handling helpers ---

// writeCertPEM writes a CERTIFICATE PEM block to path with 0o644.
// Atomically rewrites if path exists.
func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	b := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeKeyPEM marshals an ECDSA key + writes it as "EC PRIVATE KEY"
// PEM with 0o600.
func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	b := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// parseECPrivateKey decodes a "EC PRIVATE KEY" or "PRIVATE KEY" PEM
// block. Accepts the SEC1 + the PKCS8 shapes so a key encoded by
// openssl in either form loads cleanly.
func parseECPrivateKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		ec, ok := any.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key is not ECDSA (got %T)", any)
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("unexpected PEM block type %q (want EC PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}

// sha256Fingerprint returns the SHA-256 fingerprint of a DER cert in
// the conventional uppercase-hex-colon-separated form for display.
func sha256Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	hexStr := hex.EncodeToString(sum[:])
	out := make([]byte, 0, len(hexStr)+len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, strings.ToUpper(hexStr[i:i+2])...)
	}
	return string(out)
}
