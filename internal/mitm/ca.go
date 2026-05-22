// Package mitm implements gbounce's optional man-in-the-middle TLS
// inspection mode (#315 / §A13). MITM is OPT-IN: the operator must
// run `gbounce ca install`, add the generated root to the OS trust
// store, and then start the proxy with `--mode mitm`. The default
// mode is unchanged (CONNECT-tunnel passthrough) per
// `[[creates-never-mutates]]` — MITM is additive, never the default.
//
// Design boundaries (per `[[ibounce-honest-positioning]]` +
// `[[security-team-positioning-safety-not-surveillance]]`):
//
//   - The CA lives entirely on the operator's disk. No phone-home, no
//     remote signing, no shared keys across deployments per
//     `[[self-host-zero-billing-dependency]]`.
//
//   - The CA's Common Name + Issuer field is the literal string
//     "iam-jit gbounce local CA" — NO personally identifying info.
//     Operators are free to install this CA on machines they own;
//     the cert never leaves the machine unless they choose to copy it.
//
//   - The private key file is created with 0o600 permissions. The
//     MITM hot path REFUSES to start when the key file is
//     world-readable (or group-readable) — a leaked CA key is a
//     "trust this fake gbounce as me" boundary breach. Honest-fail
//     behavior makes the misconfiguration loud rather than silent.
//
//   - Per-host leaf certs are generated on-demand the first time a
//     CONNECT for that host arrives. They're cached in an in-memory
//     LRU bounded at 1024 entries (`hostCertCache`). The leaf cert
//     CN is the requested host; `subjectAltName: DNS:<host>` is set
//     so the agent's TLS stack accepts the cert.
//
//   - Cert-pinning SDKs (most modern AWS SDKs, banking SDKs, some
//     mobile SDKs) WILL break under MITM. The proxy returns a
//     graceful error to the client when the upstream handshake
//     fails for a pinning reason; operators flip back to CONNECT
//     mode for those SDKs.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// caCommonName is the CN + Issuer string we embed in every generated
// CA cert. Deliberately generic — no operator-identifying data per
// the spec's "no personal info in CN" constraint.
const caCommonName = "iam-jit gbounce local CA"

// caValidYears is how long a freshly generated CA cert is good for.
// 10 years matches the spec; operators can `gbounce ca rotate` early.
const caValidYears = 10

// hostCertValidDays is the lifetime of a per-host leaf cert.
// 90 days mirrors Let's Encrypt's lifetime; in practice the
// in-memory LRU evicts long before that.
const hostCertValidDays = 90

// CAPaths holds the on-disk locations of the CA's cert + key files +
// the directory that contains them. Keep these centralized so the CLI
// + the proxy + the rotate command all agree on one shape.
type CAPaths struct {
	Dir      string
	CertFile string
	KeyFile  string
}

// DefaultCAPaths returns the canonical CA locations under
// `~/.iam-jit/gbounce/ca/`. Honors `$HOME` (so a test can set HOME to
// a t.TempDir() and exercise the install flow hermetically).
func DefaultCAPaths() (CAPaths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return CAPaths{}, fmt.Errorf("resolve home dir: %w", err)
	}
	dir := filepath.Join(home, ".iam-jit", "gbounce", "ca")
	return CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}, nil
}

// CAInfo describes a loaded CA cert. Returned by `gbounce ca info` +
// used internally by the proxy startup check.
type CAInfo struct {
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string // sha256 hex, colon-separated, uppercase
}

// GenerateCA mints a new ECDSA P-256 CA cert + private key + writes
// them to the given paths. Refuses to overwrite an existing cert
// unless overwrite=true (the rotate command sets this; install does
// not). Permissions: cert 0o644, key 0o600, dir 0o700.
//
// Returns the loaded cert + key pair so callers can immediately use
// it for the rotate flow without re-reading disk.
func GenerateCA(paths CAPaths, overwrite bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if !overwrite {
		if _, err := os.Stat(paths.CertFile); err == nil {
			return nil, nil, fmt.Errorf("CA cert already exists at %s; use `gbounce ca rotate` to replace it", paths.CertFile)
		}
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create CA dir: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA private key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA serial: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{"iam-jit"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.AddDate(caValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	if err := writeCertPEM(paths.CertFile, der); err != nil {
		return nil, nil, err
	}
	if err := writeKeyPEM(paths.KeyFile, priv); err != nil {
		return nil, nil, err
	}
	return caCert, priv, nil
}

// LoadCA reads + parses the CA cert + key from disk. Returns an error
// that mentions the CA-install command when either file is missing.
//
// Also enforces the 0o600 key-file permissions invariant: a
// world-readable or group-readable key file fails the load (and thus
// fails proxy startup in MITM mode). Per the spec's honest-fail
// design — a leaked CA key is the boundary breach.
func LoadCA(paths CAPaths) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if _, err := os.Stat(paths.CertFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("CA cert not found at %s; run `gbounce ca install` to generate one", paths.CertFile)
		}
		return nil, nil, fmt.Errorf("stat CA cert: %w", err)
	}
	if err := EnforceKeyPermissions(paths.KeyFile); err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(paths.CertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(paths.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("CA cert PEM at %s is malformed (expected CERTIFICATE block)", paths.CertFile)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("CA key PEM at %s is malformed", paths.KeyFile)
	}
	priv, err := parseECPrivateKey(keyBlock)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

// EnforceKeyPermissions refuses to proceed when the key file has
// any group- or world-readable bits set. Windows (no POSIX perms)
// skips the check.
func EnforceKeyPermissions(keyFile string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("CA key not found at %s; run `gbounce ca install` to generate one", keyFile)
		}
		return fmt.Errorf("stat CA key: %w", err)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf(
			"refusing to load CA key at %s — permissions are %#o; a leaked CA key lets anyone forge certs trusted by every machine where you installed our CA. Fix with `chmod 600 %s` and re-run.",
			keyFile, mode, keyFile)
	}
	return nil
}

// Info returns a CAInfo for the cert at the given path. Cheap — does
// not load the private key. Used by `gbounce ca info`.
func Info(paths CAPaths) (CAInfo, error) {
	certPEM, err := os.ReadFile(paths.CertFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CAInfo{}, fmt.Errorf("CA cert not found at %s; run `gbounce ca install` to generate one", paths.CertFile)
		}
		return CAInfo{}, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return CAInfo{}, fmt.Errorf("CA cert PEM at %s is malformed", paths.CertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CAInfo{}, fmt.Errorf("parse CA cert: %w", err)
	}
	return CAInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: sha256Fingerprint(cert.Raw),
	}, nil
}

// Uninstall removes the CA cert + key from disk. Best-effort: a
// missing file is not an error (idempotent so a re-run is safe). The
// caller is responsible for printing the OS-trust-store cleanup
// reminder.
func Uninstall(paths CAPaths) error {
	for _, p := range []string{paths.CertFile, paths.KeyFile} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

// PlatformInstallInstructions returns the platform-specific OS
// trust-store install lines printed by `gbounce ca install`. Per the
// spec, separate lines for macOS, Linux (Debian/Ubuntu), Linux
// (RHEL/Fedora), and Firefox. The cert path is interpolated.
func PlatformInstallInstructions(paths CAPaths) []string {
	return []string{
		"",
		"To trust the CA on this machine, run the command for your platform:",
		"",
		"  macOS:",
		fmt.Sprintf("    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", paths.CertFile),
		"",
		"  Linux (Debian/Ubuntu):",
		fmt.Sprintf("    sudo cp %s /usr/local/share/ca-certificates/iam-jit-gbounce.crt", paths.CertFile),
		"    sudo update-ca-certificates",
		"",
		"  Linux (RHEL/Fedora):",
		fmt.Sprintf("    sudo cp %s /etc/pki/ca-trust/source/anchors/iam-jit-gbounce.crt", paths.CertFile),
		"    sudo update-ca-trust",
		"",
		"  Firefox (any OS):",
		"    Settings → Privacy & Security → Certificates → View Certificates →",
		"    Authorities → Import → select the cert file above → trust for websites.",
		"    (Firefox uses its own trust store; the OS-level install above is not enough.)",
		"",
		"To remove the CA later: `gbounce ca uninstall` + reverse the trust-store step above.",
	}
}

// PlatformUninstallReminder returns the lines printed by
// `gbounce ca uninstall` reminding the operator to remove the cert
// from the OS trust store. Removal on disk is automatic; OS-trust
// cleanup requires root + is operator-driven so we don't try to
// shell out per `[[creates-never-mutates]]`.
func PlatformUninstallReminder() []string {
	return []string{
		"",
		"The CA cert + key have been removed from disk.",
		"To also remove the CA from your OS trust store:",
		"",
		"  macOS:",
		"    sudo security delete-certificate -c 'iam-jit gbounce local CA' /Library/Keychains/System.keychain",
		"",
		"  Linux (Debian/Ubuntu):",
		"    sudo rm /usr/local/share/ca-certificates/iam-jit-gbounce.crt",
		"    sudo update-ca-certificates --fresh",
		"",
		"  Linux (RHEL/Fedora):",
		"    sudo rm /etc/pki/ca-trust/source/anchors/iam-jit-gbounce.crt",
		"    sudo update-ca-trust",
		"",
		"  Firefox: remove the 'iam-jit gbounce local CA' entry from the",
		"    Authorities tab of the certificate manager.",
	}
}
