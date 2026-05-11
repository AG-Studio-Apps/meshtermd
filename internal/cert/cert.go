// Package cert manages the daemon's self-signed TLS certificate.
//
// We generate a fresh ECDSA P-256 keypair + cert on first daemon startup
// and persist them to ~/.local/share/meshtermd/. The certificate is
// identified by the SHA-256 fingerprint of its DER encoding — that
// fingerprint travels through the SSH bootstrap to the iOS client,
// which pins it via Network.framework's verify block. There is no
// public-CA trust involved.
//
// P-256 (rather than Ed25519) because iOS Network.framework's QUIC
// ClientHello does not advertise `ed25519` in its TLS 1.3
// `signature_algorithms` extension, so an Ed25519 server cert
// triggers `CRYPTO_ERROR 0x128 (peer doesn't support any of the
// certificate's signature algorithms)` before the client's verify
// block is ever invoked. ECDSA P-256 with SHA-256 is universally
// supported in modern TLS 1.3 stacks (`ecdsa_secp256r1_sha256`,
// 0x0403). Security properties are equivalent — both ~128-bit
// classical strength, both forward-secret in TLS 1.3.
//
// All cryptographic operations use Go's standard library; this
// package introduces no new primitives.
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Default validity for a freshly minted cert. Rotation is automatic:
// LoadOrGenerate regenerates if the on-disk cert is within
// RenewalWindow of expiry (or already expired).
const DefaultValidity = 365 * 24 * time.Hour

// RenewalWindow is how close to NotAfter we trigger a regenerate
// during LoadOrGenerate. iOS clients pin the SHA-256 fingerprint, so
// rotation is silent from the client's perspective: the next
// bootstrap line carries the new fingerprint and the client
// re-pins. There's no continuity guarantee for clients holding a
// stale bootstrap line, but bootstrap tokens have a 30-second TTL
// anyway so the window where a stale fingerprint matters is
// narrow.
const RenewalWindow = 30 * 24 * time.Hour

// Fingerprint is the SHA-256 of the certificate's DER encoding —
// the value that travels through the SSH bootstrap line and is
// pinned by the iOS client.
type Fingerprint [sha256.Size]byte

// String returns the lowercase hex encoding (no separators), which
// is the format docs/roam-protocol.md mandates for the bootstrap
// line's <cert_fp> field.
func (f Fingerprint) String() string {
	return hex.EncodeToString(f[:])
}

// Manager owns the on-disk cert + key files and exposes them as a
// tls.Certificate ready to drop into a tls.Config.
type Manager struct {
	// Dir is where {cert,key}.pem live. Defaults via DefaultDir().
	Dir string

	// Validity, the duration freshly generated certs are valid for.
	// Defaults to DefaultValidity when zero.
	Validity time.Duration
}

// DefaultDir returns the conventional state directory:
// $XDG_DATA_HOME/meshtermd, falling back to $HOME/.local/share/meshtermd.
//
// Returns an error only if both XDG_DATA_HOME is unset and the user
// has no home directory — pathological enough to surface rather than
// silently picking some other location.
func DefaultDir() (string, error) {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "meshtermd"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "meshtermd"), nil
}

// LoadOrGenerate reads an existing cert+key from m.Dir, or generates
// a fresh pair if either file is missing or unreadable. Returns the
// loaded tls.Certificate and the cert's SHA-256 fingerprint (the
// value that goes into the bootstrap line).
//
// The key file is always written with mode 0600. The cert file is
// written with mode 0644 (it's safe to read; only the private key is
// sensitive). Both writes are atomic via tempfile-then-rename.
//
// Mismatched cert/key pairs are not silently regenerated — they
// return an error. A mismatched pair on disk is a sign of corruption
// or external tampering, and silently overwriting it would mask both.
func (m *Manager) LoadOrGenerate() (tls.Certificate, Fingerprint, error) {
	dir := m.Dir
	if dir == "" {
		var err error
		dir, err = DefaultDir()
		if err != nil {
			return tls.Certificate{}, Fingerprint{}, err
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("create state dir: %w", err)
	}
	// MkdirAll won't tighten a pre-existing dir's permissions, and
	// a 0755 dir lets a same-uid attacker plant a symlink at our
	// temp-file rename target. Mirror the IPC parent-dir audit (F5)
	// here: force the mode to 0o700 explicitly, then verify uid +
	// no group/other bits before we write a key into it.
	if err := os.Chmod(dir, 0o700); err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("tighten state dir perms: %w", err)
	}
	if err := verifyStateDir(dir); err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("state dir: %w", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert, fp, err := loadFromDisk(certPath, keyPath)
	switch {
	case err == nil:
		// Audit F10: regenerate if we're within the renewal window
		// or the cert has already expired. Loaded cert's leaf is
		// the first entry of cert.Certificate (DER bytes); parse
		// once to inspect NotAfter.
		if needsRotation(cert) {
			validity := m.Validity
			if validity <= 0 {
				validity = DefaultValidity
			}
			return generateAndPersist(certPath, keyPath, validity)
		}
		return cert, fp, nil
	case errors.Is(err, fs.ErrNotExist):
		// fall through to regenerate
	default:
		return tls.Certificate{}, Fingerprint{}, err
	}

	validity := m.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	return generateAndPersist(certPath, keyPath, validity)
}

// needsRotation reports whether the leaf cert is expired or within
// RenewalWindow of expiry. Errors during parse mean "rotate" — a
// cert we can't parse is one we shouldn't continue serving.
func needsRotation(cert tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Now().Add(RenewalWindow).After(leaf.NotAfter)
}

func loadFromDisk(certPath, keyPath string) (tls.Certificate, Fingerprint, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("load cert/key pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, Fingerprint{}, errors.New("loaded certificate has no DER body")
	}
	fp := sha256.Sum256(cert.Certificate[0])
	return cert, fp, nil
}

func generateAndPersist(certPath, keyPath string, validity time.Duration) (tls.Certificate, Fingerprint, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("generate ecdsa p-256 key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "meshtermd",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("create cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Atomic writes: temp file in the same dir, then rename.
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("write cert: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("write key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, Fingerprint{}, fmt.Errorf("re-parse generated pair: %w", err)
	}
	fp := sha256.Sum256(der)
	return tlsCert, fp, nil
}

// writeFileAtomic writes data to path via a tempfile-then-rename so a
// half-written file never lingers if the process dies mid-write.
// The tempfile is created with the target's intended mode so a
// subsequent open by another process (or by us) sees the right
// permissions even before rename.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".meshtermd-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// On error, clean up the tempfile.
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// verifyStateDir mirrors the IPC server's parent-dir audit (F5):
// the directory must be a regular dir, owned by the calling uid, and
// have no group/other permission bits. This prevents a same-uid
// attacker (or a user who copied their home over with rsync default
// flags) from leaving the cert + private key in a directory another
// process can read or that allows symlink races against the
// rename-temp-file pattern in writeFileAtomic.
func verifyStateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-POSIX FS (cifs, fuse without stat, etc.) — we can't
		// confirm ownership, so refuse rather than ship the key
		// into something we can't reason about.
		return fmt.Errorf("cannot inspect ownership of %s", path)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s owned by uid %d; expected %d", path, stat.Uid, os.Getuid())
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s has loose permissions %o; expected <= 0700", path, mode)
	}
	return nil
}
