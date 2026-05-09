package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadOrGenerateCreatesFreshPair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := &Manager{Dir: dir, Validity: time.Hour}

	cert, fp, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("returned tls.Certificate has no DER body")
	}

	// Files exist at expected paths.
	for _, name := range []string{"cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s on disk: %v", name, err)
		}
	}

	// Key file must be 0600.
	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key.pem mode = %o, want 0600", mode)
	}

	// Fingerprint must match SHA-256 of the cert DER.
	want := sha256.Sum256(cert.Certificate[0])
	if fp != Fingerprint(want) {
		t.Errorf("fingerprint mismatch")
	}

	// And the string form is 64 lowercase hex chars.
	if got := fp.String(); len(got) != 64 || got != strings.ToLower(got) {
		t.Errorf("fingerprint string = %q, want 64 lowercase hex chars", got)
	}
}

func TestLoadOrGenerateIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Validity must be well outside RenewalWindow so the second
	// LoadOrGenerate doesn't auto-rotate (audit F10).
	m := &Manager{Dir: dir, Validity: 2 * RenewalWindow}

	_, fp1, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Errorf("fingerprint changed between calls — second call regenerated when it should have loaded\n  first  = %s\n  second = %s", fp1, fp2)
	}
}

func TestLoadOrGenerateRotatesWithinRenewalWindow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Validity inside the renewal window: every load triggers a
	// regenerate, so fp1 != fp2.
	m := &Manager{Dir: dir, Validity: time.Hour}

	_, fp1, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Errorf("expected rotation: cert validity %v is inside RenewalWindow %v", m.Validity, RenewalWindow)
	}
}

func TestLoadOrGenerateRegeneratesWhenBothMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := &Manager{Dir: dir, Validity: time.Hour}
	_, fp1, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	// Wipe both files; next call must regenerate to a fresh fp.
	for _, name := range []string{"cert.pem", "key.pem"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	_, fp2, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp2 {
		t.Error("regeneration produced the same fingerprint — astronomically unlikely, suggests cache or RNG bug")
	}
}

func TestLoadOrGenerateRejectsMismatchedPair(t *testing.T) {
	t.Parallel()
	// Set up a valid pair.
	dir := t.TempDir()
	m := &Manager{Dir: dir, Validity: time.Hour}
	if _, _, err := m.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	// Generate a *different* key, write it where the original lived.
	other := t.TempDir()
	mOther := &Manager{Dir: other, Validity: time.Hour}
	if _, _, err := mOther.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	otherKey, err := os.ReadFile(filepath.Join(other, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := m.LoadOrGenerate(); err == nil {
		t.Error("LoadOrGenerate accepted mismatched cert/key pair")
	}
}

func TestLoadOrGenerateBubblesUpUnreadableCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Write a cert.pem that isn't a cert.
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: dir, Validity: time.Hour}
	_, _, err := m.LoadOrGenerate()
	if err == nil {
		t.Fatal("expected error when cert+key on disk are bogus")
	}
	// Should not be a "missing file" — both exist.
	if errors.Is(err, fs.ErrNotExist) {
		t.Error("got ErrNotExist for present-but-bogus files")
	}
}

func TestGeneratedCertHasExpectedShape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := &Manager{Dir: dir, Validity: 30 * time.Minute}

	cert, _, err := m.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// CommonName is set so logs / debugging show "meshtermd" rather
	// than an empty subject.
	if parsed.Subject.CommonName != "meshtermd" {
		t.Errorf("CN = %q, want meshtermd", parsed.Subject.CommonName)
	}
	// ExtKeyUsage must include ServerAuth or Network.framework's QUIC
	// path will reject the cert outright.
	hasServerAuth := false
	for _, eku := range parsed.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("cert lacks ExtKeyUsageServerAuth")
	}
	// Validity should be roughly what we asked for (with our small
	// clock-skew tolerance), not the default.
	gotValidity := parsed.NotAfter.Sub(parsed.NotBefore)
	wantValidity := 30*time.Minute + time.Minute // we subtract 1m from NotBefore for skew
	if d := gotValidity - wantValidity; d < -2*time.Second || d > 2*time.Second {
		t.Errorf("validity = %v, want ~%v", gotValidity, wantValidity)
	}
}

func TestDefaultDirRespectsXDGDataHome(t *testing.T) {
	// Cannot run in parallel — manipulates env.
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	got, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(xdg, "meshtermd")
	if got != want {
		t.Errorf("DefaultDir = %q, want %q", got, want)
	}
}

func TestDefaultDirFallsBackToHome(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no user home")
	}
	got, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".local", "share", "meshtermd")
	if got != want {
		t.Errorf("DefaultDir = %q, want %q", got, want)
	}
}

func TestFingerprintStringIsLowercaseHex(t *testing.T) {
	t.Parallel()
	var fp Fingerprint
	for i := range fp {
		fp[i] = 0xAB
	}
	got := fp.String()
	if got != strings.Repeat("ab", 32) {
		t.Errorf("fingerprint string = %q, want %q", got, strings.Repeat("ab", 32))
	}
}
