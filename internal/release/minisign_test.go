package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// testSigner is a self-contained minisign-format signature factory
// used by every test below. We don't shell out to the minisign CLI
// because (a) it may not be present in CI and (b) the format is
// stable enough to construct in 30 lines of Go.
type testSigner struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID [8]byte
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	s := &testSigner{priv: priv, pub: pub}
	if _, err := rand.Read(s.keyID[:]); err != nil {
		t.Fatalf("rand.Read keyID: %v", err)
	}
	return s
}

// trustedBlob assembles the 42-byte trusted-key payload: algo "Ed"
// (2) + keyID (8) + pubkey (32). The algo bytes on the *public-key*
// entry are informational; verification accepts both signature
// modes regardless.
func (s *testSigner) trustedBlob() []byte {
	out := make([]byte, 0, 42)
	out = append(out, 'E', 'd')
	out = append(out, s.keyID[:]...)
	out = append(out, s.pub...)
	return out
}

// sign builds a minisign-format signature file. When `hashed` is
// true, signs Blake2b-512(message) (the "ED" algorithm); otherwise
// signs the message directly ("Ed" legacy).
func (s *testSigner) sign(message []byte, trustedComment string, hashed bool) []byte {
	var inner []byte
	if hashed {
		sum := blake2b.Sum512(message)
		inner = ed25519.Sign(s.priv, sum[:])
	} else {
		inner = ed25519.Sign(s.priv, message)
	}
	algo := []byte{'E', 'd'}
	if hashed {
		algo[1] = 'D'
	}

	// Line 2 payload: algo(2) || keyID(8) || sig(64).
	line2 := make([]byte, 0, 74)
	line2 = append(line2, algo...)
	line2 = append(line2, s.keyID[:]...)
	line2 = append(line2, inner...)

	// Global signature signs inner || trusted_comment bytes.
	globalMsg := make([]byte, 0, len(inner)+len(trustedComment))
	globalMsg = append(globalMsg, inner...)
	globalMsg = append(globalMsg, []byte(trustedComment)...)
	global := ed25519.Sign(s.priv, globalMsg)

	out := fmt.Sprintf(
		"untrusted comment: test signature\n"+
			"%s\n"+
			"trusted comment: %s\n"+
			"%s\n",
		base64.StdEncoding.EncodeToString(line2),
		trustedComment,
		base64.StdEncoding.EncodeToString(global),
	)
	return []byte(out)
}

func TestVerifyLegacySignatureFromPrimaryKey(t *testing.T) {
	primary := newTestSigner(t)
	emergency := newTestSigner(t)
	body := []byte("hello, minisign\n")
	sig := primary.sign(body, "meshtermd v0.1.0", false)
	result, err := MinisignVerify(body, sig, [][]byte{primary.trustedBlob(), emergency.trustedBlob()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.KeyIndex != 0 {
		t.Errorf("KeyIndex = %d, want 0", result.KeyIndex)
	}
	if result.TrustedComment != "meshtermd v0.1.0" {
		t.Errorf("TrustedComment = %q", result.TrustedComment)
	}
}

func TestVerifyHashedSignatureFromPrimaryKey(t *testing.T) {
	// Real CI signing path: Ubuntu minisign 0.11 emits hashed (ED).
	primary := newTestSigner(t)
	emergency := newTestSigner(t)
	body := []byte("hello prehashed\n")
	sig := primary.sign(body, "meshtermd v0.1.1", true)
	result, err := MinisignVerify(body, sig, [][]byte{primary.trustedBlob(), emergency.trustedBlob()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.KeyIndex != 0 {
		t.Errorf("KeyIndex = %d, want 0", result.KeyIndex)
	}
}

func TestVerifyEmergencyKeyIsRosterIndex1(t *testing.T) {
	primary := newTestSigner(t)
	emergency := newTestSigner(t)
	body := []byte("rotation drill")
	sig := emergency.sign(body, "v0.2.0 emergency", true)
	result, err := MinisignVerify(body, sig, [][]byte{primary.trustedBlob(), emergency.trustedBlob()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.KeyIndex != 1 {
		t.Errorf("KeyIndex = %d, want 1", result.KeyIndex)
	}
}

func TestRejectsUntrustedKey(t *testing.T) {
	trusted := newTestSigner(t)
	attacker := newTestSigner(t)
	body := []byte("evil")
	sig := attacker.sign(body, "x", true)
	_, err := MinisignVerify(body, sig, [][]byte{trusted.trustedBlob()})
	if err == nil {
		t.Fatal("expected verify failure")
	}
	if ve, ok := err.(*VerifyError); !ok || ve.Kind != VerifyKeyIDMismatch {
		t.Errorf("wrong error kind: %v", err)
	}
}

func TestRejectsTamperedBody(t *testing.T) {
	signer := newTestSigner(t)
	original := []byte("real body")
	tampered := []byte("evil body")
	sig := signer.sign(original, "v1", true)
	_, err := MinisignVerify(tampered, sig, [][]byte{signer.trustedBlob()})
	if err == nil {
		t.Fatal("expected verify failure")
	}
	if ve, ok := err.(*VerifyError); !ok || ve.Kind != VerifySignatureInvalid {
		t.Errorf("wrong error kind: %v", err)
	}
}

func TestRejectsMalformedBase64(t *testing.T) {
	signer := newTestSigner(t)
	bad := []byte("untrusted comment: x\nnot~base64!!\ntrusted comment: y\nalso~not!!\n")
	_, err := MinisignVerify([]byte("x"), bad, [][]byte{signer.trustedBlob()})
	if err == nil {
		t.Fatal("expected verify failure")
	}
	if ve, ok := err.(*VerifyError); !ok || ve.Kind != VerifyMalformed {
		t.Errorf("wrong error kind: %v", err)
	}
}

func TestRejectsMissingTrustedCommentHeader(t *testing.T) {
	signer := newTestSigner(t)
	body := []byte("x")
	good := signer.sign(body, "v1", true)
	// Mangle the trusted-comment prefix.
	bad := strings.Replace(string(good), "trusted comment: ", "TRUSTED comment: ", 1)
	_, err := MinisignVerify(body, []byte(bad), [][]byte{signer.trustedBlob()})
	if ve, ok := err.(*VerifyError); !ok || ve.Kind != VerifyMalformed {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRosterDecodes(t *testing.T) {
	r, err := TrustedRoster()
	if err != nil {
		t.Fatalf("TrustedRoster: %v", err)
	}
	if len(r) != 2 {
		t.Fatalf("len = %d, want 2", len(r))
	}
	for i, k := range r {
		if len(k) != 42 {
			t.Errorf("key %d is %d bytes, want 42", i, len(k))
		}
		// Algo bytes must be "Ed".
		if k[0] != 'E' || k[1] != 'd' {
			t.Errorf("key %d algo bytes = %q, want 'Ed'", i, k[0:2])
		}
		// Sanity: not all zero.
		nonzero := false
		for _, b := range k {
			if b != 0 {
				nonzero = true
				break
			}
		}
		if !nonzero {
			t.Errorf("key %d is all zero — placeholder shipped to prod?", i)
		}
	}
}
