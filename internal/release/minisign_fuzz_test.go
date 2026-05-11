package release

import (
	"encoding/base64"
	"testing"
)

// FuzzParseMinisig is the fuzz target for the minisign signature
// parser. parseMinisig is reached on every self-update — the
// signature file is attacker-controlled (a hostile mirror or MITM can
// substitute it), and the parser runs before any cryptographic
// validation. Its contract is "returns either a parsedMinisig or a
// *VerifyError; never panics, never deadlocks". Anything else is a
// finding.
//
// Run locally with:
//
//	go test -run='^$' -fuzz=FuzzParseMinisig -fuzztime=30s ./internal/release
//
// CI runs it as a bounded job on push to main (see .github/workflows/ci.yml).
func FuzzParseMinisig(f *testing.F) {
	// Real-shape seed: a structurally-valid signature (line counts,
	// prefixes, base64 lengths) without cryptographic validity. The
	// parser doesn't check signatures, so this exercises the success
	// path through to the return.
	validShape := []byte("untrusted comment: seed\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 74)) + "\n" +
		"trusted comment: seed\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n")
	f.Add(validShape)

	// Adversarial seeds — common parser-breaker shapes that
	// libfuzzer-style mutators don't always hit quickly enough.
	seeds := [][]byte{
		{}, // empty
		[]byte("untrusted comment: x\n"),                                 // single line
		[]byte("untrusted comment:\n\n\n\n"),                             // four empty-ish lines
		[]byte("untrusted comment: x\nAA\ntrusted comment: y\nAA\n"),     // base64 of wrong length
		[]byte("untrusted comment: x\n!!!!\ntrusted comment: y\nAAAA\n"), // invalid base64
		[]byte("UNTRUSTED comment: x\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 74)) + "\n" +
			"trusted comment: y\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n"), // wrong-case prefix
		[]byte("untrusted comment: x\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 74)) + "\n" +
			"TRUSTED comment: y\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n"), // wrong-case prefix line 3
		append(append([]byte("untrusted comment: huge\n"),
			make([]byte, 128*1024)...), '\n'), // > 64 KiB cap
		[]byte("untrusted comment: x\x00embedded\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 74)) + "\n" +
			"trusted comment: y\x00embedded\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n"), // null bytes in comments
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: never panics. Either returns a struct + nil, or
		// nil + a *VerifyError. Anything else (untyped error, panic,
		// nil/nil) is a regression.
		got, err := parseMinisig(data)
		if err != nil {
			if _, ok := err.(*VerifyError); !ok {
				t.Fatalf("parseMinisig returned %T (%v); expected *VerifyError or nil", err, err)
			}
			return
		}
		if got == nil {
			t.Fatal("parseMinisig returned (nil, nil)")
		}
		// On success, expose the structural invariants the rest of
		// MinisignVerify relies on. If any of these are violated,
		// downstream code may index out-of-bounds.
		if len(got.keyID) != 8 {
			t.Fatalf("keyID len = %d, want 8", len(got.keyID))
		}
		if len(got.signature) != 64 {
			t.Fatalf("signature len = %d, want 64", len(got.signature))
		}
		if len(got.globalSignature) != 64 {
			t.Fatalf("globalSignature len = %d, want 64", len(got.globalSignature))
		}
	})
}
