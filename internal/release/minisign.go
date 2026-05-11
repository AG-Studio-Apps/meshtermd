// Package release implements meshtermd's self-update path: fetching
// signed binaries from GitHub Releases, verifying their integrity,
// and atomically swapping the running binary in place.
//
// The minisign verifier here is functionally identical to the Swift
// implementation in the iOS app (Sources/meshTerm/Roam/MinisignVerifier.swift):
// same trusted-key roster, same algorithm dispatch (Ed / ED), same
// global-signature construction. Keeping the two in lockstep means a
// release that verifies in iOS will also verify here, and vice versa.
package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// VerifyError discriminates the failure modes of MinisignVerify so
// callers can show stage-specific messages without parsing strings.
type VerifyError struct {
	Kind   VerifyErrorKind
	Detail string
}

// VerifyErrorKind enumerates verification failure modes.
type VerifyErrorKind int

const (
	// VerifyMalformed means the .minisig file didn't parse as the
	// expected 4-line minisign format.
	VerifyMalformed VerifyErrorKind = iota
	// VerifyUnsupportedAlgorithm means the algorithm bytes weren't
	// one of the two we accept (Ed legacy / ED pre-hashed).
	VerifyUnsupportedAlgorithm
	// VerifyKeyIDMismatch means no trusted key's ID matched the
	// signature's claimed signer.
	VerifyKeyIDMismatch
	// VerifySignatureInvalid means the inner signature didn't verify.
	VerifySignatureInvalid
	// VerifyTrustedCommentInvalid means the global signature over
	// (inner_sig || trusted_comment) didn't verify.
	VerifyTrustedCommentInvalid
)

func (e *VerifyError) Error() string {
	switch e.Kind {
	case VerifyMalformed:
		return fmt.Sprintf("malformed signature file: %s", e.Detail)
	case VerifyUnsupportedAlgorithm:
		return fmt.Sprintf("unsupported signature algorithm: %q", e.Detail)
	case VerifyKeyIDMismatch:
		return "signature was made by a key not in the trusted roster"
	case VerifySignatureInvalid:
		return "signature does not match the signed file"
	case VerifyTrustedCommentInvalid:
		return "trusted-comment global signature is invalid"
	}
	return fmt.Sprintf("unknown verify error (%d)", e.Kind)
}

// VerifyResult reports the outcome of a successful verification.
type VerifyResult struct {
	// KeyIndex is the index into trustedKeys of the matching key.
	// 0 = primary, 1 = emergency. Callers can flag "emergency key
	// used" as a soft warning.
	KeyIndex int
	// TrustedComment is the text the signer attached, e.g.
	// "meshtermd v0.1.1" — useful for audit logs.
	TrustedComment string
}

// minisignAlgo is the 2-byte algorithm marker on the wire.
type minisignAlgo int

const (
	algoLegacy minisignAlgo = iota // "Ed" — sign file directly
	algoHashed                     // "ED" — sign BLAKE2b-512(file)
	algoUnknown
)

// MinisignVerify checks `sigFile` (a .minisig blob) against `body`
// using each entry in `trustedKeys` in order. Returns the matched
// key's index plus the trusted-comment text. Returns *VerifyError
// on any failure.
//
// Each `trustedKeys` entry must be a 42-byte minisign public-key
// payload: algo(2) || keyID(8) || ed25519_pubkey(32). The algo
// bytes in the public-key entry are advisory (a public key can
// verify both signature modes).
func MinisignVerify(body, sigFile []byte, trustedKeys [][]byte) (*VerifyResult, error) {
	parsed, err := parseMinisig(sigFile)
	if err != nil {
		return nil, err
	}

	// Pre-hashed mode signs Blake2b-512 of the file instead of the
	// file itself. Both modes share the global-signature construction.
	var innerMessage []byte
	switch parsed.algorithm {
	case algoLegacy:
		innerMessage = body
	case algoHashed:
		sum := blake2b.Sum512(body)
		innerMessage = sum[:]
	default:
		return nil, &VerifyError{Kind: VerifyUnsupportedAlgorithm, Detail: parsed.algorithmRaw}
	}

	for idx, fullKey := range trustedKeys {
		if len(fullKey) != 42 {
			continue
		}
		keyID := fullKey[2:10]
		pubKey := ed25519.PublicKey(fullKey[10:42])

		if !bytesEqual(keyID, parsed.keyID) {
			continue
		}
		if !ed25519.Verify(pubKey, innerMessage, parsed.signature) {
			return nil, &VerifyError{Kind: VerifySignatureInvalid}
		}
		// Global signature covers inner_sig || trusted_comment bytes.
		// This is what binds the trusted comment to the signature so
		// the signer can't disown their own labelling later.
		globalMessage := make([]byte, 0, len(parsed.signature)+len(parsed.trustedComment))
		globalMessage = append(globalMessage, parsed.signature...)
		globalMessage = append(globalMessage, []byte(parsed.trustedComment)...)
		if !ed25519.Verify(pubKey, globalMessage, parsed.globalSignature) {
			return nil, &VerifyError{Kind: VerifyTrustedCommentInvalid}
		}
		return &VerifyResult{KeyIndex: idx, TrustedComment: parsed.trustedComment}, nil
	}
	return nil, &VerifyError{Kind: VerifyKeyIDMismatch}
}

type parsedMinisig struct {
	algorithm       minisignAlgo
	algorithmRaw    string
	keyID           []byte // 8 bytes
	signature       []byte // 64 bytes
	trustedComment  string
	globalSignature []byte // 64 bytes
}

func parseMinisig(data []byte) (*parsedMinisig, error) {
	// Reject overlong inputs early — a well-formed minisig is well
	// under 4 KiB even with verbose comments. This is a sanity guard,
	// not a security boundary; the real check is the signature itself.
	if len(data) > 64*1024 {
		return nil, &VerifyError{Kind: VerifyMalformed, Detail: "blob exceeds 64 KiB"}
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 4 {
		return nil, &VerifyError{Kind: VerifyMalformed, Detail: "expected at least 4 lines"}
	}

	// Line 1: untrusted comment — discarded entirely.
	if !strings.HasPrefix(lines[0], "untrusted comment:") {
		return nil, &VerifyError{Kind: VerifyMalformed, Detail: "missing untrusted-comment header"}
	}

	// Line 2: base64(algo(2) || keyID(8) || sig(64)) = 74 bytes.
	sigBlob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, &VerifyError{Kind: VerifyMalformed, Detail: "signature line is not valid base64"}
	}
	if len(sigBlob) != 74 {
		return nil, &VerifyError{Kind: VerifyMalformed,
			Detail: fmt.Sprintf("signature blob is %d bytes; expected 74", len(sigBlob))}
	}
	algoBytes := sigBlob[0:2]
	algoRaw := string(algoBytes)
	algo := algoUnknown
	switch {
	case algoBytes[0] == 'E' && algoBytes[1] == 'd':
		algo = algoLegacy
	case algoBytes[0] == 'E' && algoBytes[1] == 'D':
		algo = algoHashed
	}

	// Line 3: "trusted comment: <text>" — text bytes are part of the
	// global-signature message.
	const tcPrefix = "trusted comment: "
	if !strings.HasPrefix(lines[2], tcPrefix) {
		return nil, &VerifyError{Kind: VerifyMalformed, Detail: "missing trusted-comment header"}
	}
	trustedComment := lines[2][len(tcPrefix):]

	// Line 4: base64(global_sig(64)).
	globalBlob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil {
		return nil, &VerifyError{Kind: VerifyMalformed, Detail: "global-signature line is not valid base64"}
	}
	if len(globalBlob) != 64 {
		return nil, &VerifyError{Kind: VerifyMalformed,
			Detail: fmt.Sprintf("global signature is %d bytes; expected 64", len(globalBlob))}
	}

	return &parsedMinisig{
		algorithm:       algo,
		algorithmRaw:    algoRaw,
		keyID:           sigBlob[2:10],
		signature:       sigBlob[10:74],
		trustedComment:  trustedComment,
		globalSignature: globalBlob,
	}, nil
}

// bytesEqual is a small wrapper so callers don't import bytes just
// for one comparison. Constant-time isn't needed for keyID match —
// it's not a secret.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Pre-decoded roster lookups, computed once.
var (
	trustedRosterCache [][]byte
	trustedRosterErr  error
)

// TrustedRoster returns the embedded primary + emergency public keys
// in priority order. Index 0 is primary, 1 is emergency. Callers that
// want to gate verification (e.g. a not-yet-provisioned build) can
// check len(...) > 0 and also that the bytes aren't all-zero.
func TrustedRoster() ([][]byte, error) {
	if trustedRosterCache != nil || trustedRosterErr != nil {
		return trustedRosterCache, trustedRosterErr
	}
	var out [][]byte
	for _, b64 := range []string{primaryKeyBase64, emergencyKeyBase64} {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			trustedRosterErr = fmt.Errorf("release: trusted-key base64 decode failed: %w", err)
			return nil, trustedRosterErr
		}
		if len(raw) != 42 {
			trustedRosterErr = errors.New("release: trusted-key payload is not 42 bytes")
			return nil, trustedRosterErr
		}
		out = append(out, raw)
	}
	trustedRosterCache = out
	return out, nil
}
