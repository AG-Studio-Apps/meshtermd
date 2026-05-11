package release

// Trusted minisign public-key roster for self-update verification.
// Mirrors `Sources/meshTerm/Roam/RoamInstallConstants.swift` in the
// iOS app; both must contain the same keys so a release verified by
// one verifies in the other.
//
// Each constant is the *payload* (second line) of a minisign .minipk
// file, base64 of: algo(2) || keyID(8) || ed25519_pubkey(32) = 42 bytes.
//
// Provisioned by scripts/provision-keys.sh on 2026-05-10.
// Key IDs (little-endian hex, displayed by `minisign -G`):
//   primary:   94562DC3EC2D6EB4
//   emergency: 520352A5DCDA7F4B

const (
	// Used by CI for every signed release. The matching private key
	// lives in the meshtermd repo's MINISIGN_KEY GH Actions secret.
	primaryKeyBase64 = "RWS0bi3swy1WlKoCoCnTQtCYAvt01ue3mMxhVy/Q6qxmVOdPpt8eIyQ1"

	// Held offline. Used to issue a signed release if the primary
	// is compromised, while a new iOS + meshtermd build rotates in
	// a fresh primary. Encrypted backup in the private
	// AG-Studio-Apps/meshterm_keys repo.
	emergencyKeyBase64 = "RWRLf9rcpVIDUt3i/vzE54hXOwcFe7jK6yMwxS/bIxT2C9Ors+ke8n1u"
)
