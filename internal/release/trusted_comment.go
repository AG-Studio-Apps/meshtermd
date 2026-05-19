package release

import (
	"fmt"
	"strings"
)

// trustedCommentPrefix is the literal first token the release workflow
// writes into every signed SHA256SUMS' trusted comment via
// `minisign -t "meshtermd <tag>"` (see .github/workflows/release.yml).
// Pinning it here lets `EnforceTrustedComment` reject any comment that
// doesn't conform — including a same-key signature whose comment names
// a different repo or no tag at all.
const trustedCommentPrefix = "meshtermd "

// EnforceTrustedComment fails when the minisign trusted comment from a
// verified SHA256SUMS.minisig does not name the same tag the caller
// requested. Closes the "signature not bound to release tag" gap from
// the 2026-05-19 Codex audit: minisign verifies that *some* SHA256SUMS
// was signed by our key, but the signed payload is the SHA list — not
// the tag. Without this check, a same-key SHA256SUMS from an OLDER
// release can be re-published under a NEWER tag, the anti-rollback
// version comparison sees a newer target, and the update path
// installs an older (potentially vulnerable) binary.
//
// The signing pipeline always sets trusted comment to "meshtermd <tag>"
// (.github/workflows/release.yml :: minisign -t "meshtermd
// $GITHUB_REF_NAME"). We canonicalise both sides via strings.TrimSpace
// before comparison to absorb any trailing whitespace that crept in.
//
// Case-sensitive on purpose: our tags are lowercase ("v1.1.3"); a
// comment with "V1.1.3" would indicate a non-canonical signing path.
func EnforceTrustedComment(got, wantTag string) error {
	got = strings.TrimSpace(got)
	want := trustedCommentPrefix + wantTag
	if got != want {
		return fmt.Errorf(
			"signature trusted comment %q does not bind to requested tag %q "+
				"(expected %q)", got, wantTag, want)
	}
	return nil
}
