package session

import (
	"crypto/sha256"
	"encoding/hex"
)

// NameHash returns the first 8 hex characters of
// sha256(sid || 0x00 || name). Used in slog.Info call sites that
// would otherwise log raw session names, which can embed user input
// (Claude session topics, project codenames, ticket identifiers,
// etc.) that the operator wouldn't want surfaced in a paste-the-log
// support flow or in syslog/journald aggregation.
//
// 32 bits is enough to disambiguate a few hundred concurrent sessions
// without leaking name semantics. Sid is already logged at every
// affected call site, so operators can still correlate per-session
// events; the raw name remains available at Debug level for active
// troubleshooting (--v on the daemon's logger).
//
// The (sid, name) compound prevents two same-named sessions on the
// same daemon from sharing a hash; rename produces a new hash, which
// is intentional — the rename event itself logs the linkage.
//
// The hash is non-cryptographic in purpose (collision-resistance over
// a 32-bit output is meaningless); SHA-256 is chosen for ubiquity and
// because the codebase already imports it. The 0x00 separator avoids
// the (sid="ab", name="cd") vs (sid="abcd", name="") trivial collision.
func NameHash(sid SessionID, name string) string {
	h := sha256.New()
	h.Write(sid[:])
	h.Write([]byte{0x00})
	h.Write([]byte(name))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:4])
}
