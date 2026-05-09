// Package ipc is the unix-socket IPC between `meshtermd serve`
// (the long-running daemon that owns the session registry) and
// `meshtermd connect` (the SSH-side helper that runs once per
// bootstrap to allocate or reattach a session).
//
// The same uid+gid runs both processes — there's no auth on the
// socket beyond filesystem permissions (the socket lives at mode
// 0600 in the daemon's state dir). Threat model: anyone who can
// read the socket can already read the daemon's state directly,
// so this layer trusts its peer.
//
// Wire format reuses the protocol package's CBOR framing (length-
// prefixed CBOR body) so we have a single understanding of "what's
// on a stream" throughout the codebase.
package ipc

// Request is the union of all `meshtermd connect` → `meshtermd serve`
// messages. Discriminated by the `t` tag, like the protocol's
// control stream.
const (
	TypeAllocate = "Allocate"
	TypePing     = "Ping"
)

// AllocateRequest reserves an attach for the named session (or
// creates a new one if SessionID is empty / "new") and returns the
// info needed to build the bootstrap line.
type AllocateRequest struct {
	T string `cbor:"t"`

	// SessionID, when set to the literal string "new" or empty,
	// requests a new session. Otherwise it's a 32-char hex ID
	// matching an existing session.
	SessionID string `cbor:"sid,omitempty"`

	// Rows and Cols set the initial PTY size for new sessions.
	// Ignored when reattaching to an existing session.
	Rows uint16 `cbor:"rows,omitempty"`
	Cols uint16 `cbor:"cols,omitempty"`

	// Exec is the command line to run inside the PTY for new
	// sessions. Empty means the user's $SHELL. The first element is
	// the binary path; remaining elements are args. Ignored when
	// reattaching.
	Exec []string `cbor:"exec,omitempty"`

	// Shell overrides the default shell-resolution chain. Empty
	// means use the daemon's resolveShell logic ($SHELL → /bin/bash
	// → /bin/sh). Ignored when Exec is set or when reattaching.
	Shell string `cbor:"shell,omitempty"`
}

// AllocateResponse carries the fields that go into the bootstrap
// line printed to stdout. Ok=false means the request failed; Err
// describes the failure.
type AllocateResponse struct {
	T  string `cbor:"t"`
	Ok bool   `cbor:"ok"`

	// On success:
	SessionID   string `cbor:"sid,omitempty"`    // 32 hex chars
	AttachToken string `cbor:"tok,omitempty"`    // 32 hex chars, single-use, 30s TTL
	Port        uint16 `cbor:"port,omitempty"`   // QUIC UDP port
	CertFP      string `cbor:"cert_fp,omitempty"` // 64 hex chars, SHA-256 of cert DER

	// On failure:
	Err string `cbor:"err,omitempty"`
	Msg string `cbor:"msg,omitempty"`
}

// PingRequest is a liveness check used by `meshtermd connect` to
// verify the daemon is alive before any session work. The daemon
// echoes a PingResponse with the same nonce.
type PingRequest struct {
	T     string `cbor:"t"`
	Nonce uint64 `cbor:"n"`
}

// PingResponse echoes a PingRequest's nonce.
type PingResponse struct {
	T     string `cbor:"t"`
	Nonce uint64 `cbor:"n"`
}

// Error codes used in AllocateResponse.Err. Wire-stable strings.
const (
	ErrUnknownSession  = "unknown_session"
	ErrCapacity        = "capacity"
	ErrSpawnFailed     = "spawn_failed"
	ErrInternal        = "internal"
	ErrBadRequest      = "bad_request"
)
