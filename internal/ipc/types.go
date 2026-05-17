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
	TypeAllocate      = "Allocate"
	TypePing          = "Ping"
	TypeListSessions  = "ListSessions"
	TypeKillSession   = "KillSession"
	TypeRenameSession = "RenameSession"
	TypeStatus        = "Status"
	TypeSessionSearch = "SessionSearch"
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

	// IdleTimeoutNanos is the per-session GC timeout the client
	// is requesting. Zero means "use the daemon's default" — the
	// registry then applies whatever the operator configured via
	// `--idle-timeout` on serve. A non-zero value is clamped at
	// the daemon's `--max-idle-timeout` ceiling when one is set.
	// Ignored when reattaching: the timeout is fixed at session
	// creation; reattach inherits whatever the original Allocate
	// chose. Encoded as nanoseconds rather than time.Duration so
	// the wire form stays portable across CBOR libraries that
	// don't know about Go's Duration type.
	IdleTimeoutNanos int64 `cbor:"itn,omitempty"`

	// Name is the optional user-visible session label. When
	// SessionID is empty or "new" and Name is set, the daemon does
	// a "create-if-missing" attach — looks up an existing session
	// by name first, spawns a new one with that name if absent.
	// When SessionID is set explicitly, Name is ignored on
	// reattach (the session's identity is fixed at creation).
	// Names must be unique per daemon; collisions on a fresh
	// spawn return ErrNameInUse.
	Name string `cbor:"name,omitempty"`

	// Persist is the tri-state opt-in for cross-restart session
	// persistence:
	//   nil   → use the daemon-wide default
	//          (`meshtermd serve --persistence-default`, default on).
	//   *true  → explicitly opt this session in.
	//   *false → explicitly opt this session out.
	//
	// Pointer-to-bool is the wire-side encoding of the three states
	// (CBOR omitempty drops nil; serialises true/false explicitly).
	// This lets clients that don't care about persistence inherit
	// the daemon's policy without having to know its value, and
	// older clients that don't set the field round-trip cleanly as
	// "use default."
	//
	// Resolved through Registry.ResolvePersist into a concrete bool
	// at session-spawn time. Ignored on reattach to an existing
	// session — persistence is fixed at spawn; opt-out a running
	// session by killing + respawning.
	Persist *bool `cbor:"p,omitempty"`
}

// AllocateResponse carries the fields that go into the bootstrap
// line printed to stdout. Ok=false means the request failed; Err
// describes the failure.
type AllocateResponse struct {
	T  string `cbor:"t"`
	Ok bool   `cbor:"ok"`

	// On success:
	SessionID   string `cbor:"sid,omitempty"`     // 32 hex chars
	AttachToken string `cbor:"tok,omitempty"`     // 32 hex chars, single-use, 30s TTL
	Port        uint16 `cbor:"port,omitempty"`    // QUIC UDP port
	CertFP      string `cbor:"cert_fp,omitempty"` // 64 hex chars, SHA-256 of cert DER
	// Name is the resolved user-visible session label. Echoed back
	// so the client knows what the daemon synthesised when the
	// request didn't supply one (see ipc/types.go AllocateRequest.Name).
	Name string `cbor:"name,omitempty"`

	// On failure:
	Err string `cbor:"err,omitempty"`
	Msg string `cbor:"msg,omitempty"`
}

// SessionInfo is one row of the ListSessionsResponse inventory.
// Used both over CBOR (IPC response shape) and over JSON (the
// `meshtermd list --json` output that iOS consumes via SSH);
// field tags are short stable strings so CBOR + JSON tooling
// produce a consistent wire form.
//
// AttachedNow is preserved as a bool for backwards-compat with
// pre-multi-attach iOS clients (decoding via Codable's
// decodeIfPresent on the field). AttachedModes is the richer
// multi-attach view: one entry per attached client, value is
// "exclusive" or "readonly". Equivalent to len(AttachedModes) > 0
// for AttachedNow's purposes; emitted by daemons that know about
// the field, ignored by older clients that don't.
type SessionInfo struct {
	ID             string   `cbor:"sid" json:"id"`
	Name           string   `cbor:"name" json:"name"`
	CreatedAtNs    int64    `cbor:"cn" json:"created_at_ns"`
	LastActiveAtNs int64    `cbor:"la" json:"last_active_at_ns"`
	AttachedNow    bool     `cbor:"att" json:"attached_now"`
	AttachedModes  []string `cbor:"am,omitempty" json:"attached_modes,omitempty"`
	IdleTimeoutNs  int64    `cbor:"itn,omitempty" json:"idle_timeout_ns,omitempty"`
	Rows           uint16   `cbor:"rows,omitempty" json:"rows,omitempty"`
	Cols           uint16   `cbor:"cols,omitempty" json:"cols,omitempty"`

	// Wedge-watcher cumulative counters. Optional so older daemon
	// builds (pre-v0.9.4) can round-trip with newer mtctl clients
	// without protocol breakage. Populated for every live session;
	// zero values are valid and indicate "no wedge events for this
	// session yet". Surfaces in `meshtermd session-info` / `mtctl
	// session-info` so operators can correlate session size + age
	// with wedge frequency without grepping the JSONL.
	WedgeTotalOutBytes      uint64 `cbor:"wto,omitempty" json:"wedge_total_out_bytes,omitempty"`
	WedgeResizesObserved    uint64 `cbor:"wro,omitempty" json:"wedge_resizes_observed,omitempty"`
	WedgeSilentWedges       uint64 `cbor:"wsw,omitempty" json:"wedge_silent,omitempty"`
	WedgeCursorWedges       uint64 `cbor:"wcw,omitempty" json:"wedge_cursor_row,omitempty"`
	WedgeVerticalWalkWedges uint64 `cbor:"wvw,omitempty" json:"wedge_vertical_walk,omitempty"`
}

// ListSessionsRequest enumerates every live session on the daemon.
// No filter — the SSH boundary is the auth boundary; if you can
// reach the IPC socket you can see everything.
type ListSessionsRequest struct {
	T string `cbor:"t"`
}

// ListSessionsResponse returns the inventory snapshot. Ok=false
// indicates an internal failure; the snapshot is empty in that case.
type ListSessionsResponse struct {
	T        string        `cbor:"t"`
	Ok       bool          `cbor:"ok"`
	Sessions []SessionInfo `cbor:"sessions,omitempty"`
	Err      string        `cbor:"err,omitempty"`
	Msg      string        `cbor:"msg,omitempty"`
}

// KillSessionRequest reaps a session by ID or name. Sel is the
// selector — tried as a hex SessionID first, falls back to a name
// lookup on parse failure. Single-arg form keeps the CLI surface
// simple (`meshtermd kill <id-or-name>`).
type KillSessionRequest struct {
	T   string `cbor:"t"`
	Sel string `cbor:"sel"`
}

// KillSessionResponse mirrors AllocateResponse's success/failure
// shape. ErrUnknownSession when the selector resolves to nothing.
type KillSessionResponse struct {
	T   string `cbor:"t"`
	Ok  bool   `cbor:"ok"`
	Err string `cbor:"err,omitempty"`
	Msg string `cbor:"msg,omitempty"`
}

// RenameSessionRequest changes a session's user-visible Name. Sel
// follows the same id-or-name resolution as KillSession.
// The PTY + ring buffer + active attach are untouched — this is a
// pure-label change. Empty NewName is rejected (anonymous-by-rename
// would leave a session unreachable via the picker).
type RenameSessionRequest struct {
	T       string `cbor:"t"`
	Sel     string `cbor:"sel"`
	NewName string `cbor:"new"`
}

// RenameSessionResponse echoes the new name on success so the
// caller can confirm the daemon's view matches.
type RenameSessionResponse struct {
	T    string `cbor:"t"`
	Ok   bool   `cbor:"ok"`
	Name string `cbor:"name,omitempty"`
	Err  string `cbor:"err,omitempty"`
	Msg  string `cbor:"msg,omitempty"`
}

// StatusRequest asks the daemon for its current operational
// snapshot. Read-only; no parameters. Useful for health probes
// (Phase 5 install flow + systemd unit health checks) and for
// debugging "is the daemon I think I'm talking to actually the
// daemon I'm talking to?"
type StatusRequest struct {
	T string `cbor:"t"`
}

// StatusResponse carries one snapshot of the daemon's
// configuration + live counters. Field tags are short stable
// strings; JSON tags match the wire shape `meshtermd status
// --json` emits for tooling consumers.
type StatusResponse struct {
	T  string `cbor:"t" json:"-"`
	Ok bool   `cbor:"ok" json:"ok"`

	Version             string `cbor:"ver,omitempty" json:"version"`
	StartedAtNs         int64  `cbor:"sat,omitempty" json:"started_at_ns"`
	UptimeNs            int64  `cbor:"upt,omitempty" json:"uptime_ns"`
	QUICAddr            string `cbor:"qa,omitempty" json:"quic_addr"`
	CertFingerprint     string `cbor:"fp,omitempty" json:"cert_fingerprint"`
	SessionCount        int    `cbor:"sc,omitempty" json:"session_count"`
	MaxSessions         int    `cbor:"ms,omitempty" json:"max_sessions"`
	IdleTimeoutNs       int64  `cbor:"itn,omitempty" json:"idle_timeout_ns"`
	MaxIdleTimeoutNs    int64  `cbor:"mitn,omitempty" json:"max_idle_timeout_ns"`
	PendingTokens       int    `cbor:"pt,omitempty" json:"pending_tokens"`

	Err string `cbor:"err,omitempty" json:"err,omitempty"`
	Msg string `cbor:"msg,omitempty" json:"msg,omitempty"`
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

// SessionSearchRequest scans the named session's scrollback ring for
// regex matches. Sel follows the same id-or-name resolution as
// KillSession. Pattern is the raw Go regexp/RE2 source; the daemon
// compiles it. Anchored=true wraps the pattern with (?m) so ^/$
// match at physical newlines in the retained bytes (the truncated
// ring start is NOT treated as ^). MaxMatches caps result count;
// 0 → daemon default (10,000).
type SessionSearchRequest struct {
	T          string `cbor:"t"`
	Sel        string `cbor:"sel"`
	Pattern    string `cbor:"pat"`
	MaxMatches int    `cbor:"max,omitempty"`
	Anchored   bool   `cbor:"anc,omitempty"`
}

// SearchMatchInfo is one row in a SessionSearchResponse. Byte offsets
// are in the buffer's monotonic seq space, so the caller can ReadSince
// for surrounding context if more than the immediate line is wanted.
// LineNum is 0-based within the retained scrollback (not absolute
// across session history — the ring can't know lines that have aged
// out). JSON tags match the wire shape `meshtermd session-search
// --json` emits for tooling consumers.
type SearchMatchInfo struct {
	StartSeq uint64 `cbor:"ss" json:"start_seq"`
	EndSeq   uint64 `cbor:"es" json:"end_seq"`
	Line     string `cbor:"l"  json:"line"`
	LineNum  int    `cbor:"n"  json:"line_num"`
}

// SessionSearchResponse carries the regex hits. Ok=false on bad
// pattern, unknown session, or internal error; Matches is empty in
// that case. An empty Matches with Ok=true means "valid request, no
// matches found."
type SessionSearchResponse struct {
	T       string            `cbor:"t" json:"-"`
	Ok      bool              `cbor:"ok" json:"ok"`
	Matches []SearchMatchInfo `cbor:"m,omitempty" json:"matches,omitempty"`
	Err     string            `cbor:"err,omitempty" json:"err,omitempty"`
	Msg     string            `cbor:"msg,omitempty" json:"msg,omitempty"`
}

// Error codes used in AllocateResponse.Err. Wire-stable strings.
const (
	ErrUnknownSession = "unknown_session"
	ErrCapacity       = "capacity"
	ErrSpawnFailed    = "spawn_failed"
	ErrInternal       = "internal"
	ErrBadRequest     = "bad_request"
	ErrNameInUse      = "name_in_use"
)
