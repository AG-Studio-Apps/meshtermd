package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"
)

// SessionIDLen is the byte length of a session identifier.
const SessionIDLen = 16

// AttachMode is the role a client takes when attaching. The wire
// representation is a lowercase string on the Attach control frame
// (see `protocol.AttachModeExclusive` / `AttachModeReadonly`); we
// keep an internal Go-typed mirror so the session code doesn't
// depend on the protocol package directly.
type AttachMode int

const (
	// AttachExclusive is the default attach mode. The client
	// receives output, sends stdin, and owns the PTY size via
	// Resize. A new exclusive attach displaces any prior exclusive
	// attach (existing readonly attaches are unaffected). This is
	// the only mode pre-multi-attach clients can request, and the
	// only mode where stdin actually reaches the shell.
	AttachExclusive AttachMode = iota

	// AttachReadonly is the watcher mode. Receives output, doesn't
	// send stdin or Resize (the daemon drops them on the protocol
	// boundary so a misbehaving keystroke can't tear the
	// connection down). Any number of readonly clients can coexist
	// with each other and with a single exclusive client.
	AttachReadonly
)

// String returns the wire form of an AttachMode for logging /
// AttachAck.Mode echo. Mirrors protocol.AttachMode* constants.
func (m AttachMode) String() string {
	switch m {
	case AttachReadonly:
		return "readonly"
	default:
		return "exclusive"
	}
}

// sessionClient is the per-attach state stored inside a Session
// while a client is connected. The cancel func is the goroutine-
// local context-cancellation hook the daemon uses to evict a
// client (e.g. when an exclusive replacement displaces the prior
// exclusive). gen is the monotonic identity used by Release to
// distinguish "this is me, removing myself" from "I was already
// kicked out" — see the activeGen rationale on Session.
type sessionClient struct {
	gen    uint64
	mode   AttachMode
	cancel context.CancelFunc
}

// SessionID is a 16-byte random identifier for a Session, generated at
// session creation. The ID confers no authority on its own — see
// docs/SECURITY.md threat E.
type SessionID [SessionIDLen]byte

// NewSessionID returns a fresh random session ID using crypto/rand.
func NewSessionID() (SessionID, error) {
	var id SessionID
	_, err := rand.Read(id[:])
	return id, err
}

// String returns the hex encoding (32 chars) used in the bootstrap line
// and in client-facing diagnostics.
func (id SessionID) String() string {
	return hex.EncodeToString(id[:])
}

// Bytes returns a fresh copy of the session ID's raw bytes for
// inclusion in CBOR-encoded protocol messages where the wire form
// is `bytes` not `string`.
func (id SessionID) Bytes() []byte {
	out := make([]byte, len(id))
	copy(out, id[:])
	return out
}

// ParseSessionID parses a 32-char hex SessionID. Returns an error on
// any deviation from that format.
func ParseSessionID(s string) (SessionID, error) {
	var id SessionID
	if len(s) != SessionIDLen*2 {
		return id, errors.New("session id must be 32 hex chars")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	copy(id[:], b)
	return id, nil
}

// PTY is the abstraction the Session needs from a pseudo-terminal.
// Real implementations wrap creack/pty; tests can substitute pipes.
//
// Read returns bytes from the PTY's slave-side output (what the user
// sees on screen). Write sends bytes to the PTY's stdin (keyboard
// input). SetSize forwards a window-size change. Close terminates
// the PTY and releases the file descriptors.
type PTY interface {
	io.Reader
	io.Writer
	io.Closer
	SetSize(rows, cols uint16) error
}

// Session is one persistent terminal: a PTY + child process + an
// output ring buffer. Sessions outlive QUIC connections; clients
// attach by ID, the buffer replays anything they missed.
type Session struct {
	id      SessionID
	name    string
	created time.Time
	cap     int

	mu sync.Mutex

	buf  *RingBuffer
	pty  PTY
	rows uint16
	cols uint16

	// idleTimeout is how long this session may sit idle (no PTY
	// output, no stdin, no resize, no attach) before the registry's
	// GC reaps it. Set per-session at creation time so different
	// hosts/sessions can carry different lifetimes — a long-lived
	// dev box wants 7 days, a one-off CI shell can stay at the
	// daemon's hour default. Zero means "use the registry's
	// default", per the constructor's contract.
	idleTimeout time.Duration

	// Last time something happened on this session (PTY output or
	// active attach). Drives the registry's idle-GC.
	lastActiveAt time.Time

	// clients is the set of currently-attached clients. There is at
	// most one client whose mode is exclusive; any number whose
	// mode is readonly may coexist with it AND with each other.
	// Pre-multi-attach this was a single (cancel, gen) slot; the
	// slice form generalises to read-only watchers (Tier 1
	// shared-attach) and tmux-style co-equal pair-programming
	// (Tier 2 — protocol headroom is reserved, semantics deferred).
	clients []sessionClient

	// nextGen monotonically counts attach calls. Each successful
	// Acquire returns a fresh value; Release(gen) only removes the
	// matching client. Audit F4 (v0.0.2 review) — this replaces
	// the ctx-error-as-identity heuristic with a proper monotonic
	// generation counter so a displaced client calling Release
	// after the new owner has taken over does NOT stomp the new
	// owner's state.
	nextGen uint64

	// suppressNextRedraw is set by Resize when the kernel actually
	// fires SIGWINCH at the child shell. The Pump loop checks this
	// flag on its next chunk and, if the chunk starts with
	// `\r\x1b[K` (bash's prompt-redraw introducer from SIGWINCH),
	// drops that single chunk so it never reaches the ring buffer.
	// Without this filter, every Resize that legitimately changes
	// size leaves a stale prompt-redraw blob in the buffer; on
	// replay those redraws render at whatever cursor position they
	// were emitted at, producing the visible "extra prompts"
	// pollution that grows on each cold-start.
	suppressNextRedraw bool

	closed bool
}

// NewSession constructs a Session. The caller is expected to start
// the pump goroutine separately (see Pump). We don't do it inside the
// constructor so test code can inject deterministic behaviour.
//
// `name` is the user-visible label addressable via Registry.LookupByName
// and surfaced in `meshtermd list`. The empty string is allowed —
// such a session is anonymous (registry doesn't index it by name)
// but the daemon's spawnSession synthesises a non-empty default
// (`session-<6hex>`) so client UIs never see blank names. `name` is
// immutable post-construction; rename support is a future addition.
//
// idleTimeout = 0 means "inherit the registry's default at GC
// time"; the registry's Sweep falls back to its own idleTimeout
// when this field is zero. Pass an explicit duration to give this
// session a per-session lifetime independent of the daemon-wide
// default.
func NewSession(id SessionID, name string, pty PTY, rows, cols uint16, bufCapacity int, idleTimeout time.Duration) (*Session, error) {
	if pty == nil {
		return nil, errors.New("pty must not be nil")
	}
	if bufCapacity <= 0 {
		bufCapacity = DefaultBufferCapacity
	}
	buf, err := NewRingBuffer(bufCapacity)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &Session{
		id:           id,
		name:         name,
		created:      now,
		cap:          bufCapacity,
		buf:          buf,
		pty:          pty,
		rows:         rows,
		cols:         cols,
		idleTimeout:  idleTimeout,
		lastActiveAt: now,
	}, nil
}

// Name returns the user-visible session label. Empty for anonymous
// sessions (legacy callers that don't supply a name).
func (s *Session) Name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

// setName mutates the Session's user-visible label under its lock.
// Package-private: only the Registry calls this, as part of an
// atomic rename that ALSO updates the byName index. Callers from
// outside the package must use Registry.Rename to keep the
// indices in lockstep.
func (s *Session) setName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.name = name
}

// LastActiveAt returns the wall-clock time of the most recent
// activity event (PTY output, stdin write, resize, or attach).
// Symmetric with IdleFor; ListSessions uses this for the picker
// UI's "last active" hint.
func (s *Session) LastActiveAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActiveAt
}

// IsAttached reports whether at least one client is currently
// attached to this session, regardless of mode. Used by
// ListSessions to surface the AttachedNow flag in the picker.
// This is a snapshot — clients can come and go between this read
// and the caller observing the result.
func (s *Session) IsAttached() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients) > 0
}

// IdleTimeout returns the per-session GC timeout configured at
// construction. Returns zero when the session was constructed with
// `idleTimeout == 0` (registry-default fallback).
func (s *Session) IdleTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idleTimeout
}

// ID returns the session's hex-encoded identifier.
func (s *Session) ID() SessionID { return s.id }

// Created returns the wall-clock time the session was created.
func (s *Session) Created() time.Time { return s.created }

// Buffer exposes the underlying ring buffer for replay reads. Returns
// nil if the session has been closed.
func (s *Session) Buffer() *RingBuffer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.buf
}

// WriteStdin forwards bytes from the client to the PTY's input.
// Updates the activity timestamp so GC doesn't reap an active session
// just because output has gone quiet.
func (s *Session) WriteStdin(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrSessionClosed
	}
	pty := s.pty
	s.lastActiveAt = time.Now()
	s.mu.Unlock()
	return pty.Write(p)
}

// Resize updates the PTY's window size and remembers the latest
// values for any future re-attachers that join without sending their
// own Resize. If the new size differs from the current one, the
// kernel will fire SIGWINCH at the child shell, which (for an
// interactive bash) reacts by writing a prompt-redraw blob to the
// PTY output. We arm `suppressNextRedraw` so the Pump loop drops
// that one chunk before it enters the ring buffer — replays don't
// then accumulate stale prompt redraws on each cold-start.
func (s *Session) Resize(rows, cols uint16) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	sizeChanged := s.rows != rows || s.cols != cols
	s.rows, s.cols = rows, cols
	pty := s.pty
	s.lastActiveAt = time.Now()
	if sizeChanged {
		s.suppressNextRedraw = true
	}
	s.mu.Unlock()
	return pty.SetSize(rows, cols)
}

// shouldSuppressRedraw consumes the suppress-next-redraw flag if
// `chunk` looks like bash's SIGWINCH prompt-redraw blob (starts
// with `\r\x1b[K`). Returns true if the chunk should be skipped.
// Called by Pump on each PTY read.
func (s *Session) shouldSuppressRedraw(chunk []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.suppressNextRedraw {
		return false
	}
	// Match `\r\x1b[K` at chunk start — bash readline's
	// rl_redisplay() canonical "redraw current line" intro.
	if len(chunk) >= 4 && chunk[0] == '\r' && chunk[1] == 0x1B && chunk[2] == '[' && chunk[3] == 'K' {
		s.suppressNextRedraw = false
		return true
	}
	// Not a redraw — clear the flag anyway so we don't suppress a
	// legitimate later chunk if bash decides not to redraw for
	// whatever reason.
	s.suppressNextRedraw = false
	return false
}

// WindowSize returns the latest known window size.
func (s *Session) WindowSize() (rows, cols uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows, s.cols
}

// Acquire claims this session for a new attach with the given mode.
//
// Semantics:
//
//   - mode = AttachExclusive: any prior exclusive client is
//     displaced (its context cancelled, goroutine should observe
//     ctx.Done() and exit with reason "replaced"). Existing
//     readonly clients are unaffected — they keep observing.
//   - mode = AttachReadonly: never displaces anyone. Coexists with
//     a current exclusive client and with other readonly clients.
//
// Returns a derived context the new attacher should use; cancelling
// that context (e.g., via Release or via the registry GC'ing the
// session) terminates the new attach. `gen` is the unique identity
// of THIS attach — the caller must pass it to Release later.
func (s *Session) Acquire(parent context.Context, mode AttachMode) (context.Context, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrSessionClosed
	}
	if mode == AttachExclusive {
		// Displace any current exclusive client. We collect the
		// cancel funcs first, drop the displaced entries from the
		// slice, then call cancels OUTSIDE the lock so the
		// displaced goroutines' Release call doesn't deadlock on
		// our mu.
		kept := s.clients[:0]
		var doomed []context.CancelFunc
		for _, c := range s.clients {
			if c.mode == AttachExclusive {
				doomed = append(doomed, c.cancel)
				continue
			}
			kept = append(kept, c)
		}
		s.clients = kept
		// Defer cancels until after we drop the lock.
		defer func() {
			for _, c := range doomed {
				c()
			}
		}()
	}
	s.nextGen++
	gen := s.nextGen
	ctx, cancel := context.WithCancel(parent)
	s.clients = append(s.clients, sessionClient{
		gen:    gen,
		mode:   mode,
		cancel: cancel,
	})
	s.lastActiveAt = time.Now()
	return ctx, gen, nil
}

// Release is called by an attached client when its goroutine exits.
// Removes the client identified by `gen` from the active-clients
// slice. Idempotent — a stale gen (we were already displaced and
// removed) is a no-op, so a displaced caller calling Release after
// the new owner has taken over does NOT stomp the new owner's
// state.
func (s *Session) Release(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.clients {
		if c.gen == gen {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			return
		}
	}
}

// HasExclusiveStdinWriter reports whether at least one currently-
// attached client is in AttachExclusive mode. Used by readonly-
// pump validation paths that want to log "exclusive client should
// have written this stdin, not the readonly attempting it" — but
// the pumps don't currently need to assert that, so this method is
// reserved for future telemetry.
func (s *Session) HasExclusiveStdinWriter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		if c.mode == AttachExclusive {
			return true
		}
	}
	return false
}

// PeerModes returns a snapshot of attached clients' modes excluding
// the caller's gen. Used to populate `AttachAck.Peers` so a
// freshly-attaching client can render a "also attached: 1
// readonly" hint without needing a separate IPC roundtrip.
func (s *Session) PeerModes(excludingGen uint64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.clients))
	for _, c := range s.clients {
		if c.gen == excludingGen {
			continue
		}
		out = append(out, c.mode.String())
	}
	return out
}

// Touch refreshes the activity timestamp without changing any other
// state. Called by the pump goroutine on PTY output.
func (s *Session) Touch() {
	s.mu.Lock()
	if !s.closed {
		s.lastActiveAt = time.Now()
	}
	s.mu.Unlock()
}

// IdleFor returns how long ago the session last saw activity (PTY
// output, stdin write, resize, or attach). Used by the registry's GC
// sweep.
func (s *Session) IdleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActiveAt)
}

// Closed reports whether Close has been called.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close terminates the PTY (which sends SIGHUP to the child),
// cancels every attached client, and marks the session unusable.
// Safe to call multiple times; subsequent calls return nil.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pty := s.pty
	// Snapshot cancel funcs and clear the slice — we'll fire them
	// outside the lock so a goroutine's Release-on-exit doesn't
	// deadlock on us.
	cancels := make([]context.CancelFunc, 0, len(s.clients))
	for _, c := range s.clients {
		cancels = append(cancels, c.cancel)
	}
	s.clients = nil
	s.mu.Unlock()

	for _, c := range cancels {
		c()
	}
	if pty != nil {
		return pty.Close()
	}
	return nil
}

// Pump runs the read-PTY-into-ring-buffer loop. It blocks until the
// PTY returns io.EOF (child exited cleanly), an error, or the session
// is closed. On exit it calls Close so the registry can reap the
// session.
//
// Each PTY chunk is run through a QueryFilter that intercepts
// terminal-query escape sequences (Device Attributes, Device Status
// Report) and synthesises responses server-side — apps querying the
// terminal get answered without the query bytes ever reaching the
// ring buffer. This keeps replay-on-reattach pollution-free without
// breaking interactive apps' capability negotiation.
//
// Callers should run Pump in its own goroutine immediately after
// constructing a Session.
func (s *Session) Pump() {
	defer s.Close()
	// We allocate a small buffer; PTYs typically deliver in
	// hundreds-of-bytes chunks, occasionally a few KB. 8 KiB is more
	// than enough to not be the bottleneck.
	chunk := make([]byte, 8*1024)
	filter := NewQueryFilter(s.pty)
	for {
		n, err := s.pty.Read(chunk)
		if n > 0 {
			data := chunk[:n]
			// Drop bash's SIGWINCH-driven prompt redraw if Resize
			// just armed the flag. The redraw bytes don't add
			// information to the persistent shell state — they're
			// a transient reaction to a screen-size event — and
			// keeping them in the ring buffer means each replay
			// renders an extra prompt at the cursor position the
			// redraw was emitted at.
			if s.shouldSuppressRedraw(data) {
				s.Touch()
				if err != nil {
					return
				}
				continue
			}
			filtered := filter.Process(data)
			if len(filtered) > 0 {
				_, _ = s.buf.Write(filtered)
			}
			s.Touch()
		}
		if err != nil {
			// io.EOF or any read error means the child is gone.
			return
		}
	}
}

// ErrSessionClosed is returned by methods invoked after Close.
var ErrSessionClosed = errors.New("session is closed")
