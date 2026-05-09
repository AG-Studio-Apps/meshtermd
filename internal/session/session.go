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
	created time.Time
	cap     int

	mu sync.Mutex

	buf  *RingBuffer
	pty  PTY
	rows uint16
	cols uint16

	// Last time something happened on this session (PTY output or
	// active attach). Drives the registry's idle-GC.
	lastActiveAt time.Time

	// activeCancel cancels the goroutine of the currently-attached
	// client (if any). When a second client attaches, we cancel the
	// first to give the new one exclusive ownership. nil means no
	// active attach.
	activeCancel context.CancelFunc

	// activeGen is incremented on every Acquire. Callers that
	// successfully acquire receive their generation; Release(gen)
	// only clears the slot when gen matches activeGen, so a
	// displaced caller calling Release after the new owner has
	// taken over does NOT stomp the new owner's state. This is
	// audit F4's recommended replacement for the previous
	// ctx-error-as-identity heuristic.
	activeGen uint64

	closed bool
}

// NewSession constructs a Session. The caller is expected to start
// the pump goroutine separately (see Pump). We don't do it inside the
// constructor so test code can inject deterministic behaviour.
func NewSession(id SessionID, pty PTY, rows, cols uint16, bufCapacity int) (*Session, error) {
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
		created:      now,
		cap:          bufCapacity,
		buf:          buf,
		pty:          pty,
		rows:         rows,
		cols:         cols,
		lastActiveAt: now,
	}, nil
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
// own Resize.
func (s *Session) Resize(rows, cols uint16) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	s.rows, s.cols = rows, cols
	pty := s.pty
	s.lastActiveAt = time.Now()
	s.mu.Unlock()
	return pty.SetSize(rows, cols)
}

// WindowSize returns the latest known window size.
func (s *Session) WindowSize() (rows, cols uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows, s.cols
}

// Acquire claims this session for a new attach. If another client is
// currently attached, its context is cancelled; that goroutine should
// observe ctx.Done() and exit with reason "replaced". Returns a
// derived context the new attacher should use; cancelling that
// context (e.g., via Release or via the registry GC'ing the session)
// terminates the new attach.
func (s *Session) Acquire(parent context.Context) (context.Context, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrSessionClosed
	}
	if s.activeCancel != nil {
		// Displace the existing attach.
		s.activeCancel()
	}
	s.activeGen++
	ctx, cancel := context.WithCancel(parent)
	s.activeCancel = cancel
	s.lastActiveAt = time.Now()
	return ctx, s.activeGen, nil
}

// Release is called by an attached client when its goroutine exits.
// The caller passes the `gen` they received from Acquire; Release
// clears the active-attach slot only if gen matches the current
// active generation.
//
// A mismatch means we've been displaced and the new owner's slot
// must NOT be cleared. The previous implementation used ctx.Err()
// as identity, which gave the wrong answer when the parent ctx was
// independently cancelled (e.g., daemon-wide shutdown) — see audit
// finding F4.
//
// Idempotent: calling Release twice with the same gen, or with a
// stale gen, is a no-op.
func (s *Session) Release(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.activeGen {
		return
	}
	if s.activeCancel != nil {
		s.activeCancel = nil
	}
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
// cancels any active attach, and marks the session unusable. Safe to
// call multiple times; subsequent calls return nil.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pty := s.pty
	cancel := s.activeCancel
	s.activeCancel = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
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
// Callers should run Pump in its own goroutine immediately after
// constructing a Session.
func (s *Session) Pump() {
	defer s.Close()
	// We allocate a small buffer; PTYs typically deliver in
	// hundreds-of-bytes chunks, occasionally a few KB. 8 KiB is more
	// than enough to not be the bottleneck.
	chunk := make([]byte, 8*1024)
	for {
		n, err := s.pty.Read(chunk)
		if n > 0 {
			_, _ = s.buf.Write(chunk[:n])
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
