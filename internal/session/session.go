package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	// AttachPassive is the invisible-tap mode. Like readonly —
	// receives output, stdin/resize frames dropped — but invisible
	// to AttachedModes / PeerModes. Capped at MaxPassivePerSession.
	// See protocol.AttachModePassive for the wire-form rationale.
	AttachPassive
)

// MaxPassivePerSession caps the number of concurrent passive
// attachers per session. Resource defence; passive attaches are
// cheap (one goroutine per stream, no PTY ownership) but unbounded
// passive multi-attach would burn fds + goroutines on a runaway
// `mtctl tail` loop.
const MaxPassivePerSession = 8

// String returns the wire form of an AttachMode for logging /
// AttachAck.Mode echo. Mirrors protocol.AttachMode* constants.
func (m AttachMode) String() string {
	switch m {
	case AttachReadonly:
		return "readonly"
	case AttachPassive:
		return "passive"
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

// SeqAwarePTY is implemented by sidecar-backed PTY connections that
// expose the underlying byte-seq counter. Pump probes for this
// interface so it can ack consumed bytes back to the sidecar (freeing
// them from the sidecar's drop-oldest ring) and propagate Trunc
// events as RingBuffer.AdvanceWithGap calls. In-process PTYs
// (internal/pty.Handle) don't implement this — the legacy path
// behaves exactly as before.
type SeqAwarePTY interface {
	// ConsumeTrunc returns the byte count silently dropped since the
	// last call, resetting the counter. Pump applies this via
	// RingBuffer.AdvanceWithGap before its next Write so the daemon-
	// ring's headSeq jumps past the lost span.
	ConsumeTrunc() uint64

	// LastConsumedSeq returns the sidecar-side seq just past the
	// last byte the daemon has read off the wire (= what Pump should
	// pass to AdvanceSidecarSeq + Ack after a successful buf.Write).
	LastConsumedSeq() uint64

	// Ack tells the sidecar bytes ≤ consumedSeq can be freed.
	Ack(consumedSeq uint64) error
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

	// passiveClients is the parallel slice for AttachPassive attachers.
	// Kept separate so AttachedModes / PeerModes (which iterate only
	// `clients`) automatically hide passive watchers — no per-call
	// filtering needed. Capped at MaxPassivePerSession. Genshare the
	// same nextGen counter so Release(gen) can be a single linear
	// scan across both slices.
	passiveClients []sessionClient

	// nextGen monotonically counts attach calls. Each successful
	// Acquire returns a fresh value; Release(gen) only removes the
	// matching client. Audit F4 (v0.0.2 review) — this replaces
	// the ctx-error-as-identity heuristic with a proper monotonic
	// generation counter so a displaced client calling Release
	// after the new owner has taken over does NOT stomp the new
	// owner's state.
	nextGen uint64

	// persist indicates whether this session should be snapshotted
	// to disk so it survives daemon restart. Set at spawn time from
	// the IPC AllocateRequest's Persist field (clamped through
	// Registry.ResolvePersist so the daemon-wide default applies
	// when the client didn't specify). Persisted sessions get a
	// background flusher goroutine started by the registry.
	persist bool

	// lastSnapshotSeq is the buffer's headSeq at the last successful
	// disk snapshot. The flusher compares the buffer's current
	// headSeq to this value; if equal, nothing new has arrived and
	// the snapshot is skipped. Updated only after a successful
	// write (so a failed flush leaves dirty state and triggers
	// another attempt on the next tick).
	lastSnapshotSeq uint64

	// lastSidecarSeq is the highest sidecar-side outSeq the daemon
	// has durably committed to this session's ring. Persisted in
	// meta.cbor; consulted by the discovery path to compute the
	// FrameResume(from_seq) the daemon sends to a reattached sidecar.
	// Advanced by Pump on every successful buf.Write — protected by
	// s.mu.
	lastSidecarSeq uint64

	// restoredFromDisk is true when this Session was hydrated from
	// on-disk state at daemon startup (LoadPersisted), rather than
	// freshly spawned. Cleared the first time a client successfully
	// attaches — until then the AttachAck.Restored flag fires so
	// the client can surface a "Restored from previous session"
	// banner. After first attach the session behaves identically
	// to a freshly-spawned one.
	restoredFromDisk bool

	// firstAttachPending is true until the first AttachAck with OK=true
	// has been sent for this session. NewSession sets it; LoadPersisted
	// explicitly clears it (a restored session has, by definition, been
	// attached to before). The protocol_handler reads it via
	// ConsumeFirstAttach and clears it atomically right before sending
	// AttachAck so clients see FreshlyCreated=true on exactly one
	// attach — the very first.
	firstAttachPending bool

	// flusherCancel and flusherDone are the lifecycle handles for
	// the background snapshot goroutine. Non-nil while running.
	// Cleared by stopFlusher (called from Close). Idempotent —
	// StartFlusher checks for non-nil and no-ops.
	flusherCancel context.CancelFunc
	flusherDone   chan struct{}

	// wedge runs the resize-wedge detector. Non-nil after NewSession;
	// the daemon wires its JSONL log path via SetWedgeLogPath after
	// stateDir is resolved. The watcher updates totalOutBytes from
	// Pump and arms a deadline timer from Resize; see wedgewatch.go.
	wedge *wedgeWatcher

	// ptyByteObserver, if set, receives every chunk Pump reads from
	// the PTY (post-QueryFilter, same bytes the client renders).
	// Installed by the recovery sequencer to detect bookend markers
	// Claude prints during the save phase ("Commencing Save…" /
	// "Memory Updated, restoring…"). Cleared by the sequencer on
	// exit so a future recovery starts fresh. The observer runs in
	// the Pump goroutine; callers must keep it non-blocking and
	// thread-safe.
	ptyByteObserver func([]byte)

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
// LastSidecarSeq returns the highest sidecar outSeq the daemon has
// durably committed to this session's ring. Used by the discovery
// path to compute the FrameResume(from_seq) sent to a reattached
// sidecar. Returns 0 for fresh sessions (no sidecar bytes consumed
// yet) and for sessions hydrated from pre-v0.6 meta.cbor (which
// didn't carry the lcs field).
func (s *Session) LastSidecarSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSidecarSeq
}

// AdvanceSidecarSeq updates the watermark monotonically. No-op for
// values older than the current. Called by Pump after a successful
// buf.Write; coalesced via Pump's own ack thresholds.
func (s *Session) AdvanceSidecarSeq(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > s.lastSidecarSeq {
		s.lastSidecarSeq = seq
	}
}

// SetPersist sets whether this session should be snapshotted to disk.
// Used by the daemon when spawning a session (after resolving the
// client-requested value against the daemon-wide default) and by
// LoadPersisted when restoring (the persisted bit is round-tripped).
func (s *Session) SetPersist(p bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persist = p
}

// Persist reports whether this session is opted into disk
// snapshotting. The flusher goroutine reads this to decide whether
// to write; the GC sweep reads it to decide whether to delete the
// on-disk dir on reap.
func (s *Session) Persist() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persist
}

// RestoredFromDisk reports whether this session was reconstructed
// from on-disk state at daemon startup. The protocol_handler reads
// this when emitting AttachAck so the client sees Restored=true on
// the first reattach after a daemon restart. Idempotent — reading
// doesn't clear the flag; ClearRestoredFlag does.
func (s *Session) RestoredFromDisk() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restoredFromDisk
}

// SetRestoredFromDisk is used by LoadPersisted to mark a freshly
// hydrated session. Package-private would be nicer but we don't
// export here — the only external caller is the persistence loader
// in the same package.
func (s *Session) setRestoredFromDisk(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restoredFromDisk = v
}

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
		id:                 id,
		name:               name,
		created:            now,
		cap:                bufCapacity,
		buf:                buf,
		pty:                pty,
		rows:               rows,
		cols:               cols,
		idleTimeout:        idleTimeout,
		lastActiveAt:       now,
		firstAttachPending: true,
		wedge:              newWedgeWatcher(),
	}, nil
}

// SetWedgeLogPath wires the JSONL path the wedge watcher appends to
// when it detects a candidate resize wedge (see wedgewatch.go). Empty
// path leaves slog-only logging in place. Called by the daemon after
// stateDir is resolved; safe to call at any point after NewSession.
func (s *Session) SetWedgeLogPath(path string) {
	s.mu.Lock()
	w := s.wedge
	s.mu.Unlock()
	if w != nil {
		w.SetLogPath(path)
	}
}

// WedgeSnapshot returns the per-session cumulative metrics tracked by
// the wedge watcher. Used by `meshtermd wedge-report` and
// `meshtermd session-info` to render a summary alongside the
// JSONL contents.
func (s *Session) WedgeSnapshot() (totalOut, resizes, silent, cursor, verticalWalk uint64) {
	s.mu.Lock()
	w := s.wedge
	s.mu.Unlock()
	if w == nil {
		return 0, 0, 0, 0, 0
	}
	return w.Snapshot()
}

// OnWedge wires (or clears, with nil) a callback the wedge watcher
// invokes on every detection. The transport layer installs this when
// an exclusive client attaches so the daemon can push a
// protocol.WedgeDetected frame on the existing control stream.
// Cleared on detach so a re-attach gets a fresh subscriber without
// holding a stale closure that would write into a torn-down stream.
func (s *Session) OnWedge(cb func(WedgeNotice)) {
	s.mu.Lock()
	w := s.wedge
	s.mu.Unlock()
	if w != nil {
		w.SetOnWedge(cb)
	}
}

// SetPTYByteObserver installs (or clears, with nil) a callback that
// receives every chunk Pump reads from the PTY. Used by the recovery
// sequencer to scan for the bookend markers Claude prints during a
// save ("Commencing Save…" / "Memory Updated, restoring…"). The
// callback fires from the Pump goroutine — keep it non-blocking and
// internally thread-safe. Only one observer at a time; setting a
// non-nil callback replaces any previous one. Cleared via nil.
func (s *Session) SetPTYByteObserver(cb func([]byte)) {
	s.mu.Lock()
	s.ptyByteObserver = cb
	s.mu.Unlock()
}

// SuppressWedgeUntil silences all wedge detections on this session
// until the given wall-clock time. Used by the recovery sequencer to
// gate the false-positive storm from `claude --resume` scrollback
// replay (lots of CUDs in milliseconds, no real wedge). Pass a
// zero-value time.Time to clear suppression.
func (s *Session) SuppressWedgeUntil(t time.Time) {
	s.mu.Lock()
	w := s.wedge
	s.mu.Unlock()
	if w != nil {
		w.SuppressUntil(t)
	}
}

// ConsumeFirstAttach atomically reads and clears the firstAttachPending
// flag. Returns true on the first call for a given session and false on
// every subsequent call. The protocol_handler invokes this immediately
// before marshalling AttachAck so clients see FreshlyCreated=true on
// exactly the AttachAck that follows the first successful Acquire.
//
// Restored sessions arrive with the flag already cleared (LoadPersisted
// sets it to false) — a session reconstructed from disk has, by
// definition, been attached before; Restored=true conveys that.
func (s *Session) ConsumeFirstAttach() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.firstAttachPending
	s.firstAttachPending = false
	return v
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

// SetIdleTimeout updates the per-session GC timeout. Used by the
// daemon's reattach path: when an iOS client edits its host's
// Keep-alive setting, the next `meshtermd connect` carries a new
// --idle-timeout value; without this setter the existing session
// kept its original value and the GC reaped it at the OLD interval.
//
// Pass zero to revert to the registry's default. Callers should
// clamp via Registry.ResolveIdleTimeout first if they want the
// operator's --max-idle-timeout ceiling applied.
func (s *Session) SetIdleTimeout(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idleTimeout = d
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
// kernel fires SIGWINCH at the child shell — bash redraws its prompt,
// alt-screen TUIs (Claude Code fullscreen, htop, less, vim) repaint
// their frame.
//
// Earlier versions armed a one-shot drop-the-next-chunk filter here
// against `\r\x1b[K` to keep bash's SIGWINCH prompt redraw out of the
// ring buffer (kept replays clean). That filter is removed: the 4-byte
// match is too broad and silently swallows the first redraw chunk of
// any alt-screen renderer whose redraw starts the same way, breaking
// the visible state for the user. Cost of the removal is one extra
// prompt-redraw blob per bash resize in the ring buffer (~80 bytes,
// renders as one duplicate prompt line on replay) — well worth it to
// keep Claude/htop/vim rendering correctly.
func (s *Session) Resize(rows, cols uint16) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		slog.Warn("session.Resize: session closed — dropping",
			"sid", s.id.String(), "rows", rows, "cols", cols)
		return ErrSessionClosed
	}
	oldRows, oldCols := s.rows, s.cols
	s.rows, s.cols = rows, cols
	pty := s.pty
	s.lastActiveAt = time.Now()
	s.mu.Unlock()
	if oldRows == rows && oldCols == cols {
		slog.Debug("session.Resize: dimensions unchanged — calling SetSize anyway",
			"sid", s.id.String(), "rows", rows, "cols", cols)
	} else {
		slog.Info("session.Resize: dimensions changed",
			"sid", s.id.String(),
			"from", fmt.Sprintf("%dx%d", oldCols, oldRows),
			"to", fmt.Sprintf("%dx%d", cols, rows))
	}
	err := pty.SetSize(rows, cols)
	if err != nil {
		slog.Warn("session.Resize: PTY SetSize failed",
			"sid", s.id.String(), "err", err)
	} else {
		slog.Debug("session.Resize: PTY SetSize OK — SIGWINCH should fire",
			"sid", s.id.String(), "rows", rows, "cols", cols)
	}
	// Arm the wedge watcher only on a successful SetSize and only
	// when the geometry actually changed. A no-op resize wouldn't
	// trigger SIGWINCH, so there's no redraw to wait for.
	if err == nil && (oldRows != rows || oldCols != cols) {
		if s.wedge != nil {
			s.wedge.ArmResize(oldRows, rows, cols, s.created)
		}
	}
	return err
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
	if mode == AttachPassive {
		// Passive attaches live in a sibling slice so they're
		// invisible to AttachedModes / PeerModes by construction.
		// Cap enforced here so the transport layer doesn't need to
		// peek into Session internals.
		if len(s.passiveClients) >= MaxPassivePerSession {
			return nil, 0, ErrPassiveCapacity
		}
		s.nextGen++
		gen := s.nextGen
		ctx, cancel := context.WithCancel(parent)
		s.passiveClients = append(s.passiveClients, sessionClient{
			gen:    gen,
			mode:   mode,
			cancel: cancel,
		})
		s.lastActiveAt = time.Now()
		return ctx, gen, nil
	}
	if mode == AttachExclusive {
		// Displace any current exclusive client. We collect the
		// cancel funcs first, drop the displaced entries from the
		// slice, then call cancels OUTSIDE the lock so the
		// displaced goroutines' Release call doesn't deadlock on
		// our mu. Passive attachers are untouched — exclusive
		// turnover is invisible to them.
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
	// Passive clients live in a parallel slice; check it too.
	for i, c := range s.passiveClients {
		if c.gen == gen {
			s.passiveClients = append(s.passiveClients[:i], s.passiveClients[i+1:]...)
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

// AttachedModes returns the modes of every currently-attached
// client. Snapshot — clients can come and go between this read
// and the caller using the result. Used by ListSessions /
// session-info to render multi-attach state in pickers and CLI
// tools.
func (s *Session) AttachedModes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c.mode.String())
	}
	return out
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
// cancels every attached client, stops the persistence flusher
// (if running), and marks the session unusable. Safe to call
// multiple times; subsequent calls return nil.
//
// Close intentionally does NOT delete the session's on-disk
// persistence directory — that decision belongs to the caller:
// Registry.Remove / Sweep call DeletePersisted afterward (Kill
// or idle-GC reap should drop the on-disk state), but
// Registry.Shutdown (daemon-wide shutdown) leaves it so the next
// daemon start can restore.
//
// Close is the graceful path: when the PTY is a sidecar.Conn, this
// just closes the socket — the sidecar enters its grace timer and
// will be reattached on next daemon startup. Use Kill instead when
// the caller wants the child shell reaped immediately (e.g. user-
// invoked `mtctl kill`).
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
	cancels := make([]context.CancelFunc, 0, len(s.clients)+len(s.passiveClients))
	for _, c := range s.clients {
		cancels = append(cancels, c.cancel)
	}
	for _, c := range s.passiveClients {
		cancels = append(cancels, c.cancel)
	}
	s.clients = nil
	s.passiveClients = nil
	s.mu.Unlock()

	// Synchronously stop the flusher BEFORE closing the PTY. This
	// gives the flusher's ctx-done path a chance to do its final
	// SaveTo before we mark the session closed (and on daemon
	// shutdown that final write is what preserves the session for
	// the next daemon start).
	s.stopFlusher()

	for _, c := range cancels {
		c()
	}
	if pty != nil {
		return pty.Close()
	}
	return nil
}

// PTYKiller is the optional capability a session.PTY can implement
// to request immediate teardown of the underlying process tree (vs.
// the graceful socket-close that PTY.Close performs). The sidecar-
// backed ptyclient.Conn implements this by writing a die_now frame
// before closing the socket; the in-process pty.Handle does not
// implement this (its Close already reaps the child).
type PTYKiller interface {
	Kill() error
}

// Kill is the immediate-teardown sibling of Close. For sidecar-
// backed PTYs (the v0.6+ Roam sessions) it sends die_now so the
// child shell is SIGHUP'd within ~250 ms. For in-process PTYs it
// falls back to Close (which already SIGHUPs synchronously).
//
// Used by registry.Remove so `mtctl kill` doesn't leave the child
// shell running during the sidecar's 30s reconnect-grace window.
func (s *Session) Kill() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pty := s.pty
	cancels := make([]context.CancelFunc, 0, len(s.clients)+len(s.passiveClients))
	for _, c := range s.clients {
		cancels = append(cancels, c.cancel)
	}
	for _, c := range s.passiveClients {
		cancels = append(cancels, c.cancel)
	}
	s.clients = nil
	s.passiveClients = nil
	s.mu.Unlock()

	s.stopFlusher()

	for _, c := range cancels {
		c()
	}
	if pty == nil {
		return nil
	}
	if k, ok := pty.(PTYKiller); ok {
		return k.Kill()
	}
	return pty.Close()
}

// ErrSessionHasPTY is returned by AssignPTY when called on a session
// that already owns a PTY. Indicates a race between two attach
// handlers both trying to be the first-attach lazy spawner for a
// restored session; the loser closes its handle and continues.
var ErrSessionHasPTY = errors.New("session already has a PTY")

// AssignPTY hands ownership of a freshly-spawned PTY to a previously-
// restored Session. The caller (protocol_handler on first attach to
// a session that was hydrated by LoadPersisted) builds the *pty.Handle
// via pty.Spawn and passes it here; AssignPTY plumbs it onto s.pty
// and clears the restoredFromDisk flag so subsequent attaches see
// Restored=false on the wire.
//
// On error the caller is responsible for closing the supplied PTY —
// AssignPTY does NOT take ownership if it fails. The expected error
// is ErrSessionHasPTY (race lost to another concurrent attach);
// callers handle that by simply closing their PTY handle and
// proceeding with the normal attach path.
//
// The caller must also start the session's Pump goroutine
// (`go sess.Pump()`) after a successful AssignPTY — this method
// only wires the handle; it doesn't kick off reads.
func (s *Session) AssignPTY(p PTY) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	if s.pty != nil {
		return ErrSessionHasPTY
	}
	s.pty = p
	s.restoredFromDisk = false
	return nil
}

// StartFlusher launches the background snapshot loop. Idempotent —
// second call is a no-op (or a no-op when persist is false). The
// flusher writes via SaveTo on every interval where the buffer's
// HeadSeq has advanced past the last snapshot, plus one final write
// on stopFlusher. Failed writes are logged but don't kill the loop.
//
// `parentDir` is the daemon's state dir (the parent of `sessions/`).
// `interval` zero falls back to 30 seconds. `logger` may be nil
// (defaults to slog.Default()).
func (s *Session) StartFlusher(parentDir string, interval time.Duration, logger *slog.Logger) {
	s.mu.Lock()
	if s.flusherCancel != nil || !s.persist || s.closed {
		s.mu.Unlock()
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.flusherCancel = cancel
	s.flusherDone = make(chan struct{})
	done := s.flusherDone
	s.mu.Unlock()

	go func() {
		defer close(done)
		s.runFlusher(ctx, parentDir, interval, logger)
	}()
}

// runFlusher is the actual snapshot loop body. Exits on ctx
// cancellation; performs a final flush before returning so daemon
// shutdown preserves the most-recent state.
//
// Two paths through the dirty check:
//
//   - Normal tick: checks `s.closed`. If the session has been killed
//     (Remove/Sweep called Close), the caller will DeletePersisted
//     shortly — skip the write to avoid recreating a dir that's
//     about to be removed.
//   - ctx-done (Close-initiated shutdown): writes UNCONDITIONALLY
//     if there's dirty state, because Close intentionally preserves
//     on-disk content. The caller (daemon shutdown) needs the
//     latest snapshot for the next start. The DeletePersisted-races-
//     with-final-flush concern doesn't apply here: Close only
//     touches on-disk after stopFlusher returns (which is after this
//     function exits), and Remove's DeletePersisted runs even later.
func (s *Session) runFlusher(ctx context.Context, parentDir string, interval time.Duration, logger *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()

	flushIfDirty := func(force bool) {
		currentHead := s.buf.HeadSeq()
		s.mu.Lock()
		last := s.lastSnapshotSeq
		closed := s.closed
		s.mu.Unlock()
		if closed && !force {
			return
		}
		if currentHead == last {
			return
		}
		if err := s.SaveTo(parentDir); err != nil {
			logger.Warn("session.flusher.write_failed",
				"session", s.ID().String(),
				"err", err.Error(),
			)
		}
	}

	for {
		select {
		case <-ctx.Done():
			flushIfDirty(true)
			return
		case <-t.C:
			flushIfDirty(false)
		}
	}
}

// stopFlusher signals the flusher to exit and waits for it. Idempotent.
// Called from Close; package-private because the lifecycle is owned
// by Session itself, not by external callers.
func (s *Session) stopFlusher() {
	s.mu.Lock()
	cancel := s.flusherCancel
	done := s.flusherDone
	s.flusherCancel = nil
	s.flusherDone = nil
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
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
	seqAware, _ := s.pty.(SeqAwarePTY)
	for {
		// Surface any Trunc-before-frame from the sidecar BEFORE the
		// next Read so the daemon-ring's headSeq advances past the
		// lost span before payload bytes land on top of it.
		if seqAware != nil {
			if gap := seqAware.ConsumeTrunc(); gap > 0 {
				s.buf.AdvanceWithGap(gap)
			}
		}
		n, err := s.pty.Read(chunk)
		if n > 0 {
			data := chunk[:n]
			filtered := filter.Process(data)
			if len(filtered) > 0 {
				_, _ = s.buf.Write(filtered)
				// Feed the wedge watcher with the post-filter byte
				// stream — the same bytes the client renders, so a
				// CUP row that violates the geometry will be visible
				// here too. QueryFilter only synthesises responses to
				// terminal queries (DA/DSR); it doesn't strip CUPs.
				if s.wedge != nil {
					s.wedge.ObserveBytes(filtered, s.created)
				}
				// Fire the PTY byte observer (recovery sequencer's
				// marker detection). Snapshot under the lock so a
				// concurrent SetPTYByteObserver(nil) doesn't race
				// with the dereference.
				s.mu.Lock()
				obs := s.ptyByteObserver
				s.mu.Unlock()
				if obs != nil {
					obs(filtered)
				}
			}
			if seqAware != nil {
				// Watermark the highest sidecar seq we've durably
				// committed. Best-effort Ack — a network error here
				// just means the sidecar will get our up-to-date lcs
				// on the next attach via FrameResume.
				seq := seqAware.LastConsumedSeq()
				s.AdvanceSidecarSeq(seq)
				_ = seqAware.Ack(seq)
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

// ErrPassiveCapacity is returned by Acquire(AttachPassive) when the
// session already has MaxPassivePerSession passive watchers. Transport
// layer maps this to AttachAck.Err = AttachErrCapacity on the wire.
var ErrPassiveCapacity = errors.New("session passive-attach capacity reached")
