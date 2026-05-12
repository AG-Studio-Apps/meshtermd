package session

import (
	"context"
	"sync/atomic"
	"time"
)

// TermiosSnooper is the optional interface a PTY may implement to
// report the slave-side ECHO and ICANON termios flags. internal/pty.Handle
// implements it via tcgetattr on the master fd; internal/ptyclient.Conn
// proxies it through the sidecar's FrameQueryEcho frame; tests
// substitute a deterministic fake.
//
// Returns ok=false to mean "couldn't query right now" — the watcher
// treats that as a transient hiccup, not a state flip. When ok=true,
// both echo and canon carry definitive values.
type TermiosSnooper interface {
	TermiosState() (echo, canon, ok bool)
}

// EchoState mirrors the wire `EchoConfirm.echo_state` field. The
// daemon emits this tri-state because tcgetattr can fail transiently
// (closed fd, kernel hiccup); clients arm predictions on `on`, disarm
// hard on `off`, and stay conservative on `unknown`.
//
// The same tri-state is reused for the ICANON flag on TermiosSnapshot.Canon —
// the semantics are identical even though the wire field name differs
// (EchoConfirm.CanonMode is a bool with "unknown" suppressed at emit
// time by the watcher, so the wire never carries an explicit unknown
// for canon).
type EchoState string

const (
	EchoStateOn      EchoState = "on"
	EchoStateOff     EchoState = "off"
	EchoStateUnknown EchoState = "unknown"
)

// TermiosSnapshot is the watcher's combined view of the PTY's
// slave-side ECHO and ICANON flags. Reused for both: a fresh poll
// observes both bits simultaneously, and clients use both for
// independent prediction decisions (ECHO for printable-char echo,
// ICANON for backspace + line editing).
type TermiosSnapshot struct {
	Echo  EchoState
	Canon EchoState
}

// DefaultEchoPollInterval is the period between successive tcgetattr
// calls in the watcher's loop. 100ms is fast enough that the client's
// prediction state catches up to a vim entry / exit before the user
// types the next key (typical typing speed 100–200ms), and slow
// enough that the syscall cost is negligible.
const DefaultEchoPollInterval = 100 * time.Millisecond

// WatchTermios polls a TermiosSnooper on a fixed interval and fires
// onChange whenever either flag flips (ECHO or ICANON). The watcher
// exits when ctx is cancelled; never returns an error — a closed fd
// just surfaces as repeated ok=false reads.
//
// onChange is called from the watcher's own goroutine. Callers should
// hand off via a channel or a quick non-blocking write to a per-client
// queue; don't do work that might block the next poll.
//
// If pty doesn't implement TermiosSnooper, WatchTermios returns
// immediately — clients fall back to their own heuristics (Stage A in
// the predictive-echo design).
func WatchTermios(ctx context.Context, pty PTY, interval time.Duration, onChange func(TermiosSnapshot)) {
	snooper, ok := pty.(TermiosSnooper)
	if !ok {
		return
	}
	WatchTermiosOn(ctx, snooper, interval, onChange)
}

// WatchTermios is exposed as a method on Session for the common case
// of "watch the termios of MY PTY." Session owns its PTY privately so
// callers can't reach it directly; this method threads the public
// surface. Blocks until ctx is cancelled or the session is closed.
func (s *Session) WatchTermios(ctx context.Context, interval time.Duration, onChange func(TermiosSnapshot)) {
	s.mu.Lock()
	pty := s.pty
	closed := s.closed
	s.mu.Unlock()
	if closed || pty == nil {
		return
	}
	WatchTermios(ctx, pty, interval, onChange)
}

// WatchTermiosOn is the testable form of WatchTermios — takes the
// snooper directly instead of fishing it out of a PTY.
func WatchTermiosOn(ctx context.Context, snooper TermiosSnooper, interval time.Duration, onChange func(TermiosSnapshot)) {
	if interval <= 0 {
		interval = DefaultEchoPollInterval
	}
	// External inspection (tests, debug-only `meshtermd status`
	// introspection) reads `last` without blocking the watcher goroutine.
	var last atomic.Value
	last.Store(TermiosSnapshot{Echo: EchoStateUnknown, Canon: EchoStateUnknown})

	t := time.NewTicker(interval)
	defer t.Stop()

	// Prime: report the initial reading so the client doesn't sit on
	// unknown for the first poll interval after attach.
	emitIfChanged(snooper, &last, onChange)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			emitIfChanged(snooper, &last, onChange)
		}
	}
}

// emitIfChanged polls the snooper and fires onChange if either flag
// has performed a real (non-unknown) on↔off transition. Each flag is
// debounced independently — a flap on echo while canon stays unknown
// still emits (echo has a real transition); the symmetric case fires
// for canon. If neither flag has a real transition, no emit.
func emitIfChanged(snooper TermiosSnooper, last *atomic.Value, onChange func(TermiosSnapshot)) {
	cur := pollSnapshot(snooper)
	prev := last.Load().(TermiosSnapshot)
	if cur == prev {
		return
	}
	last.Store(cur)
	// Suppress unknown-flapping per channel. We only emit when at
	// least one channel made a real on↔off transition.
	if !realTransition(prev.Echo, cur.Echo) && !realTransition(prev.Canon, cur.Canon) {
		return
	}
	onChange(cur)
}

// realTransition reports whether prev → cur is a meaningful (non-
// unknown-involving) flag flip. Used to suppress "on → unknown → on"
// flapping when tcgetattr briefly errors.
func realTransition(prev, cur EchoState) bool {
	if prev == cur {
		return false
	}
	if prev == EchoStateUnknown || cur == EchoStateUnknown {
		return false
	}
	return true
}

// pollSnapshot turns one snooper read into a TermiosSnapshot.
func pollSnapshot(s TermiosSnooper) TermiosSnapshot {
	echo, canon, ok := s.TermiosState()
	if !ok {
		return TermiosSnapshot{Echo: EchoStateUnknown, Canon: EchoStateUnknown}
	}
	return TermiosSnapshot{
		Echo:  flagToState(echo),
		Canon: flagToState(canon),
	}
}

func flagToState(b bool) EchoState {
	if b {
		return EchoStateOn
	}
	return EchoStateOff
}
