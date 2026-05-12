package session

import (
	"context"
	"sync/atomic"
	"time"
)

// EchoSnooper is the optional interface a PTY may implement to report
// the slave-side ECHO termios flag. internal/pty.Handle implements it
// via tcgetattr on the master fd; tests substitute a deterministic
// fake.
//
// Returns `ok=false` to mean "couldn't query right now" — the watcher
// treats that as a transient hiccup, not a state flip.
type EchoSnooper interface {
	EchoEnabled() (echo bool, ok bool)
}

// EchoState mirrors the wire `EchoConfirm.echo_state` field in the
// Roam protocol: a tri-state because the daemon can't always tell
// whether ECHO is on or off (e.g., the PTY hasn't been initialised
// yet, or the kernel returned an error). Clients arm predictions on
// `on`, disarm hard on `off`, and stay conservative on `unknown`.
type EchoState string

const (
	EchoStateOn      EchoState = "on"
	EchoStateOff     EchoState = "off"
	EchoStateUnknown EchoState = "unknown"
)

// DefaultEchoPollInterval is the period between successive
// `tcgetattr` calls in the watcher's loop. 100ms is fast enough that
// the client's prediction state catches up to a vim entry / exit
// before the user types the next key (typical typing speed is
// 100-200ms between keys), and slow enough that the syscall cost is
// negligible.
const DefaultEchoPollInterval = 100 * time.Millisecond

// WatchEcho polls `pty.EchoEnabled` on a fixed interval and fires
// `onChange` whenever the cached state flips. The watcher exits when
// ctx is cancelled; it never returns an error — a closed fd just
// surfaces as repeated `ok=false` reads.
//
// `onChange` is called from the watcher's own goroutine. Callers
// should hand off via a channel or a quick non-blocking write to a
// per-client queue; don't do work that might block the next poll.
//
// If `pty` doesn't implement EchoSnooper, WatchEcho returns
// immediately — the daemon falls back to the client-side prompt-sniff
// heuristic in Stage A. Tests can also call WatchEchoOn directly to
// inject a custom snooper.
func WatchEcho(ctx context.Context, pty PTY, interval time.Duration, onChange func(EchoState)) {
	snooper, ok := pty.(EchoSnooper)
	if !ok {
		return
	}
	WatchEchoOn(ctx, snooper, interval, onChange)
}

// WatchEcho is also exposed as a method on Session for the common
// case of "watch the echo state of MY PTY, and call onChange when it
// flips." The Session owns its PTY field privately so callers can't
// reach it directly; this method threads the public surface.
//
// Blocks until ctx is cancelled or the session is closed.
func (s *Session) WatchEcho(ctx context.Context, interval time.Duration, onChange func(EchoState)) {
	s.mu.Lock()
	pty := s.pty
	closed := s.closed
	s.mu.Unlock()
	if closed || pty == nil {
		return
	}
	WatchEcho(ctx, pty, interval, onChange)
}

// WatchEchoOn is the testable form of WatchEcho — takes the snooper
// directly instead of fishing it out of a PTY.
func WatchEchoOn(ctx context.Context, snooper EchoSnooper, interval time.Duration, onChange func(EchoState)) {
	if interval <= 0 {
		interval = DefaultEchoPollInterval
	}
	// We track the last reported state in an atomic so external
	// inspection (tests, debug-only `meshtermd status` introspection
	// in v0.4+) can read it without blocking the goroutine.
	var last atomic.Value
	last.Store(EchoStateUnknown)

	t := time.NewTicker(interval)
	defer t.Stop()

	// Prime: report the initial reading so the client doesn't sit on
	// `unknown` for the first 100ms after attach.
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

func emitIfChanged(snooper EchoSnooper, last *atomic.Value, onChange func(EchoState)) {
	cur := pollState(snooper)
	prev := last.Load().(EchoState)
	if cur == prev {
		return
	}
	last.Store(cur)
	// Skip emitting transitions to/from unknown so the client doesn't
	// see "on → unknown → on" flapping when the kernel briefly fails
	// the ioctl. Only on ↔ off transitions matter for the prediction
	// engine.
	if prev == EchoStateUnknown || cur == EchoStateUnknown {
		return
	}
	onChange(cur)
}

func pollState(s EchoSnooper) EchoState {
	echo, ok := s.EchoEnabled()
	if !ok {
		return EchoStateUnknown
	}
	if echo {
		return EchoStateOn
	}
	return EchoStateOff
}
