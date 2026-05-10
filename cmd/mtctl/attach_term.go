package main

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// terminalSession bundles the local-side terminal state we have to
// touch when attaching: original termios for restore-on-exit, the
// fd we drove raw, and a channel that fires on SIGWINCH.
//
// All operations are reversible — `restore()` undoes makeRaw and
// stops the signal handler. Always defer it before doing anything
// else, and call it from every error path.
type terminalSession struct {
	fd        int
	oldState  *term.State
	winchChan chan os.Signal
}

// enterRaw puts os.Stdin into raw mode and arms a SIGWINCH handler.
// The caller MUST `defer ts.restore()` immediately after a successful
// return — leaving the terminal in raw mode permanently strands the
// user's shell (no echo, no line editing). Restore is idempotent and
// safe to call from cleanup paths.
//
// Returns ErrNotATerminal when stdin isn't a TTY (e.g. mtctl invoked
// from a script or with `< /dev/null`). Callers should refuse to
// attach in that case — there's no terminal to drive.
func enterRaw() (*terminalSession, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, ErrNotATerminal
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	return &terminalSession{fd: fd, oldState: old, winchChan: winch}, nil
}

// restore reverses enterRaw. Safe to call multiple times; the second
// call is a no-op.
func (ts *terminalSession) restore() {
	if ts == nil {
		return
	}
	if ts.winchChan != nil {
		signal.Stop(ts.winchChan)
		ts.winchChan = nil
	}
	if ts.oldState != nil {
		_ = term.Restore(ts.fd, ts.oldState)
		ts.oldState = nil
	}
}

// size returns the current terminal dimensions, clamped to the
// protocol's uint16 range. Returns (24, 80) as a fallback when the
// platform refuses to answer — the daemon will treat that as a
// reasonable starting size and the user's first SIGWINCH will
// correct it.
func (ts *terminalSession) size() (rows, cols uint16) {
	w, h, err := term.GetSize(ts.fd)
	if err != nil || w <= 0 || h <= 0 {
		return 24, 80
	}
	return clampDim(h), clampDim(w)
}

func clampDim(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 0xFFFF {
		return 0xFFFF
	}
	return uint16(n)
}

// ErrNotATerminal is returned by enterRaw when stdin isn't a TTY.
// Attach can't function without one — every byte we read from
// stdin gets forwarded to the remote shell, which expects raw
// input from a real terminal.
var ErrNotATerminal = errors.New("mtctl attach: stdin is not a terminal")

// escapeWatcher buffers stdin bytes looking for the `~.` chord
// (mosh / ssh convention) at the start of a line. When the chord is
// seen, the watcher signals via the channel returned by `done()`
// and the byte stream is interrupted — the `~` and `.` are NOT
// forwarded to the remote shell.
//
// State machine:
//
//	atLineStart: just saw \n or just started. ~ here → maybeEscape.
//	             anything else → normal, forward.
//	maybeEscape: just buffered a `~` at line-start. We're holding
//	             that `~` back; if the next byte is `.` we detach.
//	             If `~`, that's the "escape the escape" convention:
//	             forward a literal `~` and stay in maybeEscape so
//	             the user can chain. Anything else: forward the
//	             buffered `~` THEN the new byte, transition based
//	             on the byte (\n → atLineStart, else → normal).
//	normal:      not at start of a line. \n → atLineStart, ~ here
//	             is just a literal ~ to forward. Anything else
//	             stays normal.
type escapeWatcher struct {
	state escapeState
}

type escapeState int

const (
	escAtLineStart escapeState = iota
	escMaybeEscape
	escNormal
)

func newEscapeWatcher() *escapeWatcher {
	// First byte of the session is treated as line-start so an
	// instant `~.` after connect still works. Cheap convenience.
	return &escapeWatcher{state: escAtLineStart}
}

// process takes a slice of bytes read from local stdin and returns
// the bytes that should be forwarded to the remote shell. If the
// detach chord fires, `detach` is true and the bytes after the
// chord (if any in this read) are dropped — the caller is about
// to close the connection anyway.
func (w *escapeWatcher) process(in []byte) (out []byte, detach bool) {
	if len(in) == 0 {
		return nil, false
	}
	out = make([]byte, 0, len(in))
	for _, b := range in {
		switch w.state {
		case escAtLineStart:
			if b == '~' {
				w.state = escMaybeEscape
				continue // hold the ~
			}
			out = append(out, b)
			if b == '\r' || b == '\n' {
				// stay at line-start
			} else {
				w.state = escNormal
			}
		case escMaybeEscape:
			switch b {
			case '.':
				// Detach chord. Drop the ~ and the . — don't
				// forward, signal upward.
				return out, true
			case '~':
				// Doubled tilde: forward one literal ~, stay in
				// maybeEscape so a chord can still follow on the
				// next pair.
				out = append(out, '~')
			default:
				// Buffered ~ was just a stray; emit it then the
				// new byte. State transitions based on the new
				// byte's role.
				out = append(out, '~', b)
				if b == '\r' || b == '\n' {
					w.state = escAtLineStart
				} else {
					w.state = escNormal
				}
			}
		case escNormal:
			out = append(out, b)
			if b == '\r' || b == '\n' {
				w.state = escAtLineStart
			}
		}
	}
	return out, false
}

// Compile-time assert that *os.File satisfies the writer the pumps
// need. Catches a future drift if anyone replaces os.Stdout under
// our feet (e.g. via an io.Writer interface).
var _ io.Writer = (*os.File)(nil)
