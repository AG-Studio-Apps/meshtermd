// Package pty wraps creack/pty to spawn a child process attached to
// a PTY pair, exposing the io.Reader / io.Writer / io.Closer +
// SetSize surface that internal/session expects.
//
// The child is spawned with a curated environment allowlist (HOME,
// PATH, TERM, etc.) per docs/SECURITY.md self-audit checklist —
// passing the daemon's full env to the child would leak any creds
// the operator has set. Users who need specific variables should
// export them from their shell's rc files, not rely on inheritance.
package pty

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	cpty "github.com/creack/pty"
)

// envAllowlist is the small set of variables we pass through from
// the daemon's environment to the child shell. Anything else either
// (a) belongs in the user's shell rc files or (b) is a daemon-only
// concern the child shouldn't see.
//
// Variables passed through:
//   HOME       — shells need this to resolve ~
//   PATH       — without this, even `ls` doesn't work
//   SHELL      — some prompts and scripts read $SHELL
//   USER       — user identity for prompts, scripts
//   LOGNAME    — POSIX equivalent of USER
//   LANG       — locale for character encoding
//   LC_ALL     — locale override
//   TERM       — terminal type; we set this to "xterm-256color" by
//                default but pass through if the operator overrode it
//   TZ         — timezone, occasionally needed by scripts
var envAllowlist = []string{
	"HOME",
	"PATH",
	"SHELL",
	"USER",
	"LOGNAME",
	"LANG",
	"LC_ALL",
	"TERM",
	"TZ",
}

// SpawnConfig configures a child shell + PTY.
type SpawnConfig struct {
	// Shell is the absolute path to the shell binary. If empty, we
	// resolve in this order: $SHELL, /bin/bash, /bin/sh.
	Shell string

	// Args are the arguments passed after the shell name. Typical
	// values: nil for an interactive shell, or [-c, "tmux new -A
	// -s name"] for a wrapped command.
	Args []string

	// Rows and Cols set the initial PTY window size.
	Rows uint16
	Cols uint16

	// ExtraEnv is appended to the curated allowlist environment.
	// Used by callers to inject session-scoped variables (e.g.
	// MESHTERM_SESSION_ID) without rebuilding the allowlist.
	ExtraEnv []string
}

// Handle is the live PTY + child handle. It satisfies
// session.PTY (Read/Write/Close + SetSize) so a Session can hold one
// directly.
type Handle struct {
	pt        *os.File // master side
	cmd       *exec.Cmd
	closeOnce sync.Once
	closeErr  error

	// fdMu serialises access to h.pt's underlying fd between Close()
	// and operations that read h.pt.Fd() (currently just EchoEnabled
	// — Read/Write go through h.pt.Read/Write which the os.File
	// internals already make safe across Close). Without this lock
	// the race detector flags EchoEnabled's Fd() call against the
	// pump goroutine's eventual Close() on session teardown.
	//
	// `closed` is set under the write lock before pt.Close runs and
	// gates EchoEnabled. Without this gate, a watcher tick that starts
	// after Close returns can still call Fd() while internal/poll's
	// deferred destroy (triggered when Pump's pending Read unwinds)
	// is mutating the file's internal state.
	fdMu   sync.RWMutex
	closed bool
}

// Spawn starts the child and returns a Handle. The child inherits
// the PTY's slave side as its controlling terminal, stdin, stdout,
// stderr (creack/pty wires this).
//
// Returns an error if no shell can be resolved or the fork/exec
// fails.
func Spawn(cfg SpawnConfig) (*Handle, error) {
	shell, err := resolveShell(cfg.Shell)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(shell, cfg.Args...)
	cmd.Env = buildEnv(cfg.ExtraEnv)

	rows, cols := cfg.Rows, cfg.Cols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	pt, err := cpty.StartWithSize(cmd, &cpty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}
	return &Handle{pt: pt, cmd: cmd}, nil
}

// Read implements io.Reader. On Linux, when the child exits, the PTY
// master returns EIO instead of EOF (documented kernel behaviour);
// we translate that to io.EOF so Pump's `if err != nil` path handles
// it cleanly without per-OS branching higher up.
func (h *Handle) Read(b []byte) (int, error) {
	n, err := h.pt.Read(b)
	if err != nil && isPTYEOF(err) {
		err = io.EOF
	}
	return n, err
}

// isPTYEOF reports whether err is the Linux "child exited and the
// slave side is closed" condition, which manifests as EIO on the
// master fd. macOS returns EOF directly, so this is mostly a Linux
// adaptation.
func isPTYEOF(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var perr *os.PathError
	if errors.As(err, &perr) && errors.Is(perr.Err, syscall.EIO) {
		return true
	}
	return errors.Is(err, syscall.EIO)
}

// Write implements io.Writer.
func (h *Handle) Write(b []byte) (int, error) { return h.pt.Write(b) }

// SetSize forwards a window-size change to the PTY. The child
// receives SIGWINCH automatically via the kernel.
func (h *Handle) SetSize(rows, cols uint16) error {
	return cpty.Setsize(h.pt, &cpty.Winsize{Rows: rows, Cols: cols})
}

// Close terminates the child and releases the PTY file descriptor.
// Idempotent: subsequent calls return the same result without
// re-firing SIGHUP or re-launching the Wait goroutine (calling
// Wait twice on the same Cmd is a data race in the stdlib).
//
// We send SIGHUP (conventional "your terminal went away"), reap the
// child in a background goroutine so Close doesn't block, and close
// the master fd. Callers detect child exit via the Pump goroutine
// observing EOF from Read.
func (h *Handle) Close() error {
	h.closeOnce.Do(func() {
		if h.cmd != nil && h.cmd.Process != nil {
			// Best-effort SIGHUP; ignore "already finished".
			_ = h.cmd.Process.Signal(syscall.SIGHUP)
			// Reap in the background. The exit code is not
			// inspected — callers know the child is gone via the
			// PTY's EOF.
			go func() {
				_ = h.cmd.Wait()
			}()
		}
		// Take the write lock so any in-flight EchoEnabled (read
		// lock) finishes before we close the master fd. Without this
		// the Fd() call inside EchoEnabled races with Close per the
		// os.File semantics. Set `closed` under the same lock so any
		// subsequent EchoEnabled tick observes the flag and skips
		// Fd() entirely — Pump's deferred destroy still races with a
		// late Fd() call otherwise.
		h.fdMu.Lock()
		defer h.fdMu.Unlock()
		h.closed = true
		if err := h.pt.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			h.closeErr = err
		}
	})
	return h.closeErr
}

// resolveShell returns an absolute path to a shell, in this order:
// the explicit cfg.Shell value, $SHELL, /bin/bash, /bin/sh.
// Returns an error if none of those resolve to a real executable.
func resolveShell(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if s := os.Getenv("SHELL"); s != "" {
		candidates = append(candidates, s)
	}
	candidates = append(candidates, "/bin/bash", "/bin/sh")

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", errors.New("no usable shell found (tried SHELL, /bin/bash, /bin/sh)")
}

// buildEnv constructs the child's environment from the allowlist
// plus any caller-supplied additions. Sets sensible defaults for
// TERM and LANG when the daemon has no value to inherit.
func buildEnv(extra []string) []string {
	env := make([]string, 0, len(envAllowlist)+len(extra)+2)
	for _, key := range envAllowlist {
		// Treat empty values as "not set" — passing "TERM=" through
		// is worse than letting our default kick in, and t.Setenv in
		// tests sets to empty rather than unsetting.
		v, ok := os.LookupEnv(key)
		if !ok || v == "" {
			continue
		}
		env = append(env, key+"="+v)
	}
	// Ensure TERM is set; iOS clients render xterm-256color
	// reasonably and SwiftTerm advertises it.
	if !envContains(env, "TERM") {
		env = append(env, "TERM=xterm-256color")
	}
	// Ensure LANG is sane; many shells warn loudly without one.
	if !envContains(env, "LANG") && !envContains(env, "LC_ALL") {
		env = append(env, "LANG=C.UTF-8")
	}
	env = append(env, extra...)
	return env
}

func envContains(env []string, key string) bool {
	prefix := key + "="
	for _, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// Compile-time check: Handle implements io.ReadWriteCloser. SetSize
// is verified at the use-site (session.PTY interface).
var _ io.ReadWriteCloser = (*Handle)(nil)
