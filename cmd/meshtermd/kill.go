package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

// Exit codes for `meshtermd kill`. Aligned with connect:
//
//	0  ok
//	1  generic error (bad flag, transport)
//	2  daemon not running
//	3  unknown session (selector resolved to nothing)
const (
	killExitOK               = 0
	killExitGenericError     = 1
	killExitDaemonNotRunning = 2
	killExitUnknownSession   = 3
)

// runKill reaps one or more sessions. Three modes:
//
//   - `meshtermd kill <id-or-name>`  - exact selector, single session
//   - `meshtermd kill <glob>`        - shell-style glob match on names
//                                       (e.g. 'build-*'); kills every
//                                       match, errors if 0 match
//   - `meshtermd kill --all`         - reap every session (requires
//                                       --yes confirmation, or stdin
//                                       prompt 'y' to proceed)
//
// Glob is detected by the presence of `*`, `?`, or `[` in the
// selector — selectors without those metacharacters are treated as
// exact (preserves existing single-selector behaviour).
func runKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	all := fs.Bool("all", false, "kill every session on the daemon (requires --yes or interactive confirm)")
	yes := fs.Bool("yes", false, "skip the interactive 'are you sure?' prompt for batch operations")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd kill [flags] <id-or-name|glob>\n")
		fmt.Fprintf(fs.Output(), "       meshtermd kill --all [--yes]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	socketPath := *socket
	if socketPath == "" {
		socketPath = discoverClientSocketPath()
	}
	client := ipc.NewClient(socketPath, *timeout)

	if *all {
		if fs.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "meshtermd kill: --all takes no positional argument")
			return killExitGenericError
		}
		return runKillAll(client, *yes, *timeout)
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "meshtermd kill: exactly one selector required (id, name, glob, or --all)")
		fs.Usage()
		return killExitGenericError
	}
	selector := fs.Arg(0)

	if isGlobSelector(selector) {
		return runKillGlob(client, selector, *yes, *timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	resp, err := client.KillSession(ctx, selector)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintf(os.Stderr, "meshtermd kill: daemon not running at %s.\n", socketPath)
			return killExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd kill: %v\n", err)
		return killExitGenericError
	}
	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd kill: %s: %s\n", resp.Err, resp.Msg)
		if resp.Err == ipc.ErrUnknownSession {
			return killExitUnknownSession
		}
		return killExitGenericError
	}
	return killExitOK
}

// runKillAll kills every session on the daemon. Confirmation gate:
// `--yes` flag bypasses; otherwise prompt on stdin (skipped when
// stdin isn't a TTY — non-interactive callers MUST pass --yes,
// avoiding accidental "kill all" from a script's stray pipe).
func runKillAll(client *ipc.Client, yes bool, timeout time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	list, err := client.ListSessions(ctx)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "meshtermd kill --all: daemon not running.")
			return killExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd kill --all: list: %v\n", err)
		return killExitGenericError
	}
	if !list.Ok || len(list.Sessions) == 0 {
		fmt.Fprintln(os.Stderr, "meshtermd kill --all: no sessions on daemon.")
		return killExitOK
	}

	if !yes {
		if !isStdinInteractive() {
			fmt.Fprintln(os.Stderr,
				"meshtermd kill --all: stdin is not a TTY; pass --yes to kill all sessions non-interactively.")
			return killExitGenericError
		}
		fmt.Fprintf(os.Stderr, "Kill %d session(s)? [y/N] ", len(list.Sessions))
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(os.Stderr, "aborted.")
			return killExitGenericError
		}
	}

	return killBatch(client, list.Sessions, timeout)
}

// runKillGlob filters sessions by name pattern, applies the same
// confirmation gate as --all when more than one matches, then
// kills each in turn.
func runKillGlob(client *ipc.Client, pattern string, yes bool, timeout time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	list, err := client.ListSessions(ctx)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "meshtermd kill: daemon not running.")
			return killExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd kill: list: %v\n", err)
		return killExitGenericError
	}
	if !list.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd kill: list: %s: %s\n", list.Err, list.Msg)
		return killExitGenericError
	}

	matches := make([]ipc.SessionInfo, 0)
	for _, s := range list.Sessions {
		ok, err := filepath.Match(pattern, s.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd kill: bad glob pattern %q: %v\n", pattern, err)
			return killExitGenericError
		}
		if ok {
			matches = append(matches, s)
		}
	}
	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "meshtermd kill: no session names match %q\n", pattern)
		return killExitUnknownSession
	}

	// Single-match glob: just kill it without prompting (parity
	// with the exact-selector path). 2+ matches gates on confirm.
	if len(matches) > 1 && !yes {
		if !isStdinInteractive() {
			fmt.Fprintf(os.Stderr,
				"meshtermd kill: %q matches %d sessions; pass --yes to kill non-interactively.\n",
				pattern, len(matches))
			return killExitGenericError
		}
		names := make([]string, 0, len(matches))
		for _, s := range matches {
			names = append(names, s.Name)
		}
		fmt.Fprintf(os.Stderr, "Kill %d session(s) matching %q? %v [y/N] ",
			len(matches), pattern, names)
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(os.Stderr, "aborted.")
			return killExitGenericError
		}
	}

	return killBatch(client, matches, timeout)
}

// killBatch invokes KillSession on each session in the slice.
// Reports per-session failures on stderr but continues; exit code
// is OK if every kill succeeded, generic-error if any failed.
func killBatch(client *ipc.Client, sessions []ipc.SessionInfo, timeout time.Duration) int {
	failed := 0
	for _, s := range sessions {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		resp, err := client.KillSession(ctx, s.ID)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd kill: %s (%s): %v\n", s.Name, s.ID, err)
			failed++
			continue
		}
		if !resp.Ok {
			fmt.Fprintf(os.Stderr, "meshtermd kill: %s (%s): %s: %s\n",
				s.Name, s.ID, resp.Err, resp.Msg)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "killed %s (%s)\n", s.Name, s.ID[:12])
	}
	if failed > 0 {
		return killExitGenericError
	}
	return killExitOK
}

// isGlobSelector reports whether s contains shell-glob metacharacters.
// Anything else is treated as an exact selector and routed straight
// to KillSession (preserves the pre-glob CLI behaviour).
func isGlobSelector(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// isStdinInteractive: cheap probe — true when os.Stdin's mode bit
// indicates a character device (i.e. a TTY). Pipes / redirected
// files come back false. Used to decide whether to prompt or
// require --yes on batch operations.
func isStdinInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
