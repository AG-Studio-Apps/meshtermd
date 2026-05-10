package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
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

// runKill reaps a session by hex SessionID or by Name. Single
// positional arg; daemon resolves which kind it is.
func runKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd kill [flags] <id-or-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "meshtermd kill: exactly one selector required (id or name)")
		fs.Usage()
		return killExitGenericError
	}
	selector := fs.Arg(0)

	socketPath := *socket
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}

	client := ipc.NewClient(socketPath, *timeout)
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
