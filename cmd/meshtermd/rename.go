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

// Exit codes for `meshtermd rename`. Aligned with kill:
//
//	0  ok
//	1  generic error (bad flag, transport, empty new name)
//	2  daemon not running
//	3  unknown session (selector resolved to nothing)
//	5  name already in use (distinct from "unknown" so scripts
//	   can branch)
const (
	renameExitOK               = 0
	renameExitGenericError     = 1
	renameExitDaemonNotRunning = 2
	renameExitUnknownSession   = 3
	renameExitNameInUse        = 5
)

// runRename changes the user-visible Name of a live session. The
// PTY, ring buffer, and any in-flight QUIC attach are unaffected —
// the session itself keeps running. Only the picker label changes.
func runRename(args []string) int {
	fs := flag.NewFlagSet("rename", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd rename [flags] <id-or-name> <new-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "meshtermd rename: need exactly two args: <id-or-name> <new-name>")
		fs.Usage()
		return renameExitGenericError
	}
	selector := fs.Arg(0)
	newName := fs.Arg(1)
	if newName == "" {
		fmt.Fprintln(os.Stderr, "meshtermd rename: new name must not be empty")
		return renameExitGenericError
	}

	socketPath := *socket
	if socketPath == "" {
		socketPath = discoverClientSocketPath()
	}

	client := ipc.NewClient(socketPath, *timeout)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.RenameSession(ctx, selector, newName)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintf(os.Stderr, "meshtermd rename: daemon not running at %s.\n", socketPath)
			return renameExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd rename: %v\n", err)
		return renameExitGenericError
	}
	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd rename: %s: %s\n", resp.Err, resp.Msg)
		switch resp.Err {
		case ipc.ErrUnknownSession:
			return renameExitUnknownSession
		case ipc.ErrNameInUse:
			return renameExitNameInUse
		default:
			return renameExitGenericError
		}
	}
	return renameExitOK
}
