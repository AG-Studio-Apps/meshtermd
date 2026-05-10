package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// runRename changes the user-visible Name of a remote session.
// PTY + ring buffer + active attach are unaffected.
func runRename(args []string) int {
	fs := flag.NewFlagSet("rename", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the ssh round-trip")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl rename [flags] <id-or-name> <new-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "mtctl rename: need exactly two args: <id-or-name> <new-name>")
		fs.Usage()
		return exitConfig
	}

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}
	selector := fs.Arg(0)
	newName := fs.Arg(1)
	if newName == "" {
		fmt.Fprintln(os.Stderr, "mtctl rename: new name must not be empty")
		return exitConfig
	}

	remote := fmt.Sprintf("meshtermd rename %s %s",
		shellQuote(selector), shellQuote(newName))

	ctx := context.Background()
	_, stderr, code, err := runRemote(ctx, target, remote, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl rename: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "%s", stderr)
		// 3 = unknown_session, 5 = name_in_use (from the daemon CLI's
		// exit-code convention). Pass through so scripts can branch.
		if code == 3 || code == 5 {
			return code
		}
		return exitRemote
	}
	return exitOK
}
