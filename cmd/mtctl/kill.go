package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// runKill reaps a remote session by hex SessionID or by Name. The
// remote `meshtermd kill` resolves whichever the selector turns out
// to be.
func runKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the ssh round-trip")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl kill [flags] <id-or-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "mtctl kill: exactly one selector required (id or name)")
		fs.Usage()
		return exitConfig
	}

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}
	selector := fs.Arg(0)

	// The daemon's CLI accepts the selector as a single positional
	// arg. Single-quote it so a name with shell metacharacters can't
	// break out of the remote `bash -c`.
	remote := "meshtermd kill " + shellQuote(selector)

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, remote, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl kill: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		// Daemon's CLI emits readable stderr; surface it.
		fmt.Fprintf(os.Stderr, "%s", stderr)
		// Pass through specific exit codes that scripts care about
		// (3 = unknown_session). Anything else → generic remote.
		if code == 3 {
			return 3
		}
		return exitRemote
	}
	// On success the daemon emits nothing useful on stdout (kill
	// is a side-effect). Drain any noise for cleanliness.
	_ = stdout
	return exitOK
}
