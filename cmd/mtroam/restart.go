package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// runRestart cycles the remote daemon via its detected supervisor.
// Thin wrapper around `ssh host mtroamd restart`. With the v0.6.x
// pty-sidecar architecture, in-flight sessions survive a daemon
// restart, so this is safe to invoke unattended.
func runRestart(args []string) int {
	fs := flag.NewFlagSet("restart", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running mtroamd (or set $MTROAM_HOST)")
	timeout := fs.Duration("timeout", 45*time.Second,
		"max time to wait for the ssh round-trip (default exceeds the daemon's own 30s restart timeout)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtroam restart [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, "mtroamd restart", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtroam restart: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		// Surface daemon's stderr (e.g. "supervisor not reachable"),
		// neutralizing any escape bytes in the daemon-supplied string.
		fmt.Fprintf(os.Stderr, "%s", sanitizeMultilineForDisplay(stderr))
		return exitRemote
	}
	// Daemon emits a friendly "✓ Daemon restarted via <mgr>" line on
	// stdout; pass it through (sanitized — the <mgr> name is
	// daemon-supplied) so the user sees confirmation.
	safe := sanitizeMultilineForDisplay(stdout)
	fmt.Print(safe)
	if !endsWithNewline(safe) {
		fmt.Println()
	}
	return exitOK
}
