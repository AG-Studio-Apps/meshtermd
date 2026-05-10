package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

// runNew creates a new named session on the remote daemon without
// attaching to it. Under the hood we run `meshtermd connect --session
// new --name <name>` — that returns an MTRM_QUIC bootstrap line + an
// attach token whose TTL (30 s) expires unused. The session itself
// stays alive on the daemon, ready to be picked up by the iOS app or
// a future `mtctl attach` (Tier 3).
//
// Useful for: scripted spawn ("cron the dev box to create a
// 'nightly-build' session at 02:00 so you can attach from your phone
// over breakfast"), pre-creating a labelled session before opening
// the iOS app, or one-shot "I want a buffer that survives my
// laptop's reboot, name it now."
func runNew(args []string) int {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 15*time.Second, "max time to wait for the ssh round-trip")
	name := fs.String("name", "", "user-visible session name (required)")
	shell := fs.String("shell", "", "override the user's shell on the remote ($SHELL → /bin/bash → /bin/sh)")
	rows := fs.Uint("rows", 24, "initial PTY rows")
	cols := fs.Uint("cols", 80, "initial PTY cols")
	idleTimeout := fs.Duration("idle-timeout", 0, "per-session idle timeout (0 = use daemon default)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl new --name <name> [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "mtctl new: --name is required")
		fs.Usage()
		return exitConfig
	}

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	// Build the remote command. We delegate to the daemon's CLI
	// rather than reimplementing its arg parsing — keeps mtctl
	// minimal and lets the daemon evolve its flag surface without
	// breaking us.
	cmd := fmt.Sprintf(
		"meshtermd connect --session new --name %s --rows %d --cols %d",
		shellQuote(*name), *rows, *cols,
	)
	if *shell != "" {
		cmd += " --shell " + shellQuote(*shell)
	}
	if *idleTimeout > 0 {
		cmd += fmt.Sprintf(" --idle-timeout %ds", int((*idleTimeout).Seconds()))
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, cmd, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl new: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "%s", stderr)
		return exitRemote
	}

	// The daemon's `connect` prints the MTRM_QUIC bootstrap line on
	// stdout. We intentionally discard it — Tier 1 mtctl doesn't
	// attach. The attach token will expire in 30 s; the session
	// itself stays alive on the daemon, ready for the iOS app to
	// pick up via the picker.
	_ = stdout

	fmt.Printf("created session %q on %s\n", *name, target)
	return exitOK
}
