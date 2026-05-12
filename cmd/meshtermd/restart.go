package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/release"
	"github.com/AG-Studio-Apps/meshtermd/internal/svcmgr"
)

// runRestart implements `meshtermd restart [--timeout D]`.
//
// Cycles the daemon via the detected supervisor (systemd-user /
// launchd / nohup). No confirmation prompt: with the v0.6.x pty-
// sidecar architecture, in-flight sessions survive a daemon restart
// (the sidecar processes own the PTYs, and the daemon reattaches via
// FrameResume on next boot), so the operation is safe to invoke
// unattended. Matches `systemctl restart`'s no-prompt UX.
//
// Exit codes:
//
//	0  daemon restarted
//	1  supervisor unreachable or restart failed
//	2  bad flags
func runRestart(args []string) int {
	fs := flag.NewFlagSet("restart", flag.ExitOnError)
	timeout := fs.Duration("timeout", 30*time.Second,
		"max time to wait for the supervisor to complete the restart")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd restart [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	mgr := svcmgr.Detect(ctx)
	binPath := release.JoinBin()
	fmt.Printf("▸ Restarting daemon via %s\n", mgr.Name())
	if err := mgr.Restart(ctx, binPath); err != nil {
		if errors.Is(err, svcmgr.ErrUnavailable) {
			fmt.Fprintf(os.Stderr,
				"restart: %s supervisor not reachable from this process\n",
				mgr.Name())
			return 1
		}
		fmt.Fprintf(os.Stderr, "restart via %s: %v\n", mgr.Name(), err)
		return 1
	}
	fmt.Printf("✓ Daemon restarted via %s\n", mgr.Name())
	return 0
}
