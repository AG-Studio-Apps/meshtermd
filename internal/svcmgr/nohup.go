package svcmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// nohup is the fallback Manager for hosts without a reachable
// systemd-user / launchd. It just exec's `setsid nohup <bin> serve
// --socket ... </dev/null >/tmp/meshtermd.log 2>&1 &`, same as the
// iOS installer does over SSH.
//
// Remove is a no-op (nothing to clean up — no unit file). Stop uses
// `pkill -u <uid> -f 'meshtermd serve'` so it catches any running
// daemon regardless of how it was started.
type nohup struct{}

func (n *nohup) Name() string { return "nohup" }

// Available is always true — this is the universal fallback. Detect
// uses it only when neither systemd-user nor launchd is reachable.
func (n *nohup) Available(ctx context.Context) bool { return true }

func (n *nohup) Stop(ctx context.Context) error {
	// Try the pidfile first (exact PID, no collateral damage).
	// Fall back to `pkill -x meshtermd` (exact basename match) so a
	// kill -9'd daemon that left a stale pidfile still gets cleaned
	// up. We intentionally do NOT use `pkill -f 'meshtermd serve'`
	// — that catches editors / scripts with "meshtermd serve" in
	// their argv.
	if pidfileKill() {
		return nil
	}
	uid := strconv.Itoa(os.Getuid())
	_ = exec.CommandContext(ctx, "pkill", "-u", uid, "-x", "meshtermd").Run()
	return nil
}

// pidfileKill mirrors signaledFromPidFile in cmd/meshtermd/lifecycle.go
// but is duplicated here so the svcmgr package doesn't pull the cmd
// package as a dep. Returns true if a SIGTERM was sent.
func pidfileKill() bool {
	candidates := []string{}
	if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
		candidates = append(candidates, rd+"/meshtermd.pid")
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home+"/.local/share/meshtermd/meshtermd.pid")
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			_ = os.Remove(path)
			continue
		}
		_ = os.Remove(path)
		return true
	}
	return false
}

func (n *nohup) Start(ctx context.Context, binPath string) error {
	// Replicate the iOS installer's "setsid nohup ... &" idiom:
	// new session, ignore SIGHUP, redirect stdio so the SSH parent
	// can exit cleanly. We're already in a process here, so we
	// don't need the outer `&` — `Process.Release` after Start
	// detaches us from the child.
	cmd := exec.CommandContext(ctx, binPath, "serve",
		"--addr", "0.0.0.0:51820",
		"--socket", homePath(".local", "share", "meshtermd", "meshtermd.sock"),
	)
	// New session so SIGHUP from our parent doesn't propagate.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	logFile, err := os.OpenFile("/tmp/meshtermd.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open logfile: %w", err)
	}
	defer logFile.Close()
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start meshtermd: %w", err)
	}
	// Detach: the child runs independently of our process tree.
	// Without Release the OS would keep it as a zombie until we
	// wait on it, which we never will.
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release process: %w", err)
	}
	// Give the daemon a beat to bind its sockets so a Start →
	// Status call in the caller sees a running daemon.
	time.Sleep(250 * time.Millisecond)
	return nil
}

func (n *nohup) Restart(ctx context.Context, binPath string) error {
	if err := n.Stop(ctx); err != nil {
		return err
	}
	// Brief pause so the port is released before the next bind.
	time.Sleep(500 * time.Millisecond)
	return n.Start(ctx, binPath)
}

func (n *nohup) Remove(ctx context.Context) error { return nil }

// UnitPath returns "" because nohup has no unit/plist on disk.
func (n *nohup) UnitPath() string { return "" }
