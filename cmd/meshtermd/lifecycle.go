package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// killOrphanDaemon SIGTERMs any `meshtermd serve` owned by the
// current uid that isn't tracked by the active svcmgr. Catches the
// case where someone ran `meshtermd serve &` manually or where a
// previous install fell back to nohup and the supervisor handover
// left a free-running process.
//
// Strategy in priority order:
//  1. PID file at $dir/meshtermd.pid (written by `serve`). Exact
//     match, no collateral damage. Most common path on a
//     normally-installed host.
//  2. `pkill -u <uid> -x meshtermd` — exact basename match.
//     Catches a daemon started by a binary at a different path
//     than what we know about (e.g. /tmp/meshterm). Still tight
//     enough that a user's vim doesn't get hit.
//
// We deliberately do NOT use `pkill -f 'meshtermd serve'` — that
// substring-matches against the full command line and catches text
// editors, shells with that string in their argv, etc.
func killOrphanDaemon(ctx context.Context) error {
	if signaledFromPidFile() {
		return nil
	}
	uid := strconv.Itoa(os.Getuid())
	cmd := exec.CommandContext(ctx, "pkill", "-u", uid, "-x", "meshtermd")
	_ = cmd.Run() // exit 1 = no matches; collapse to nil
	return nil
}

// signaledFromPidFile reads the conventional pid file and SIGTERMs
// the process it points at. Returns true if a SIGTERM was actually
// sent (caller can skip the fallback). Best-effort: malformed files,
// stale pids, permission errors all return false.
func signaledFromPidFile() bool {
	// Try both candidate locations; the daemon picks one based on
	// whether XDG_RUNTIME_DIR was set when it started.
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
			// Process gone already, or not ours; remove the
			// stale file so the next run doesn't trip on it.
			_ = os.Remove(path)
			continue
		}
		// Best-effort cleanup of the pidfile — the daemon's own
		// `defer os.Remove(pidPath)` will do this on graceful
		// shutdown, but on a kill -9 it might be left behind.
		_ = os.Remove(path)
		return true
	}
	return false
}
