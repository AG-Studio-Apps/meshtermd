// Package svcmgr abstracts the host service manager (systemd-user /
// launchd / direct exec) so meshtermd's uninstall + update flows
// don't need to branch in three places. Each Manager implements a
// minimal stop / start / restart interface, plus a `Detect` helper
// that picks the right backend at runtime.
package svcmgr

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Manager is implemented per-platform. Operations are best-effort:
// `Stop` on a not-running daemon returns nil, not an error. Implementations
// must be safe to call when the underlying supervisor isn't reachable
// (e.g. systemctl --user with no user-bus); in that case they should
// return ErrUnavailable so the caller can pick a fallback.
type Manager interface {
	// Name returns a short label for logging ("systemd-user", "launchd", "nohup").
	Name() string
	// Available returns true if this manager can drive the daemon
	// on this host right now. Used by Detect to pick the backend.
	Available(ctx context.Context) bool
	// Stop terminates the running daemon. Idempotent; a "no such
	// service" condition is not an error.
	Stop(ctx context.Context) error
	// Start launches the daemon. May invoke `<binPath> serve` directly
	// (nohup case) or call out to the supervisor (systemctl / launchctl).
	Start(ctx context.Context, binPath string) error
	// Restart is `Stop` followed by `Start`. Implementations may
	// supply a more efficient native restart if available.
	Restart(ctx context.Context, binPath string) error
	// Remove tears down the supervisor's record of the daemon (unit
	// file, plist, etc.) so future runs of Detect don't pick this
	// manager back up. Returns nil if nothing to remove.
	Remove(ctx context.Context) error
}

// ErrUnavailable is returned by Manager methods when the supervisor
// isn't reachable from this process (no user-bus, no launchctl, etc.).
var ErrUnavailable = errors.New("svcmgr: supervisor not reachable")

// Detect returns the most-appropriate Manager for the current host.
// Preference order (matches the iOS installer):
//  1. systemd-user (Linux with a reachable user-bus)
//  2. launchd     (macOS only)
//  3. nohup       (fallback — direct setsid+nohup, no supervisor)
//
// Always returns a non-nil Manager. The fallback nohup manager
// works on every POSIX host so detection never fails.
func Detect(ctx context.Context) Manager {
	if runtime.GOOS == "linux" {
		sd := &systemdUser{}
		if sd.Available(ctx) {
			return sd
		}
	}
	if runtime.GOOS == "darwin" {
		ld := &launchd{}
		if ld.Available(ctx) {
			return ld
		}
	}
	return &nohup{}
}

// commandExists returns true if `name` is on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// fileExists is the bare-minimum existence check for unit/plist
// files. We don't care if it's a regular file vs symlink vs device —
// the supervisor will reject anything weird.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// homePath joins relative path components onto $HOME. Used by every
// backend for unit/plist/state-dir locations.
func homePath(parts ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to current dir — the supervisor will surface
		// a clearer error than we'd construct here.
		return filepath.Join(parts...)
	}
	return filepath.Join(append([]string{home}, parts...)...)
}
