package ptysidecar

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Pidfile owns an exclusive, flock-protected pidfile on disk.
// Format: two lines — PID, then the absolute path of the running
// binary. The flock is held for the lifetime of *Pidfile and is
// released by Close, which also unlinks the file. A second concurrent
// Acquire on the same path fails with ErrPidfileLocked.
type Pidfile struct {
	path string
	f    *os.File
}

// ErrPidfileLocked is returned by AcquirePidfile when an existing
// holder still has the flock — the path's previous sidecar is still
// alive.
var ErrPidfileLocked = errors.New("ptysidecar: pidfile already locked by another process")

// AcquirePidfile opens (or creates) the pidfile at path, takes an
// exclusive non-blocking flock, and writes "<pid>\n<binary>\n". On
// success the returned *Pidfile must be Close()d on shutdown.
//
// Returns ErrPidfileLocked if another live process holds the lock.
// In that case the caller should refuse to start (the daemon
// discovery path treats this as "session already has a sidecar").
func AcquirePidfile(path, binary string) (*Pidfile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open pidfile %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrPidfileLocked
		}
		return nil, fmt.Errorf("flock pidfile %s: %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("truncate pidfile %s: %w", path, err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seek pidfile %s: %w", path, err)
	}
	if _, err := fmt.Fprintf(f, "%d\n%s\n", os.Getpid(), binary); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write pidfile %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync pidfile %s: %w", path, err)
	}
	return &Pidfile{path: path, f: f}, nil
}

// Close releases the flock, closes the fd, and unlinks the pidfile
// from disk. Idempotent.
func (p *Pidfile) Close() error {
	if p == nil || p.f == nil {
		return nil
	}
	_ = unix.Flock(int(p.f.Fd()), unix.LOCK_UN)
	_ = p.f.Close()
	p.f = nil
	return os.Remove(p.path)
}

// ReadPidfile parses an existing pidfile without taking the lock.
// Used by the daemon's discovery path to find living sidecars.
func ReadPidfile(path string) (pid int, binary string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 2 {
		return 0, "", fmt.Errorf("ptysidecar: pidfile %s is malformed (got %d lines)", path, len(lines))
	}
	pid, err = strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return 0, "", fmt.Errorf("ptysidecar: pidfile %s: parse pid: %w", path, err)
	}
	binary = strings.TrimSpace(lines[1])
	return pid, binary, nil
}

// ProcessAlive reports whether the given pid refers to a running
// process. Implemented via kill(pid, 0) per POSIX semantics.
func ProcessAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := unix.Kill(pid, 0)
	if err == nil {
		return true
	}
	// EPERM means the process exists but we don't own it — for our
	// purposes that still counts as "alive."
	return errors.Is(err, unix.EPERM)
}
