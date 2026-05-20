package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
)

// portStateFile is the on-disk filename inside the daemon data dir
// where we persist the last-successfully-bound QUIC UDP port. One
// integer per file. Plain text so a human can `cat` it.
const portStateFile = "quic-port"

// readPortState returns the persisted preferred UDP port, or 0 if
// the file is missing, empty, unparseable, or otherwise unusable.
// Never returns an error: a corrupt or unreadable state file just
// means we have no preference and bind from the configured default.
// Caller treats 0 as "no preference."
func readPortState(stateDir string) uint16 {
	if stateDir == "" {
		return 0
	}
	path := filepath.Join(stateDir, portStateFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Debug("transport: read port state",
				"path", path, "err", err)
		}
		return 0
	}
	n, err := strconv.ParseUint(string(bytes.TrimSpace(raw)), 10, 16)
	if err != nil || n == 0 {
		slog.Warn("transport: port state unparseable, ignoring",
			"path", path, "raw", string(raw), "err", err)
		return 0
	}
	return uint16(n)
}

// writePortState persists the just-bound UDP port to the daemon
// data dir. Atomic via tempfile-then-rename so a crash mid-write
// doesn't leave a corrupt file. Best-effort: a write failure is
// logged but never returned — the daemon shouldn't refuse to start
// because the state file is unwriteable (e.g., read-only home dir,
// quota exhaustion). The next start just rediscovers the port.
func writePortState(stateDir string, port uint16) {
	if stateDir == "" {
		return
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		slog.Warn("transport: mkdir state dir for port state",
			"dir", stateDir, "err", err)
		return
	}
	path := filepath.Join(stateDir, portStateFile)
	tmp, err := os.CreateTemp(stateDir, portStateFile+".tmp-*")
	if err != nil {
		slog.Warn("transport: create temp file for port state",
			"dir", stateDir, "err", err)
		return
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := fmt.Fprintf(tmp, "%d\n", port); err != nil {
		slog.Warn("transport: write port state", "path", tmpPath, "err", err)
		cleanup()
		return
	}
	if err := tmp.Close(); err != nil {
		slog.Warn("transport: close port state tempfile",
			"path", tmpPath, "err", err)
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		slog.Warn("transport: rename port state", "from", tmpPath, "to", path, "err", err)
		_ = os.Remove(tmpPath)
		return
	}
}
