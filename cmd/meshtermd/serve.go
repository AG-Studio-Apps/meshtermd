package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/daemon"
)

// runServe is the long-running daemon mode. It owns the session
// registry, accepts QUIC connections, and listens on a unix socket
// for `meshtermd connect` invocations.
//
// Exits 0 on graceful shutdown (SIGINT / SIGTERM), non-zero on
// startup error.
func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0",
		"QUIC bind address (host:port; port 0 = ephemeral). "+
			"Default 127.0.0.1: the iOS client reaches us via the same hostname they SSH'd to. "+
			"Override to 0.0.0.0 only if you genuinely need remote QUIC on a non-loopback path.")
	socket := fs.String("socket", "", "unix socket path for the connect helper (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	maxSessions := fs.Int("max-sessions", 0, "concurrent session cap (0 = default 100)")
	idleTimeout := fs.Duration("idle-timeout", 0, "default idle timeout for sessions whose client didn't request one (0 = 1h)")
	maxIdleTimeout := fs.Duration("max-idle-timeout", 0,
		"ceiling on per-session idle-timeout requests from clients. 0 = no ceiling (appropriate for personal-server "+
			"deployments). Set on shared/multi-user hosts to bound resource cost (e.g. 168h = 7d).")
	verbose := fs.Bool("v", false, "verbose logging (slog DEBUG level)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd serve [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	socketPath := *socket
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}

	d, err := daemon.New(daemon.Config{
		QUICAddr:       *addr,
		IPCSocketPath:  socketPath,
		MaxSessions:    *maxSessions,
		IdleTimeout:    *idleTimeout,
		MaxIdleTimeout: *maxIdleTimeout,
		Logger:         logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshtermd serve: %v\n", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Write our PID to a file next to the IPC socket so the uninstall
	// and update commands can SIGTERM us exactly, instead of relying
	// on a `pkill -f` substring match against the argv (which catches
	// editors / shells / scripts with "meshtermd serve" anywhere in
	// their command line). Best-effort: if the write fails the daemon
	// keeps running, and the fallback pkill path still works.
	pidPath := pidFilePath(socketPath)
	_ = writePidFile(pidPath)
	defer func() { _ = os.Remove(pidPath) }()

	// Print one-line status to stdout so a parent process / wrapper
	// script can confirm we're up. Diagnostics go via the slog
	// handler on stderr.
	fmt.Printf("meshtermd ready quic_addr=%s socket=%s\n", d.Addr(), d.IPCSocketPath())

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "meshtermd serve: %v\n", err)
		return 1
	}
	logger.Info("meshtermd stopped")
	return 0
}

// defaultSocketPath returns $XDG_RUNTIME_DIR/meshtermd.sock when
// XDG_RUNTIME_DIR is set, falling back to the cert state dir.
// XDG_RUNTIME_DIR is the conventional location for unix sockets
// because systemd auto-cleans it on logout; the data dir is a
// reasonable fallback for distros that don't set it.
func defaultSocketPath() string {
	if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
		return filepath.Join(rd, "meshtermd.sock")
	}
	dataDir, err := cert.DefaultDir()
	if err != nil {
		// Fall back to the current directory as a last resort. The
		// `meshtermd serve` invocation will fail with a more useful
		// error than this (e.g., bind permission), but we don't
		// want to crash on startup just because os.UserHomeDir is
		// unhappy.
		return "meshtermd.sock"
	}
	return filepath.Join(dataDir, "meshtermd.sock")
}

// nopWriter discards writes. Reserved for the future quiet-mode
// flag; not used yet but referenced by future flag work.
var _ io.Writer = (*nopWriter)(nil) //nolint:unused

type nopWriter struct{} //nolint:unused

func (*nopWriter) Write(p []byte) (int, error) { return len(p), nil } //nolint:unused

// Reserved for future flag integration: a bigger idle timeout knob.
var _ = (1 * time.Second) //nolint:unused

// pidFilePath returns the conventional pid-file path: a sibling of
// the IPC socket so any caller who can resolve the socket can also
// resolve the pid file. Uninstall + update use it to SIGTERM the
// running daemon exactly, instead of pkill -f against argv.
func pidFilePath(socketPath string) string {
	return filepath.Join(filepath.Dir(socketPath), "meshtermd.pid")
}

// writePidFile writes the current process's pid to `path` as a
// single decimal line. Mode 0o600 — same trust level as the IPC
// socket. Best-effort: caller should ignore failures (a missing
// pidfile makes uninstall fall back to pkill, which still works).
func writePidFile(path string) error {
	pid := []byte(fmt.Sprintf("%d\n", os.Getpid()))
	return os.WriteFile(path, pid, 0o600)
}
