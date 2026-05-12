package daemon

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
)

// TestMain handles the case where the daemon spawns the test binary
// as its `pty-sidecar` subprocess. In production the daemon binary
// (`meshtermd`) re-execs itself with `pty-sidecar` args; under `go
// test`, `os.Executable()` returns the test binary, so we need a
// shim here that dispatches the same way `cmd/meshtermd` does.
//
// Without this shim, the daemon test process forks itself with
// pty-sidecar args; the testing framework doesn't recognise those,
// retries the test list, and the recursion exhausts file descriptors.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == "pty-sidecar" {
		os.Exit(runPtySidecarForTests(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// runPtySidecarForTests is a duplicate of cmd/meshtermd.runPtySidecar
// scoped to the test binary. Kept in sync by hand — the flag surface
// is small and frozen.
func runPtySidecarForTests(args []string) int {
	fs := flag.NewFlagSet("pty-sidecar", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	socket := fs.String("socket", "", "")
	pidfile := fs.String("pidfile", "", "")
	sessionID := fs.String("session-id", "", "")
	shell := fs.String("shell", "", "")
	rows := fs.Uint("rows", 24, "")
	cols := fs.Uint("cols", 80, "")
	envFile := fs.String("env-file", "", "")
	graceSecs := fs.Int("grace-secs", ptysidecar.DefaultGraceSecs, "")
	ringBytes := fs.Int("ring-bytes", ptysidecar.DefaultRingBytes, "")
	logPath := fs.String("log", "", "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *socket == "" || *pidfile == "" {
		fmt.Fprintln(os.Stderr, "pty-sidecar: --socket and --pidfile are required")
		return 2
	}

	var sink io.Writer = os.Stderr
	if *logPath != "" {
		if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			sink = f
		}
	}
	logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := ptysidecar.Run(ctx, ptysidecar.Config{
		SocketPath:  *socket,
		PidfilePath: *pidfile,
		SessionID:   *sessionID,
		Shell:       *shell,
		Rows:        uint16(*rows),
		Cols:        uint16(*cols),
		EnvFile:     *envFile,
		GraceSecs:   *graceSecs,
		RingBytes:   *ringBytes,
		Logger:      logger,
	}); err != nil {
		logger.Error("sidecar.run_failed", "err", err.Error())
		return 1
	}
	return 0
}
