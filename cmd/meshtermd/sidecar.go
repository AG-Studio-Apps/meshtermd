package main

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

	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
)

// runPtySidecar is the entry point for the `pty-sidecar` subcommand.
// The daemon spawns one of these per session; it owns the PTY master
// fd + child shell and forwards bytes to/from the daemon over a
// per-session Unix socket. See internal/ptysidecar for the design.
//
// Not invoked manually — flag parse failures still print usage so
// tooling can introspect via `meshtermd pty-sidecar --help`.
func runPtySidecar(args []string) int {
	fs := flag.NewFlagSet("pty-sidecar", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	socket := fs.String("socket", "", "path to bind for the per-session Unix socket (required)")
	pidfile := fs.String("pidfile", "", "path to write the flock'd pidfile (required)")
	sessionID := fs.String("session-id", "", "hex sessionID, used in log fields (optional)")
	shell := fs.String("shell", "", "absolute path to child shell ($SHELL → /bin/sh if empty)")
	rows := fs.Uint("rows", 24, "initial PTY rows")
	cols := fs.Uint("cols", 80, "initial PTY cols")
	envFile := fs.String("env-file", "", "path to KEY=VAL\\n env file; deleted by sidecar after read")
	graceSecs := fs.Int("grace-secs", ptysidecar.DefaultGraceSecs, "seconds to wait for daemon reconnect before reaping child")
	ringBytes := fs.Int("ring-bytes", ptysidecar.DefaultRingBytes, "capacity of the drop-oldest output ring")
	logPath := fs.String("log", "", "log file path; default stderr")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *socket == "" || *pidfile == "" {
		fmt.Fprintln(os.Stderr, "pty-sidecar: --socket and --pidfile are required")
		fs.Usage()
		return 2
	}
	if *rows > 0xFFFF || *cols > 0xFFFF {
		fmt.Fprintln(os.Stderr, "pty-sidecar: --rows and --cols must fit in uint16")
		return 2
	}

	logger := buildSidecarLogger(*logPath)

	cfg := ptysidecar.Config{
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
	}

	// SIGTERM/SIGINT handling lives inside Run; we hand it a
	// cancellable context so the daemon can also tear us down by
	// closing the socket and waiting.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := ptysidecar.Run(ctx, cfg); err != nil {
		logger.Error("sidecar.run_failed", "err", err.Error())
		return 1
	}
	return 0
}

func buildSidecarLogger(path string) *slog.Logger {
	var sink io.Writer = os.Stderr
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			sink = f
		}
	}
	return slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
