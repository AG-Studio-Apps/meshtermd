package ptyclient

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/pty"
	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
)

// SpawnConfig is the input to SpawnNew. The daemon fills this in and
// hands it to ptyclient — the sidecar process itself takes its
// equivalent inputs via command-line flags wired in
// cmd/meshtermd/sidecar.go.
type SpawnConfig struct {
	// SessionID is hex (32 chars); used to compute the per-session
	// state dir under StateDir/sessions/.
	SessionID string

	// Shell is the absolute path of the child shell. Empty falls back
	// to $SHELL → /bin/sh inside the sidecar.
	Shell string

	// ShellArgs is appended after the shell binary name. Typically nil.
	ShellArgs []string

	// Rows / Cols seed the PTY's initial dimensions.
	Rows, Cols uint16

	// ExtraEnv is written to the per-session env-file as additional
	// KEY=VAL lines beyond the curated allowlist the daemon would
	// otherwise pass directly.
	ExtraEnv []string

	// StateDir is the daemon's persistence root (e.g.
	// ~/.local/share/meshtermd). Sidecar artefacts live under
	// {StateDir}/sessions/{sessionID}/.
	StateDir string

	// DaemonBinary is the path to re-exec with the pty-sidecar
	// subcommand. Cache os.Executable() at daemon startup and pass
	// it in.
	DaemonBinary string

	// GraceSecs overrides the sidecar's default 30 s reconnect-grace
	// timeout. 0 → DefaultGraceSecs.
	GraceSecs int

	// RingBytes overrides the sidecar's drop-oldest output ring
	// capacity. 0 → ptysidecar.DefaultRingBytes.
	RingBytes int

	// Logger is used for spawn-side logs only; the sidecar gets its
	// own log file via the --log flag (or the daemon's parent fd if
	// nil — wired in sidecar.go).
	Logger *slog.Logger

	// Stderr is the file to which the spawned sidecar process's
	// stderr is bound. Defaults to os.Stderr (so sidecar logs flow
	// into systemd's journal alongside the daemon's). Tests pass
	// io.Discard to avoid keeping the test binary's stderr fd open
	// past sidecar reap, which makes `go test` park at WaitDelay.
	//
	// nil = use os.Stderr.
	Stderr io.Writer
}

// SpawnNew launches a new sidecar, dials its socket, and returns a
// ready *Conn. Both PTYSpawner callsites in the daemon swap from
// pty.Spawn to this.
//
// On any failure the sidecar (if started) is signalled and the
// session-dir artefacts are cleaned up before returning the error.
func SpawnNew(ctx context.Context, cfg SpawnConfig) (*Conn, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("ptyclient.SpawnNew: SessionID is required")
	}
	if cfg.DaemonBinary == "" {
		return nil, fmt.Errorf("ptyclient.SpawnNew: DaemonBinary is required")
	}
	if cfg.StateDir == "" {
		return nil, fmt.Errorf("ptyclient.SpawnNew: StateDir is required")
	}

	sessionDir := filepath.Join(cfg.StateDir, "sessions", cfg.SessionID)
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir session dir: %w", err)
	}

	sockPath := filepath.Join(sessionDir, "sidecar.sock")
	pidPath := filepath.Join(sessionDir, "sidecar.pid")
	// Remove any stale socket from a previous crashed sidecar. The
	// pidfile is gated by flock so we leave it alone — the sidecar's
	// AcquirePidfile will return ErrPidfileLocked if a live owner
	// still holds it.
	_ = os.Remove(sockPath)

	// Write the env file. We build the same curated allowlist +
	// defaults that pty.Spawn would have used in-process, then append
	// ExtraEnv. The sidecar reads + unlinks on startup.
	fullEnv := pty.BuildEnv(cfg.ExtraEnv)
	envPath, err := writeEnvFile(sessionDir, fullEnv)
	if err != nil {
		return nil, fmt.Errorf("write env-file: %w", err)
	}

	grace := cfg.GraceSecs
	if grace <= 0 {
		grace = ptysidecar.DefaultGraceSecs
	}
	ring := cfg.RingBytes
	if ring <= 0 {
		ring = ptysidecar.DefaultRingBytes
	}

	args := []string{
		"pty-sidecar",
		"--socket=" + sockPath,
		"--pidfile=" + pidPath,
		"--session-id=" + cfg.SessionID,
		"--rows=" + strconv.Itoa(int(cfg.Rows)),
		"--cols=" + strconv.Itoa(int(cfg.Cols)),
		"--env-file=" + envPath,
		"--grace-secs=" + strconv.Itoa(grace),
		"--ring-bytes=" + strconv.Itoa(ring),
	}
	if cfg.Shell != "" {
		args = append(args, "--shell="+cfg.Shell)
	}
	for _, a := range cfg.ShellArgs {
		// Shell args are passed through the daemon's flag-set as a
		// repeating positional after `--`. Today we don't pass any,
		// so we keep the surface minimal; if a future use case needs
		// it we can introduce a --shell-arg=… repeating flag here.
		_ = a
	}

	cmd := exec.Command(cfg.DaemonBinary, args...)
	// Setsid both detaches from any controlling terminal AND creates
	// a fresh session/process group rooted at the sidecar — so a
	// SIGTERM to the daemon's pgid doesn't propagate. Setpgid is
	// redundant alongside Setsid and on some kernels conflicts with
	// it, so we use Setsid alone.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	// Don't inherit stdin/stdout/stderr — the sidecar logs to its
	// own slog handler (stderr inside the sidecar's process; the
	// systemd journal collects it via the unit's logging by default,
	// but only if we don't disconnect — for now leave stderr connected
	// so the sidecar's log lines surface in journalctl alongside the
	// daemon's).
	cmd.Stdin = nil
	cmd.Stdout = nil
	if cfg.Stderr != nil {
		cmd.Stderr = cfg.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		_ = os.Remove(envPath)
		return nil, fmt.Errorf("start sidecar: %w", err)
	}
	// Release immediately — we don't want the kernel holding a zombie
	// slot waiting for us to Wait(). The sidecar is its own process
	// group and will exit on its own.
	sidecarPID := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		logger.Warn("ptyclient.process_release_failed", "err", err.Error())
	}

	// Dial the sidecar's socket with bounded retry — sidecar takes
	// 50–200 ms to bind on a healthy host.
	sock, dialErr := dialWithBackoff(ctx, sockPath)
	if dialErr != nil {
		// Tear down anything we can find.
		_ = os.Remove(envPath)
		killSidecar(pidPath, logger)
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("dial sidecar at %s (pid=%d): %w", sockPath, sidecarPID, dialErr)
	}

	logger.Info("ptyclient.spawned",
		"session", cfg.SessionID,
		"pid", sidecarPID,
		"socket", sockPath,
	)

	// Env file is single-use — the sidecar has already read it. Best-
	// effort removal; if it's gone already (sidecar's own unlink),
	// that's fine.
	_ = os.Remove(envPath)

	return newConn(cfg.SessionID, sock, logger), nil
}

// dialWithBackoff polls the socket path until it's connectable or
// the deadline expires. 3 s budget, 25 ms intervals.
func dialWithBackoff(ctx context.Context, sockPath string) (net.Conn, error) {
	const (
		totalBudget = 3 * time.Second
		step        = 25 * time.Millisecond
	)
	deadline := time.Now().Add(totalBudget)
	var lastErr error
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c, err := net.DialTimeout("unix", sockPath, 250*time.Millisecond)
		if err == nil {
			return c, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("sidecar socket not ready within %s: %w", totalBudget, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(step):
		}
	}
}

// killSidecar best-effort signals a sidecar whose pidfile is on disk.
// Used in error cleanup paths.
func killSidecar(pidPath string, logger *slog.Logger) {
	pid, _, err := ptysidecar.ReadPidfile(pidPath)
	if err != nil {
		return
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		logger.Debug("ptyclient.kill_sidecar_failed", "pid", pid, "err", err.Error())
	}
}

// writeEnvFile dumps env (one KEY=VAL per line) to a 0600 file
// inside sessionDir and returns the path. Sidecar reads + unlinks
// on startup.
func writeEnvFile(sessionDir string, env []string) (string, error) {
	f, err := os.CreateTemp(sessionDir, "sidecar-env-*")
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	for _, kv := range env {
		if _, err := fmt.Fprintln(f, kv); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return "", err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
