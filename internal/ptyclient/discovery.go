package ptyclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"syscall"

	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// dialDiscoveryTimeout is the per-session dial budget when
// re-attaching to an existing sidecar at daemon startup. A live,
// healthy sidecar responds immediately; the timeout is for the
// "process is alive but not serving" pathology (which we then treat
// as a stale sidecar and SIGTERM).
const dialDiscoveryTimeout = 500 * time.Millisecond

// Discover walks {stateDir}/sessions/<sid>/sidecar.{pid,sock} for
// every SessionID present in reg, and reattaches each live sidecar
// onto its session via AssignPTY + a fresh Pump goroutine.
//
// Returns the count of sessions successfully reattached. Per-session
// errors are logged at info level (not warn — a stale pidfile after a
// host crash is the normal case, not a regression).
//
// Must be called AFTER session.LoadPersisted has populated the
// registry but BEFORE the QUIC server starts accepting connections —
// the lazy-spawn path in protocol_handler.lazySpawnRestoredPTY relies
// on the session having either a sidecar.Conn assigned OR no PTY at
// all (it spawns a fresh one if missing). A half-reattached session
// would be neither.
func Discover(ctx context.Context, reg *session.Registry, stateDir string, logger *slog.Logger) (int, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if stateDir == "" {
		return 0, errors.New("ptyclient.Discover: stateDir is required")
	}
	sessionsDir := filepath.Join(stateDir, "sessions")

	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read %s: %w", sessionsDir, err)
	}

	var reattached int
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		sidStr := ent.Name()
		sid, perr := session.ParseSessionID(sidStr)
		if perr != nil {
			continue
		}
		sess, lerr := reg.Lookup(sid)
		if lerr != nil {
			// Not in the registry — LoadPersisted didn't restore it.
			// Probably means the meta.cbor was deleted or unparseable;
			// the sidecar artefacts (if any) are orphaned. Skip.
			continue
		}
		didReattach, derr := reattachOne(ctx, sess, filepath.Join(sessionsDir, sidStr), logger)
		if derr != nil {
			logger.Info("session.sidecar.skip", "session", sidStr, "reason", derr.Error())
			continue
		}
		if didReattach {
			reattached++
		}
	}
	return reattached, nil
}

// reattachOne tries to reconnect to a single session's sidecar. Returns
// (true, nil) on successful reattach. Returns (false, nil) if there's
// no sidecar artefacts at all (normal — session was persisted via the
// v0.5.0 scrollback path with no sidecar). Returns (false, err) for
// every other case (stale pidfile, dead process, dial refused, etc.).
func reattachOne(ctx context.Context, sess *session.Session, sessionDir string, logger *slog.Logger) (bool, error) {
	pidPath := filepath.Join(sessionDir, "sidecar.pid")
	sockPath := filepath.Join(sessionDir, "sidecar.sock")

	if _, statErr := os.Stat(pidPath); errors.Is(statErr, os.ErrNotExist) {
		// No sidecar was ever spawned for this session, or it cleaned
		// up after itself on its last shutdown. Either way: nothing
		// to discover, no error — the lazy-spawn path handles attach.
		return false, nil
	}

	pid, _, err := ptysidecar.ReadPidfile(pidPath)
	if err != nil {
		_ = os.Remove(pidPath)
		_ = os.Remove(sockPath)
		return false, fmt.Errorf("read pidfile: %w", err)
	}

	if !ptysidecar.ProcessAlive(pid) {
		_ = os.Remove(pidPath)
		_ = os.Remove(sockPath)
		return false, fmt.Errorf("stale pidfile (pid=%d not alive)", pid)
	}

	// Refuse to dial through a symlink. Mirrors the same guard the
	// IPC server applies before binding its socket (internal/ipc/
	// server.go:100-107). A same-uid attacker who can write into
	// the session dir before this point would otherwise be able to
	// redirect daemon I/O for the session to their own listener via
	// a planted symlink at sidecar.sock. The 0o700 parent dir limits
	// exposure to same-uid, but defence-in-depth at this layer too.
	if info, lerr := os.Lstat(sockPath); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(pidPath)
			_ = os.Remove(sockPath)
			return false, fmt.Errorf("refuse to dial: %s is a symlink", sockPath)
		}
	}

	sock, derr := net.DialTimeout("unix", sockPath, dialDiscoveryTimeout)
	if derr != nil {
		// Process is alive but not serving — likely a crashed sidecar
		// that didn't unlink its pidfile. SIGTERM it; sidecar's
		// signal handler will clean up, then this session falls back
		// to the lazy-spawn path on next attach.
		_ = signalPid(pid)
		_ = os.Remove(pidPath)
		_ = os.Remove(sockPath)
		return false, fmt.Errorf("process alive but socket dial failed: %w", derr)
	}

	conn := newConn(sess.ID().String(), sock, logger)

	// Send FrameResume(lastSidecarSeq) BEFORE AssignPTY + Pump start.
	// The sidecar's peekResumeOrDispatch consumes the frame with a
	// 50 ms deadline and SeekReads its ring; the first FrameStdout we
	// then receive carries the seq we asked for. Without this, the
	// sidecar would replay un-acked bytes from its current readOutSeq,
	// re-numbering bytes the daemon already committed.
	if err := conn.SendResume(sess.LastSidecarSeq()); err != nil {
		_ = conn.Close()
		return false, fmt.Errorf("SendResume: %w", err)
	}

	if err := sess.AssignPTY(conn); err != nil {
		_ = conn.Close()
		// AssignPTY returns ErrSessionHasPTY if the session somehow
		// already had a PTY. At startup that should be impossible —
		// nothing has had a chance to call lazySpawnRestoredPTY yet.
		// Log and skip.
		return false, fmt.Errorf("AssignPTY: %w", err)
	}
	go sess.Pump()

	logger.Info("session.sidecar.reattached",
		"session", sess.ID().String(),
		"name_hash", session.NameHash(sess.ID(), sess.Name()),
		"sidecar_pid", pid,
		"resume_from", sess.LastSidecarSeq(),
	)
	logger.Debug("session.sidecar.reattached.name",
		"session", sess.ID().String(),
		"name", sess.Name(),
	)
	return true, nil
}

// signalPid sends SIGTERM via the syscall package; used to nudge a
// non-responsive sidecar into cleaning up before we orphan its
// artefacts.
func signalPid(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}
