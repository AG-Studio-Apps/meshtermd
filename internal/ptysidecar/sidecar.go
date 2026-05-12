package ptysidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	cpty "github.com/creack/pty"
)

// DefaultGraceSecs is the time the sidecar will wait for the daemon
// to reconnect after a socket disconnect before SIGHUPing its child
// and exiting. 30s comfortably covers `systemctl restart meshtermd`
// (measured ~3s on Pi 4) with 10× headroom.
const DefaultGraceSecs = 30

// Config holds the parameters passed in from the daemon on spawn.
type Config struct {
	SocketPath  string       // absolute path to bind for daemon ↔ sidecar IPC
	PidfilePath string       // absolute path for the flock'd pidfile
	SessionID   string       // hex sessionID; informational, used in log fields
	Shell       string       // absolute path to the child shell; falls back to $SHELL → /bin/sh
	ShellArgs   []string     // additional args after the shell name (typically nil)
	Rows        uint16       // initial PTY rows (0 → 24)
	Cols        uint16       // initial PTY cols (0 → 80)
	EnvFile     string       // path to KEY=VAL\n env file; deleted by sidecar after read
	GraceSecs   int          // seconds to wait for daemon reconnect before reaping child
	RingBytes   int          // capacity of the drop-oldest output ring (0 → DefaultRingBytes)
	Logger      *slog.Logger // nil → discard
}

// Run is the sidecar's entry point. It blocks until the sidecar has
// fully shut down (child reaped, listener closed, pidfile + socket
// unlinked). Returns nil on clean shutdown; returns a non-nil error
// only for setup failures (pidfile already locked, PTY spawn failed,
// listener bind failed).
func Run(ctx context.Context, cfg Config) error {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	binaryPath, _ := os.Executable()

	// 1. Acquire pidfile (flock). Refuses if another sidecar is alive.
	pf, err := AcquirePidfile(cfg.PidfilePath, binaryPath)
	if err != nil {
		return fmt.Errorf("acquire pidfile: %w", err)
	}
	defer pf.Close()

	// 2. Load env file then immediately remove it from disk. We need
	//    the env in this process's memory; leaving the file around
	//    after fork is a needless creds-on-disk window.
	env, err := loadEnvFile(cfg.EnvFile)
	if err != nil {
		return fmt.Errorf("load env-file %q: %w", cfg.EnvFile, err)
	}
	if cfg.EnvFile != "" {
		_ = os.Remove(cfg.EnvFile)
	}

	// 3. Resolve shell, spawn child + PTY.
	shell := cfg.Shell
	if shell == "" {
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
	}
	rows, cols := cfg.Rows, cfg.Cols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	cmd := exec.Command(shell, cfg.ShellArgs...)
	cmd.Env = env
	master, err := cpty.StartWithSize(cmd, &cpty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return fmt.Errorf("spawn pty: %w", err)
	}

	// 4. Bind listener. Remove any stale socket from a previous
	//    crashed sidecar at the same path.
	_ = os.Remove(cfg.SocketPath)
	lis, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		_ = master.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGHUP)
			_, _ = cmd.Process.Wait()
		}
		return fmt.Errorf("listen unix %s: %w", cfg.SocketPath, err)
	}
	if cerr := os.Chmod(cfg.SocketPath, 0o600); cerr != nil {
		log.Warn("sidecar.socket_chmod_failed", "err", cerr.Error())
	}

	// 5. Ring buffer.
	ringBytes := cfg.RingBytes
	if ringBytes <= 0 {
		ringBytes = DefaultRingBytes
	}
	ring := NewRing(ringBytes)

	// 6. G_ptyread: forever, reads master → ring. Exits on EOF/EIO.
	ptyReadDone := make(chan struct{})
	go func() {
		defer close(ptyReadDone)
		buf := make([]byte, 4096)
		for {
			n, rerr := master.Read(buf)
			if n > 0 {
				_, _ = ring.Write(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}()

	// 7. G_childwait: blocks on cmd.Wait then pushes exit info.
	childExitCh := make(chan childExit, 1)
	go func() {
		werr := cmd.Wait()
		childExitCh <- buildChildExit(cmd, werr)
	}()

	// 8. Signal watch (SIGTERM/SIGINT).
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	// 9. Accept loop pushes new conns onto connCh. Only one is
	//    consumed at a time; second concurrent dials are rejected by
	//    the supervisor with a sentinel child_exit{signal=EBUSY}.
	connCh := make(chan net.Conn, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, aerr := lis.Accept()
			if aerr != nil {
				return
			}
			connCh <- c
		}
	}()

	graceDur := time.Duration(cfg.GraceSecs) * time.Second
	if graceDur <= 0 {
		graceDur = DefaultGraceSecs * time.Second
	}

	log.Info("sidecar.started",
		"session", cfg.SessionID,
		"pid", os.Getpid(),
		"socket", cfg.SocketPath,
		"shell", shell,
		"grace_secs", int(graceDur/time.Second),
		"ring_bytes", ringBytes,
	)

	// 10. Supervisor loop runs until the sidecar has decided to exit.
	state := &supervisor{
		cfg:           cfg,
		log:           log,
		master:        master,
		cmd:           cmd,
		ring:          ring,
		listener:      lis,
		ptyReadDone:   ptyReadDone,
		childExitCh:   childExitCh,
		sigCh:         sigCh,
		ctx:           ctx,
		graceDuration: graceDur,
	}
	reason := state.run(connCh)

	// 11. Stop accept loop and run teardown.
	_ = lis.Close()
	<-acceptDone
	_ = os.Remove(cfg.SocketPath)

	state.teardown(reason)
	return nil
}

// childExit packages cmd.Wait into wire-friendly numbers.
type childExit struct {
	code   int32
	signal int32
}

func buildChildExit(cmd *exec.Cmd, _ error) childExit {
	if cmd.ProcessState == nil {
		return childExit{code: -1, signal: 0}
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() {
			return childExit{code: 0, signal: int32(ws.Signal())}
		}
		return childExit{code: int32(ws.ExitStatus()), signal: 0}
	}
	return childExit{code: int32(cmd.ProcessState.ExitCode()), signal: 0}
}

// loadEnvFile reads KEY=VAL lines from path. Lines starting with '#'
// or empty are ignored. Path may be empty, in which case the daemon's
// own environment is inherited (this is only useful for the unit
// tests; real spawns always pass an explicit env file).
func loadEnvFile(path string) ([]string, error) {
	if path == "" {
		return os.Environ(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		env = append(env, string(line))
	}
	return env, nil
}

// supervisor owns the sidecar's runtime state and drives the central
// select-loop that arbitrates between the attached and detached
// states.
type supervisor struct {
	cfg           Config
	log           *slog.Logger
	master        *os.File
	cmd           *exec.Cmd
	ring          *Ring
	listener      net.Listener
	ptyReadDone   <-chan struct{}
	childExitCh   chan childExit
	sigCh         <-chan os.Signal
	ctx           context.Context
	graceDuration time.Duration

	// exitInfoSeen is set after the supervisor has consumed a value
	// from childExitCh — used by teardown to skip the SIGHUP path.
	exitInfoSeen bool
}

type exitReason int

const (
	exitChildGone exitReason = iota
	exitDieNow
	exitGraceTimeout
	exitSignal
	exitContext
)

func (r exitReason) String() string {
	switch r {
	case exitChildGone:
		return "child_gone"
	case exitDieNow:
		return "die_now"
	case exitGraceTimeout:
		return "grace_timeout"
	case exitSignal:
		return "signal"
	case exitContext:
		return "ctx_done"
	}
	return "unknown"
}

func (s *supervisor) run(connCh <-chan net.Conn) exitReason {
	var (
		active     *clientPumps
		exitInfo   *childExit
		graceTimer *time.Timer
		graceCh    <-chan time.Time
	)

	armGrace := func() {
		graceTimer = time.NewTimer(s.graceDuration)
		graceCh = graceTimer.C
	}
	disarmGrace := func() {
		if graceTimer != nil {
			if !graceTimer.Stop() {
				select {
				case <-graceTimer.C:
				default:
				}
			}
			graceTimer = nil
			graceCh = nil
		}
	}

	// Start detached.
	armGrace()

	for {
		var (
			activeDone   <-chan struct{}
			activeDieNow <-chan struct{}
		)
		if active != nil {
			activeDone = active.done
			activeDieNow = active.dieNow
		}

		select {
		case <-s.ctx.Done():
			s.log.Info("sidecar.ctx_done")
			if active != nil {
				_ = active.conn.Close()
				<-active.done
			}
			return exitContext

		case sig := <-s.sigCh:
			s.log.Info("sidecar.signal_received", "sig", sig.String())
			if active != nil {
				_ = active.conn.Close()
				<-active.done
			}
			return exitSignal

		case info := <-s.childExitCh:
			s.exitInfoSeen = true
			s.log.Info("sidecar.child_exited", "code", info.code, "signal", info.signal)
			exitInfo = &info
			// Wait for G_ptyread to drain whatever the kernel buffered
			// past EOF; the resulting bytes go into the ring.
			<-s.ptyReadDone
			if active != nil {
				active.drainRingAndSendExit(s.ring, info)
				_ = active.conn.Close()
				<-active.done
			}
			return exitChildGone

		case <-graceCh:
			s.log.Info("sidecar.grace_timeout_fired", "secs", int(s.graceDuration/time.Second))
			return exitGraceTimeout

		case c := <-connCh:
			if active != nil {
				s.log.Warn("sidecar.second_connection_refused")
				_ = WriteFrame(c, FrameChildExit, EncodeChildExit(0, int32(syscall.EBUSY)))
				_ = c.Close()
				continue
			}
			disarmGrace()
			s.log.Info("sidecar.client_attached")
			active = startClientPumps(c, s.master, s.ring, s.log)
			// Eager drain so the reconnecting daemon doesn't wait for
			// the next ring notification to receive buffered output.
			active.drainRing(s.ring)
			// If the child already exited (rare — child died while
			// detached), deliver the exit frame now and bail.
			if exitInfo != nil {
				_ = active.writeFrame(FrameChildExit, EncodeChildExit(exitInfo.code, exitInfo.signal))
				_ = active.conn.Close()
				<-active.done
				return exitChildGone
			}

		case <-activeDieNow:
			s.log.Info("sidecar.die_now_received")
			_ = active.conn.Close()
			<-active.done
			active = nil
			return exitDieNow

		case <-activeDone:
			s.log.Info("sidecar.client_detached", "ring_dropped_bytes", s.ring.Dropped())
			active = nil
			if exitInfo != nil {
				return exitChildGone
			}
			armGrace()
		}
	}
}

// teardown is called exactly once after the supervisor exits. It
// reaps the child (SIGHUP → wait → SIGKILL), closes the PTY master,
// and waits for G_ptyread to drain.
func (s *supervisor) teardown(reason exitReason) {
	s.log.Info("sidecar.teardown_begin", "reason", reason.String())

	if !s.exitInfoSeen && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGHUP)
		select {
		case <-s.childExitCh:
		case <-time.After(2 * time.Second):
			s.log.Warn("sidecar.child_unresponsive_to_sighup_sending_sigkill")
			_ = s.cmd.Process.Signal(syscall.SIGKILL)
			select {
			case <-s.childExitCh:
			case <-time.After(2 * time.Second):
				s.log.Error("sidecar.child_hung_after_sigkill_giving_up")
			}
		}
	}

	_ = s.master.Close()
	<-s.ptyReadDone

	s.log.Info("sidecar.teardown_complete", "ring_dropped_bytes", s.ring.Dropped())
}

// clientPumps tracks the goroutines servicing one attached client.
type clientPumps struct {
	conn    net.Conn
	writeMu sync.Mutex // serialises all WriteFrame calls
	done    chan struct{}
	dieNow  chan struct{}
}

func (cp *clientPumps) writeFrame(t FrameType, body []byte) error {
	cp.writeMu.Lock()
	defer cp.writeMu.Unlock()
	return WriteFrame(cp.conn, t, body)
}

// drainRing pulls everything currently in the ring and sends it as
// FrameStdout frames. Returns silently on conn write errors — the
// reader goroutine will pick up the close on its next read.
func (cp *clientPumps) drainRing(ring *Ring) {
	const chunk = 16 * 1024
	buf := make([]byte, chunk)
	for {
		n := ring.Drain(buf)
		if n == 0 {
			return
		}
		if err := cp.writeFrame(FrameStdout, buf[:n]); err != nil {
			return
		}
	}
}

// drainRingAndSendExit drains then writes the FrameChildExit frame.
func (cp *clientPumps) drainRingAndSendExit(ring *Ring, info childExit) {
	cp.drainRing(ring)
	_ = cp.writeFrame(FrameChildExit, EncodeChildExit(info.code, info.signal))
}

func startClientPumps(conn net.Conn, master *os.File, ring *Ring, log *slog.Logger) *clientPumps {
	cp := &clientPumps{
		conn:   conn,
		done:   make(chan struct{}),
		dieNow: make(chan struct{}),
	}

	var wg sync.WaitGroup
	wg.Add(2)

	readerDone := make(chan struct{})

	go func() {
		defer wg.Done()
		defer close(readerDone)
		var dieNowFired bool
		for {
			t, body, err := ReadFrame(conn)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					log.Debug("sidecar.client_reader_exit", "err", err.Error())
				}
				return
			}
			switch t {
			case FrameStdin:
				_, _ = master.Write(body)
			case FrameResize:
				rows, cols, derr := DecodeResize(body)
				if derr != nil {
					log.Warn("sidecar.bad_resize_body", "err", derr.Error())
					continue
				}
				_ = cpty.Setsize(master, &cpty.Winsize{Rows: rows, Cols: cols})
			case FrameQueryEcho:
				_ = cp.writeFrame(FrameEchoState, []byte{readEchoState(master)})
			case FrameDieNow:
				if !dieNowFired {
					dieNowFired = true
					close(cp.dieNow)
				}
				return
			default:
				log.Warn("sidecar.unknown_frame_type", "type", uint8(t))
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			select {
			case <-readerDone:
				return
			case <-ring.NotifyCh():
				cp.drainRing(ring)
			}
		}
	}()

	go func() {
		wg.Wait()
		close(cp.done)
	}()

	return cp
}

// readEchoState issues a tcgetattr on the PTY master and reports the
// slave-side ECHO flag for the wire (1=on, 0=off, 2=unknown).
func readEchoState(master *os.File) byte {
	echo, ok := echoEnabled(master)
	if !ok {
		return EchoUnknown
	}
	if echo {
		return EchoOn
	}
	return EchoOff
}
