package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// runAttach is the Tier 3 headline: SSH-bootstrap → QUIC handshake →
// raw-mode terminal pumps → user's local terminal is now connected
// to the remote shell.
//
// Selector resolution:
//
//	mtctl attach <hex-id>      → reattach by SessionID (32 hex chars)
//	mtctl attach <name>        → daemon's create-if-missing flow
//	mtctl attach new --name X  → explicit fresh spawn (no implicit
//	                             reattach even if X exists)
//
// Disconnect: type `~.` on a fresh line (mosh / ssh convention).
// Closes the QUIC connection cleanly; daemon keeps the session
// alive for the next attach. Force-quit via SIGTERM also restores
// the terminal via the deferred restore.
func runAttach(args []string) int {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 15*time.Second, "max time to wait for the SSH bootstrap + QUIC handshake")
	createName := fs.String("name", "", "with `attach new`, the name to give the fresh session (else daemon synthesises)")
	idleTimeout := fs.Duration("idle-timeout", 0, "per-session idle timeout for a fresh spawn (0 = daemon default)")
	shell := fs.String("shell", "", "with `attach new`, override the remote $SHELL")
	mode := fs.String("mode", "exclusive",
		"attach mode. 'exclusive' (default) sends stdin and owns PTY size — displaces any prior exclusive client. "+
			"'readonly' is a watcher: receives output only, can't type, can't resize. Multiple readonly clients can "+
			"coexist with each other and with one exclusive client.")
	noPredict := fs.Bool("no-predict", false,
		"disable predictive local echo. By default mtctl mirrors typed characters to your terminal immediately "+
			"so typing feels instant on lossy or high-latency links; the prediction is confirmed when the daemon's "+
			"real echo arrives. Pass --no-predict to fall back to the byte-by-byte wait-for-the-daemon experience.")
	persist := fs.Bool("persist", false,
		"opt this session into cross-restart persistence on fresh spawn. Mutually exclusive with --no-persist; "+
			"when neither is set, the daemon's --persistence-default applies. Ignored when reattaching to an "+
			"existing session (persistence is fixed at spawn).")
	noPersist := fs.Bool("no-persist", false,
		"opt this session OUT of cross-restart persistence on fresh spawn.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl attach [flags] <id-or-name|new>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "mtctl attach: exactly one selector required (hex id, name, or 'new')")
		fs.Usage()
		return exitConfig
	}
	selector := fs.Arg(0)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}
	resolvedMode := protocol.AttachModeExclusive
	switch *mode {
	case "exclusive", "":
		resolvedMode = protocol.AttachModeExclusive
	case "readonly", "watch", "ro":
		resolvedMode = protocol.AttachModeReadonly
	default:
		fmt.Fprintf(os.Stderr, "mtctl attach: unknown --mode %q (want exclusive or readonly)\n", *mode)
		return exitConfig
	}

	if *persist && *noPersist {
		fmt.Fprintln(os.Stderr, "mtctl attach: --persist and --no-persist are mutually exclusive")
		return exitConfig
	}
	var persistPtr *bool
	if *persist {
		v := true
		persistPtr = &v
	} else if *noPersist {
		v := false
		persistPtr = &v
	}

	// Hand off to a function with proper defer-restore so any panic
	// or early-return path still puts the terminal back to cooked
	// mode. attachRun returns an exit code.
	return attachRun(target, selector, *createName, *shell, resolvedMode, *idleTimeout, *timeout, *noPredict, persistPtr)
}

func attachRun(target, selector, createName, shell, mode string, idleTimeout, deadline time.Duration, noPredict bool, persist *bool) int {
	// Phase 1: SSH bootstrap. Translate the selector into the right
	// `meshtermd connect` flags and capture the MTRM_QUIC line.
	bootstrap, err := bootstrapForAttach(target, selector, createName, shell, idleTimeout, deadline, persist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: bootstrap: %v\n", err)
		return exitRemote
	}

	// Phase 2: dial QUIC.
	dialHost := sshHostOnly(target)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), deadline)
	conn, err := dialDaemonQUIC(dialCtx, dialHost, bootstrap.port, bootstrap.certFingerprint)
	dialCancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: %v\n", err)
		return exitRemote
	}
	defer conn.CloseWithError(0, "client exit")

	// Phase 3: open the single bidi stream, do the Attach handshake.
	streamCtx, streamCancel := context.WithTimeout(context.Background(), deadline)
	stream, err := conn.OpenStreamSync(streamCtx)
	streamCancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: open stream: %v\n", err)
		return exitRemote
	}

	// Enter raw mode BEFORE Attach so the initial replay renders
	// into the user's already-raw terminal. Restoring is the LAST
	// thing that happens on exit (defer LIFO).
	ts, err := enterRaw()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: %v\n", err)
		return exitConfig
	}
	defer ts.restore()

	rows, cols := ts.size()

	// Send Attach. Tagged-frame envelope: type=Control, body=CBOR Attach.
	attachBody, err := protocol.MarshalAttach(protocol.Attach{
		V:         1,
		Token:     bootstrap.attachToken,
		SessionID: bootstrap.sessionID,
		AckSeq:    0, // mtctl always starts fresh: no in-memory ack state
		Rows:      rows,
		Cols:      cols,
		Mode:      mode,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: marshal Attach: %v\n", err)
		return exitErr
	}
	if err := protocol.WriteTaggedFrame(stream, protocol.FrameTypeControl, attachBody); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: send Attach: %v\n", err)
		return exitRemote
	}

	// Read the first frame — must be AttachAck on the control type.
	ackType, ackBody, err := protocol.ReadTaggedFrame(stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: read AttachAck: %v\n", err)
		return exitRemote
	}
	if ackType != protocol.FrameTypeControl {
		fmt.Fprintf(os.Stderr, "mtctl attach: expected control frame, got tag %d\n", ackType)
		return exitRemote
	}
	mt, err := protocol.PeekType(ackBody)
	if err != nil || mt != protocol.TypeAttachAck {
		fmt.Fprintf(os.Stderr, "mtctl attach: expected AttachAck, got %q\n", mt)
		return exitRemote
	}
	var ack protocol.AttachAck
	if err := protocol.StrictDecMode.Unmarshal(ackBody, &ack); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl attach: decode AttachAck: %v\n", err)
		return exitRemote
	}
	if !ack.OK {
		fmt.Fprintf(os.Stderr, "mtctl attach: daemon rejected: %s: %s\n", ack.Err, ack.Msg)
		return exitRemote
	}
	// One-line status to stderr so the user sees who else is on
	// the session and what mode they ended up with. Goes to stderr
	// so it doesn't interfere with the replayed shell output on
	// stdout.
	if len(ack.Peers) > 0 {
		fmt.Fprintf(os.Stderr, "[mtctl: attached %s; %d other client(s): %s]\r\n",
			ack.Mode, len(ack.Peers), strings.Join(ack.Peers, ", "))
	} else if mode == protocol.AttachModeReadonly {
		fmt.Fprintf(os.Stderr, "[mtctl: attached readonly; no other clients]\r\n")
	}

	// Phase 4: spin pumps. Each pump exits via `done`; the run loop
	// waits for the first exit, then tears the rest down.
	pCtx, pCancel := context.WithCancel(context.Background())
	defer pCancel()

	// Serialise writes to the QUIC stream — multiple goroutines
	// emit frames (stdin pump, SIGWINCH handler, ping responder).
	var writeMu sync.Mutex
	writeFrame := func(t uint8, body []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteTaggedFrame(stream, t, body)
	}

	// Stdout writes happen from both the stdin pump (predictive local
	// echo) and the stdout pump (real daemon output). Serialise them
	// so the two streams don't interleave mid-byte.
	var stdoutMu sync.Mutex
	writeStdout := func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		_, err := os.Stdout.Write(b)
		return err
	}

	predictor := NewPredictionEngine()
	if noPredict || mode == protocol.AttachModeReadonly {
		// Readonly attachers don't send stdin, so there's nothing to
		// predict. Disable so OnUserInput / OnDaemonOutput are no-ops.
		predictor.Disable()
	}

	done := make(chan error, 4)

	readonly := mode == protocol.AttachModeReadonly

	go runStdoutPump(pCtx, stream, writeFrame, writeStdout, predictor, done)
	// Stdin pump runs even in readonly so the `~.` detach chord
	// still works — the watcher consumes bytes locally and just
	// doesn't forward them when readonly is set. SIGWINCH is
	// pointless in readonly (daemon drops Resize frames anyway, and
	// the exclusive client owns the size we observe), so skip it.
	go runStdinPump(pCtx, stream, writeFrame, writeStdout, predictor, readonly, done)
	if !readonly {
		go runSigwinchPump(pCtx, ts, writeFrame, done)
	}

	// Block on the first pump to bail out (clean disconnect, EOF
	// from server, read error, or user typing ~.).
	exitErr := <-done
	pCancel()

	// Best-effort Goodbye before close. Don't sweat errors — the
	// connection might already be dead.
	if exitErr == errDetached {
		goodbye, _ := protocol.MarshalGoodbye(protocol.Goodbye{
			Reason: protocol.ReasonClientClose,
		})
		_ = writeFrame(protocol.FrameTypeControl, goodbye)
	}

	// `ts.restore` runs via defer. Print a final newline so the
	// user's prompt isn't squashed against the remote shell's last
	// line — only do this when we exited cleanly (detach or EOF).
	if exitErr == errDetached || exitErr == errPeerClosed {
		ts.restore() // restore explicitly before printing to stderr
		fmt.Fprintln(os.Stderr)
		if exitErr == errPeerClosed {
			fmt.Fprintln(os.Stderr, "session ended.")
		} else {
			fmt.Fprintln(os.Stderr, "detached.")
		}
		return exitOK
	}
	ts.restore()
	fmt.Fprintf(os.Stderr, "\nmtctl attach: %v\n", exitErr)
	return exitRemote
}

// Sentinel errors returned by the pumps to indicate WHY they bailed.
// `errDetached` is the friendly user-driven exit (`~.` chord).
// `errPeerClosed` is the daemon ending the session (shell exited).
// Anything else is an actual error worth logging.
var (
	errDetached   = errors.New("user detached")
	errPeerClosed = errors.New("peer closed")
)

// sshHostOnly extracts the hostname from a `user@host` SSH target.
// `host` may itself be an IP, an IPv6 literal in brackets, or an
// ssh_config alias — we just strip the optional user@ prefix.
//
// IPv6 literals are passed through as-is; net.JoinHostPort (in
// dialDaemonQUIC) handles the bracketing on the way to net.Dial.
func sshHostOnly(target string) string {
	if at := strings.LastIndex(target, "@"); at >= 0 && at+1 < len(target) {
		return target[at+1:]
	}
	return target
}

// stdoutPump reads tagged frames from the QUIC stream and dispatches:
//   - FrameTypeStdout → run the payload through the prediction engine
//     (which may suppress confirmed-prediction bytes or prepend
//     rollback sequences), then write the result to stdout.
//   - FrameTypeControl → CBOR-decode; Pong is a no-op for now,
//     Goodbye triggers a clean exit. Future Ping (server-initiated)
//     can be answered by us — currently the daemon's Ping is on the
//     keepalive path and we just ignore it.
func runStdoutPump(ctx context.Context, stream *quic.Stream, write frameWriter, writeOut stdoutWriter, predictor *PredictionEngine, done chan<- error) {
	for {
		if ctx.Err() != nil {
			return
		}
		t, body, err := protocol.ReadTaggedFrame(stream)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				done <- errPeerClosed
				return
			}
			done <- fmt.Errorf("read frame: %w", err)
			return
		}
		switch t {
		case protocol.FrameTypeStdout:
			_, payload, derr := protocol.DecodeStdoutBody(body)
			if derr != nil {
				done <- fmt.Errorf("decode stdout: %w", derr)
				return
			}
			toWrite := predictor.OnDaemonOutput(payload)
			if werr := writeOut(toWrite); werr != nil {
				done <- fmt.Errorf("write stdout: %w", werr)
				return
			}
		case protocol.FrameTypeControl:
			mt, perr := protocol.PeekType(body)
			if perr != nil {
				continue // ignore mangled control frames (forward compat)
			}
			switch mt {
			case protocol.TypeGoodbye:
				done <- errPeerClosed
				return
			case protocol.TypePing:
				// Echo a Pong with the same nonce. Keeps the
				// daemon's keepalive happy on quiet links.
				var ping protocol.Ping
				if uerr := protocol.StrictDecMode.Unmarshal(body, &ping); uerr != nil {
					continue
				}
				pong, _ := protocol.MarshalPong(protocol.Pong{Nonce: ping.Nonce})
				_ = write(protocol.FrameTypeControl, pong)
			case protocol.TypePong, protocol.TypeAck:
				// Pong: response to our own keepalive (currently
				// none — quic-go's KeepAlivePeriod handles it).
				// Ack: server doesn't send these to us.
				continue
			default:
				continue
			}
		default:
			continue
		}
	}
}

// runStdinPump reads from os.Stdin in raw mode, watches for the
// `~.` detach chord, and forwards everything else as
// FrameTypeStdin tagged frames. When `readonly` is set, forwarded
// bytes are dropped on the floor — the watcher still runs so the
// detach chord works, but the user's keystrokes don't reach the
// remote shell.
//
// Predictive local echo: forwarded bytes are also handed to the
// prediction engine. If the engine is armed and the bytes are
// predictable (printable ASCII), it returns a mirror that we write
// to stdout immediately — so typing feels instant on a high-RTT
// link. The daemon's real echo arrives later and is reconciled by
// the prediction engine on the stdout pump side.
func runStdinPump(ctx context.Context, stream *quic.Stream, write frameWriter, writeOut stdoutWriter, predictor *PredictionEngine, readonly bool, done chan<- error) {
	_ = stream // we only ever write; the stream is held by `write`
	watcher := newEscapeWatcher()
	buf := make([]byte, 4*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			forwarded, detach := watcher.process(buf[:n])
			if !readonly && len(forwarded) > 0 {
				// Mirror predicted bytes locally BEFORE sending to the
				// daemon so the keystroke appears instantly. The daemon
				// send still happens — predictive echo is purely
				// additive.
				if mirror := predictor.OnUserInput(forwarded); len(mirror) > 0 {
					if werr := writeOut(mirror); werr != nil {
						done <- fmt.Errorf("write predicted echo: %w", werr)
						return
					}
				}
				if werr := write(protocol.FrameTypeStdin, forwarded); werr != nil {
					done <- fmt.Errorf("send stdin: %w", werr)
					return
				}
			}
			if detach {
				done <- errDetached
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				done <- errPeerClosed
				return
			}
			done <- fmt.Errorf("read stdin: %w", err)
			return
		}
	}
}

// runSigwinchPump watches for window-size changes and emits Resize
// control frames. Coalesces rapid bursts (terminal-app drag-resize)
// by sleeping briefly between sends — without coalescing we'd flood
// the daemon with Resize frames during a single resize gesture.
func runSigwinchPump(ctx context.Context, ts *terminalSession, write frameWriter, done chan<- error) {
	const debounce = 100 * time.Millisecond
	var lastRows, lastCols uint16
	lastRows, lastCols = ts.size()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ts.winchChan:
			// Drain any further SIGWINCH events that piled up.
			drained := true
			for drained {
				select {
				case <-ts.winchChan:
				default:
					drained = false
				}
			}
			rows, cols := ts.size()
			if rows == lastRows && cols == lastCols {
				continue
			}
			lastRows, lastCols = rows, cols
			body, err := protocol.MarshalResize(protocol.Resize{Rows: rows, Cols: cols})
			if err != nil {
				continue
			}
			if werr := write(protocol.FrameTypeControl, body); werr != nil {
				done <- fmt.Errorf("send resize: %w", werr)
				return
			}
			time.Sleep(debounce)
		}
	}
}

// frameWriter is the serialised stream-write shape — same as the
// daemon-side helper of the same name in internal/transport.
type frameWriter func(t uint8, body []byte) error

// stdoutWriter is the serialised local-terminal-write shape. Both the
// stdin pump (predicted echo) and the stdout pump (real daemon output)
// produce bytes destined for os.Stdout; this funnel keeps them from
// interleaving mid-byte.
type stdoutWriter func(b []byte) error
