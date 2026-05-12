package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// runTail attaches to an existing session in AttachModePassive (the
// invisible-tap mode added in v0.6.2). Streams the session's live
// output to the local terminal — no stdin sent, no terminal raw mode,
// no scrollback replay. Exits on Ctrl-C, peer close (session ended),
// or read error.
//
// Selector resolution:
//
//	mtctl tail <hex-id>   → attach by SessionID (32 hex chars)
//	mtctl tail <name>     → resolve name via `mtctl list --json`
//	                        first; refuses to spawn-on-miss (unlike
//	                        `mtctl attach`, which create-if-missing's)
//
// Unlike attach, tail does NOT enter raw mode — the local terminal
// stays cooked, so `mtctl tail dev | grep ERROR` works as a normal
// shell pipe. The trade is that ANSI escape sequences from the
// remote shell render literally (cursor moves, colours) if the
// terminal is interactive. For full-screen apps in the remote
// session (vim, htop) the rendering will be chaotic — that's the
// nature of "tail the byte stream."
func runTail(args []string) int {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 15*time.Second,
		"max time to wait for the SSH bootstrap + QUIC handshake")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl tail [flags] <id-or-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "mtctl tail: exactly one selector required (hex id or name)")
		fs.Usage()
		return exitConfig
	}
	selector := fs.Arg(0)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return tailRun(ctx, target, selector, *timeout)
}

// tailRun owns the connection lifecycle: resolve selector, bootstrap
// over SSH, dial QUIC, send passive Attach, run the stdout pump.
// Returns an exit code; the deferred QUIC close fires on any path.
func tailRun(ctx context.Context, target, selector string, deadline time.Duration) int {
	// 1. Resolve selector to a hex SessionID. Unlike attach we refuse
	//    the create-if-missing path: passive-tailing a session that
	//    doesn't exist should fail loudly, not spawn a fresh shell.
	hexID, err := resolveSelectorToHexID(ctx, target, selector, deadline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: %v\n", err)
		return exitRemote
	}

	// 2. SSH bootstrap. bootstrapForAttach takes the hex-ID path
	//    cleanly (no name fallback, no create-if-missing).
	bootstrap, err := bootstrapForAttach(target, hexID, "", "", 0, deadline, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: bootstrap: %v\n", err)
		return exitRemote
	}

	// 3. Dial QUIC.
	dialHost := sshHostOnly(target)
	dialCtx, dialCancel := context.WithTimeout(ctx, deadline)
	conn, err := dialDaemonQUIC(dialCtx, dialHost, bootstrap.port, bootstrap.certFingerprint)
	dialCancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: %v\n", err)
		return exitRemote
	}
	defer conn.CloseWithError(0, "client exit")

	// 4. Open the single bidi stream and send Attach with Mode=passive
	//    and AckSeq=MaxUint64 — the daemon clamps to current head so
	//    no scrollback replay (live-only per design).
	streamCtx, streamCancel := context.WithTimeout(ctx, deadline)
	stream, err := conn.OpenStreamSync(streamCtx)
	streamCancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: open stream: %v\n", err)
		return exitRemote
	}

	attachBody, err := protocol.MarshalAttach(protocol.Attach{
		V:         1,
		Token:     bootstrap.attachToken,
		SessionID: bootstrap.sessionID,
		AckSeq:    math.MaxUint64, // live-only: clamps to head, no replay
		Mode:      protocol.AttachModePassive,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: marshal Attach: %v\n", err)
		return exitErr
	}
	if err := protocol.WriteTaggedFrame(stream, protocol.FrameTypeControl, attachBody); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: send Attach: %v\n", err)
		return exitRemote
	}

	// 5. Wait for AttachAck.
	ackType, ackBody, err := protocol.ReadTaggedFrame(stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: read AttachAck: %v\n", err)
		return exitRemote
	}
	if ackType != protocol.FrameTypeControl {
		fmt.Fprintf(os.Stderr, "mtctl tail: expected control frame, got tag %d\n", ackType)
		return exitRemote
	}
	mt, err := protocol.PeekType(ackBody)
	if err != nil || mt != protocol.TypeAttachAck {
		fmt.Fprintf(os.Stderr, "mtctl tail: expected AttachAck, got %q\n", mt)
		return exitRemote
	}
	var ack protocol.AttachAck
	if err := protocol.StrictDecMode.Unmarshal(ackBody, &ack); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl tail: decode AttachAck: %v\n", err)
		return exitRemote
	}
	if !ack.OK {
		fmt.Fprintf(os.Stderr, "mtctl tail: daemon rejected: %s: %s\n", ack.Err, ack.Msg)
		return exitRemote
	}
	fmt.Fprintln(os.Stderr, "[mtctl: tailing — Ctrl-C to detach]")

	// 6. Run only the stdout pump. No stdin pump, no escape watcher,
	//    no SIGWINCH — passive observers don't drive the shell.
	var writeMu sync.Mutex
	writeFrame := func(t uint8, body []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteTaggedFrame(stream, t, body)
	}
	done := make(chan error, 1)
	go tailStdoutPump(ctx, stream, writeFrame, done)

	select {
	case <-ctx.Done():
		// Ctrl-C or SIGTERM. Send a clean Goodbye before close.
		goodbye, _ := protocol.MarshalGoodbye(protocol.Goodbye{
			Reason: protocol.ReasonClientClose,
		})
		_ = writeFrame(protocol.FrameTypeControl, goodbye)
		fmt.Fprintln(os.Stderr, "\n[mtctl: detached]")
		return exitOK
	case err := <-done:
		if errors.Is(err, errPeerClosed) {
			fmt.Fprintln(os.Stderr, "\n[mtctl: session ended]")
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "mtctl tail: %v\n", err)
		return exitRemote
	}
}

// tailStdoutPump is a stripped-down stdout pump: reads frames, writes
// FrameTypeStdout payloads directly to stdout (no predictor), answers
// FrameTypePing with Pong so the daemon's keepalive doesn't tear us
// down on quiet links. Exits via `done` on EOF / peer close / error.
func tailStdoutPump(ctx context.Context, stream io.Reader, write frameWriter, done chan<- error) {
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
			if _, werr := os.Stdout.Write(payload); werr != nil {
				done <- fmt.Errorf("write stdout: %w", werr)
				return
			}
		case protocol.FrameTypeControl:
			mt, perr := protocol.PeekType(body)
			if perr != nil {
				continue
			}
			switch mt {
			case protocol.TypeGoodbye:
				done <- errPeerClosed
				return
			case protocol.TypePing:
				var ping protocol.Ping
				if uerr := protocol.StrictDecMode.Unmarshal(body, &ping); uerr != nil {
					continue
				}
				pong, _ := protocol.MarshalPong(protocol.Pong{Nonce: ping.Nonce})
				_ = write(protocol.FrameTypeControl, pong)
			default:
				continue
			}
		default:
			continue
		}
	}
}

// resolveSelectorToHexID returns the hex SessionID for the given
// selector. If selector is already a 32-char hex ID it's returned
// as-is. Otherwise we ssh-run `meshtermd list --json` to find a
// session whose Name matches, and return its hex ID. Returns an
// error if no match is found — refuses to spawn-on-miss, which is
// the behaviour difference between `mtctl tail` and `mtctl attach`.
func resolveSelectorToHexID(ctx context.Context, target, selector string, timeout time.Duration) (string, error) {
	if isHexSessionID(selector) {
		return selector, nil
	}
	stdout, stderr, code, err := runRemote(ctx, target, "meshtermd list --json", timeout)
	if err != nil {
		return "", fmt.Errorf("list: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("list: remote exit %d: %s", code, stderr)
	}
	var sessions []ipc.SessionInfo
	if err := json.Unmarshal([]byte(stdout), &sessions); err != nil {
		return "", fmt.Errorf("list: parse: %w", err)
	}
	for _, s := range sessions {
		if s.Name == selector {
			return s.ID, nil
		}
	}
	return "", fmt.Errorf("no session named %q (mtctl tail refuses to spawn — use `mtctl attach %s` to create + attach)",
		selector, selector)
}
