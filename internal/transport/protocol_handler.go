package transport

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// drainBriefly runs an unbuffered drain on the control stream for
// up to `d` so the AttachAck failure frame we just wrote actually
// hits the wire before the deferred CloseWithError tears the
// connection down. quic-go's Stream.Close marks the write side
// done but doesn't block until bytes drain — without the drain
// the client sees a bare CONNECTION_CLOSE instead of our typed
// AttachAck error message.
//
// Audit F-G (v0.0.2 review): replaces an earlier ctxReader pattern
// that spawned a child goroutine per Read and leaked it until QUIC
// teardown. SetReadDeadline does the same job natively without the
// goroutine cost.
func drainBriefly(s *quic.Stream, d time.Duration) {
	_ = s.SetReadDeadline(time.Now().Add(d))
	_, _ = io.Copy(io.Discard, s)
}

// ProtocolHandler is the real Handler that drives the Roam protocol
// per docs/roam-protocol.md. One ProtocolHandler is shared across
// all accepted connections — it holds no per-connection state, only
// the session.Registry it dispatches into.
//
// HandleConnection orchestrates the per-attach goroutines and waits
// for any of them to return before tearing down. The whole protocol
// runs on one client-initiated bidirectional stream: every frame is
// wrapped in a `[u8 type][u32 len][body]` tagged envelope, where
// type ∈ {control, stdin, stdout}. The Attach handshake is the
// first frame; AttachAck is the response.
//
// We use a single stream rather than QUIC multistream because iOS
// Network.framework's NWMultiplexGroup-based multistream API has
// proved unworkable: NWConnection(from: NWConnectionGroup) returns
// nil if called immediately after group.start, and the parent group
// never transitions to .ready without a child being opened first
// (chicken-and-egg). Type-tagged framing on a single bidi stream
// keeps the persistence + replay-on-reattach semantics intact
// without depending on Apple's multistream API.
type ProtocolHandler struct {
	Registry *session.Registry
	Logger   *slog.Logger

	// PTYSpawner is the lazy-spawn factory the handler calls when a
	// client attaches to a session that was restored from disk by
	// LoadPersisted (and therefore has Session.pty == nil). The daemon
	// wires this to a closure that spawns either an in-process
	// pty.Handle or a sidecar-backed ptyclient.Conn (per-session,
	// crash-survivable), then starts Session.Pump in a new goroutine.
	// The *Session is passed in so sidecar-backed spawns can name
	// their per-session state dir by the SessionID. Nil-safe: when
	// this field is nil, restored sessions can't be reattached (the
	// AttachAck reports a generic error) — tests that don't exercise
	// restore can leave it unset.
	PTYSpawner func(sess *session.Session, rows, cols uint16) (session.PTY, error)
}

// HandleConnection implements Handler.
func (h *ProtocolHandler) HandleConnection(ctx context.Context, conn *quic.Conn) {
	log := h.logger().With("remote", conn.RemoteAddr().String())
	log.InfoContext(ctx, "accepted connection")

	// Default close: 0 + empty (graceful). Pumps may overwrite if
	// they hit a protocol violation.
	closeErr := uint64(0)
	closeMsg := ""
	defer func() {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(closeErr), closeMsg)
	}()

	// Accept the single bidi stream — the whole protocol multiplexes
	// over this one stream via tagged-frame envelopes.
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		log.WarnContext(ctx, "accept stream", "err", err)
		return
	}

	att, err := readAttach(ctrl)
	if err != nil {
		log.WarnContext(ctx, "read Attach", "err", err)
		// closeMsg goes on the wire in CONNECTION_CLOSE; never
		// echo peer-supplied bytes back to the peer (audit F8 —
		// peer can shape err.Error() via the "got %q" formatter).
		// Use a small fixed table keyed on err class instead.
		closeErr = errCodeFor(err)
		closeMsg = closeMsgFor(closeErr)
		return
	}

	sess, err := h.resolveAttach(att, ctrl)
	if err != nil {
		// resolveAttach already wrote the AttachAck failure response.
		// Close the control stream's write side, then drain briefly
		// so the AttachAck makes it on the wire before the deferred
		// CloseWithError tears the connection down.
		_ = ctrl.Close()
		drainBriefly(ctrl, 500*time.Millisecond)
		log.InfoContext(ctx, "attach rejected", "err", err)
		return
	}

	// Resolve the requested attach mode. Empty / unknown → exclusive
	// (back-compat with v0 clients that don't set the field).
	attachMode := session.AttachExclusive
	switch att.Mode {
	case protocol.AttachModeReadonly:
		attachMode = session.AttachReadonly
	case protocol.AttachModePassive:
		attachMode = session.AttachPassive
	}

	// Lazy-spawn the PTY for sessions hydrated by LoadPersisted. The
	// session's scrollback is already populated from the on-disk
	// snapshot; we just need a fresh shell process to attach to.
	// Capture the restored flag NOW so the AttachAck a few lines
	// below can report it (AssignPTY clears the flag).
	wasRestored := sess.RestoredFromDisk()
	if wasRestored {
		if err := h.lazySpawnRestoredPTY(ctx, sess, att.Rows, att.Cols, log); err != nil {
			_ = sendAttachAck(ctrl, protocol.AttachAck{
				V:   1,
				Err: protocol.AttachErrUnknownSession,
				Msg: "restored session: " + err.Error(),
			})
			return
		}
	}

	// Acquire the session — exclusive displaces any prior exclusive
	// (whose pumps observe attachCtx.Done() and unwind), readonly
	// just adds to the live-clients slice. Either way, gen is what
	// we pass to Release on exit so a displaced re-entry doesn't
	// clobber the new owner (audit F4).
	attachCtx, attachGen, err := sess.Acquire(ctx, attachMode)
	if err != nil {
		ackErr := protocol.AttachErrUnknownSession
		if errors.Is(err, session.ErrPassiveCapacity) {
			ackErr = protocol.AttachErrCapacity
		}
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: ackErr,
			Msg: err.Error(),
		})
		return
	}
	defer sess.Release(attachGen)

	// Only the exclusive client owns the PTY size. Readonly clients'
	// Rows/Cols on the Attach are the dimensions of THEIR local
	// terminal — they observe whatever the exclusive client is
	// driving, even if mismatched. Honouring readonly resize would
	// fight the exclusive client's geometry and cause SIGWINCH
	// thrashing.
	if attachMode == session.AttachExclusive && att.Rows > 0 && att.Cols > 0 {
		_ = sess.Resize(att.Rows, att.Cols)
	}

	buf := sess.Buffer()
	if buf == nil {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrUnknownSession,
			Msg: "session closed",
		})
		return
	}

	start, head, trunc := computeReplayWindow(buf, att.AckSeq)

	// Sync writes on the single stream — outputPump and the read
	// pump's control responses (Pong, AttachAck etc.) both call
	// writeFrame; quic-go's Stream.Write is not safe for concurrent
	// callers, so we serialise via this mutex.
	var writeMu sync.Mutex
	writeFrame := func(t uint8, body []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteTaggedFrame(ctrl, t, body)
	}

	resolvedMode := protocol.AttachModeExclusive
	switch attachMode {
	case session.AttachReadonly:
		resolvedMode = protocol.AttachModeReadonly
	case session.AttachPassive:
		resolvedMode = protocol.AttachModePassive
	}
	ackBody, err := protocol.MarshalAttachAck(protocol.AttachAck{
		V:         1,
		OK:        true,
		SessionID: sess.ID().Bytes(),
		Start:     start,
		BufSeq:    head,
		Trunc:     trunc,
		Mode:      resolvedMode,
		Peers:     sess.PeerModes(attachGen),
		Restored:  wasRestored,
		RTTNanos:  conn.ConnectionStats().SmoothedRTT.Nanoseconds(),
	})
	if err != nil {
		log.WarnContext(ctx, "marshal AttachAck", "err", err)
		return
	}
	if err := writeFrame(protocol.FrameTypeControl, ackBody); err != nil {
		log.WarnContext(ctx, "send AttachAck", "err", err)
		return
	}

	// Structured attach event — operators tailing the daemon's
	// stderr can see who's coming and going, and a multi-attach
	// debugging session can pivot on session_id + mode + peer
	// counts without grepping through free-text log lines.
	log.InfoContext(ctx, "session.attach",
		"session", sess.ID().String(),
		"name", sess.Name(),
		"mode", resolvedMode,
		"gen", attachGen,
		"peers", len(sess.PeerModes(attachGen)),
		"replay_start", start,
		"replay_truncated", trunc,
	)
	defer log.InfoContext(ctx, "session.detach",
		"session", sess.ID().String(),
		"name", sess.Name(),
		"mode", resolvedMode,
		"gen", attachGen,
	)

	pumpsCtx, pumpsCancel := context.WithCancel(attachCtx)
	defer pumpsCancel()

	var wg sync.WaitGroup
	wg.Add(4)

	// RTT notify: every 5 seconds while attached, emit an RTTNotify
	// control frame with quic-go's smoothed-RTT estimate. Clients drive
	// `--predict=adaptive` thresholds + `~?` info display from this.
	// One ticker per attach — RTT can drift independently per path,
	// and the per-client cost is one syscall + one frame every 5s.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pumpsCtx.Done():
				return
			case <-ticker.C:
				rtt := conn.ConnectionStats().SmoothedRTT.Nanoseconds()
				if rtt <= 0 {
					continue // handshake hasn't seeded the smoothing window yet
				}
				body, err := protocol.MarshalRTTNotify(protocol.RTTNotify{RTTNanos: rtt})
				if err != nil {
					continue
				}
				// Best-effort: write errors mean the connection is dying;
				// other pumps will observe ctx.Done() shortly.
				_ = writeFrame(protocol.FrameTypeControl, body)
			}
		}
	}()

	// Output pump: read from the session's ring buffer and emit
	// FrameTypeStdout frames on the single stream.
	go func() {
		defer wg.Done()
		defer pumpsCancel()
		if err := outputPump(pumpsCtx, sess, ctrl, writeFrame, start); err != nil && !errors.Is(err, context.Canceled) {
			log.DebugContext(pumpsCtx, "output pump exit", "err", err)
		}
	}()

	// Read pump: parse tagged frames from the single stream and
	// dispatch by type. Control frames (Ack/Resize/Ping/Goodbye)
	// route through the existing control handler; stdin frames
	// stream into the PTY.
	go func() {
		defer wg.Done()
		defer pumpsCancel()
		if err := readPump(pumpsCtx, sess, ctrl, writeFrame, attachMode); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			log.DebugContext(pumpsCtx, "read pump exit", "err", err)
		}
	}()

	// Echo watcher (Stage B): polls the PTY's slave-side ECHO termios
	// flag and emits EchoConfirm frames whenever it flips. Clients use
	// these to authoritatively toggle predictive-echo arming (vim
	// entry disarms instantly; shell prompt return rearms). One
	// watcher per attach for simplicity — duplicate syscalls across
	// co-attached clients are cheap. No-op if the PTY implementation
	// doesn't support tcgetattr (e.g., the pipe-backed test PTY).
	go func() {
		defer wg.Done()
		sess.WatchTermios(pumpsCtx, session.DefaultEchoPollInterval, func(s session.TermiosSnapshot) {
			body, err := protocol.MarshalEchoConfirm(protocol.EchoConfirm{
				EchoState: string(s.Echo),
				CanonMode: s.Canon == session.EchoStateOn,
			})
			if err != nil {
				return
			}
			// Write errors are silent — if the stream is dead, the
			// read/output pumps will exit on their own and tear the
			// connection down. EchoConfirm is best-effort by spec.
			_ = writeFrame(protocol.FrameTypeControl, body)
		})
	}()

	wg.Wait()
	log.InfoContext(ctx, "connection closed", "session", sess.ID().String())
}

// lazySpawnRestoredPTY handles the first-attach-after-restart path
// for a session that was hydrated from disk by LoadPersisted. The
// session's scrollback is already populated from the snapshot, but
// the PTY field is nil (no shell process — the previous daemon
// instance's child died on its SIGTERM). We spawn a fresh shell at
// the session's saved dimensions, hand it to Session.AssignPTY, and
// start the Pump goroutine so subsequent output flows into the same
// ring buffer the restored scrollback lives in.
//
// Concurrency: two simultaneous attaches can race here. AssignPTY's
// nil-check + ErrSessionHasPTY tells the loser they lost; the loser
// closes its handle and proceeds with a normal attach. No retry
// needed — the winner's spawn is what both clients end up attached
// to.
func (h *ProtocolHandler) lazySpawnRestoredPTY(ctx context.Context, sess *session.Session, rows, cols uint16, log *slog.Logger) error {
	if h.PTYSpawner == nil {
		return errors.New("daemon not configured for restored sessions")
	}
	if rows == 0 || cols == 0 {
		// Fall back to the session's persisted dimensions.
		savedRows, savedCols := sess.WindowSize()
		if rows == 0 {
			rows = savedRows
		}
		if cols == 0 {
			cols = savedCols
		}
	}
	handle, err := h.PTYSpawner(sess, rows, cols)
	if err != nil {
		return fmt.Errorf("spawn PTY: %w", err)
	}
	if err := sess.AssignPTY(handle); err != nil {
		// Race lost OR session was closed in the meantime. Either
		// way, close our handle so we don't leak the child shell.
		// Closer is the PTY interface's Close method.
		if closer, ok := handle.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		if errors.Is(err, session.ErrSessionHasPTY) {
			// Winner's PTY is in place; attach can proceed.
			return nil
		}
		return err
	}
	// We won the race — start the pump so output flows.
	go sess.Pump()
	log.InfoContext(ctx, "session.restored.lazy_spawn",
		"session", sess.ID().String(),
		"name", sess.Name(),
		"rows", rows,
		"cols", cols,
	)
	return nil
}

func (h *ProtocolHandler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// resolveAttach validates the token + session id and consumes the
// token. On failure it sends an AttachAck{ok:false} on the control
// stream and returns the underlying error so the caller can log.
func (h *ProtocolHandler) resolveAttach(att protocol.Attach, ctrl *quic.Stream) (*session.Session, error) {
	if len(att.Token) != session.AttachTokenLen {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrBadToken,
			Msg: "token length mismatch",
		})
		return nil, errors.New("invalid token length")
	}
	if len(att.SessionID) != session.SessionIDLen {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrUnknownSession,
			Msg: "session id length mismatch",
		})
		return nil, errors.New("invalid session id length")
	}
	var tok session.AttachToken
	copy(tok[:], att.Token)
	sess, err := h.Registry.ConsumeAttachToken(tok)
	if err != nil {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrBadToken,
			Msg: err.Error(),
		})
		return nil, err
	}
	// Constant-time SID compare. The win here is small in absolute
	// terms (the registry's map lookup already exposes more timing
	// than the byte compare ever would, and 128 bits of entropy
	// makes guessing not a practical attack surface), but the
	// SECURITY.md self-audit checklist explicitly requires this
	// pattern and it costs us nothing.
	sid := sess.ID()
	if subtle.ConstantTimeCompare(att.SessionID, sid[:]) != 1 {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrUnknownSession,
			Msg: "session id does not match the token's session",
		})
		return nil, errors.New("session id / token mismatch")
	}
	return sess, nil
}

// readAttach reads the first tagged frame from the stream and
// validates it's a control frame carrying an Attach. Returns
// sentinel errors so the caller can pick the right QUIC application
// error code via errors.Is.
//
// Notably we do NOT include the peer-supplied "got %q" type tag in
// the wrapped error — that string round-trips into the
// CONNECTION_CLOSE reason via closeMsgFor, and we don't echo peer
// bytes there (audit F8).
func readAttach(s *quic.Stream) (protocol.Attach, error) {
	frameType, body, err := protocol.ReadTaggedFrame(s)
	if err != nil {
		return protocol.Attach{}, fmt.Errorf("%w: %v", errAttachBadFrame, err)
	}
	if frameType != protocol.FrameTypeControl {
		return protocol.Attach{}, errAttachWrongFirstFrame
	}
	t, err := protocol.PeekType(body)
	if err != nil {
		return protocol.Attach{}, fmt.Errorf("%w: %v", errAttachBadFrame, err)
	}
	if t != protocol.TypeAttach {
		return protocol.Attach{}, errAttachWrongFirstFrame
	}
	var att protocol.Attach
	if err := protocol.StrictDecMode.Unmarshal(body, &att); err != nil {
		return protocol.Attach{}, fmt.Errorf("%w: %v", errAttachBadFrame, err)
	}
	return att, nil
}

// sendAttachAck encodes a CBOR AttachAck and writes it as a control-
// type tagged frame on the single stream. Used by resolveAttach for
// failure responses where the writeMu serialiser isn't yet in scope.
func sendAttachAck(s *quic.Stream, ack protocol.AttachAck) error {
	body, err := protocol.MarshalAttachAck(ack)
	if err != nil {
		return err
	}
	return protocol.WriteTaggedFrame(s, protocol.FrameTypeControl, body)
}

// Sentinel errors readAttach returns. Classifying via errors.Is
// rather than substring-matching English strings keeps the
// classification stable when error messages are reformulated
// (audit F9).
var (
	errAttachWrongFirstFrame = errors.New("expected Attach as first control frame")
	errAttachBadFrame        = errors.New("could not decode Attach frame")
)

// errCodeFor maps an attach-handshake error to a QUIC application
// error code. Used only for the connection-close path; AttachAck
// failures use protocol.AttachErr* strings on the wire.
func errCodeFor(err error) uint64 {
	switch {
	case errors.Is(err, errAttachWrongFirstFrame):
		return protocol.ErrStreamWrongOrder
	case errors.Is(err, errAttachBadFrame):
		return protocol.ErrBadFrame
	default:
		return protocol.ErrProtocolViolation
	}
}

// closeMsgFor returns a fixed-string close reason for the given
// error code. Never includes peer-supplied bytes — the close reason
// rides in a CONNECTION_CLOSE frame and a malicious peer could
// otherwise shape its own input back into our outbound diagnostics.
func closeMsgFor(code uint64) string {
	switch code {
	case protocol.ErrStreamWrongOrder:
		return "expected Attach as first control frame"
	case protocol.ErrBadFrame:
		return "control frame decode failed"
	case protocol.ErrProtocolViolation:
		return "protocol violation"
	case protocol.ErrOversizedFrame:
		return "control frame exceeded size limit"
	default:
		return "internal error"
	}
}

// computeReplayWindow figures out where on the buffer the replay
// stream should start, given the client's last-acked seq. Three
// cases per docs/roam-protocol.md § 7.3 and § 11.5:
//
//   1. ack >= tail: replay from ack, no truncation
//   2. ack <  tail: replay from tail, truncated=true (some output lost)
//   3. ack >  head: nothing to replay (client claims to have seen
//      bytes we never sent — bug, treat as ack=head)
func computeReplayWindow(buf *session.RingBuffer, ack uint64) (start, head uint64, trunc bool) {
	tail := buf.TailSeq()
	head = buf.HeadSeq()
	start = ack
	if start < tail {
		start = tail
		trunc = true
	}
	if start > head {
		start = head
	}
	return start, head, trunc
}
