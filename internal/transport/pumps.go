package transport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// frameWriter sends one tagged frame on the protocol's single bidi
// stream. The protocol_handler creates this with a mutex so the
// output pump and the read pump's control-response sends don't race
// on quic-go's Stream.Write.
type frameWriter func(t uint8, body []byte) error

// outputPump streams the session's ring buffer onto the wire as
// FrameTypeStdout tagged frames (body = `[u64 BE seq][raw bytes]`).
// It blocks on RingBuffer.WaitForData when the buffer has nothing
// past the last-sent seq, and returns when ctx cancels (typical
// teardown path).
//
// fromSeq is the position to start emitting from — the AttachAck's
// Start field; this is either the client's last_ack_seq, or the
// buffer's tail when ack < tail (truncated replay).
//
// Audit F-D (v0.0.2 review): cancelOnDone is symmetric with the
// readPump's F11 fix. RingBuffer.WaitForData honours ctx, but
// once data is in hand the goroutine can pin in `quic-go` Stream
// write when the peer's flow-control window is full; CancelWrite
// on ctx-cancel unblocks that path so the goroutine exits within
// milliseconds of teardown rather than at MaxIdleTimeout.
func outputPump(ctx context.Context, sess *session.Session, s *quic.Stream, write frameWriter, fromSeq uint64) error {
	cancelOnDone(ctx, func() { s.CancelWrite(0) })
	buf := sess.Buffer()
	if buf == nil {
		return nil
	}
	seq := fromSeq
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, newSeq, _ := buf.ReadSince(seq, protocol.MaxOutputFramePayload)
		if len(data) > 0 {
			body := protocol.EncodeStdoutBody(seq, data)
			if err := write(protocol.FrameTypeStdout, body); err != nil {
				return err
			}
			seq = newSeq
			continue
		}
		// Nothing available — block until more arrives or ctx cancels.
		if _, err := buf.WaitForData(ctx, seq); err != nil {
			return err
		}
	}
}

// readPump reads tagged frames from the single bidi stream and
// dispatches by type:
//
//   - FrameTypeStdin: raw payload streams into the session's PTY,
//     UNLESS the attach is readonly — in which case stdin is
//     silently discarded. We don't tear the connection down on a
//     readonly stdin frame because a misbehaving keystroke
//     shouldn't kick the client off the session.
//   - FrameTypeControl: CBOR-decoded; Ack/Resize/Ping/Goodbye are
//     handled via handleControlFrame (with control-side writes
//     going through the same `write` writer). Resize is also
//     dropped for readonly attaches — the exclusive client owns
//     the PTY size.
//
// quic-go's Read does NOT abort on context cancel; without an
// explicit CancelRead a stuck Read would pin this goroutine until
// QUIC's idle timeout. We watch ctx in a sidecar (audit F11).
func readPump(ctx context.Context, sess *session.Session, s *quic.Stream, write frameWriter, mode session.AttachMode) error {
	cancelOnDone(ctx, func() { s.CancelRead(0) })
	// Per-attach mutable state for handleControlFrame. Lives on this
	// goroutine's stack; readPump processes frames serially so no
	// locking is required.
	var st attachState
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frameType, body, err := protocol.ReadTaggedFrame(s)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch frameType {
		case protocol.FrameTypeStdin:
			if mode != session.AttachExclusive {
				continue // silently drop; only exclusive clients drive the shell
			}
			if len(body) > 0 {
				if _, werr := sess.WriteStdin(body); werr != nil {
					return werr
				}
			}
		case protocol.FrameTypeControl:
			if err := handleControlFrame(sess, body, write, mode, &st); err != nil {
				return err
			}
		default:
			// FrameTypeStdout from the client is a protocol violation
			// (only the server emits stdout). Ignore for forward
			// compat instead of tearing down — the same posture as
			// unknown CBOR control message types.
			continue
		}
	}
}

// attachState holds per-attach mutable state threaded through
// handleControlFrame. Allocated on readPump's stack; readPump
// processes frames serially, so no synchronisation is required.
//
// Today only the Replay rate limiter uses this; future per-attach
// counters (Resize coalescing, Recover throttle) can land here too.
type attachState struct {
	// lastReplayAt is the wall-clock time the most recent Replay
	// request from this attach was served (zero-value means "none
	// yet"). The Replay handler refuses a follow-up within
	// replayMinInterval to defend against bandwidth amplification —
	// each Replay can re-emit up to RingBuffer capacity (4 MiB) of
	// downlink data from a ~30-byte uplink frame.
	lastReplayAt time.Time
}

// replayMinInterval is the minimum wall-clock gap the daemon enforces
// between successive Replay requests on the same attach. Legitimate
// use cases (orientation change → reflow on iOS) fire one Replay per
// device rotation, far below this rate. Anything faster is treated
// as a flood attempt and silently dropped (matches the posture for
// other policy violations — readonly Stdin, readonly Resize, etc.).
const replayMinInterval = 1 * time.Second

// handleControlFrame dispatches one CBOR control message read off
// the single stream. Mirrors the previous controlPump body, except
// outbound responses (Pong) go through the shared frameWriter so
// they're serialised against outputPump's writes.
//
// Per the protocol spec, Ack is informational in v0 — we don't trim
// the ring buffer below the ack point yet (the buffer's FIFO drop
// policy already bounds memory). Future versions may use Ack to
// keep the buffer larger when network is healthy and clients keep up.
func handleControlFrame(sess *session.Session, body []byte, write frameWriter, mode session.AttachMode, st *attachState) error {
	t, err := protocol.PeekType(body)
	if err != nil {
		return err
	}
	switch t {
	case protocol.TypeAck:
		// v0: informational only.
		return nil
	case protocol.TypeResize:
		// Only exclusive clients change PTY size — they own
		// geometry. Readonly and passive clients' Resize frames are
		// dropped silently rather than tearing the connection down.
		if mode != session.AttachExclusive {
			slog.Debug("resize: dropped (non-exclusive client)",
				"sid", sess.ID().String(), "mode", mode)
			return nil
		}
		var m protocol.Resize
		if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
			slog.Warn("resize: malformed CBOR — dropped",
				"sid", sess.ID().String(), "err", err)
			return nil // skip malformed; don't tear the connection down
		}
		// Audit F-I (v0.0.2 review): defense-in-depth daemon-side
		// floor + ceiling on PTY dimensions. The kernel ioctl rejects
		// most pathological values, but a peer-supplied 1×1 or 65535
		// has no legitimate use and clamping here matches the iOS
		// client's own pre-send sanity check. Bounds live in limits.go
		// and are shared with the Attach-frame path in protocol_handler.
		if !dimsInBounds(m.Rows, m.Cols) {
			slog.Warn("resize: out-of-range dimensions — dropped",
				"sid", sess.ID().String(), "rows", m.Rows, "cols", m.Cols)
			return nil
		}
		slog.Info("resize: received from client",
			"sid", sess.ID().String(), "rows", m.Rows, "cols", m.Cols)
		if err := sess.Resize(m.Rows, m.Cols); err != nil {
			slog.Warn("resize: session.Resize returned error",
				"sid", sess.ID().String(), "err", err)
		}
		return nil
	case protocol.TypePing:
		var m protocol.Ping
		if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
			return nil
		}
		pong, err := protocol.MarshalPong(protocol.Pong{Nonce: m.Nonce})
		if err != nil {
			return err
		}
		return write(protocol.FrameTypeControl, pong)
	case protocol.TypeReplay:
		// v0.8.0+ scrollback-replay request. Client (typically iOS
		// on rotation) wants the daemon to re-emit the byte stream
		// from FromSeq onward so SwiftTerm can repaint scrollback
		// at the new column count. Emit ReplayMark first (the
		// client's reset boundary), then re-stream the requested
		// window via the same FrameTypeStdout frames the output
		// pump uses. Live PTY output continues to flow through the
		// pump concurrently — the client's reset on ReplayMark
		// handles any seq overlap by discarding pre-mark state.
		//
		// Pre-v1.0 hardening (audit Finding M5): an authenticated
		// peer can otherwise flood TypeReplay{FromSeq:0} and force
		// the daemon to re-emit up to RingBuffer capacity (4 MiB)
		// per ~30-byte uplink — ~140,000× bandwidth amplification.
		// Throttle to one Replay per second per attach; silently
		// drop the excess (codebase convention for policy drops).
		now := time.Now()
		if !st.lastReplayAt.IsZero() && now.Sub(st.lastReplayAt) < replayMinInterval {
			slog.Debug("replay: dropped (rate limit)",
				"sid", sess.ID().String(),
				"since_last_ms", now.Sub(st.lastReplayAt).Milliseconds())
			return nil
		}
		st.lastReplayAt = now
		var m protocol.Replay
		if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
			return nil // malformed; ignore rather than tear down
		}
		buf := sess.Buffer()
		if buf == nil {
			return nil // session closed
		}
		headSeq := buf.HeadSeq()
		tailSeq := buf.TailSeq()
		actualFrom := m.FromSeq
		trunc := false
		if actualFrom < tailSeq {
			actualFrom = tailSeq
			trunc = true
		}
		if actualFrom > headSeq {
			actualFrom = headSeq
		}
		mark, err := protocol.MarshalReplayMark(protocol.ReplayMark{
			FromSeq: actualFrom,
			Trunc:   trunc,
		})
		if err != nil {
			return err
		}
		if err := write(protocol.FrameTypeControl, mark); err != nil {
			return err
		}
		// Re-stream the window. Each frame is at most
		// MaxOutputFramePayload bytes; we loop until the requested
		// window is exhausted. The output pump may interleave its
		// own live frames between ours — the frameWriter mutex
		// keeps each frame atomic on the wire, and the client's
		// reset on ReplayMark handles any overlap.
		seq := actualFrom
		for seq < headSeq {
			data, newSeq, _ := buf.ReadSince(seq, protocol.MaxOutputFramePayload)
			if len(data) == 0 {
				break
			}
			out := protocol.EncodeStdoutBody(seq, data)
			if err := write(protocol.FrameTypeStdout, out); err != nil {
				return err
			}
			seq = newSeq
		}
		return nil
	case protocol.TypeRecover:
		// Only exclusive clients can drive recovery — same posture as
		// Resize (geometry-owning). Readonly / passive Recovers are
		// silently dropped rather than tearing the connection down.
		if mode != session.AttachExclusive {
			slog.Debug("recover: dropped (non-exclusive client)",
				"sid", sess.ID().String(), "mode", mode)
			return nil
		}
		var m protocol.Recover
		if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
			slog.Warn("recover: malformed CBOR — dropped",
				"sid", sess.ID().String(), "err", err)
			return nil
		}
		slog.Info("recover: received request from client",
			"sid", sess.ID().String(),
			"grace_ms", m.GraceMillis,
			"custom_prompt", m.SavePrompt != "")
		// Run the sequencer in its own goroutine — it takes seconds
		// to tens of seconds and we must NOT block readPump (which
		// services keystrokes + future control frames).
		// Detached context: a client disconnect mid-recovery should
		// NOT abort the save/restart — the user typically wants the
		// work preserved regardless of network state, and the
		// post-recovery session is intact for the next attach. The
		// per-stage RecoverProgress frames are best-effort; failures
		// to write them (e.g. peer gone) are logged but don't abort
		// the sequencer.
		go runRecover(context.Background(), sess, m, write)
		return nil
	case protocol.TypeGoodbye:
		return io.EOF // signal graceful close to readPump
	default:
		// Unknown control message type — ignore for forward compat.
		return nil
	}
}

// cancelOnDone fires `cancel` when ctx is cancelled. Used by pumps
// to escape blocking quic-go Reads on context cancel.
func cancelOnDone(ctx context.Context, cancel func()) {
	go func() {
		<-ctx.Done()
		cancel()
	}()
}
