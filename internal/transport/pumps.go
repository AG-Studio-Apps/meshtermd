package transport

import (
	"context"
	"errors"
	"io"

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
			if mode == session.AttachReadonly {
				continue // silently drop; readonly clients can't drive the shell
			}
			if len(body) > 0 {
				if _, werr := sess.WriteStdin(body); werr != nil {
					return werr
				}
			}
		case protocol.FrameTypeControl:
			if err := handleControlFrame(sess, body, write, mode); err != nil {
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

// handleControlFrame dispatches one CBOR control message read off
// the single stream. Mirrors the previous controlPump body, except
// outbound responses (Pong) go through the shared frameWriter so
// they're serialised against outputPump's writes.
//
// Per the protocol spec, Ack is informational in v0 — we don't trim
// the ring buffer below the ack point yet (the buffer's FIFO drop
// policy already bounds memory). Future versions may use Ack to
// keep the buffer larger when network is healthy and clients keep up.
func handleControlFrame(sess *session.Session, body []byte, write frameWriter, mode session.AttachMode) error {
	t, err := protocol.PeekType(body)
	if err != nil {
		return err
	}
	switch t {
	case protocol.TypeAck:
		// v0: informational only.
		return nil
	case protocol.TypeResize:
		// Readonly clients can't change PTY size — the exclusive
		// client owns geometry. Drop silently rather than tearing
		// the connection down.
		if mode == session.AttachReadonly {
			return nil
		}
		var m protocol.Resize
		if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
			return nil // skip malformed; don't tear the connection down
		}
		// Audit F-I (v0.0.2 review): defense-in-depth daemon-side
		// floor + ceiling on PTY dimensions. The kernel ioctl rejects
		// most pathological values, but a peer-supplied 1×1 or 65535
		// has no legitimate use and clamping here matches the iOS
		// client's own pre-send sanity check.
		if m.Rows < 3 || m.Cols < 10 || m.Rows > 1000 || m.Cols > 1000 {
			return nil
		}
		_ = sess.Resize(m.Rows, m.Cols)
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
