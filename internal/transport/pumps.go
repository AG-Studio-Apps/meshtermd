package transport

import (
	"context"
	"errors"
	"io"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// outputPump streams the session's ring buffer to the client's
// stdout stream, framing each chunk with [seq][len][payload]. It
// blocks on RingBuffer.WaitForData when the buffer has nothing
// past the last-sent seq, and returns when ctx cancels (typical
// teardown path).
//
// fromSeq is the position to start emitting from — the AttachAck's
// Start field; this is either the client's last_ack_seq, or the
// buffer's tail when ack < tail (truncated replay).
func outputPump(ctx context.Context, sess *session.Session, w *quic.SendStream, fromSeq uint64) error {
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
			if err := protocol.EncodeOutputFrame(w, seq, data); err != nil {
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

// inputPump forwards the client's stdin stream into the session's
// PTY. The QUIC stream's reliability + ordering means we don't need
// any framing — bytes received are bytes typed.
//
// quic-go's ReceiveStream.Read does NOT abort on context cancel;
// without an explicit CancelRead a stuck Read would pin this
// goroutine until QUIC's idle timeout. We watch ctx in a sidecar
// and call CancelRead when it fires (audit F11).
func inputPump(ctx context.Context, sess *session.Session, r *quic.ReceiveStream) error {
	cancelOnDone(ctx, func() { r.CancelRead(0) })
	chunk := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := r.Read(chunk)
		if n > 0 {
			if _, werr := sess.WriteStdin(chunk[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
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

// controlPump reads control-stream frames from the client (Ack,
// Resize, Ping, Goodbye) and dispatches them. Returns nil on a
// graceful Goodbye, ctx.Err on cancel, or any frame/decode error
// otherwise.
//
// Per the protocol spec, Ack is informational in v0 — we don't
// trim the ring buffer below the ack point yet (the buffer's FIFO
// drop policy already bounds memory). Future versions may use Ack
// to keep the buffer larger when network is healthy and clients
// keep up.
func controlPump(ctx context.Context, sess *session.Session, s *quic.Stream) error {
	cancelOnDone(ctx, func() { s.CancelRead(0) })
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := protocol.ReadFrame(s)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		t, err := protocol.PeekType(body)
		if err != nil {
			return err
		}
		switch t {
		case protocol.TypeAck:
			// v0: informational only. We could pass to Session for
			// buffer management; currently a no-op.
			continue
		case protocol.TypeResize:
			var m protocol.Resize
			if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
				continue // skip malformed; don't tear the connection down
			}
			if m.Rows > 0 && m.Cols > 0 {
				_ = sess.Resize(m.Rows, m.Cols)
			}
		case protocol.TypePing:
			var m protocol.Ping
			if err := protocol.StrictDecMode.Unmarshal(body, &m); err != nil {
				continue
			}
			pong, err := protocol.MarshalPong(protocol.Pong{Nonce: m.Nonce})
			if err != nil {
				return err
			}
			if err := protocol.WriteFrame(s, pong); err != nil {
				return err
			}
		case protocol.TypeGoodbye:
			return nil
		default:
			// Unknown frame type — ignore for forward compat.
			continue
		}
	}
}
