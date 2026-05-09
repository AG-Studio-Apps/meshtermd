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

// ctxReader wraps an io.Reader so a context cancel returns from
// Read with the ctx error. Used by the rejection drain — without
// this, io.Copy would block until the client EOFs even when our
// timeout has fired.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := c.r.Read(p)
		ch <- result{n, err}
	}()
	select {
	case res := <-ch:
		return res.n, res.err
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

// ProtocolHandler is the real Handler that drives the Roam protocol
// per docs/roam-protocol.md. One ProtocolHandler is shared across
// all accepted connections — it holds no per-connection state, only
// the session.Registry it dispatches into.
//
// HandleConnection orchestrates the per-attach goroutines and waits
// for any of them to return before tearing down. Stream lifecycles
// are: client opens Control (bidi), client opens Data (bidi). The
// data stream is full-duplex — the client side writes raw stdin
// keystrokes; the server side writes [seq][len][bytes] output
// frames. The Attach handshake is the first thing on Control;
// AttachAck is sent on the same stream.
//
// We use two bidi streams instead of one bidi + two uni because iOS
// Network.framework's NWConnection(from: NWConnectionGroup) only
// supports opening client-initiated bidirectional streams.
type ProtocolHandler struct {
	Registry *session.Registry
	Logger   *slog.Logger
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

	// Accept the control stream — client opens it first, bidirectional.
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		log.WarnContext(ctx, "accept control stream", "err", err)
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
		// Close the control stream's write side, then wait for the
		// client to read it and close from their side. quic-go's
		// Stream.Close marks the write side done but doesn't block
		// until the bytes hit the wire; if we tear down the
		// connection too quickly the AttachAck frame is dropped and
		// the client sees a bare CONNECTION_CLOSE instead of our
		// typed error message. Reading until the peer closes (or a
		// short cap fires) gives the AttachAck time to drain.
		_ = ctrl.Close()
		drainCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, _ = io.Copy(io.Discard, &ctxReader{ctx: drainCtx, r: ctrl})
		cancel()
		log.InfoContext(ctx, "attach rejected", "err", err)
		return
	}

	// Acquire the session — displaces any prior attach, whose
	// pumps will observe attachCtx.Done() and unwind. The gen
	// handle is what we pass to Release so a displaced re-entry
	// doesn't clobber the new owner (audit F4).
	attachCtx, attachGen, err := sess.Acquire(ctx)
	if err != nil {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrUnknownSession,
			Msg: err.Error(),
		})
		return
	}
	defer sess.Release(attachGen)

	if att.Rows > 0 && att.Cols > 0 {
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

	if err := sendAttachAck(ctrl, protocol.AttachAck{
		V:         1,
		OK:        true,
		SessionID: sess.ID().Bytes(),
		Start:     start,
		BufSeq:    head,
		Trunc:     trunc,
	}); err != nil {
		log.WarnContext(ctx, "send AttachAck", "err", err)
		return
	}

	// Open the data stream — server-initiated bidi. We initiate
	// rather than waiting for the client because iOS NW.framework's
	// `NWConnection(from: group)` returns a stream ID but won't put
	// a STREAM frame on the wire until the client writes; if the
	// user hasn't typed yet there's nothing to write, and a
	// daemon-side AcceptStream would hang. By opening from the
	// daemon and writing an immediate zero-length output beacon, the
	// stream materialises promptly in the client's newConnectionHandler.
	//
	// Client writes raw stdin to this stream; we write [seq][len][bytes]
	// output frames to the same stream. inputPump and outputPump
	// share it (independent read + write directions on a bidi stream
	// are safe under quic-go).
	dataStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.WarnContext(ctx, "open data stream", "err", err)
		return
	}
	defer dataStream.Close()

	// Open beacon: zero-length output frame at the replay-start seq.
	// EncodeOutputFrame writes [seq][len=0][no payload], which
	// DecodeOutputFrame handles cleanly. The first server-side write
	// is what causes quic-go to flush the STREAM frame and the iOS
	// client's newConnectionHandler to fire.
	if err := protocol.EncodeOutputFrame(dataStream, start, nil); err != nil {
		log.WarnContext(ctx, "send data stream open beacon", "err", err)
		return
	}

	pumpsCtx, pumpsCancel := context.WithCancel(attachCtx)
	defer pumpsCancel()

	var wg sync.WaitGroup
	wg.Add(3)

	// Output pump runs immediately on the data stream's server-write
	// side. It never blocks waiting for the client to start writing
	// stdin.
	go func() {
		defer wg.Done()
		defer pumpsCancel()
		if err := outputPump(pumpsCtx, sess, dataStream, start); err != nil && !errors.Is(err, context.Canceled) {
			log.DebugContext(pumpsCtx, "output pump exit", "err", err)
		}
	}()

	// Input pump reads from the data stream's client-write side and
	// pipes into the session's PTY.
	go func() {
		defer wg.Done()
		defer pumpsCancel()
		if err := inputPump(pumpsCtx, sess, dataStream); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			log.DebugContext(pumpsCtx, "input pump exit", "err", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer pumpsCancel()
		if err := controlPump(pumpsCtx, sess, ctrl); err != nil &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			log.DebugContext(pumpsCtx, "control pump exit", "err", err)
		}
	}()

	wg.Wait()
	log.InfoContext(ctx, "connection closed", "session", sess.ID().String())
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

// readAttach reads the first frame from the control stream and
// validates it's an Attach. Returns sentinel errors so the caller
// can pick the right QUIC application error code via errors.Is.
//
// Notably we do NOT include the peer-supplied "got %q" type tag in
// the wrapped error — that string round-trips into the
// CONNECTION_CLOSE reason via closeMsgFor, and we don't echo peer
// bytes there (audit F8).
func readAttach(ctrl *quic.Stream) (protocol.Attach, error) {
	body, err := protocol.ReadFrame(ctrl)
	if err != nil {
		return protocol.Attach{}, fmt.Errorf("%w: %v", errAttachBadFrame, err)
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

// sendAttachAck stamps the type discriminator and writes the framed
// response on the control stream.
func sendAttachAck(s *quic.Stream, ack protocol.AttachAck) error {
	body, err := protocol.MarshalAttachAck(ack)
	if err != nil {
		return err
	}
	return protocol.WriteFrame(s, body)
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
