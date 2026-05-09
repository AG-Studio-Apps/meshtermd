package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
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
// are: client opens Control (bidi), client opens Stdin (uni), server
// opens Stdout (uni). The Attach handshake is the first thing on
// Control; AttachAck is sent on the same stream.
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
		closeErr = errCodeFor(err)
		closeMsg = err.Error()
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
	// pumps will observe attachCtx.Done() and unwind.
	attachCtx, err := sess.Acquire(ctx)
	if err != nil {
		_ = sendAttachAck(ctrl, protocol.AttachAck{
			V:   1,
			Err: protocol.AttachErrUnknownSession,
			Msg: err.Error(),
		})
		return
	}
	defer sess.Release(attachCtx)

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

	stdoutStream, err := conn.OpenUniStream()
	if err != nil {
		log.WarnContext(ctx, "open stdout stream", "err", err)
		return
	}
	defer stdoutStream.Close()

	// quic-go's OpenUniStream is lazy: the peer doesn't see the
	// stream until we send data on it. Write a zero-length output
	// frame at the replay-start seq as a deterministic "stream open"
	// beacon — DecodeOutputFrame handles len=0 cleanly, so this is
	// a no-op in payload terms but ensures the client's
	// AcceptUniStream returns even if there's no buffered output
	// yet.
	if err := protocol.EncodeOutputFrame(stdoutStream, start, nil); err != nil {
		log.WarnContext(ctx, "send stdout open beacon", "err", err)
		return
	}

	pumpsCtx, pumpsCancel := context.WithCancel(attachCtx)
	defer pumpsCancel()

	var wg sync.WaitGroup
	wg.Add(3)

	// Output pump runs immediately — never blocks waiting for the
	// client's stdin stream to appear.
	go func() {
		defer wg.Done()
		defer pumpsCancel()
		if err := outputPump(pumpsCtx, sess, stdoutStream, start); err != nil && !errors.Is(err, context.Canceled) {
			log.DebugContext(pumpsCtx, "output pump exit", "err", err)
		}
	}()

	// Input pump accepts the client's stdin uni stream at its own
	// leisure. The client may delay opening it (e.g., during initial
	// replay) without blocking output.
	go func() {
		defer wg.Done()
		defer pumpsCancel()
		stdinStream, err := conn.AcceptUniStream(pumpsCtx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				log.DebugContext(pumpsCtx, "accept stdin stream", "err", err)
			}
			return
		}
		if err := inputPump(pumpsCtx, sess, stdinStream); err != nil &&
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
	var wantSid session.SessionID
	copy(wantSid[:], att.SessionID)
	if wantSid != sess.ID() {
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
// validates it's an Attach. Returns ErrProtocolViolation-shaped
// errors on wrong-frame conditions so the caller can pick the right
// QUIC application error code.
func readAttach(ctrl *quic.Stream) (protocol.Attach, error) {
	body, err := protocol.ReadFrame(ctrl)
	if err != nil {
		return protocol.Attach{}, fmt.Errorf("read attach frame: %w", err)
	}
	t, err := protocol.PeekType(body)
	if err != nil {
		return protocol.Attach{}, fmt.Errorf("peek attach type: %w", err)
	}
	if t != protocol.TypeAttach {
		return protocol.Attach{}, fmt.Errorf("expected Attach, got %q", t)
	}
	var att protocol.Attach
	if err := cbor.Unmarshal(body, &att); err != nil {
		return protocol.Attach{}, fmt.Errorf("decode attach: %w", err)
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

// errCodeFor maps an attach-handshake error to a QUIC application
// error code. Used only for the connection-close path; AttachAck
// failures use protocol.AttachErr* strings on the wire.
func errCodeFor(err error) uint64 {
	msg := err.Error()
	switch {
	case containsAny(msg, "expected Attach"):
		return protocol.ErrStreamWrongOrder
	case containsAny(msg, "decode attach", "peek attach"):
		return protocol.ErrBadFrame
	default:
		return protocol.ErrProtocolViolation
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	// stdlib strings.Index would do — kept inline so the package
	// import set stays minimal and the helper is local to this
	// error-classification path.
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
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
