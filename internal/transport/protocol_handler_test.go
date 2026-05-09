package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// fakePTY mirrors the in-memory PTY used by the session package's
// tests. Local copy to keep test imports clean.
type fakePTY struct {
	mu      sync.Mutex
	out     bytes.Buffer
	outCond *sync.Cond
	in      bytes.Buffer
	closed  bool
}

func newFakePTY() *fakePTY {
	p := &fakePTY{}
	p.outCond = sync.NewCond(&p.mu)
	return p
}

func (p *fakePTY) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.out.Len() == 0 && !p.closed {
		p.outCond.Wait()
	}
	if p.closed && p.out.Len() == 0 {
		return 0, io.EOF
	}
	return p.out.Read(b)
}

func (p *fakePTY) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errors.New("write on closed pty")
	}
	return p.in.Write(b)
}

func (p *fakePTY) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	p.outCond.Broadcast()
	return nil
}

func (p *fakePTY) SetSize(rows, cols uint16) error { return nil }

func (p *fakePTY) push(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.out.Write(b)
	p.outCond.Broadcast()
}

func (p *fakePTY) stdinSeen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.in.String()
}

// runHandlerHarness sets up a Registry + Session + Server +
// ProtocolHandler and returns the listening address, fingerprint,
// and a cleanup func. The test client dials this address.
type harness struct {
	addr    string
	fp      []byte // SHA-256 fingerprint hex unused; tests use pinningClientTLS via the server tests
	reg     *session.Registry
	sess    *session.Session
	pty     *fakePTY
	cleanup func()
}

func newHandlerHarness(t *testing.T) *harness {
	t.Helper()
	c, fp := freshCert(t)
	reg := session.NewRegistry(0, time.Hour, time.Hour)
	id, _ := session.NewSessionID()
	pty := newFakePTY()
	sess, err := session.NewSession(id, pty, 24, 80, 4096)
	if err != nil {
		t.Fatal(err)
	}
	go sess.Pump()
	if err := reg.Add(sess); err != nil {
		t.Fatal(err)
	}

	handler := &ProtocolHandler{Registry: reg}
	srv, err := New(Config{Addr: "127.0.0.1:0", Cert: c, Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)

	cleanup := func() {
		cancel()
		_ = srv.Close()
		_ = sess.Close()
		reg.Shutdown()
	}

	return &harness{
		addr:    srv.Addr().String(),
		fp:      fp[:],
		reg:     reg,
		sess:    sess,
		pty:     pty,
		cleanup: cleanup,
	}
}

// dialAndAttach drives the client side of the Attach handshake on
// the single-stream tagged-frame protocol. Returns the QUIC
// connection, the (single) bidi stream, and the AttachAck. All
// subsequent traffic — stdin frames from the test, stdout frames
// from the daemon, control responses — flows over the same stream.
func dialAndAttach(t *testing.T, h *harness, sid session.SessionID, token session.AttachToken) (*quic.Conn, *quic.Stream, protocol.AttachAck) {
	t.Helper()
	var fp [32]byte
	copy(fp[:], h.fp)

	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, h.addr,
		pinningClientTLS(fp, protocol.ALPN),
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	body, err := protocol.MarshalAttach(protocol.Attach{
		V:         1,
		Token:     token[:],
		SessionID: sid[:],
		Rows:      24,
		Cols:      80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteTaggedFrame(stream, protocol.FrameTypeControl, body); err != nil {
		t.Fatalf("write Attach: %v", err)
	}

	// Read AttachAck — must be a control-typed tagged frame.
	frameType, ackBody, err := protocol.ReadTaggedFrame(stream)
	if err != nil {
		t.Fatalf("read AttachAck: %v", err)
	}
	if frameType != protocol.FrameTypeControl {
		t.Fatalf("AttachAck frame type = %d, want FrameTypeControl", frameType)
	}
	var ack protocol.AttachAck
	if err := cbor.Unmarshal(ackBody, &ack); err != nil {
		t.Fatalf("decode AttachAck: %v", err)
	}
	return conn, stream, ack
}

// readNextStdoutFrame blocks until the daemon sends the next
// FrameTypeStdout frame on `stream` and returns its decoded
// (seq, payload). Skips any non-stdout frames (e.g. Pong) so tests
// can consume stdout without being confused by control replies.
func readNextStdoutFrame(t *testing.T, stream *quic.Stream) (uint64, []byte) {
	t.Helper()
	for {
		frameType, body, err := protocol.ReadTaggedFrame(stream)
		if err != nil {
			t.Fatalf("read tagged frame: %v", err)
		}
		if frameType != protocol.FrameTypeStdout {
			continue
		}
		seq, payload, err := protocol.DecodeStdoutBody(body)
		if err != nil {
			t.Fatalf("decode stdout body: %v", err)
		}
		return seq, payload
	}
}

func TestProtocolHandlerHappyPath(t *testing.T) {
	t.Parallel()
	h := newHandlerHarness(t)
	defer h.cleanup()

	tok, err := h.reg.IssueAttachToken(h.sess.ID())
	if err != nil {
		t.Fatal(err)
	}

	conn, stream, ack := dialAndAttach(t, h, h.sess.ID(), tok)
	defer conn.CloseWithError(0, "")
	defer stream.Close()

	if !ack.OK {
		t.Fatalf("AttachAck.OK = false, err=%q msg=%q", ack.Err, ack.Msg)
	}

	// PTY pushes some output; ensure it arrives as one or more
	// FrameTypeStdout frames on the same stream.
	want := []byte("hello-from-pty")
	h.pty.push(want)

	got := make([]byte, 0, len(want))
	for len(got) < len(want) {
		_, payload := readNextStdoutFrame(t, stream)
		got = append(got, payload...)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestProtocolHandlerStdinReachesPTY(t *testing.T) {
	t.Parallel()
	h := newHandlerHarness(t)
	defer h.cleanup()

	tok, _ := h.reg.IssueAttachToken(h.sess.ID())
	conn, stream, ack := dialAndAttach(t, h, h.sess.ID(), tok)
	defer conn.CloseWithError(0, "")
	defer stream.Close()
	if !ack.OK {
		t.Fatalf("AttachAck.OK = false: %s %s", ack.Err, ack.Msg)
	}

	// Send stdin as a tagged frame on the same single stream.
	if err := protocol.WriteTaggedFrame(stream, protocol.FrameTypeStdin, []byte("hi\n")); err != nil {
		t.Fatal(err)
	}

	// Wait for the bytes to arrive at the PTY.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.pty.stdinSeen() == "hi\n" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("PTY stdin did not receive client bytes; saw %q", h.pty.stdinSeen())
}

func TestProtocolHandlerRejectsBadToken(t *testing.T) {
	t.Parallel()
	h := newHandlerHarness(t)
	defer h.cleanup()

	var bad session.AttachToken // zero-valued, not in registry
	conn, stream, ack := dialAndAttach(t, h, h.sess.ID(), bad)
	defer conn.CloseWithError(0, "")
	defer stream.Close()

	if ack.OK {
		t.Error("AttachAck.OK = true on bogus token")
	}
	if ack.Err != protocol.AttachErrBadToken {
		t.Errorf("Err = %q, want %q", ack.Err, protocol.AttachErrBadToken)
	}
}

func TestProtocolHandlerRejectsMismatchedSessionID(t *testing.T) {
	t.Parallel()
	h := newHandlerHarness(t)
	defer h.cleanup()

	tok, _ := h.reg.IssueAttachToken(h.sess.ID())
	// Use a different session_id than the one the token authorises.
	other, _ := session.NewSessionID()
	conn, stream, ack := dialAndAttach(t, h, other, tok)
	defer conn.CloseWithError(0, "")
	defer stream.Close()

	if ack.OK {
		t.Error("AttachAck.OK = true on session_id mismatch")
	}
	if ack.Err != protocol.AttachErrUnknownSession {
		t.Errorf("Err = %q, want %q", ack.Err, protocol.AttachErrUnknownSession)
	}
}

func TestProtocolHandlerReplaysBufferedOutputOnReattach(t *testing.T) {
	t.Parallel()
	h := newHandlerHarness(t)
	defer h.cleanup()

	// First attach + drop it, but leave bytes in the buffer.
	tok, _ := h.reg.IssueAttachToken(h.sess.ID())
	conn1, stream1, ack1 := dialAndAttach(t, h, h.sess.ID(), tok)
	if !ack1.OK {
		t.Fatalf("first attach failed: %s %s", ack1.Err, ack1.Msg)
	}
	conn1.CloseWithError(0, "")
	stream1.Close()

	// PTY emits while disconnected — these bytes accumulate in the
	// session's ring buffer.
	missed := []byte("output-while-disconnected")
	h.pty.push(missed)
	// Give Pump a moment to copy into the ring buffer.
	time.Sleep(20 * time.Millisecond)

	// Reattach with last_ack_seq=0 — server should replay everything
	// since the head was advanced past 0.
	tok2, _ := h.reg.IssueAttachToken(h.sess.ID())
	conn2, stream2, ack2 := dialAndAttach(t, h, h.sess.ID(), tok2)
	defer conn2.CloseWithError(0, "")
	defer stream2.Close()

	if !ack2.OK {
		t.Fatalf("reattach failed: %s %s", ack2.Err, ack2.Msg)
	}
	if ack2.BufSeq < uint64(len(missed)) {
		t.Errorf("AttachAck.BufSeq = %d, want ≥ %d", ack2.BufSeq, len(missed))
	}

	// Read stdout frames until we've seen the missed bytes.
	got := make([]byte, 0, len(missed))
	for len(got) < len(missed) {
		_, payload := readNextStdoutFrame(t, stream2)
		got = append(got, payload...)
	}
	if !bytes.Contains(got, missed) {
		t.Errorf("replay missing %q; got %q", missed, got)
	}
}
