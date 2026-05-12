// Package ptyclient is the daemon-side client for an out-of-process
// PTY sidecar. A *Conn implements session.PTY + session.EchoSnooper
// over a per-session Unix socket — Session.Pump can read/write/resize
// a sidecar-backed PTY with no changes to its loop. The sidecar
// itself lives at internal/ptysidecar; the wire format is documented
// there.
package ptyclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
)

// ErrSidecarGone is returned by Conn.Read when the sidecar's socket
// has closed without sending a clean FrameChildExit. The session
// should be torn down; on next attach the lazy-spawn path will fire
// a fresh sidecar (same UX as a v0.5.0 restored session).
var ErrSidecarGone = errors.New("ptyclient: sidecar socket closed unexpectedly")

// ErrSidecarBusy is returned by SpawnNew/Discover when the sidecar
// answers a dial with the EBUSY sentinel — another daemon (or stale
// connection) currently owns the conn. The caller should treat this
// as "no usable sidecar" and fall back to the lazy-spawn path.
var ErrSidecarBusy = errors.New("ptyclient: sidecar reports busy (another daemon attached?)")

// Conn is a session.PTY + session.EchoSnooper backed by a Unix
// socket to a sidecar process. One Conn per attached sidecar; new
// Conn per session (no pooling).
type Conn struct {
	sessionID string
	sock      net.Conn
	logger    *slog.Logger

	// writeMu serialises all WriteFrame calls on sock.
	writeMu sync.Mutex

	// Read side:
	//   readerDone is closed when runFrameReader exits.
	//   readBuf is the demux destination for FrameStdout bodies.
	//   readCond signals readers (the Pump goroutine) on every
	//     append to readBuf or on readErr transition.
	readerDone chan struct{}

	readMu   sync.Mutex
	readCond *sync.Cond
	readBuf  bytes.Buffer
	readErr  error // set once; never cleared

	// Per-byte seq tracking from the new FrameStdout envelope:
	//   - lastDeliveredSeq is the seq just past the last byte appended
	//     to readBuf. Used to compute the consumed-through value the
	//     caller passes to Ack().
	//   - pendingGapBytes is incremented when a FrameStdout arrives
	//     with StdoutFlagTruncBefore set; the consumer reads it via
	//     ConsumeTrunc() between Reads and bumps its own session ring
	//     headSeq accordingly.
	seqMu            sync.Mutex
	lastDeliveredSeq uint64
	pendingGapBytes  uint64
	seqValid         bool // false until the first FrameStdout arrives

	// Echo state cache. last echo_state body[0] received from sidecar;
	// EchoEnabled() reads under echoMu.
	echoMu      sync.Mutex
	echoVal     byte // ptysidecar.EchoOff / EchoOn / EchoUnknown
	echoValid   bool // false until first FrameEchoState arrives

	// Child-exit metadata (captured for diagnostics; not surfaced via
	// the PTY interface today). Set by runFrameReader on FrameChildExit
	// before it sets readErr=io.EOF.
	exitInfoOnce sync.Once
	exitInfo     *ChildExit

	closeOnce sync.Once
	closeErr  error
}

// ChildExit packages the FrameChildExit body for callers that need
// to know how the child died. Currently unused by the daemon's
// session machinery (it just sees io.EOF) but exposed for debugging
// + future hooks.
type ChildExit struct {
	Code   int32
	Signal int32
}

// newConn wraps a connected Unix socket as a *Conn. The caller has
// already dialed (and optionally sent any handshake — there is none
// today). The returned Conn starts its frame-reader goroutine
// immediately.
func newConn(sessionID string, sock net.Conn, logger *slog.Logger) *Conn {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := &Conn{
		sessionID:  sessionID,
		sock:       sock,
		logger:     logger,
		readerDone: make(chan struct{}),
		echoVal:    ptysidecar.EchoUnknown,
	}
	c.readCond = sync.NewCond(&c.readMu)
	go c.runFrameReader()
	return c
}

// Read implements io.Reader. Blocks until at least one byte is
// available, the sidecar reports child_exit (→ io.EOF), or the
// socket dies (→ ErrSidecarGone). Returns (0, err) only when there
// are no bytes left to deliver alongside the error.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.readBuf.Len() == 0 && c.readErr == nil {
		c.readCond.Wait()
	}
	if c.readBuf.Len() > 0 {
		// Deliver bytes first; the error surfaces on the next call
		// once the buffer is fully drained.
		return c.readBuf.Read(p)
	}
	return 0, c.readErr
}

// Write implements io.Writer by wrapping p in a FrameStdin and
// shipping it across the socket. Returns (len(p), nil) on success.
// FrameStdin payload is capped at MaxFramePayload; callers are
// expected to chunk larger inputs themselves (session.Pump never
// produces >8 KiB writes).
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.writeFrame(ptysidecar.FrameStdin, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SetSize implements session.PTY by encoding the new dimensions as
// a FrameResize. Returns the socket write error verbatim.
func (c *Conn) SetSize(rows, cols uint16) error {
	return c.writeFrame(ptysidecar.FrameResize, ptysidecar.EncodeResize(rows, cols))
}

// EchoEnabled implements session.EchoSnooper. Sends a FrameQueryEcho
// to the sidecar (best effort) and returns the cached value. The
// watcher's poll interval (100 ms) is the natural pace for queries;
// proactive pushes from the sidecar (on each FrameStdin tick) also
// keep the cache fresh between explicit queries.
func (c *Conn) EchoEnabled() (echo, ok bool) {
	// Fire-and-forget query. Failure to send is fine — the cache
	// remains whatever it was and the watcher gets ok=false until
	// the sidecar pushes a fresh state via the proactive path.
	_ = c.writeFrame(ptysidecar.FrameQueryEcho, nil)

	c.echoMu.Lock()
	defer c.echoMu.Unlock()
	if !c.echoValid {
		return false, false
	}
	switch c.echoVal {
	case ptysidecar.EchoOn:
		return true, true
	case ptysidecar.EchoOff:
		return false, true
	default:
		return false, false
	}
}

// Close shuts the socket; the sidecar sees EOF and enters its grace
// timer (default 30 s) waiting for a daemon reconnect. Idempotent.
// Use Kill() for `mtctl kill` semantics — that path sends die_now
// before closing.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.sock.Close()
		// Wake any blocked Read.
		c.readMu.Lock()
		if c.readErr == nil {
			c.readErr = io.EOF
		}
		c.readCond.Broadcast()
		c.readMu.Unlock()
	})
	return c.closeErr
}

// Kill is the immediate-teardown sibling of Close. Writes a
// FrameDieNow then closes the socket. The sidecar SIGHUPs its child
// within ~250 ms and exits, no grace timer.
func (c *Conn) Kill() error {
	// Best-effort: a write error here just means the socket is
	// already gone — Close handles the rest.
	_ = c.writeFrame(ptysidecar.FrameDieNow, nil)
	return c.Close()
}

// ChildExit returns the child's exit info if the sidecar has
// reported it. Returns nil before that. Read until io.EOF first to
// guarantee the sidecar has had a chance to deliver the frame.
func (c *Conn) ChildExit() *ChildExit {
	c.exitInfoOnce.Do(func() {})
	return c.exitInfo
}

// SessionID returns the hex sessionID supplied at construction. Used
// for log correlation only.
func (c *Conn) SessionID() string { return c.sessionID }

// writeFrame is the serialisation point for every outgoing frame on
// this Conn. Multiple goroutines (Pump → Write, watcher →
// EchoEnabled, registry → Kill) may call it concurrently.
func (c *Conn) writeFrame(t ptysidecar.FrameType, body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return ptysidecar.WriteFrame(c.sock, t, body)
}

// runFrameReader is the sole consumer of incoming frames. Demuxes
// FrameStdout → readBuf (parsing the seq-prefixed envelope; Trunc
// flag accumulates in pendingGapBytes), FrameEchoState → echoVal,
// FrameChildExit → translates to io.EOF on the read side. Returns
// on any socket read error (clean EOF or otherwise), setting
// readErr appropriately.
func (c *Conn) runFrameReader() {
	defer close(c.readerDone)
	for {
		t, body, err := ptysidecar.ReadFrame(c.sock)
		if err != nil {
			c.setReadErr(translateSocketReadError(err))
			return
		}
		switch t {
		case ptysidecar.FrameStdout:
			firstSeq, flags, payload, derr := ptysidecar.DecodeStdoutBody(body)
			if derr != nil {
				c.logger.Warn("ptyclient.bad_stdout_body", "err", derr.Error(), "session", c.sessionID)
				continue
			}
			c.handleStdout(firstSeq, flags, payload)
		case ptysidecar.FrameEchoState:
			if len(body) == 1 {
				c.storeEcho(body[0])
			}
		case ptysidecar.FrameChildExit:
			code, sig, derr := ptysidecar.DecodeChildExit(body)
			if derr == nil {
				c.exitInfo = &ChildExit{Code: code, Signal: sig}
			}
			c.maybeSurfaceBusy(code, sig)
			c.setReadErr(io.EOF)
			return
		default:
			c.logger.Warn("ptyclient.unknown_frame_type", "type", uint8(t), "session", c.sessionID)
		}
	}
}

// handleStdout records the gap-before signal (if any) and appends
// the payload to readBuf, advancing lastDeliveredSeq.
func (c *Conn) handleStdout(firstSeq uint64, flags byte, payload []byte) {
	c.seqMu.Lock()
	if flags&ptysidecar.StdoutFlagTruncBefore != 0 {
		// The dropped span is [previousLastDeliveredSeq, firstSeq).
		// Until we've received any byte, previousLastDeliveredSeq is
		// unknown — use firstSeq alone as the gap-marker boundary;
		// the daemon already knows how many bytes it asked for vs got
		// back via its FrameResume(from_seq) → firstSeq diff.
		if c.seqValid {
			c.pendingGapBytes += firstSeq - c.lastDeliveredSeq
		}
	}
	if len(payload) > 0 {
		c.lastDeliveredSeq = firstSeq + uint64(len(payload))
		c.seqValid = true
	} else if !c.seqValid {
		c.lastDeliveredSeq = firstSeq
		c.seqValid = true
	}
	c.seqMu.Unlock()

	if len(payload) > 0 {
		c.appendOutput(payload)
	}
}

// ConsumeTrunc returns the number of bytes silently dropped since
// the last call (and resets the counter). The Pump goroutine reads
// this between Read calls and advances the daemon's session ring via
// RingBuffer.AdvanceWithGap so iOS's existing AttachAck.trunc fires
// on next attach. Returns 0 when no gap has accumulated.
func (c *Conn) ConsumeTrunc() uint64 {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	gap := c.pendingGapBytes
	c.pendingGapBytes = 0
	return gap
}

// LastDeliveredSeq returns the sidecar-side seq just past the last
// byte delivered to readBuf. Callers use this as the watermark for
// Ack(seq); we ack what we've durably committed to our session ring,
// which is bounded above by lastDeliveredSeq.
func (c *Conn) LastDeliveredSeq() uint64 {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	return c.lastDeliveredSeq
}

// SendResume emits a FrameResume(from_seq) to the sidecar. Called by
// Discover on reattach so the sidecar's drainer rewinds (or fast-
// forwards) to where the daemon's persisted ring left off. Best
// effort: a write error means the conn is gone and the caller will
// see ErrSidecarGone on the next Read.
func (c *Conn) SendResume(fromSeq uint64) error {
	return c.writeFrame(ptysidecar.FrameResume, ptysidecar.EncodeSeq(fromSeq))
}

// Ack tells the sidecar it can free bytes whose seq is < consumedSeq.
// Called by Pump after a buf.Write — coalesced via the Pump's own
// 64 KiB / 200 ms thresholds (see internal/session/session.go). Best
// effort: a write error is logged silently; the daemon's next
// reconnect will resend an Ack anyway via the persisted lcs.
func (c *Conn) Ack(consumedSeq uint64) error {
	return c.writeFrame(ptysidecar.FrameAck, ptysidecar.EncodeSeq(consumedSeq))
}

// maybeSurfaceBusy upgrades a child_exit with the EBUSY signal
// sentinel to ErrSidecarBusy so SpawnNew/Discover can distinguish
// "sidecar is already serving another daemon" from "child exited."
func (c *Conn) maybeSurfaceBusy(code, sig int32) {
	if code == 0 && sig == int32(syscall.EBUSY) {
		c.setReadErr(fmt.Errorf("%w (sidecar refused with EBUSY)", ErrSidecarBusy))
	}
}

func (c *Conn) appendOutput(body []byte) {
	if len(body) == 0 {
		return
	}
	c.readMu.Lock()
	c.readBuf.Write(body)
	c.readCond.Broadcast()
	c.readMu.Unlock()
}

func (c *Conn) storeEcho(val byte) {
	c.echoMu.Lock()
	c.echoVal = val
	c.echoValid = true
	c.echoMu.Unlock()
}

func (c *Conn) setReadErr(err error) {
	c.readMu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.readCond.Broadcast()
	c.readMu.Unlock()
}

// WaitClosed blocks until the frame-reader goroutine has fully
// exited. Used by tests; the production code path relies on
// Pump observing EOF and falling through to Session.Close.
func (c *Conn) WaitClosed(timeout time.Duration) error {
	select {
	case <-c.readerDone:
		return nil
	case <-time.After(timeout):
		return errors.New("ptyclient: reader goroutine did not exit within timeout")
	}
}

// translateSocketReadError maps the various read-error shapes onto a
// stable error type. Clean EOF at a frame boundary is io.EOF;
// anything else is wrapped in ErrSidecarGone for the upstream
// session-teardown path.
func translateSocketReadError(err error) error {
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if errors.Is(err, net.ErrClosed) {
		return io.EOF
	}
	return fmt.Errorf("%w: %v", ErrSidecarGone, err)
}
