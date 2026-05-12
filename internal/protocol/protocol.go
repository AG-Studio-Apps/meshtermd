// Package protocol implements the wire format for meshTerm's Roam
// protocol over QUIC. See docs/roam-protocol.md.
//
// Three things live here:
//
//   - Constants — the ALPN string, frame size limits, error codes
//   - Typed message structs (Attach, AttachAck, Ack, Resize, Ping,
//     Pong, Goodbye) covering the control stream
//   - WriteFrame / ReadFrame — length-prefixed CBOR framing for the
//     control stream, plus the helpers that pack/unpack typed
//     messages
//
// The output stream's framing (`[uint64 seq][uint32 len][bytes]`) is
// in this package too, since it's a wire-level concern; the QUIC
// transport package reaches in for it.
//
// All structures use the field-name tags from docs/roam-protocol.md
// so the on-wire CBOR keys match the spec verbatim.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// StrictDecMode is the CBOR decode mode every wire-facing path in
// this codebase routes through. It enforces conservative limits on
// array elements, map pairs, and nesting depth so a malicious peer
// can't ship a 64 KiB control frame whose CBOR body claims a
// gigantic map count and force allocation pressure.
//
// Limits picked against the actual messages we exchange:
//   - MaxMapPairs 64       — Attach has 7 pairs; AttachAck max ~9
//   - MaxArrayElements 256 — no current message uses arrays, but
//                            being permissive here costs nothing
//   - MaxNestedLevels 8    — every control message is a flat map;
//                            8 is generous future-proofing
var StrictDecMode cbor.DecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		MaxArrayElements: 256,
		MaxMapPairs:      64,
		MaxNestedLevels:  8,
	}.DecMode()
	if err != nil {
		// Static config; should never panic. If it does, fail
		// fast at startup rather than serving traffic with a
		// silently-degraded decoder.
		panic(fmt.Sprintf("protocol: build StrictDecMode: %v", err))
	}
	return dm
}()

// ALPN is the application-layer protocol negotiation token sent on
// the QUIC handshake. v0 uses "meshterm/0" (development); promotion to
// v1 increments the suffix per docs/roam-protocol.md § 5.2.
const ALPN = "meshterm/0"

// MaxControlFrameBytes is the cap on a single control-stream frame's
// CBOR body. Sized generously for Attach (the largest legitimate
// message); anything bigger is a protocol violation per § 13.
const MaxControlFrameBytes = 64 * 1024

// MaxOutputFramePayload is the cap on a single output-stream frame's
// payload bytes. Larger PTY chunks must be split across frames per
// § 8.
const MaxOutputFramePayload = 16 * 1024

// MaxDatagramBytes is the cap on a QUIC datagram's payload, including
// the CBOR overhead. Sized to fit comfortably under typical path MTUs
// without QUIC datagram fragmentation.
const MaxDatagramBytes = 1200

// Wire-level error codes per docs/roam-protocol.md § 13. Each is the
// QUIC application error code that should be sent when terminating a
// connection due to that condition.
const (
	ErrOversizedFrame     uint64 = 1001
	ErrBadFrame           uint64 = 1002
	ErrProtocolViolation  uint64 = 1003
	ErrBadToken           uint64 = 1004
	ErrStreamWrongOrder   uint64 = 1005
	ErrOversizedDatagram  uint64 = 1006
	ErrInternal           uint64 = 2000
)

// Type tags for the discriminated-union encoding of control messages.
// These match the "t" key value emitted on the wire.
const (
	TypeAttach      = "Attach"
	TypeAttachAck   = "AttachAck"
	TypeAck         = "Ack"
	TypeResize      = "Resize"
	TypePing        = "Ping"
	TypePong        = "Pong"
	TypeGoodbye     = "Goodbye"
	TypeEchoConfirm = "EchoConfirm"
)

// EchoState mirrors the tri-state value carried in EchoConfirm.
// The daemon emits these from the termios watcher; clients toggle
// predictive-echo arming based on the value.
const (
	EchoStateOn      = "on"
	EchoStateOff     = "off"
	EchoStateUnknown = "unknown"
)

// Reason codes for Goodbye. Defined as constants so callers don't
// scatter raw strings.
const (
	ReasonClientClose  = "client_close"
	ReasonSessionEnded = "session_ended"
	ReasonShutdown     = "shutdown"
	ReasonError        = "error"
	ReasonReplaced     = "replaced"
)

// Attach mode constants. The wire encoding is the lowercase-string
// field on Attach and AttachAck; an empty string is treated as
// "exclusive" for backward compat with v0 clients that don't set
// the field. iOS today emits no Mode and inherits exclusive
// semantics — the post-change default exactly matches the
// pre-change behaviour.
const (
	// AttachModeExclusive: the default. Receives output, sends
	// stdin, owns PTY size via Resize. A new exclusive attach
	// displaces any prior exclusive client. Readonly clients are
	// unaffected by exclusive turnover.
	AttachModeExclusive = "exclusive"

	// AttachModeReadonly: receives output only. Stdin frames from
	// this client are silently dropped by the daemon — they're not
	// a protocol violation (a misbehaving keystroke shouldn't tear
	// the connection down). Resize frames are also dropped: the
	// PTY size is owned by the exclusive client; readonly clients
	// just observe whatever bytes arrive. Multiple readonly
	// clients can coexist with each other and with one exclusive
	// client. Use case: monitor a long-running build from your
	// phone while you type on the laptop, or watch a colleague
	// working from across the office.
	AttachModeReadonly = "readonly"
)

// Error codes for AttachAck.Err per § 7.3.
const (
	AttachErrUnknownSession      = "unknown_session"
	AttachErrBadToken            = "bad_token"
	AttachErrVersionUnsupported  = "version_unsupported"
	AttachErrCapacity            = "capacity"
	AttachErrReplaced            = "replaced"
)

// Attach is the first message a client sends on the control stream.
type Attach struct {
	T         string `cbor:"t"`
	V         uint32 `cbor:"v"`
	Token     []byte `cbor:"tok"`
	SessionID []byte `cbor:"sid"`
	AckSeq    uint64 `cbor:"ack"`
	Rows      uint16 `cbor:"rows"`
	Cols      uint16 `cbor:"cols"`
	// Mode is the requested attach role: "exclusive" (default) or
	// "readonly". Empty/missing → "exclusive" for backward compat
	// with v0 clients (iOS pre-multi-attach, mtctl pre-Tier 3.5).
	// Unknown values are treated as "exclusive" — same compat
	// posture; the server doesn't fail closed on a future mode it
	// doesn't recognise.
	Mode string `cbor:"mode,omitempty"`
}

// AttachAck is the server's response to Attach.
//
// `Mode` echoes the resolved role — clients can confirm the
// daemon honoured their request (or fell back to exclusive on an
// unknown value). `Peers` is the snapshot of co-attached clients'
// modes ("exclusive", "readonly") at the moment of this attach;
// useful for the picker UI ("also attached: 1 readonly").
type AttachAck struct {
	T         string   `cbor:"t"`
	V         uint32   `cbor:"v"`
	OK        bool     `cbor:"ok"`
	SessionID []byte   `cbor:"sid,omitempty"`
	Start     uint64   `cbor:"start,omitempty"`
	BufSeq    uint64   `cbor:"buf_seq,omitempty"`
	Trunc     bool     `cbor:"trunc,omitempty"`
	Mode      string   `cbor:"mode,omitempty"`
	Peers     []string `cbor:"peers,omitempty"`
	Err       string   `cbor:"err,omitempty"`
	Msg       string   `cbor:"msg,omitempty"`
	// Restored is true when the session this attach is connecting to
	// was reconstructed from on-disk state at the daemon's most
	// recent startup, rather than freshly spawned. Set on the FIRST
	// successful attach after a daemon restart; the daemon clears
	// the session's restoredFromDisk flag immediately after sending
	// the AttachAck so subsequent reattaches (within the same daemon
	// run) see Restored=false.
	//
	// Clients use this to surface a "Restored from previous session"
	// banner so users understand they're seeing replayed scrollback,
	// not output from a still-running shell — the actual shell is a
	// fresh process that the daemon lazy-spawned on this attach.
	// Forward-compat: older clients ignore the field with no UI
	// difference; CBOR omitempty keeps the wire form small in the
	// non-restored common case.
	Restored bool `cbor:"r,omitempty"`
}

// Ack reports the highest output sequence number the client has
// rendered. Sent at most once per 100 ms while output is flowing.
type Ack struct {
	T   string `cbor:"t"`
	Seq uint64 `cbor:"seq"`
}

// Resize forwards a window-size change to the PTY.
type Resize struct {
	T    string `cbor:"t"`
	Rows uint16 `cbor:"rows"`
	Cols uint16 `cbor:"cols"`
}

// Ping requests a Pong with the same nonce.
type Ping struct {
	T     string `cbor:"t"`
	Nonce uint32 `cbor:"n"`
}

// Pong is the response to a Ping.
type Pong struct {
	T     string `cbor:"t"`
	Nonce uint32 `cbor:"n"`
}

// EchoConfirm is sent by the daemon (server → client) whenever the
// PTY's slave-side ECHO termios flag flips. Clients use it to toggle
// predictive local echo: `on` → safe to predict, `off` → vim/less/
// password prompt territory, disarm hard. `unknown` is sent when
// the daemon can't determine state (e.g., tcgetattr failed); clients
// treat that as a soft suggestion to stay conservative.
//
// v0: control-stream message. Spec § 10.1 reserves the slot as a
// datagram for future low-latency optimisation; we stick with the
// control stream here so the existing tagged-frame dispatch handles
// it without datagram plumbing on both ends.
//
// `StdinSeq` is reserved for future client-side echo prediction
// synchronisation (the daemon can stamp "this state applied AFTER
// stdin sequence N"); not used in v0.
type EchoConfirm struct {
	T         string `cbor:"t"`
	StdinSeq  uint64 `cbor:"sin,omitempty"`
	EchoState string `cbor:"es"`
}

// Goodbye is the last message either side sends before closing.
type Goodbye struct {
	T      string `cbor:"t"`
	Reason string `cbor:"reason"`
}

// MarshalAttach / UnmarshalAttach (etc.) are convenience wrappers that
// also stamp the type discriminator on the way out. Callers should
// prefer these over hand-rolling cbor.Marshal so the "t" field is
// guaranteed correct.

func MarshalAttach(m Attach) ([]byte, error)         { m.T = TypeAttach; return cborMarshal(m) }
func MarshalAttachAck(m AttachAck) ([]byte, error)   { m.T = TypeAttachAck; return cborMarshal(m) }
func MarshalAck(m Ack) ([]byte, error)               { m.T = TypeAck; return cborMarshal(m) }
func MarshalResize(m Resize) ([]byte, error)         { m.T = TypeResize; return cborMarshal(m) }
func MarshalPing(m Ping) ([]byte, error)             { m.T = TypePing; return cborMarshal(m) }
func MarshalPong(m Pong) ([]byte, error)             { m.T = TypePong; return cborMarshal(m) }
func MarshalGoodbye(m Goodbye) ([]byte, error)       { m.T = TypeGoodbye; return cborMarshal(m) }
func MarshalEchoConfirm(m EchoConfirm) ([]byte, error) {
	m.T = TypeEchoConfirm
	return cborMarshal(m)
}

// PeekType extracts only the "t" field from a CBOR frame body. Used by
// ReadFrame to dispatch to the right typed unmarshal.
func PeekType(body []byte) (string, error) {
	var d struct {
		T string `cbor:"t"`
	}
	if err := StrictDecMode.Unmarshal(body, &d); err != nil {
		return "", err
	}
	if d.T == "" {
		return "", errors.New("frame missing required 't' discriminator")
	}
	return d.T, nil
}

// Frame type discriminators for the single-stream Roam protocol.
// Every frame on the bidi stream is wrapped in a tagged envelope:
//
//	[u8 type][u32 BE length][body]
//
// Stays in sync with iOS `RoamProtocol.FrameType` — both sides MUST
// agree.
const (
	FrameTypeControl uint8 = 0 // body = CBOR-encoded control message
	FrameTypeStdin   uint8 = 1 // client → server only; body = raw stdin bytes
	FrameTypeStdout  uint8 = 2 // server → client only; body = [u64 BE seq][raw bytes]
)

// WriteTaggedFrame writes a `[u8 type][u32 BE len][body]` envelope.
// The body is rejected if its length exceeds MaxControlFrameBytes
// (the unified per-frame ceiling — covers control, stdin, and the
// stdout body's seq+payload combined).
func WriteTaggedFrame(w io.Writer, t uint8, body []byte) error {
	if len(body) > MaxControlFrameBytes {
		return fmt.Errorf("tagged frame body %d bytes exceeds limit %d", len(body), MaxControlFrameBytes)
	}
	var hdr [5]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write tagged frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write tagged frame body: %w", err)
	}
	return nil
}

// ReadTaggedFrame reads exactly one tagged envelope from r and
// returns the type tag + body. Frames larger than MaxControlFrameBytes
// return an error without consuming the oversized body — the
// connection MUST be torn down with ErrOversizedFrame.
func ReadTaggedFrame(r io.Reader) (uint8, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err // io.EOF, io.ErrUnexpectedEOF, or transport error
	}
	t := hdr[0]
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > MaxControlFrameBytes {
		return 0, nil, fmt.Errorf("tagged frame length %d exceeds limit %d", n, MaxControlFrameBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, fmt.Errorf("read tagged frame body: %w", err)
	}
	return t, body, nil
}

// EncodeStdoutBody composes the body of an FrameTypeStdout frame:
// `[u64 BE seq][raw bytes]`. The caller wraps this in WriteTaggedFrame
// with FrameTypeStdout.
func EncodeStdoutBody(seq uint64, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(out[0:8], seq)
	copy(out[8:], payload)
	return out
}

// DecodeStdoutBody splits an FrameTypeStdout body into (seq, payload).
// payload aliases body[8:] — caller must copy if the body slice may
// be reused.
func DecodeStdoutBody(body []byte) (uint64, []byte, error) {
	if len(body) < 8 {
		return 0, nil, fmt.Errorf("stdout body %d bytes < 8 bytes for seq header", len(body))
	}
	seq := binary.BigEndian.Uint64(body[0:8])
	return seq, body[8:], nil
}

// WriteFrame writes a length-prefixed CBOR frame to w. The body is
// rejected if its length exceeds MaxControlFrameBytes — that's a bug
// in the caller, not a wire issue.
func WriteFrame(w io.Writer, body []byte) error {
	if len(body) > MaxControlFrameBytes {
		return fmt.Errorf("frame body %d bytes exceeds limit %d", len(body), MaxControlFrameBytes)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads exactly one length-prefixed CBOR frame from r.
// Returns the raw body bytes; caller dispatches via PeekType. Frames
// larger than MaxControlFrameBytes return an error without consuming
// the oversized body — the connection MUST be torn down with
// ErrOversizedFrame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err // io.EOF, io.ErrUnexpectedEOF, or transport error — caller decides
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxControlFrameBytes {
		return nil, fmt.Errorf("frame length %d exceeds limit %d", n, MaxControlFrameBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	return body, nil
}

// EncodeOutputFrame writes the [uint64 seq][uint32 len][bytes] header
// + payload for one output-stream frame. Per § 8, payload is capped at
// MaxOutputFramePayload — callers (the daemon's stdout-pump) split
// larger PTY chunks into multiple frames.
func EncodeOutputFrame(w io.Writer, seq uint64, payload []byte) error {
	if len(payload) > MaxOutputFramePayload {
		return fmt.Errorf("output frame payload %d bytes exceeds limit %d", len(payload), MaxOutputFramePayload)
	}
	var hdr [12]byte
	binary.BigEndian.PutUint64(hdr[0:8], seq)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write output frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write output frame payload: %w", err)
	}
	return nil
}

// DecodeOutputFrame reads one [uint64 seq][uint32 len][bytes] frame
// from r. Returns the seq number and the payload bytes (a fresh
// allocation owned by the caller).
func DecodeOutputFrame(r io.Reader) (seq uint64, payload []byte, err error) {
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	seq = binary.BigEndian.Uint64(hdr[0:8])
	n := binary.BigEndian.Uint32(hdr[8:12])
	if n > MaxOutputFramePayload {
		return 0, nil, fmt.Errorf("output frame payload %d bytes exceeds limit %d", n, MaxOutputFramePayload)
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read output frame payload: %w", err)
	}
	return seq, payload, nil
}

// cborMarshal centralises the CBOR encoding options so every
// outbound frame is canonical. We use the CTAP2 encoding mode
// (deterministic length-canonical, sorted maps) as a known-stable
// canonical form — RFC 8949 § 4.2.1.
func cborMarshal(v any) ([]byte, error) {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(v)
}
