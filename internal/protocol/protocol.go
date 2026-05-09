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
	TypeAttach    = "Attach"
	TypeAttachAck = "AttachAck"
	TypeAck       = "Ack"
	TypeResize    = "Resize"
	TypePing      = "Ping"
	TypePong      = "Pong"
	TypeGoodbye   = "Goodbye"
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
}

// AttachAck is the server's response to Attach.
type AttachAck struct {
	T         string `cbor:"t"`
	V         uint32 `cbor:"v"`
	OK        bool   `cbor:"ok"`
	SessionID []byte `cbor:"sid,omitempty"`
	Start     uint64 `cbor:"start,omitempty"`
	BufSeq    uint64 `cbor:"buf_seq,omitempty"`
	Trunc     bool   `cbor:"trunc,omitempty"`
	Err       string `cbor:"err,omitempty"`
	Msg       string `cbor:"msg,omitempty"`
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

// PeekType extracts only the "t" field from a CBOR frame body. Used by
// ReadFrame to dispatch to the right typed unmarshal.
func PeekType(body []byte) (string, error) {
	var d struct {
		T string `cbor:"t"`
	}
	if err := cbor.Unmarshal(body, &d); err != nil {
		return "", err
	}
	if d.T == "" {
		return "", errors.New("frame missing required 't' discriminator")
	}
	return d.T, nil
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
