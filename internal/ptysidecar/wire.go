// Package ptysidecar implements the per-session PTY-owning helper
// process. The daemon spawns one of these per shell session; the
// sidecar holds the PTY master fd + child shell as a direct
// subprocess and forwards bytes to/from the daemon over a per-session
// Unix-domain socket. The sidecar survives daemon restarts so live
// processes (claude, vim, top, builds) keep running across
// `systemctl restart meshtermd`.
//
// The architecture is documented in docs/sidecar.md and the design is
// summarised at the top of sidecar.go. This file defines the wire
// format shared between the sidecar and its daemon-side client
// (internal/ptyclient).
package ptysidecar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// FrameType identifies one of the seven sidecar↔daemon message
// kinds. The wire format is frozen: any future change ships as a
// fresh sidecar binary (new sessions only — existing sessions keep
// their pinned binary).
type FrameType uint8

// Frame type constants. Direction is informational; the codec doesn't
// enforce it (a misdirected frame just produces an unknown type the
// receiver logs and ignores).
const (
	FrameStdin     FrameType = 0x01 // daemon → sidecar: raw PTY input
	FrameResize    FrameType = 0x02 // daemon → sidecar: [u16 rows][u16 cols]
	FrameQueryEcho FrameType = 0x03 // daemon → sidecar: request termios echo state
	FrameDieNow    FrameType = 0x04 // daemon → sidecar: SIGHUP child + exit immediately
	FrameAck       FrameType = 0x05 // daemon → sidecar: [u64 consumed_through] free bytes ≤ this seq
	FrameResume    FrameType = 0x06 // daemon → sidecar: [u64 from_seq] reposition read cursor

	FrameStdout    FrameType = 0x10 // sidecar → daemon: [u64 first_byte_seq][u8 flags][N bytes]
	FrameEchoState FrameType = 0x11 // sidecar → daemon: [u8 echo][u8 canon?] (canon optional; 0=off 1=on 2=unknown)
	FrameChildExit FrameType = 0x12 // sidecar → daemon: [i32 code][i32 signal]
)

// Flag bits for FrameStdout body. The flags byte sits between the
// seq prefix and the payload bytes.
const (
	// StdoutFlagTruncBefore signals that bytes were silently dropped
	// between the previous FrameStdout's last byte and this frame's
	// first byte. The daemon advances its session-ring headSeq past
	// the gap (no payload bytes for the lost span) so iOS's existing
	// AttachAck.trunc semantics fire on the next attach.
	StdoutFlagTruncBefore byte = 0x01
)

// MaxFramePayload bounds the body length of any single frame. Sized
// to match the daemon's protocol.MaxControlFrameBytes so the sidecar
// never has to expect a larger frame than the daemon can legitimately
// produce.
const MaxFramePayload = 64 * 1024

// EchoState wire values for FrameEchoState body[0].
const (
	EchoOff     byte = 0
	EchoOn      byte = 1
	EchoUnknown byte = 2
)

// CanonState wire values for FrameEchoState body[1] (v0.7.0+).
// Same 0/1/2 mapping as EchoState. Body length ≥ 2 indicates the
// sidecar is v0.7.0+; body length == 1 (legacy) means the daemon
// should treat canon as Unknown. Daemons must tolerate both lengths
// because a v0.7.0 daemon may reconnect to a sidecar spawned by an
// older daemon during the upgrade window.
const (
	CanonOff     byte = 0
	CanonOn      byte = 1
	CanonUnknown byte = 2
)

// ErrFrameTooLarge is returned by ReadFrame when the length prefix
// exceeds MaxFramePayload. The connection is no longer safe to read
// from and should be closed.
var ErrFrameTooLarge = errors.New("ptysidecar: frame body exceeds MaxFramePayload")

// frameHeaderLen is the on-wire size of [u8 type][u32 BE len].
const frameHeaderLen = 5

// ReadFrame reads one frame from r and returns its type and body.
// The body slice is freshly allocated for each call. Returns io.EOF
// only at a clean frame boundary (mid-frame EOFs surface as
// io.ErrUnexpectedEOF).
func ReadFrame(r io.Reader) (FrameType, []byte, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := FrameType(hdr[0])
	length := binary.BigEndian.Uint32(hdr[1:])
	if length > MaxFramePayload {
		return 0, nil, fmt.Errorf("%w: type=0x%02x len=%d", ErrFrameTooLarge, t, length)
	}
	if length == 0 {
		return t, nil, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return t, body, nil
}

// WriteFrame writes one frame to w. Returns the underlying writer's
// error verbatim. Caller is responsible for serialising concurrent
// writes — neither the sidecar nor the daemon expects multiple
// goroutines hammering the same conn.
func WriteFrame(w io.Writer, t FrameType, body []byte) error {
	if len(body) > MaxFramePayload {
		return fmt.Errorf("%w: type=0x%02x len=%d", ErrFrameTooLarge, t, len(body))
	}
	var hdr [frameHeaderLen]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// EncodeResize builds the body of a FrameResize frame.
func EncodeResize(rows, cols uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], rows)
	binary.BigEndian.PutUint16(b[2:4], cols)
	return b
}

// DecodeResize parses a FrameResize body. Returns an error if the
// body length is not exactly 4 bytes.
func DecodeResize(body []byte) (rows, cols uint16, err error) {
	if len(body) != 4 {
		return 0, 0, fmt.Errorf("ptysidecar: resize body must be 4 bytes, got %d", len(body))
	}
	rows = binary.BigEndian.Uint16(body[0:2])
	cols = binary.BigEndian.Uint16(body[2:4])
	return rows, cols, nil
}

// EncodeChildExit builds the body of a FrameChildExit frame. `code`
// is the process exit code (0 if killed by signal); `signal` is the
// signal number (0 if exited normally).
func EncodeChildExit(code, signal int32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], uint32(code))
	binary.BigEndian.PutUint32(b[4:8], uint32(signal))
	return b
}

// DecodeChildExit parses a FrameChildExit body.
func DecodeChildExit(body []byte) (code, signal int32, err error) {
	if len(body) != 8 {
		return 0, 0, fmt.Errorf("ptysidecar: child_exit body must be 8 bytes, got %d", len(body))
	}
	code = int32(binary.BigEndian.Uint32(body[0:4]))
	signal = int32(binary.BigEndian.Uint32(body[4:8]))
	return code, signal, nil
}

// EncodeSeq builds an 8-byte body carrying a single u64 seq value.
// Used as the body of FrameAck (consumed_through) and FrameResume
// (from_seq).
func EncodeSeq(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

// DecodeSeq parses an 8-byte seq body. Used for FrameAck + FrameResume.
func DecodeSeq(body []byte) (seq uint64, err error) {
	if len(body) != 8 {
		return 0, fmt.Errorf("ptysidecar: seq body must be 8 bytes, got %d", len(body))
	}
	return binary.BigEndian.Uint64(body), nil
}

// stdoutHeaderLen is the on-wire size of [u64 first_seq][u8 flags].
const stdoutHeaderLen = 9

// EncodeStdoutBody builds a FrameStdout body. The first 8 bytes carry
// the seq of `payload[0]`; the next byte carries flags; the rest is
// the payload. A zero-payload frame (purely a Trunc signal) is legal
// — `payload` may be nil.
func EncodeStdoutBody(firstSeq uint64, flags byte, payload []byte) []byte {
	b := make([]byte, stdoutHeaderLen+len(payload))
	binary.BigEndian.PutUint64(b[0:8], firstSeq)
	b[8] = flags
	if len(payload) > 0 {
		copy(b[9:], payload)
	}
	return b
}

// DecodeStdoutBody parses a FrameStdout body. Returns the seq of the
// first payload byte (or, when payload is empty, the next seq the
// drainer would have emitted had bytes been available), the flags
// byte, and a slice that aliases `body` for the payload portion.
//
// The returned `payload` shares backing memory with `body` — callers
// that retain it across the next ReadFrame must copy.
func DecodeStdoutBody(body []byte) (firstSeq uint64, flags byte, payload []byte, err error) {
	if len(body) < stdoutHeaderLen {
		return 0, 0, nil, fmt.Errorf("ptysidecar: stdout body must be ≥%d bytes, got %d", stdoutHeaderLen, len(body))
	}
	firstSeq = binary.BigEndian.Uint64(body[0:8])
	flags = body[8]
	if len(body) > stdoutHeaderLen {
		payload = body[stdoutHeaderLen:]
	}
	return firstSeq, flags, payload, nil
}
