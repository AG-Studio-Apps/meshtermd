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

	FrameStdout    FrameType = 0x10 // sidecar → daemon: raw PTY output
	FrameEchoState FrameType = 0x11 // sidecar → daemon: [u8 echo] 0=off 1=on 2=unknown
	FrameChildExit FrameType = 0x12 // sidecar → daemon: [i32 code][i32 signal]
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
