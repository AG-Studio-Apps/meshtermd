package ptysidecar

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		typ  FrameType
		body []byte
	}{
		{"stdin small", FrameStdin, []byte("hello world")},
		{"stdin empty", FrameStdin, nil},
		{"resize", FrameResize, EncodeResize(40, 120)},
		{"query_echo", FrameQueryEcho, nil},
		{"die_now", FrameDieNow, nil},
		{"stdout chunk", FrameStdout, bytes.Repeat([]byte("xy"), 1024)},
		{"echo_state on", FrameEchoState, []byte{EchoOn}},
		{"child_exit normal", FrameChildExit, EncodeChildExit(42, 0)},
		{"child_exit signal", FrameChildExit, EncodeChildExit(0, 9)},
		{"max payload", FrameStdout, bytes.Repeat([]byte{0xab}, MaxFramePayload)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tc.typ, tc.body); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			gotType, gotBody, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if gotType != tc.typ {
				t.Errorf("type: want 0x%02x, got 0x%02x", tc.typ, gotType)
			}
			if !bytes.Equal(gotBody, tc.body) && !(len(gotBody) == 0 && len(tc.body) == 0) {
				t.Errorf("body mismatch: want %d bytes, got %d bytes", len(tc.body), len(gotBody))
			}
		})
	}
}

func TestWriteFrameRejectsOverlongBody(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, FrameStdout, make([]byte, MaxFramePayload+1))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrameRejectsOverlongLengthPrefix(t *testing.T) {
	// Hand-craft a header that claims a 1 MiB body.
	var buf bytes.Buffer
	buf.WriteByte(byte(FrameStdout))
	buf.Write([]byte{0x00, 0x10, 0x00, 0x00}) // len = 0x100000 = 1 MiB
	_, _, err := ReadFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrameCleanEOF(t *testing.T) {
	_, _, err := ReadFrame(strings.NewReader(""))
	if err != io.EOF {
		t.Fatalf("expected io.EOF on empty reader, got %v", err)
	}
}

func TestReadFrameMidFrameEOFIsUnexpected(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(FrameStdout))
	buf.Write([]byte{0x00, 0x00, 0x00, 0x05}) // claims 5 bytes
	buf.WriteString("abc")                    // only 3
	_, _, err := ReadFrame(&buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestEncodeDecodeResize(t *testing.T) {
	for _, tc := range []struct{ rows, cols uint16 }{
		{24, 80}, {40, 120}, {1, 1}, {65535, 65535},
	} {
		body := EncodeResize(tc.rows, tc.cols)
		gotRows, gotCols, err := DecodeResize(body)
		if err != nil {
			t.Fatalf("DecodeResize(%d, %d): %v", tc.rows, tc.cols, err)
		}
		if gotRows != tc.rows || gotCols != tc.cols {
			t.Errorf("roundtrip: want (%d, %d), got (%d, %d)", tc.rows, tc.cols, gotRows, gotCols)
		}
	}
}

func TestDecodeResizeRejectsShortBody(t *testing.T) {
	_, _, err := DecodeResize([]byte{0x00})
	if err == nil {
		t.Fatal("expected error on short body")
	}
}

func TestEncodeDecodeChildExit(t *testing.T) {
	for _, tc := range []struct{ code, signal int32 }{
		{0, 0}, {1, 0}, {42, 0}, {0, 9}, {0, 15}, {-1, 0},
	} {
		body := EncodeChildExit(tc.code, tc.signal)
		gotCode, gotSignal, err := DecodeChildExit(body)
		if err != nil {
			t.Fatalf("DecodeChildExit(%d, %d): %v", tc.code, tc.signal, err)
		}
		if gotCode != tc.code || gotSignal != tc.signal {
			t.Errorf("roundtrip: want (%d, %d), got (%d, %d)", tc.code, tc.signal, gotCode, gotSignal)
		}
	}
}
