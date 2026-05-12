package ptyclient

import (
	"bytes"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
)

// pipePair returns a Conn under test plus the "sidecar" end of a
// net.Pipe — the test side writes frames the Conn will consume and
// reads frames the Conn produces.
func pipePair(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	clientSide, sidecarSide := net.Pipe()
	conn := newConn("testsess", clientSide, nil)
	t.Cleanup(func() {
		_ = conn.Close()
		_ = sidecarSide.Close()
	})
	return conn, sidecarSide
}

func TestConnReadDeliversStdoutFrame(t *testing.T) {
	conn, sidecar := pipePair(t)
	go func() {
		_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameStdout,
			ptysidecar.EncodeStdoutBody(0, 0, []byte("hello world")))
	}()
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello world" {
		t.Errorf("got %q, want %q", buf[:n], "hello world")
	}
	if conn.LastDeliveredSeq() != uint64(len("hello world")) {
		t.Errorf("LastDeliveredSeq: want %d, got %d", len("hello world"), conn.LastDeliveredSeq())
	}
}

func TestConnReadEOFOnChildExit(t *testing.T) {
	conn, sidecar := pipePair(t)
	go func() {
		_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameStdout,
			ptysidecar.EncodeStdoutBody(0, 0, []byte("partial")))
		_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameChildExit, ptysidecar.EncodeChildExit(42, 0))
	}()
	// First read returns the buffered bytes.
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("first Read: %v", err)
	}
	if string(buf[:n]) != "partial" {
		t.Errorf("first Read body: got %q", buf[:n])
	}
	// Second read returns 0, io.EOF.
	n, err = conn.Read(buf)
	if n != 0 || err != io.EOF {
		t.Errorf("second Read: got (%d, %v), want (0, EOF)", n, err)
	}
	// ChildExit info is captured.
	if info := conn.ChildExit(); info == nil || info.Code != 42 {
		t.Errorf("ChildExit: got %+v", info)
	}
}

func TestConnWriteEncodesFrameStdin(t *testing.T) {
	conn, sidecar := pipePair(t)
	done := make(chan struct{})
	var got struct {
		typ  ptysidecar.FrameType
		body []byte
	}
	go func() {
		defer close(done)
		t, body, err := ptysidecar.ReadFrame(sidecar)
		if err == nil {
			got.typ = t
			got.body = body
		}
	}()
	n, err := conn.Write([]byte("keys"))
	if err != nil || n != 4 {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	<-done
	if got.typ != ptysidecar.FrameStdin || string(got.body) != "keys" {
		t.Errorf("framing wrong: typ=0x%02x body=%q", got.typ, got.body)
	}
}

func TestConnSetSizeEncodesResize(t *testing.T) {
	conn, sidecar := pipePair(t)
	done := make(chan struct{})
	var got struct {
		typ  ptysidecar.FrameType
		body []byte
	}
	go func() {
		defer close(done)
		t, body, err := ptysidecar.ReadFrame(sidecar)
		if err == nil {
			got.typ = t
			got.body = body
		}
	}()
	if err := conn.SetSize(40, 120); err != nil {
		t.Fatalf("SetSize: %v", err)
	}
	<-done
	if got.typ != ptysidecar.FrameResize {
		t.Errorf("typ: got 0x%02x, want FrameResize", got.typ)
	}
	if !bytes.Equal(got.body, ptysidecar.EncodeResize(40, 120)) {
		t.Errorf("body mismatch: got %v", got.body)
	}
}

func TestConnEchoEnabledCachesUpdates(t *testing.T) {
	conn, sidecar := pipePair(t)
	// Background sidecar reader: drain every FrameQueryEcho and reply
	// with EchoOn so the daemon's cache populates. Starts FIRST so
	// the very first EchoEnabled call doesn't deadlock on the
	// synchronous net.Pipe write.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = sidecar.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, _, err := ptysidecar.ReadFrame(sidecar)
			if err != nil {
				continue
			}
			_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameEchoState, []byte{ptysidecar.EchoOn})
		}
	}()
	defer func() {
		close(stop)
		_ = sidecar.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		<-done
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if echo, ok := conn.EchoEnabled(); ok && echo {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("EchoEnabled did not see on=true within 2s")
}

func TestConnKillWritesDieNowThenCloses(t *testing.T) {
	conn, sidecar := pipePair(t)
	var got ptysidecar.FrameType
	done := make(chan struct{})
	go func() {
		defer close(done)
		typ, _, err := ptysidecar.ReadFrame(sidecar)
		if err == nil {
			got = typ
		}
	}()
	if err := conn.Kill(); err != nil {
		t.Logf("Kill returned (expected on closed pipe): %v", err)
	}
	<-done
	if got != ptysidecar.FrameDieNow {
		t.Errorf("Kill should write die_now; got 0x%02x", got)
	}
}

func TestConnSocketBreakSurfacesErrSidecarGone(t *testing.T) {
	conn, sidecar := pipePair(t)
	// Sidecar end goes away mid-stream (no clean child_exit).
	go func() {
		// Send a partial header to provoke an unexpected EOF on the
		// daemon side.
		_, _ = sidecar.Write([]byte{0x10, 0x00, 0x00, 0x00})
		_ = sidecar.Close()
	}()
	buf := make([]byte, 8)
	_, err := conn.Read(buf)
	if !errors.Is(err, ErrSidecarGone) && err != io.EOF {
		t.Errorf("expected ErrSidecarGone or io.EOF on broken socket, got %v", err)
	}
}

func TestConnEBUSYChildExitSurfacesAsBusy(t *testing.T) {
	conn, sidecar := pipePair(t)
	go func() {
		_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameChildExit,
			ptysidecar.EncodeChildExit(0, int32(syscall.EBUSY)))
	}()
	buf := make([]byte, 8)
	_, err := conn.Read(buf)
	if !errors.Is(err, ErrSidecarBusy) {
		t.Errorf("expected ErrSidecarBusy on EBUSY child_exit, got %v", err)
	}
}

func TestConnTruncFlagSurfacesViaConsumeTrunc(t *testing.T) {
	conn, sidecar := pipePair(t)
	// Sidecar emits two frames: first establishes the read cursor at
	// seq 10, second has Trunc flag with firstSeq=20 (so 10 bytes of
	// gap between them).
	go func() {
		_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameStdout,
			ptysidecar.EncodeStdoutBody(10, 0, []byte("aaaaaaaaaa"))) // seqs 10..20
		_ = ptysidecar.WriteFrame(sidecar, ptysidecar.FrameStdout,
			ptysidecar.EncodeStdoutBody(30, ptysidecar.StdoutFlagTruncBefore, []byte("bbbbbbbbbb"))) // seqs 30..40, 10-byte gap
	}()
	buf := make([]byte, 32)
	// First read drains all in-flight bytes.
	deadline := time.Now().Add(2 * time.Second)
	var got []byte
	for time.Now().Before(deadline) && len(got) < 20 {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("Read err: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "aaaaaaaaaabbbbbbbbbb" {
		t.Errorf("payload concatenation: got %q", got)
	}
	if gap := conn.ConsumeTrunc(); gap != 10 {
		t.Errorf("ConsumeTrunc: want 10, got %d", gap)
	}
	if gap := conn.ConsumeTrunc(); gap != 0 {
		t.Errorf("second ConsumeTrunc should return 0 after reset, got %d", gap)
	}
	if conn.LastDeliveredSeq() != 40 {
		t.Errorf("LastDeliveredSeq: want 40, got %d", conn.LastDeliveredSeq())
	}
}

func TestConnSendResumeEncodesFrameResume(t *testing.T) {
	conn, sidecar := pipePair(t)
	done := make(chan struct{})
	var got struct {
		typ  ptysidecar.FrameType
		body []byte
	}
	go func() {
		defer close(done)
		t, body, _ := ptysidecar.ReadFrame(sidecar)
		got.typ = t
		got.body = body
	}()
	if err := conn.SendResume(12345); err != nil {
		t.Fatalf("SendResume: %v", err)
	}
	<-done
	if got.typ != ptysidecar.FrameResume {
		t.Errorf("typ: got 0x%02x, want FrameResume", got.typ)
	}
	seq, err := ptysidecar.DecodeSeq(got.body)
	if err != nil || seq != 12345 {
		t.Errorf("body decode: seq=%d err=%v", seq, err)
	}
}

func TestConnAckEncodesFrameAck(t *testing.T) {
	conn, sidecar := pipePair(t)
	done := make(chan struct{})
	var got struct {
		typ  ptysidecar.FrameType
		body []byte
	}
	go func() {
		defer close(done)
		t, body, _ := ptysidecar.ReadFrame(sidecar)
		got.typ = t
		got.body = body
	}()
	if err := conn.Ack(99999); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	<-done
	if got.typ != ptysidecar.FrameAck {
		t.Errorf("typ: got 0x%02x, want FrameAck", got.typ)
	}
	seq, err := ptysidecar.DecodeSeq(got.body)
	if err != nil || seq != 99999 {
		t.Errorf("body decode: seq=%d err=%v", seq, err)
	}
}

func TestConnCloseIsIdempotent(t *testing.T) {
	conn, _ := pipePair(t)
	if err := conn.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
