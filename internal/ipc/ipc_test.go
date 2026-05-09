package ipc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// echoHandler is a Handler whose Allocate just echoes back the
// SessionID with a stub token, and whose Ping echoes the nonce.
type echoHandler struct {
	called int
}

func (h *echoHandler) HandleAllocate(ctx context.Context, req AllocateRequest) AllocateResponse {
	h.called++
	if req.SessionID == "fail" {
		return AllocateResponse{Ok: false, Err: ErrCapacity, Msg: "test failure"}
	}
	return AllocateResponse{
		Ok:          true,
		SessionID:   req.SessionID,
		AttachToken: "token-" + req.SessionID,
		Port:        4242,
		CertFP:      "fp-stub",
	}
}

func (h *echoHandler) HandlePing(ctx context.Context, req PingRequest) PingResponse {
	return PingResponse{Nonce: req.Nonce}
}

func startServer(t *testing.T, h Handler) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "meshtermd.sock")
	srv, err := NewServer(socket, h)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go srv.Serve(context.Background())
	// Give Serve a moment to enter Accept.
	time.Sleep(20 * time.Millisecond)
	return srv, socket
}

func TestNewServerRejectsNilHandler(t *testing.T) {
	t.Parallel()
	if _, err := NewServer(filepath.Join(t.TempDir(), "x.sock"), nil); err == nil {
		t.Error("NewServer accepted nil handler")
	}
}

func TestNewServerCreatesSocketWith0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "meshtermd.sock")
	srv, err := NewServer(socket, &echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	// Stat the socket; mode should be 0600.
	info, err := osStat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("socket mode = %o, want 0600", mode)
	}
}

func TestAllocateRoundTrip(t *testing.T) {
	t.Parallel()
	h := &echoHandler{}
	_, socket := startServer(t, h)
	c := NewClient(socket, 0)

	resp, err := c.Allocate(context.Background(), AllocateRequest{
		SessionID: "abc123",
		Rows:      24,
		Cols:      80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Ok {
		t.Errorf("resp.Ok = false, err=%q msg=%q", resp.Err, resp.Msg)
	}
	if resp.SessionID != "abc123" {
		t.Errorf("SessionID = %q, want abc123", resp.SessionID)
	}
	if resp.AttachToken != "token-abc123" {
		t.Errorf("AttachToken = %q, want token-abc123", resp.AttachToken)
	}
	if resp.Port != 4242 {
		t.Errorf("Port = %d, want 4242", resp.Port)
	}
}

func TestAllocateFailureRoundTrip(t *testing.T) {
	t.Parallel()
	_, socket := startServer(t, &echoHandler{})
	c := NewClient(socket, 0)

	resp, err := c.Allocate(context.Background(), AllocateRequest{SessionID: "fail"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Ok {
		t.Error("resp.Ok = true on a request that should have failed")
	}
	if resp.Err != ErrCapacity {
		t.Errorf("Err = %q, want %q", resp.Err, ErrCapacity)
	}
}

func TestPingRoundTrip(t *testing.T) {
	t.Parallel()
	_, socket := startServer(t, &echoHandler{})
	c := NewClient(socket, 0)
	resp, err := c.Ping(context.Background(), 0xdeadbeef)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Nonce != 0xdeadbeef {
		t.Errorf("Nonce = %x, want deadbeef", resp.Nonce)
	}
}

func TestClientReportsDaemonNotRunning(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(t.TempDir(), "nope.sock")
	c := NewClient(socket, 100*time.Millisecond)
	_, err := c.Ping(context.Background(), 1)
	if !errors.Is(err, ErrDaemonNotRunning) {
		t.Errorf("err = %v, want ErrDaemonNotRunning", err)
	}
}

func TestServeReplacesStaleSocket(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "meshtermd.sock")
	// Plant a stale file at the socket path (NOT a real socket).
	// NewServer should remove it and bind cleanly.
	if err := writeFile(socket, "stale", 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(socket, &echoHandler{})
	if err != nil {
		t.Fatalf("NewServer with stale socket: %v", err)
	}
	defer srv.Close()
}

func TestCloseRemovesSocket(t *testing.T) {
	t.Parallel()
	srv, socket := startServer(t, &echoHandler{})
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := osStat(socket); err == nil {
		t.Error("socket file still present after Close")
	}
}
