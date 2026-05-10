package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// startDaemon brings up a Daemon on ephemeral ports + sockets in a
// fresh tmpdir. Returns the running daemon, an IPC client targeting
// it, and a cleanup func.
func startDaemon(t *testing.T) (*Daemon, *ipc.Client, func()) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("daemon assumes POSIX (PTY + unix socket)")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}

	tmp := t.TempDir()
	// audit F5: NewServer rejects socket parent dirs with mode > 0700.
	if err := os.Chmod(tmp, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	socket := filepath.Join(tmp, "meshtermd.sock")

	d, err := New(Config{
		QUICAddr:      "127.0.0.1:0",
		IPCSocketPath: socket,
		CertDir:       tmp,
		IdleTimeout:   time.Hour,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()

	// Wait for the IPC socket to appear (Run starts goroutines async).
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("daemon socket did not appear within 1s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cleanup := func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Error("daemon Run did not return within 2s of cancel")
		}
	}
	return d, ipc.NewClient(socket, time.Second), cleanup
}

func TestDaemonAllocateNewSessionReturnsValidBootstrap(t *testing.T) {
	t.Parallel()
	d, c, cleanup := startDaemon(t)
	defer cleanup()

	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Rows:      24,
		Cols:      80,
		Shell:     "/bin/sh",
		Exec:      []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Ok {
		t.Fatalf("Ok=false: %s %s", resp.Err, resp.Msg)
	}

	// session_id: 32 hex chars
	if len(resp.SessionID) != 32 {
		t.Errorf("SessionID len = %d, want 32", len(resp.SessionID))
	}
	if _, err := session.ParseSessionID(resp.SessionID); err != nil {
		t.Errorf("ParseSessionID(%q): %v", resp.SessionID, err)
	}
	// attach_token: 32 hex chars
	if len(resp.AttachToken) != 32 {
		t.Errorf("AttachToken len = %d, want 32", len(resp.AttachToken))
	}
	if _, err := session.ParseAttachToken(resp.AttachToken); err != nil {
		t.Errorf("ParseAttachToken(%q): %v", resp.AttachToken, err)
	}
	// cert_fp: 64 hex chars matching the daemon's cert
	if len(resp.CertFP) != 64 {
		t.Errorf("CertFP len = %d, want 64", len(resp.CertFP))
	}
	if resp.CertFP != d.CertFingerprint().String() {
		t.Errorf("CertFP = %q, want %q", resp.CertFP, d.CertFingerprint().String())
	}
	// port: matches daemon's QUIC addr
	wantPort := uint16(d.quic.Addr().Port)
	if resp.Port != wantPort {
		t.Errorf("Port = %d, want %d", resp.Port, wantPort)
	}
}

func TestDaemonReattachLooksUpExistingSession(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	first, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Rows:      24, Cols: 80,
		Shell: "/bin/sh",
		Exec:  []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !first.Ok {
		t.Fatalf("first allocate: %v %s %s", err, first.Err, first.Msg)
	}

	second, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: first.SessionID, // reattach
	})
	if err != nil || !second.Ok {
		t.Fatalf("reattach allocate: %v %s %s", err, second.Err, second.Msg)
	}
	if second.SessionID != first.SessionID {
		t.Errorf("reattach session id = %q, want %q", second.SessionID, first.SessionID)
	}
	if second.AttachToken == first.AttachToken {
		t.Error("reattach issued the same attach_token (must be fresh)")
	}
}

func TestDaemonReattachOnUnknownSessionFails(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: strings.Repeat("ab", 16), // 32-char hex, not present
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Ok {
		t.Error("Ok=true on reattach to unknown session")
	}
	if resp.Err != ipc.ErrUnknownSession {
		t.Errorf("Err = %q, want %q", resp.Err, ipc.ErrUnknownSession)
	}
}

// TestDaemonAllocateAssignsDefaultName asserts that Allocate without
// a Name still produces a non-empty user-visible name.
func TestDaemonAllocateAssignsDefaultName(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Shell:     "/bin/sh",
		Exec:      []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("allocate: %v %s %s", err, resp.Err, resp.Msg)
	}
	if resp.Name == "" {
		t.Error("Name = \"\", want a daemon-synthesised default")
	}
	if !strings.HasPrefix(resp.Name, "session-") {
		t.Errorf("Name = %q, want session-* default", resp.Name)
	}
}

// TestDaemonAllocateNameRoundtripsThroughResponse asserts that the
// Name field on the request comes back on the response — clients
// rely on this to confirm what the daemon resolved (especially in
// the create-if-missing flow where the server may attach to a
// pre-existing session of that name and the client wants to know
// about it).
func TestDaemonAllocateNameRoundtripsThroughResponse(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Name:      "namedreq",
		Shell:     "/bin/sh",
		Exec:      []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("allocate: %v %s %s", err, resp.Err, resp.Msg)
	}
	if resp.Name != "namedreq" {
		t.Errorf("Name = %q, want %q (echo)", resp.Name, "namedreq")
	}
}

// TestDaemonAllocateByNameAttachExisting verifies the create-if-
// missing idiom. Two Allocates with the same Name and SessionID="new"
// must return the SAME SessionID — the second call attached to the
// first's session rather than spawning a duplicate.
func TestDaemonAllocateByNameAttachExisting(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	first, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "shared",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !first.Ok {
		t.Fatalf("first allocate: %v %s", err, first.Err)
	}

	// Second allocate with same name + SessionID="new" — must
	// reattach, not spawn.
	second, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "shared",
	})
	if err != nil || !second.Ok {
		t.Fatalf("second allocate: %v %s", err, second.Err)
	}
	if second.SessionID != first.SessionID {
		t.Errorf("second.SessionID = %q, want %q (must reattach by name, not spawn)",
			second.SessionID, first.SessionID)
	}
	if second.AttachToken == first.AttachToken {
		t.Error("second allocate reused the same attach token (must be fresh)")
	}
}

// TestDaemonAllocateByNameCreateIfMissing verifies the spawn-if-
// missing branch. Allocate with a fresh name → daemon spawns a new
// session; the returned SessionID is non-empty and the resolved
// Name matches the request.
func TestDaemonAllocateByNameCreateIfMissing(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "fresh",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("allocate: %v %s", err, resp.Err)
	}
	if resp.Name != "fresh" {
		t.Errorf("Name = %q, want %q", resp.Name, "fresh")
	}
	if resp.SessionID == "" {
		t.Error("SessionID empty on successful create-if-missing")
	}
}

// TestDaemonListSessions exercises the inventory snapshot. Spawn 2
// named sessions, list, expect both with their names + non-zero
// timestamps + AttachedNow=false.
func TestDaemonListSessions(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	a, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "alpha",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !a.Ok {
		t.Fatalf("allocate alpha: %v %s", err, a.Err)
	}
	b, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "beta",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !b.Ok {
		t.Fatalf("allocate beta: %v %s", err, b.Err)
	}

	list, err := c.ListSessions(context.Background())
	if err != nil || !list.Ok {
		t.Fatalf("list: %v %s", err, list.Err)
	}
	if len(list.Sessions) != 2 {
		t.Fatalf("list returned %d sessions, want 2", len(list.Sessions))
	}
	names := map[string]bool{}
	for _, s := range list.Sessions {
		names[s.Name] = true
		if s.ID == "" {
			t.Error("session has empty ID in list response")
		}
		if s.CreatedAtNs == 0 || s.LastActiveAtNs == 0 {
			t.Errorf("session %s has zero timestamps", s.Name)
		}
		if s.AttachedNow {
			t.Errorf("session %s reports AttachedNow=true before any QUIC attach", s.Name)
		}
	}
	if !names["alpha"] || !names["beta"] {
		t.Errorf("names = %v, want alpha+beta", names)
	}
}

// TestDaemonKillSessionByName covers the name-based kill path.
func TestDaemonKillSessionByName(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	created, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "doomed",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !created.Ok {
		t.Fatalf("allocate: %v %s", err, created.Err)
	}

	resp, err := c.KillSession(context.Background(), "doomed")
	if err != nil || !resp.Ok {
		t.Fatalf("kill: %v %s", err, resp.Err)
	}

	// Verify it's gone via List.
	list, _ := c.ListSessions(context.Background())
	for _, s := range list.Sessions {
		if s.ID == created.SessionID {
			t.Error("session still present after kill")
		}
	}

	// Killing again should report unknown_session, not crash.
	again, err := c.KillSession(context.Background(), "doomed")
	if err != nil {
		t.Fatal(err)
	}
	if again.Ok {
		t.Error("second kill succeeded; want unknown_session")
	}
	if again.Err != ipc.ErrUnknownSession {
		t.Errorf("Err = %q, want %q", again.Err, ipc.ErrUnknownSession)
	}
}

// TestDaemonKillSessionByID covers the hex-ID kill path.
func TestDaemonKillSessionByID(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	created, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "byidtarget",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !created.Ok {
		t.Fatalf("allocate: %v %s", err, created.Err)
	}

	resp, err := c.KillSession(context.Background(), created.SessionID)
	if err != nil || !resp.Ok {
		t.Fatalf("kill by id: %v %s", err, resp.Err)
	}

	list, _ := c.ListSessions(context.Background())
	if len(list.Sessions) != 0 {
		t.Errorf("list after kill = %d sessions, want 0", len(list.Sessions))
	}
}

func TestDaemonClientReportsDaemonNotRunning(t *testing.T) {
	t.Parallel()
	c := ipc.NewClient(filepath.Join(t.TempDir(), "no-daemon.sock"), 100*time.Millisecond)
	_, err := c.Ping(context.Background(), 1)
	if !errors.Is(err, ipc.ErrDaemonNotRunning) {
		t.Errorf("err = %v, want ErrDaemonNotRunning", err)
	}
}

// TestDaemonEndToEndAttach is the headline integration test:
// daemon spawns a sleep, client allocates, dials QUIC with cert
// pinning, runs the Attach handshake, expects AttachAck.Ok=true.
func TestDaemonEndToEndAttach(t *testing.T) {
	t.Parallel()
	d, c, cleanup := startDaemon(t)
	defer cleanup()

	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Rows:      24, Cols: 80,
		Shell: "/bin/sh",
		Exec:  []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil || !resp.Ok {
		t.Fatalf("allocate: %v %s %s", err, resp.Err, resp.Msg)
	}

	wantFP, err := hexToFP(resp.CertFP)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // verified via fingerprint below
		NextProtos:         []string{protocol.ALPN},
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer cert")
			}
			got := sha256.Sum256(rawCerts[0])
			if got != wantFP {
				return fmt.Errorf("cert fp mismatch: got %x", got)
			}
			return nil
		},
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := fmt.Sprintf("127.0.0.1:%d", resp.Port)
	conn, err := quic.DialAddr(dialCtx, addr, tlsCfg, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.CloseWithError(0, "")

	ctrl, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := session.ParseAttachToken(resp.AttachToken)
	sid, _ := session.ParseSessionID(resp.SessionID)
	body, err := protocol.MarshalAttach(protocol.Attach{
		V: 1, Token: tok[:], SessionID: sid[:], Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteTaggedFrame(ctrl, protocol.FrameTypeControl, body); err != nil {
		t.Fatal(err)
	}

	frameType, respBody, err := protocol.ReadTaggedFrame(ctrl)
	if err != nil {
		t.Fatalf("read AttachAck: %v", err)
	}
	if frameType != protocol.FrameTypeControl {
		t.Fatalf("AttachAck frame type = %d, want FrameTypeControl", frameType)
	}
	var ack protocol.AttachAck
	if err := cbor.Unmarshal(respBody, &ack); err != nil {
		t.Fatal(err)
	}
	if !ack.OK {
		t.Errorf("AttachAck.OK = false: %s %s", ack.Err, ack.Msg)
	}
	// Daemon's Allocate path should have used the same fingerprint
	// we just verified.
	if d.CertFingerprint().String() != resp.CertFP {
		t.Errorf("daemon CertFingerprint mismatch")
	}
}

// hexToFP turns the hex-encoded fingerprint from the bootstrap line
// back into the [32]byte form NWConnection's verify block (or our
// test client) needs.
func hexToFP(s string) (cert.Fingerprint, error) {
	var fp cert.Fingerprint
	if len(s) != 64 {
		return fp, fmt.Errorf("fingerprint hex must be 64 chars, got %d", len(s))
	}
	for i := 0; i < 32; i++ {
		v, err := decodeHexByte(s[2*i : 2*i+2])
		if err != nil {
			return fp, err
		}
		fp[i] = v
	}
	return fp, nil
}

func decodeHexByte(s string) (byte, error) {
	b := []byte(s)
	hi := hexNibble(b[0])
	lo := hexNibble(b[1])
	if hi == 0xff || lo == 0xff {
		return 0, fmt.Errorf("invalid hex %q", s)
	}
	return hi<<4 | lo, nil
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0xff
}

// silence the bytes import for go vet — used by hexToFP via tests
// indirectly elsewhere in the package's evolution.
var _ = bytes.Equal
