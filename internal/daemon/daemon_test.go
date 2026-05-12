package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// shortTempDir is t.TempDir()'s short cousin: t.TempDir encodes the
// full test-function name into the path, which combines with the
// per-session subdirectory ({stateDir}/sessions/{32-hex-sid}/sidecar
// .sock) to push the daemon's per-session unix socket path past
// Linux's 108-byte limit. We mint a short, randomly-named dir under
// /tmp instead and register cleanup with the test.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mtd-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// killLeftoverSidecars walks {stateDir}/sessions/<sid>/sidecar.pid
// and SIGKILLs each live sidecar, then waits up to 2 s for the
// pidfile to disappear (or the process to be unreachable). Used by
// test cleanup to short-circuit the 30 s production grace timer + to
// close the inherited stderr fd that's keeping `go test` parked at
// WaitDelay.
//
// SIGKILL rather than SIGTERM because we don't need a graceful
// teardown here — the temp dir is about to be RemoveAll'd anyway.
func killLeftoverSidecars(stateDir string) {
	sessionsDir := filepath.Join(stateDir, "sessions")
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return
	}
	var pids []int
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pidPath := filepath.Join(sessionsDir, ent.Name(), "sidecar.pid")
		data, rerr := os.ReadFile(pidPath)
		if rerr != nil {
			continue
		}
		// pidfile format: "PID\nbinary_path\n" — first line is the PID.
		line := strings.SplitN(string(data), "\n", 2)[0]
		pid, perr := strconv.Atoi(strings.TrimSpace(line))
		if perr != nil || pid <= 0 {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
		pids = append(pids, pid)
	}
	// Wait for the kernel to reap (or at least make the pid unreachable).
	// Without this, the inherited stderr fd lingers and go test's
	// WaitDelay fires.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		alive := false
		for _, pid := range pids {
			if syscall.Kill(pid, 0) == nil {
				alive = true
				break
			}
		}
		if !alive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

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

	tmp := shortTempDir(t)
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
		SidecarStderr: io.Discard,
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
		// Sidecars spawned during the test enter a 30 s grace timer on
		// daemon disconnect waiting for a reattach (production
		// semantics). Tests can't wait that long — walk the state dir
		// and SIGTERM any sidecar.pid we find so `go test` can release
		// child-process fds and the test binary can exit.
		killLeftoverSidecars(tmp)
	}
	// 5 s IPC timeout. Spawning a sidecar in tests means forking the
	// (large) test binary and dialing its unix socket with backoff —
	// the 1 s budget used by mtctl in production isn't safe under
	// `go test` on cold caches.
	return d, ipc.NewClient(socket, 5*time.Second), cleanup
}

// TestDaemonPersistenceRoundTrip verifies the end-to-end persistence
// flow at the daemon level: start a daemon, allocate a persisted
// session, type bytes into its buffer, stop the daemon, start a fresh
// daemon on the same state dir, confirm the session is restored with
// scrollback intact and Restored-flag set.
func TestDaemonPersistenceRoundTrip(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("daemon assumes POSIX")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	tmp := shortTempDir(t)
	if err := os.Chmod(tmp, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	socket := filepath.Join(tmp, "meshtermd.sock")

	d1, err := New(Config{
		QUICAddr:                 "127.0.0.1:0",
		IPCSocketPath:            socket,
		CertDir:                  tmp,
		IdleTimeout:              time.Hour,
		PersistenceFlushInterval: 50 * time.Millisecond,
		SidecarStderr:            io.Discard,
	})
	if err != nil {
		t.Fatalf("daemon.New (first): %v", err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	d1Done := make(chan error, 1)
	go func() { d1Done <- d1.Run(ctx1) }()
	waitForSocket(t, socket)

	// Allocate a persisted session.
	c := ipc.NewClient(socket, 5*time.Second)
	persistTrue := true
	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Name:      "persist-test",
		Rows:      24, Cols: 80,
		Shell:   "/bin/sh",
		Exec:    []string{"-c", "while true; do sleep 1; done"},
		Persist: &persistTrue,
	})
	if err != nil || !resp.Ok {
		t.Fatalf("allocate: %v %s %s", err, resp.Err, resp.Msg)
	}
	sid, err := session.ParseSessionID(resp.SessionID)
	if err != nil {
		t.Fatal(err)
	}

	// Inject scrollback so we can verify it round-trips through disk.
	sess, err := d1.registry.Lookup(sid)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "persistence end-to-end test\n"
	if _, err := sess.Buffer().Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	// Wait for the flusher to checkpoint at least once.
	deadline := time.Now().Add(500 * time.Millisecond)
	sessionDir := filepath.Join(tmp, "sessions", sid.String())
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(sessionDir, "meta.cbor")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(sessionDir, "meta.cbor")); err != nil {
		t.Fatalf("flusher did not write meta.cbor within 500ms: %v", err)
	}

	// Stop the first daemon. The deferred Shutdown in Registry.Run
	// fires final flushes via Session.Close → stopFlusher.
	cancel1()
	select {
	case <-d1Done:
	case <-time.After(2 * time.Second):
		t.Fatal("first daemon did not exit within 2s")
	}

	// Start a fresh daemon on the same state dir; expect the session
	// to be restored from disk.
	d2, err := New(Config{
		QUICAddr:      "127.0.0.1:0",
		IPCSocketPath: socket,
		CertDir:       tmp,
		IdleTimeout:   time.Hour,
		SidecarStderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("daemon.New (second): %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	d2Done := make(chan error, 1)
	go func() { d2Done <- d2.Run(ctx2) }()
	waitForSocket(t, socket)
	defer func() {
		cancel2()
		<-d2Done
	}()

	restored, err := d2.registry.Lookup(sid)
	if err != nil {
		t.Fatalf("session not restored: %v", err)
	}
	// Note: with the v0.6 sidecar split, RestoredFromDisk is cleared by
	// Discover/AssignPTY at startup (the daemon-side session has a live
	// PTY conn again). The "restored" signal users actually consume is
	// AttachAck.restored, which is sampled before AssignPTY clears the
	// flag — covered by transport-level tests. Here we just confirm the
	// scrollback round-tripped through disk.
	data, _, _ := restored.Buffer().ReadSince(0, 0)
	if !strings.Contains(string(data), payload) {
		t.Errorf("scrollback after restart: %q does not contain %q", data, payload)
	}
}

// waitForSocket polls until the IPC socket file appears or fails the
// test after a short deadline. Used by tests that start daemons in
// goroutines.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket did not appear within 1s: %s", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDaemonSessionBufferBytesConfigFlowsThrough verifies that
// Config.SessionBufferBytes from `meshtermd serve --session-buffer-bytes N`
// actually reaches the per-session RingBuffer that spawnSession creates.
// Without this, the flag would silently default to 4 MiB and operators
// wouldn't see their `--session-buffer-bytes 16777216` take effect.
func TestDaemonSessionBufferBytesConfigFlowsThrough(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("daemon assumes POSIX")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	tmp := shortTempDir(t)
	if err := os.Chmod(tmp, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	socket := filepath.Join(tmp, "meshtermd.sock")

	const want = 8 * 1024 * 1024 // 8 MiB; non-default so a regression to the 4 MiB const fails this test.

	d, err := New(Config{
		QUICAddr:           "127.0.0.1:0",
		IPCSocketPath:      socket,
		CertDir:            tmp,
		IdleTimeout:        time.Hour,
		SessionBufferBytes: want,
		SidecarStderr:      io.Discard,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()
	defer func() {
		cancel()
		<-runDone
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon socket did not appear within 1s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	c := ipc.NewClient(socket, 5*time.Second)
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
		t.Fatalf("Allocate failed: %s %s", resp.Err, resp.Msg)
	}
	sid, err := session.ParseSessionID(resp.SessionID)
	if err != nil {
		t.Fatalf("ParseSessionID(%q): %v", resp.SessionID, err)
	}
	sess, err := d.registry.Lookup(sid)
	if err != nil {
		t.Fatalf("registry.Lookup: %v", err)
	}
	if got := sess.Buffer().Capacity(); got != want {
		t.Errorf("session buffer Capacity() = %d, want %d", got, want)
	}
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

// TestDaemonReattachUpdatesIdleTimeout reproduces the 2026-05-12
// bug report: a user edited the iOS Keep-alive picker from 1h to
// 30d, but the daemon's existing session kept its original 1h
// timeout and got GC'd at the old interval. lookupOrCreateSession
// must apply the new value on reattach.
func TestDaemonReattachUpdatesIdleTimeout(t *testing.T) {
	t.Parallel()
	d, c, cleanup := startDaemon(t)
	defer cleanup()

	// First allocate: 1h timeout (matches iOS's .oneHour preset).
	first, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID:        "new",
		Name:             "dev",
		Rows:             24, Cols: 80,
		Shell:            "/bin/sh",
		Exec:             []string{"-c", "while true; do sleep 1; done"},
		IdleTimeoutNanos: int64(time.Hour),
	})
	if err != nil || !first.Ok {
		t.Fatalf("first allocate: %v %s %s", err, first.Err, first.Msg)
	}
	sid, err := session.ParseSessionID(first.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := d.registry.Lookup(sid)
	if err != nil {
		t.Fatal(err)
	}
	if got := sess.IdleTimeout(); got != time.Hour {
		t.Fatalf("post-spawn idle timeout = %v, want 1h", got)
	}

	// Simulate the user editing Keep-alive to 30d in iOS, then
	// reattaching. iOS reattaches by SessionID, not Name, after the
	// first connect — but the by-name path also has to apply the
	// update, so cover both.
	thirtyDays := 30 * 24 * time.Hour
	second, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID:        first.SessionID,
		IdleTimeoutNanos: int64(thirtyDays),
	})
	if err != nil || !second.Ok {
		t.Fatalf("reattach by id: %v %s %s", err, second.Err, second.Msg)
	}
	if got := sess.IdleTimeout(); got != thirtyDays {
		t.Errorf("after reattach by id: idle timeout = %v, want %v", got, thirtyDays)
	}

	// Reattach by NAME path (iOS create-if-missing). Drop back to 1h.
	third, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID:        "new",
		Name:             "dev",
		Rows:             24, Cols: 80,
		IdleTimeoutNanos: int64(time.Hour),
	})
	if err != nil || !third.Ok {
		t.Fatalf("reattach by name: %v %s %s", err, third.Err, third.Msg)
	}
	if third.SessionID != first.SessionID {
		t.Fatalf("by-name reattach hit a different session: got %q want %q", third.SessionID, first.SessionID)
	}
	if got := sess.IdleTimeout(); got != time.Hour {
		t.Errorf("after reattach by name: idle timeout = %v, want 1h", got)
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

// TestDaemonStatusReturnsLiveCounters: spawn N sessions, then
// Status reports the matching count, a non-zero uptime, and the
// expected idle-timeout config.
func TestDaemonStatusReturnsLiveCounters(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	for i := 0; i < 3; i++ {
		_, err := c.Allocate(context.Background(), ipc.AllocateRequest{
			SessionID: "new", Name: fmt.Sprintf("s%d", i),
			Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	resp, err := c.Status(context.Background())
	if err != nil || !resp.Ok {
		t.Fatalf("status: %v %s", err, resp.Err)
	}
	if resp.SessionCount != 3 {
		t.Errorf("SessionCount = %d, want 3", resp.SessionCount)
	}
	if resp.MaxSessions <= 0 {
		t.Errorf("MaxSessions = %d, want > 0", resp.MaxSessions)
	}
	if resp.IdleTimeoutNs <= 0 {
		t.Errorf("IdleTimeoutNs = %d, want > 0", resp.IdleTimeoutNs)
	}
	if resp.UptimeNs <= 0 {
		t.Errorf("UptimeNs = %d, want > 0", resp.UptimeNs)
	}
	if resp.QUICAddr == "" {
		t.Error("QUICAddr empty in status response")
	}
	if resp.CertFingerprint == "" {
		t.Error("CertFingerprint empty in status response")
	}
}

// TestDaemonRenameSessionByName covers the end-to-end rename via
// IPC: spawn → rename by name → verify list reflects the new name
// and the old name no longer resolves.
func TestDaemonRenameSessionByName(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	_, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "oldlabel",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil {
		t.Fatal(err)
	}

	rn, err := c.RenameSession(context.Background(), "oldlabel", "newlabel")
	if err != nil || !rn.Ok {
		t.Fatalf("rename: %v %s %s", err, rn.Err, rn.Msg)
	}
	if rn.Name != "newlabel" {
		t.Errorf("rename echoed Name = %q, want %q", rn.Name, "newlabel")
	}

	list, _ := c.ListSessions(context.Background())
	var found bool
	for _, s := range list.Sessions {
		if s.Name == "newlabel" {
			found = true
		}
		if s.Name == "oldlabel" {
			t.Error("old name still appears in list after rename")
		}
	}
	if !found {
		t.Error("new name not in list after rename")
	}
}

// TestDaemonRenameSessionEmptyNewNameErrors: the daemon rejects an
// empty NewName at the IPC layer (a session must remain reachable
// via the picker; anonymous-by-rename would orphan it).
func TestDaemonRenameSessionEmptyNewNameErrors(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	_, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "anchor",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.RenameSession(context.Background(), "anchor", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Ok {
		t.Error("Ok=true with empty new name; want bad_request")
	}
	if resp.Err != ipc.ErrBadRequest {
		t.Errorf("Err = %q, want %q", resp.Err, ipc.ErrBadRequest)
	}
}

// TestDaemonRenameSessionCollisionErrors: renaming to a name held
// by another session returns ErrNameInUse; the source session
// retains its old name.
func TestDaemonRenameSessionCollisionErrors(t *testing.T) {
	t.Parallel()
	_, c, cleanup := startDaemon(t)
	defer cleanup()

	_, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "first",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new", Name: "second",
		Shell: "/bin/sh", Exec: []string{"-c", "while true; do sleep 1; done"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.RenameSession(context.Background(), "second", "first")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Ok {
		t.Error("Ok=true on collision; want name_in_use")
	}
	if resp.Err != ipc.ErrNameInUse {
		t.Errorf("Err = %q, want %q", resp.Err, ipc.ErrNameInUse)
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
