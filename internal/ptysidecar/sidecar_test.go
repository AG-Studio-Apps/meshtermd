package ptysidecar

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dialWithRetry polls for the sidecar socket coming up. Healthy
// spawn lands within ~50–100 ms; we give 3 s.
func dialWithRetry(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("unix", path)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startSidecar boots Run in a goroutine with a /bin/cat shell. It
// returns the socket path, pidfile path, and a function that waits
// for Run to return. The supplied ctx cancels the sidecar.
func startSidecar(t *testing.T, ctx context.Context, mods ...func(*Config)) (string, string, func() error) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		SocketPath:  filepath.Join(dir, "sidecar.sock"),
		PidfilePath: filepath.Join(dir, "sidecar.pid"),
		SessionID:   "test",
		Shell:       "/bin/cat",
		Rows:        24,
		Cols:        80,
		GraceSecs:   1,
		RingBytes:   1024,
	}
	for _, m := range mods {
		m(&cfg)
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	return cfg.SocketPath, cfg.PidfilePath, func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(8 * time.Second):
			t.Fatal("sidecar Run did not return within 8s")
			return nil
		}
	}
}

func TestSidecarEchoRoundTripViaCat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sockPath, _, wait := startSidecar(t, ctx)

	conn := dialWithRetry(t, sockPath)
	defer conn.Close()

	// Write FrameStdin "hello\n" → expect FrameStdout containing "hello\n".
	if err := WriteFrame(conn, FrameStdin, []byte("hello\n")); err != nil {
		t.Fatalf("WriteFrame stdin: %v", err)
	}

	gotEcho := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		ft, body, err := ReadFrame(conn)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			t.Fatalf("ReadFrame: %v", err)
			break
		}
		if ft == FrameStdout && len(body) > 0 {
			gotEcho = true
			break
		}
	}
	if !gotEcho {
		t.Fatal("no FrameStdout with body received within 2s")
	}

	cancel()
	_ = wait()
}

func TestSidecarDieNowExitsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sockPath, _, wait := startSidecar(t, ctx)
	conn := dialWithRetry(t, sockPath)
	defer conn.Close()

	start := time.Now()
	if err := WriteFrame(conn, FrameDieNow, nil); err != nil {
		t.Fatalf("WriteFrame die_now: %v", err)
	}
	if err := wait(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("die_now teardown took %s (want < 3s)", elapsed)
	}
}

func TestSidecarGraceTimeoutKillsChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sockPath, _, wait := startSidecar(t, ctx, func(c *Config) {
		c.GraceSecs = 1
	})
	conn := dialWithRetry(t, sockPath)

	// Close the conn — the sidecar should enter grace, wait ~1s, then exit.
	start := time.Now()
	_ = conn.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 700*time.Millisecond || elapsed > 4*time.Second {
		t.Errorf("grace teardown took %s (want ~1s ± slack)", elapsed)
	}
}

func TestSidecarBuffersWhileDetachedThenDrains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	// Use a shell that produces output autonomously (independent of
	// stdin), so the ring fills while no client is attached.
	cfg := Config{
		SocketPath:  filepath.Join(dir, "sidecar.sock"),
		PidfilePath: filepath.Join(dir, "sidecar.pid"),
		SessionID:   "test",
		Shell:       "/bin/sh",
		ShellArgs:   []string{"-c", "for i in 1 2 3 4 5 6 7 8 9 10; do echo line$i; sleep 0.05; done; sleep 5"},
		Rows:        24,
		Cols:        80,
		GraceSecs:   30,
		RingBytes:   4096,
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	// Attach briefly then detach immediately, before the shell has
	// produced its output.
	conn1 := dialWithRetry(t, cfg.SocketPath)
	_ = conn1.Close()

	// Sleep long enough for the shell to emit several lines while
	// nothing is attached — those bytes accumulate in the ring.
	time.Sleep(600 * time.Millisecond)

	conn2 := dialWithRetry(t, cfg.SocketPath)
	t.Cleanup(func() { _ = conn2.Close() })

	var got []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn2.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		ft, body, err := ReadFrame(conn2)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			break
		}
		if ft == FrameStdout {
			got = append(got, body...)
			if bytesContains(got, "line1") {
				break
			}
		}
	}
	if !bytesContains(got, "line1") {
		t.Fatalf("expected reattach to drain buffered output containing %q, got %q", "line1", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func bytesContains(haystack []byte, needle string) bool {
	return len(haystack) > 0 && stringContains(string(haystack), needle)
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSidecarSecondConcurrentDialRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sockPath, _, wait := startSidecar(t, ctx, func(c *Config) {
		c.GraceSecs = 30
	})

	conn1 := dialWithRetry(t, sockPath)
	defer conn1.Close()
	// Let the supervisor accept conn1 before we dial conn2.
	time.Sleep(100 * time.Millisecond)

	conn2 := dialWithRetry(t, sockPath)
	defer conn2.Close()
	// We expect a child_exit frame with signal == EBUSY.
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	tf, body, err := ReadFrame(conn2)
	if err != nil {
		t.Fatalf("read on refused conn: %v", err)
	}
	if tf != FrameChildExit {
		t.Errorf("want FrameChildExit on refused conn, got 0x%02x", tf)
	}
	_, sig, derr := DecodeChildExit(body)
	if derr != nil {
		t.Fatalf("DecodeChildExit: %v", derr)
	}
	if sig == 0 {
		t.Errorf("expected non-zero signal in refused frame, got %d", sig)
	}

	cancel()
	_ = wait()
}

func TestSidecarChildExitFramePropagated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	cfg := Config{
		SocketPath:  filepath.Join(dir, "sidecar.sock"),
		PidfilePath: filepath.Join(dir, "sidecar.pid"),
		SessionID:   "test",
		Shell:       "/bin/sh",
		ShellArgs:   []string{"-c", "sleep 0.3; exit 42"},
		Rows:        24,
		Cols:        80,
		GraceSecs:   5,
		RingBytes:   1024,
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	conn := dialWithRetry(t, cfg.SocketPath)
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// The child exits immediately; we should receive a FrameChildExit
	// with code=42 (the shell's `exit 42`).
	var (
		gotChildExit bool
		gotCode      int32
	)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		tf, body, err := ReadFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			break
		}
		if tf == FrameChildExit {
			gotChildExit = true
			gotCode, _, _ = DecodeChildExit(body)
			break
		}
	}
	if !gotChildExit {
		t.Fatal("no FrameChildExit received")
	}
	if gotCode != 42 {
		t.Errorf("child_exit.code: want 42, got %d", gotCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestSidecarRefusesIfPidfileLocked(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "sidecar.pid")

	// First sidecar — gets the pidfile.
	pf1, err := AcquirePidfile(pidPath, "test-binary")
	if err != nil {
		t.Fatalf("AcquirePidfile #1: %v", err)
	}
	defer pf1.Close()

	cfg := Config{
		SocketPath:  filepath.Join(dir, "sidecar.sock"),
		PidfilePath: pidPath,
		SessionID:   "test",
		Shell:       "/bin/cat",
	}
	rerr := Run(context.Background(), cfg)
	if !errors.Is(rerr, ErrPidfileLocked) {
		t.Fatalf("expected ErrPidfileLocked, got %v", rerr)
	}
}

func TestSidecarRemovesEnvFileAfterReading(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "env")
	if err := os.WriteFile(envPath, []byte("FOO=bar\nBAZ=qux\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{
		SocketPath:  filepath.Join(dir, "sidecar.sock"),
		PidfilePath: filepath.Join(dir, "sidecar.pid"),
		SessionID:   "test",
		Shell:       "/bin/cat",
		EnvFile:     envPath,
		GraceSecs:   1,
	}
	var done sync.WaitGroup
	done.Add(1)
	var runErr atomic.Value
	go func() {
		defer done.Done()
		if err := Run(ctx, cfg); err != nil {
			runErr.Store(err)
		}
	}()
	// Wait briefly for Run to load + delete the env file.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(envPath); errors.Is(err, os.ErrNotExist) {
			cancel()
			done.Wait()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	done.Wait()
	if e := runErr.Load(); e != nil {
		t.Logf("Run error: %v", e)
	}
	t.Fatal("env file still on disk after sidecar startup")
}
