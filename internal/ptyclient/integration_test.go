//go:build integration

package ptyclient

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ptysidecar"
)

// buildTestBinary compiles cmd/meshtermd into a temp file once per
// test process and returns its absolute path. The same binary
// supports the pty-sidecar subcommand we exercise via SpawnNew.
var (
	testBinPath string
	testBinOnce sync.Once
	testBinErr  error
)

func testBinary(t *testing.T) string {
	t.Helper()
	testBinOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "meshtermd-itest-*")
		if err != nil {
			testBinErr = err
			return
		}
		binPath := filepath.Join(tmpDir, "meshtermd")
		cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/meshtermd")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			testBinErr = err
			return
		}
		testBinPath = binPath
	})
	if testBinErr != nil {
		t.Fatalf("build test binary: %v", testBinErr)
	}
	return testBinPath
}

// TestSpawnNewEchoRoundTrip starts a real sidecar with /bin/cat and
// verifies stdin→stdout flows end-to-end through the daemon-side
// Conn.
func TestSpawnNewEchoRoundTrip(t *testing.T) {
	bin := testBinary(t)
	stateDir := t.TempDir()

	conn, err := SpawnNew(context.Background(), SpawnConfig{
		SessionID:    "0123456789abcdef0123456789abcdef",
		Shell:        "/bin/cat",
		Rows:         24, Cols: 80,
		StateDir:     stateDir,
		DaemonBinary: bin,
		GraceSecs:    5,
		RingBytes:    1024,
	})
	if err != nil {
		t.Fatalf("SpawnNew: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read in a goroutine and stop when we've seen "hello"; main
	// goroutine enforces the 3s wall-clock budget so a hung Read
	// can't park us forever.
	type readResult struct {
		got []byte
		err error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		var got []byte
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
				if bytesContains(got, "hello") {
					resultCh <- readResult{got: got}
					return
				}
			}
			if err != nil {
				resultCh <- readResult{got: got, err: err}
				return
			}
		}
	}()

	select {
	case r := <-resultCh:
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			t.Fatalf("Read err: %v", r.err)
		}
		if !bytesContains(r.got, "hello") {
			t.Errorf("echo did not round-trip; got %q", r.got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no echo data within 3s")
	}
}

func bytesContains(haystack []byte, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == needle {
			return true
		}
	}
	return false
}

// TestSpawnNewKillExitsImmediately checks that Kill() causes the
// sidecar to tear down within the die_now budget (~250ms-2s).
func TestSpawnNewKillExitsImmediately(t *testing.T) {
	bin := testBinary(t)
	stateDir := t.TempDir()
	sessionID := "fedcba9876543210fedcba9876543210"

	conn, err := SpawnNew(context.Background(), SpawnConfig{
		SessionID:    sessionID,
		Shell:        "/bin/cat",
		Rows:         24, Cols: 80,
		StateDir:     stateDir,
		DaemonBinary: bin,
		GraceSecs:    30,
		RingBytes:    1024,
	})
	if err != nil {
		t.Fatalf("SpawnNew: %v", err)
	}

	// Read the sidecar PID from its pidfile so we can watch it die.
	pidPath := filepath.Join(stateDir, "sessions", sessionID, "sidecar.pid")
	pid, _, err := ptysidecar.ReadPidfile(pidPath)
	if err != nil {
		t.Fatalf("ReadPidfile: %v", err)
	}

	_ = pid // captured for log/debug only; we detect exit via pidfile unlink

	start := time.Now()
	if err := conn.Kill(); err != nil {
		t.Logf("Kill returned (often expected on closed socket): %v", err)
	}

	// The sidecar unlinks its pidfile via the deferred pf.Close() in
	// ptysidecar.Run — so pidfile absence == sidecar's main has
	// returned. (Polling syscall.Kill(pid, 0) would falsely succeed
	// while the kernel still holds the zombie slot, since we
	// Process.Released and never Wait().)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(pidPath); errors.Is(statErr, os.ErrNotExist) {
			elapsed := time.Since(start)
			if elapsed > 3*time.Second {
				t.Errorf("Kill teardown took %s (want <3s)", elapsed)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sidecar did not unlink pidfile within 5s of Kill")
}
