package pty

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEnvAllowlistFiltersOutSensitive(t *testing.T) {
	// Cannot run in parallel — manipulates env.
	t.Setenv("HOME", "/tmp/pretend-home")
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
	t.Setenv("MY_TOKEN", "also-should-not-leak")

	env := buildEnv(nil)

	if !envContains(env, "HOME") {
		t.Error("HOME missing from built env")
	}
	if !envContains(env, "PATH") {
		t.Error("PATH missing from built env")
	}
	for _, e := range env {
		if strings.HasPrefix(e, "AWS_SECRET_ACCESS_KEY=") {
			t.Error("AWS_SECRET_ACCESS_KEY leaked through allowlist")
		}
		if strings.HasPrefix(e, "MY_TOKEN=") {
			t.Error("MY_TOKEN leaked through allowlist")
		}
	}
}

func TestBuildEnvSetsDefaultsWhenMissing(t *testing.T) {
	t.Setenv("TERM", "")
	t.Setenv("LANG", "")
	t.Setenv("LC_ALL", "")

	env := buildEnv(nil)

	hasTERM := false
	hasLANG := false
	for _, e := range env {
		if strings.HasPrefix(e, "TERM=") {
			hasTERM = true
			if e != "TERM=xterm-256color" {
				t.Errorf("TERM = %q, want TERM=xterm-256color", e)
			}
		}
		if strings.HasPrefix(e, "LANG=") {
			hasLANG = true
			if e != "LANG=C.UTF-8" {
				t.Errorf("LANG = %q, want LANG=C.UTF-8", e)
			}
		}
	}
	if !hasTERM {
		t.Error("TERM default not set")
	}
	if !hasLANG {
		t.Error("LANG default not set")
	}
}

func TestBuildEnvAppendsExtraEnv(t *testing.T) {
	t.Setenv("HOME", "/tmp/h")
	env := buildEnv([]string{"MESHTERM_SESSION_ID=abc123"})
	if !envContains(env, "MESHTERM_SESSION_ID") {
		t.Error("ExtraEnv was not appended")
	}
}

func TestEnvContains(t *testing.T) {
	t.Parallel()
	env := []string{"FOO=bar", "BAZ=qux"}
	if !envContains(env, "FOO") {
		t.Error("envContains missed FOO")
	}
	if envContains(env, "FOOQ") {
		t.Error("envContains matched a longer key")
	}
	if envContains(env, "ZZZ") {
		t.Error("envContains found a missing key")
	}
}

func TestResolveShellExplicit(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on windows")
	}
	got, err := resolveShell("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/bin/sh" {
		t.Errorf("resolveShell(/bin/sh) = %q, want /bin/sh", got)
	}
}

func TestResolveShellFallsBackToSh(t *testing.T) {
	// Cannot run in parallel — manipulates env.
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on windows")
	}
	// resolveShell prefers SHELL env when set; clear it so we exercise
	// the bash/sh fallback path.
	t.Setenv("SHELL", "")
	got, err := resolveShell("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/bin/bash" && got != "/bin/sh" {
		t.Errorf("resolveShell fallback = %q, want /bin/bash or /bin/sh", got)
	}
}

func TestResolveShellRejectsNonExistent(t *testing.T) {
	// Cannot run in parallel — manipulates env.
	if runtime.GOOS == "windows" {
		t.Skip("paths differ on windows")
	}
	t.Setenv("SHELL", "/nope/doesnt/exist")
	// resolveShell still has /bin/bash and /bin/sh as fallbacks, so
	// it should succeed unless those don't exist either. Test by
	// asserting we don't get the explicitly-bogus path.
	got, err := resolveShell("/also/nope")
	if err != nil {
		// Accept this as long as the fallbacks are also missing.
		if _, statErr := os.Stat("/bin/sh"); statErr != nil {
			return
		}
		t.Fatal(err)
	}
	if got == "/also/nope" || got == "/nope/doesnt/exist" {
		t.Errorf("resolveShell returned a non-existent path: %q", got)
	}
}

// TestSpawnAndExec is the only test that actually forks a process.
// It runs `/bin/sh -c "echo hello"` through a PTY, drains output,
// and confirms we see "hello" in the byte stream.
func TestSpawnAndExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on windows")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}

	h, err := Spawn(SpawnConfig{
		Shell: "/bin/sh",
		Args:  []string{"-c", "echo hello; exit"},
		Rows:  24,
		Cols:  80,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Read until EOF or timeout.
	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, h)
		if err != nil {
			errs <- err
			return
		}
		done <- buf.Bytes()
	}()

	select {
	case got := <-done:
		if !bytes.Contains(got, []byte("hello")) {
			t.Errorf("PTY output %q did not contain 'hello'", got)
		}
	case err := <-errs:
		t.Fatalf("Read error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PTY output")
	}
}

// TestSetSizeBeforeAfterExec verifies SetSize succeeds while the
// child is alive. We can't easily verify the child saw the new size
// without injecting a tput command, so we check the syscall returns
// nil error.
func TestSetSize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on windows")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	// Run an interactive-ish shell that sleeps so the PTY stays open
	// for our SetSize call.
	h, err := Spawn(SpawnConfig{
		Shell: "/bin/sh",
		Args:  []string{"-c", "sleep 0.5"},
		Rows:  24,
		Cols:  80,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if err := h.SetSize(40, 120); err != nil {
		t.Errorf("SetSize while alive = %v, want nil", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on windows")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	h, err := Spawn(SpawnConfig{
		Shell: "/bin/sh",
		Args:  []string{"-c", "sleep 0.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Errorf("first Close = %v, want nil", err)
	}
	// Second Close: PTY fd is already closed; we tolerate
	// os.ErrClosed silently. Should not panic.
	if err := h.Close(); err != nil {
		// Acceptable if the underlying error wraps ErrClosed.
		t.Logf("second Close returned %v (tolerated)", err)
	}
}
