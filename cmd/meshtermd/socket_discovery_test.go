package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverPicksXDGWhenSocketExists verifies the priority: if a
// socket is sitting at $XDG_RUNTIME_DIR/meshtermd.sock, that's the
// path discoverClientSocketPath returns — even when the persistent
// fallback would also be valid.
func TestDiscoverPicksXDGWhenSocketExists(t *testing.T) {
	tmp := t.TempDir()
	xdgDir := filepath.Join(tmp, "xdg")
	if err := os.MkdirAll(xdgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	xdgSock := filepath.Join(xdgDir, "meshtermd.sock")
	mustCreateSocketFile(t, xdgSock)

	t.Setenv("XDG_RUNTIME_DIR", xdgDir)

	got := discoverClientSocketPath()
	if got != xdgSock {
		t.Errorf("got %q, want %q", got, xdgSock)
	}
}

// TestDiscoverFallsBackToPersistentWhenXDGMissing simulates the
// SSH-exec case (XDG_RUNTIME_DIR unset). Should always pick the
// persistent path under $HOME/.local/share/meshtermd.
func TestDiscoverFallsBackToPersistentWhenXDGMissing(t *testing.T) {
	// Force the unset state. t.Setenv to "" still leaves it set;
	// use os.Unsetenv for the duration of the test.
	originalXDG := os.Getenv("XDG_RUNTIME_DIR")
	_ = os.Unsetenv("XDG_RUNTIME_DIR")
	t.Cleanup(func() {
		if originalXDG != "" {
			_ = os.Setenv("XDG_RUNTIME_DIR", originalXDG)
		}
	})

	got := discoverClientSocketPath()
	if !pathHasSuffix(got, "/.local/share/meshtermd/meshtermd.sock") {
		t.Errorf("got %q, want a path ending in .local/share/meshtermd/meshtermd.sock", got)
	}
}

// TestDiscoverFallsBackToPersistentWhenXDGEmpty is the laptop-with-
// gnome-but-no-daemon-bound-there case: XDG_RUNTIME_DIR is set but
// no socket file lives there. Discovery should silently fall through
// to the persistent path so the daemon installed via iOS (which pins
// the persistent path) is still reachable.
func TestDiscoverFallsBackToPersistentWhenXDGEmpty(t *testing.T) {
	tmp := t.TempDir()
	// Set XDG but don't create the socket file in it.
	t.Setenv("XDG_RUNTIME_DIR", tmp)

	got := discoverClientSocketPath()
	if !pathHasSuffix(got, "/.local/share/meshtermd/meshtermd.sock") {
		t.Errorf("got %q; expected fallback to persistent path", got)
	}
}

func mustCreateSocketFile(t *testing.T, path string) {
	t.Helper()
	// Stat-based discovery doesn't require an actual unix socket —
	// any regular file at the path satisfies os.Stat.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func pathHasSuffix(p, suffix string) bool {
	// strings.HasSuffix would do but we want to be defensive against
	// system-specific home-dir prefixes (e.g. /var/root on macOS CI).
	if len(p) < len(suffix) {
		return false
	}
	return p[len(p)-len(suffix):] == suffix
}
