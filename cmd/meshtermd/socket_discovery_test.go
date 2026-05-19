package main

import (
	"net"
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
	// VerifyClientSocket requires os.ModeSocket — a regular file no
	// longer passes (Codex audit 2026-05-19, MEDIUM). Listen so the
	// inode is a real unix socket. SetUnlinkOnClose(false) prevents
	// Go's default cleanup from removing the path when the listener
	// is closed — we want the socket inode to outlive this helper
	// (discoverClientSocketPath only checks the path, doesn't dial).
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(path)
	})
}

// TestDiscoverRefusesXDGSocketWithLooseParentPerms exercises the
// "world-writable XDG_RUNTIME_DIR" guard. With the parent dir at 0o777
// VerifyParentDir rejects the candidate, discovery falls back to the
// persistent path regardless of what's at the XDG location.
func TestDiscoverRefusesXDGSocketWithLooseParentPerms(t *testing.T) {
	tmp := t.TempDir()
	xdgDir := filepath.Join(tmp, "xdg-loose")
	if err := os.MkdirAll(xdgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Force loose perms (MkdirAll honours umask).
	if err := os.Chmod(xdgDir, 0o777); err != nil {
		t.Fatal(err)
	}
	xdgSock := filepath.Join(xdgDir, "meshtermd.sock")
	mustCreateSocketFile(t, xdgSock)
	t.Setenv("XDG_RUNTIME_DIR", xdgDir)

	got := discoverClientSocketPath()
	if !pathHasSuffix(got, "/.local/share/meshtermd/meshtermd.sock") {
		t.Errorf("got %q; expected fallback to persistent path (loose XDG parent should be refused)", got)
	}
}

// TestDiscoverRefusesXDGSymlinkAtSocketPath catches an attacker who
// can write to a properly-permissioned XDG_RUNTIME_DIR but plants a
// symlink at the socket name. VerifyClientSocket sees ModeSymlink
// and refuses; discovery falls back.
func TestDiscoverRefusesXDGSymlinkAtSocketPath(t *testing.T) {
	tmp := t.TempDir()
	xdgDir := filepath.Join(tmp, "xdg-symlink")
	if err := os.MkdirAll(xdgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(tmp, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realSock := filepath.Join(realDir, "real.sock")
	mustCreateSocketFile(t, realSock)
	xdgSock := filepath.Join(xdgDir, "meshtermd.sock")
	if err := os.Symlink(realSock, xdgSock); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", xdgDir)

	got := discoverClientSocketPath()
	if !pathHasSuffix(got, "/.local/share/meshtermd/meshtermd.sock") {
		t.Errorf("got %q; expected fallback to persistent (symlink at socket path should be refused)", got)
	}
}

// TestDiscoverRefusesXDGNonSocketAtPath covers the "regular file
// planted at the discovery name" case — pre-fix this would have been
// accepted via os.Stat.
func TestDiscoverRefusesXDGNonSocketAtPath(t *testing.T) {
	tmp := t.TempDir()
	xdgDir := filepath.Join(tmp, "xdg-regfile")
	if err := os.MkdirAll(xdgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	xdgSock := filepath.Join(xdgDir, "meshtermd.sock")
	f, err := os.Create(xdgSock)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Setenv("XDG_RUNTIME_DIR", xdgDir)

	got := discoverClientSocketPath()
	if !pathHasSuffix(got, "/.local/share/meshtermd/meshtermd.sock") {
		t.Errorf("got %q; expected fallback to persistent (non-socket at path should be refused)", got)
	}
}

func pathHasSuffix(p, suffix string) bool {
	// strings.HasSuffix would do but we want to be defensive against
	// system-specific home-dir prefixes (e.g. /var/root on macOS CI).
	if len(p) < len(suffix) {
		return false
	}
	return p[len(p)-len(suffix):] == suffix
}
