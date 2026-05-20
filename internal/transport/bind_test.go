package transport

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// pickFreeUDPPort asks the kernel for an ephemeral UDP port, releases
// it, and returns the number. The returned port is highly likely (not
// strictly guaranteed) to be free in the immediate next call to bind.
// Acceptable for tests because the worst case is a flaky test rerun.
func pickFreeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	_ = conn.Close()
	return port
}

func TestBindUDPWithFallbackHappyPath(t *testing.T) {
	port := pickFreeUDPPort(t)
	dir := t.TempDir()
	addr := "127.0.0.1:" + strconv.FormatUint(uint64(port), 10)

	conn, err := bindUDPWithFallback(addr, dir)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer conn.Close()

	bound := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	if bound != port {
		t.Errorf("happy path bound %d, want %d", bound, port)
	}
	if stuck := readPortState(dir); stuck != port {
		t.Errorf("state file: got %d, want %d", stuck, port)
	}
}

func TestBindUDPWithFallbackFallsThroughOnEADDRINUSE(t *testing.T) {
	port := pickFreeUDPPort(t)

	// Pre-bind the preferred port to simulate a WireGuard-style
	// collision. Hold it for the duration of the test.
	blocker, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"), Port: int(port),
	})
	if err != nil {
		t.Fatalf("pre-bind blocker: %v", err)
	}
	defer blocker.Close()

	dir := t.TempDir()
	addr := "127.0.0.1:" + strconv.FormatUint(uint64(port), 10)

	conn, err := bindUDPWithFallback(addr, dir)
	if err != nil {
		t.Fatalf("bind with collision: %v", err)
	}
	defer conn.Close()

	bound := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	if bound == port {
		t.Errorf("bound the blocked port %d — fallback didn't trigger", port)
	}
	if bound < port || bound > port+FallbackPortSpan {
		t.Errorf("bound %d outside fallback range %d–%d",
			bound, port, port+FallbackPortSpan)
	}
	// State file should reflect the actually-bound port, not the
	// configured preference.
	if stuck := readPortState(dir); stuck != bound {
		t.Errorf("state file: got %d, want %d (the bound port)", stuck, bound)
	}
}

func TestBindUDPWithFallbackHonoursStickiness(t *testing.T) {
	// Set up a state file pointing at a specific port. Use
	// DefaultQUICPort as the preferred port so stickiness is
	// active (it's gated to default-port preference only).
	stickyPort := pickFreeUDPPort(t)
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, portStateFile),
		[]byte(strconv.FormatUint(uint64(stickyPort), 10)+"\n"),
		0o600,
	); err != nil {
		t.Fatalf("seed state file: %v", err)
	}

	addr := "127.0.0.1:" + strconv.FormatUint(uint64(DefaultQUICPort), 10)
	conn, err := bindUDPWithFallback(addr, dir)
	if err != nil {
		// If DefaultQUICPort happens to be in use in CI, the
		// test would land on a fallback. Stickiness should still
		// have placed stickyPort *first* in the candidate list,
		// so we'd land on stickyPort unless that's ALSO taken.
		// Just skip the test in that pathological case.
		t.Skipf("bind: %v (possibly transient port conflict)", err)
	}
	defer conn.Close()

	bound := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	if bound != stickyPort {
		t.Errorf("with sticky=%d + default pref, bound %d, want %d",
			stickyPort, bound, stickyPort)
	}
}

func TestBindUDPWithFallbackEphemeralPortNoFallback(t *testing.T) {
	// Port 0 means "OS picks ephemeral". The fallback logic is
	// inappropriate here — bind once, no stickiness write.
	dir := t.TempDir()
	conn, err := bindUDPWithFallback("127.0.0.1:0", dir)
	if err != nil {
		t.Fatalf("bind ephemeral: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr().(*net.UDPAddr).Port == 0 {
		t.Errorf("OS-picked port should be non-zero")
	}
	// State file should NOT have been written for ephemeral binds —
	// stickiness on a port the caller asked the OS to pick doesn't
	// make sense.
	if stuck := readPortState(dir); stuck != 0 {
		t.Errorf("ephemeral bind should not persist; got stuck=%d", stuck)
	}
}

func TestBindUDPWithFallbackPropagatesNonEADDRINUSE(t *testing.T) {
	// Binding to a privileged port (<1024) without root produces
	// EACCES, not EADDRINUSE. The bind loop must surface this
	// immediately instead of falling through.
	if syscall.Getuid() == 0 {
		t.Skip("running as root — can't test EACCES surfacing")
	}
	dir := t.TempDir()
	_, err := bindUDPWithFallback("127.0.0.1:80", dir)
	if err == nil {
		t.Fatal("expected error binding to port 80 as non-root")
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("got EADDRINUSE, want a non-EADDRINUSE error")
	}
	// Should NOT contain "no free UDP port" — that's the fallback-
	// exhausted message, which we'd hit only if we were incorrectly
	// treating EACCES as EADDRINUSE.
	if strings.Contains(err.Error(), "no free UDP port") {
		t.Errorf("bind loop incorrectly treated EACCES as EADDRINUSE: %v", err)
	}
}
