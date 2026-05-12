//go:build linux

package ptysidecar

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoEnabled mirrors internal/pty/echo_state_linux.go: issue
// tcgetattr on the PTY master fd and report the slave-side ECHO
// flag. ok=false means the syscall errored (fd closed, kernel
// hiccup) — caller should report EchoUnknown.
func echoEnabled(master *os.File) (echo, ok bool) {
	t, err := unix.IoctlGetTermios(int(master.Fd()), unix.TCGETS)
	if err != nil {
		return false, false
	}
	return t.Lflag&unix.ECHO != 0, true
}

// termiosFlags returns both ECHO and ICANON flags in one tcgetattr
// call. Used by v0.7.0+ sidecar emit paths to carry both bits in
// the FrameEchoState body. ok=false means the syscall errored;
// caller should report Unknown for both. ICANON indicates line-
// buffered (canonical) mode; raw-mode apps (vim, htop, password
// prompts) clear it. Clients use canon to gate backspace prediction.
func termiosFlags(master *os.File) (echo, canon, ok bool) {
	t, err := unix.IoctlGetTermios(int(master.Fd()), unix.TCGETS)
	if err != nil {
		return false, false, false
	}
	return t.Lflag&unix.ECHO != 0, t.Lflag&unix.ICANON != 0, true
}
