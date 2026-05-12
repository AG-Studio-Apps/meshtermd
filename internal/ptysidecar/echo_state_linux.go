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
