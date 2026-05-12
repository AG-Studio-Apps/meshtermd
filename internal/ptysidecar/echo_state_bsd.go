//go:build darwin || freebsd

package ptysidecar

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoEnabled mirrors internal/pty/echo_state_bsd.go.
func echoEnabled(master *os.File) (echo, ok bool) {
	t, err := unix.IoctlGetTermios(int(master.Fd()), unix.TIOCGETA)
	if err != nil {
		return false, false
	}
	return t.Lflag&unix.ECHO != 0, true
}
