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

// termiosFlags returns both ECHO and ICANON flags in one tcgetattr.
// See echo_state_linux.go for the contract. BSD uses TIOCGETA.
func termiosFlags(master *os.File) (echo, canon, ok bool) {
	t, err := unix.IoctlGetTermios(int(master.Fd()), unix.TIOCGETA)
	if err != nil {
		return false, false, false
	}
	return t.Lflag&unix.ECHO != 0, t.Lflag&unix.ICANON != 0, true
}
