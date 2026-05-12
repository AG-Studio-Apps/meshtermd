//go:build linux

package pty

import "golang.org/x/sys/unix"

// EchoEnabled returns whether the slave-side ECHO termios flag is
// currently set. We query the master fd; the kernel reports the
// slave's termios because both sides share the structure. ok=false
// means the query failed (fd closed, kernel error) and the caller
// should treat the result as "unknown" — not as a state change.
//
// Linux uses the TCGETS ioctl.
func (h *Handle) EchoEnabled() (echo bool, ok bool) {
	t, err := unix.IoctlGetTermios(int(h.pt.Fd()), unix.TCGETS)
	if err != nil {
		return false, false
	}
	return t.Lflag&unix.ECHO != 0, true
}
