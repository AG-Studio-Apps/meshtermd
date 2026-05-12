//go:build darwin || freebsd

package pty

import "golang.org/x/sys/unix"

// EchoEnabled returns whether the slave-side ECHO termios flag is
// currently set. See echo_state_linux.go for the contract.
//
// Darwin and FreeBSD both use the TIOCGETA ioctl (BSD-lineage
// constant). The Termios.Lflag width differs between the two
// (uint64 on Darwin, uint32 on FreeBSD), but the comparison
// promotes either to int so the ECHO check is identical.
func (h *Handle) EchoEnabled() (echo bool, ok bool) {
	h.fdMu.RLock()
	defer h.fdMu.RUnlock()
	if h.closed {
		return false, false
	}
	t, err := unix.IoctlGetTermios(int(h.pt.Fd()), unix.TIOCGETA)
	if err != nil {
		return false, false
	}
	return t.Lflag&unix.ECHO != 0, true
}
