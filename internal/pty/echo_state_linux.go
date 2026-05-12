//go:build linux

package pty

import "golang.org/x/sys/unix"

// TermiosState returns the slave-side ECHO and ICANON termios flags
// in one tcgetattr call. We query the master fd; the kernel reports
// the slave's termios because both sides share the structure.
// ok=false means the query failed (fd closed, kernel error) and the
// caller should treat both flags as "unknown" — not as a state change.
//
// Linux uses the TCGETS ioctl.
//
// ECHO governs printable-char echo (cleared by `read -s`, vim, etc).
// ICANON governs line-buffered (canonical) mode (cleared by raw apps).
// Clients arm printable-char prediction on ECHO=on, arm backspace +
// line-edit prediction on ICANON=on.
func (h *Handle) TermiosState() (echo, canon, ok bool) {
	h.fdMu.RLock()
	defer h.fdMu.RUnlock()
	if h.closed {
		return false, false, false
	}
	t, err := unix.IoctlGetTermios(int(h.pt.Fd()), unix.TCGETS)
	if err != nil {
		return false, false, false
	}
	return t.Lflag&unix.ECHO != 0, t.Lflag&unix.ICANON != 0, true
}
