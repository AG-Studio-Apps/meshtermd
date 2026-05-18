package transport

// PTY-dimension floor + ceiling enforced server-side as defence-in-depth
// against peer-supplied pathological values. The kernel's TIOCSWINSZ
// ioctl rejects most extremes, but a 1×1 or 65535×65535 has no legitimate
// terminal use and these bounds match the iOS client's own pre-send
// sanity check. Applied to both Resize CONTROL frames (handleControlFrame)
// and the Attach frame's initial Rows/Cols (protocol_handler) so the two
// entry points have symmetric posture.
//
// Audit history: F-I introduced the Resize-frame clamp; v1.0 hardening
// (audit Finding 7.1 / LOW) extended it to the Attach path and extracted
// the values here so any future bound change touches one location.
const (
	MinPTYRows uint16 = 3
	MaxPTYRows uint16 = 1000
	MinPTYCols uint16 = 10
	MaxPTYCols uint16 = 1000
)

// dimsInBounds reports whether the given (rows, cols) pair lies within
// the inclusive [MinPTYRows..MaxPTYRows] × [MinPTYCols..MaxPTYCols] range.
// Callers drop (or in the case of Attach, ignore) the dimensions on false.
func dimsInBounds(rows, cols uint16) bool {
	return rows >= MinPTYRows && rows <= MaxPTYRows &&
		cols >= MinPTYCols && cols <= MaxPTYCols
}
