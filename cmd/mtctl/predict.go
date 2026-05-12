package main

import (
	"bytes"
	"sync"
	"time"
)

// PredictionEngine is the client-only (Stage A) predictive local echo
// for `mtctl attach`. It sits between the stdin pump (which forwards
// bytes to the daemon) and the stdout pump (which renders daemon output
// to the user's terminal), and gives the user an instant on-keystroke
// echo without waiting for the network round-trip.
//
// Design summary (see docs/predictive-echo.md for the long form):
//
//   - We maintain a FIFO queue of pending predictions: (byte, time).
//     When the user types a "predictable" byte (printable ASCII excl.
//     space-affecting controls), we mirror it to stdout immediately
//     AND queue it.
//   - When the daemon sends output, we walk the bytes against the
//     queue head. A matching byte CONFIRMS the prediction — we
//     suppress writing it locally because we already wrote it during
//     OnUserInput. A non-matching byte ROLLS BACK every pending
//     prediction via "\b \b" sequences, then writes the daemon byte
//     normally.
//   - Arming heuristic: watch the trailing 80 bytes of daemon output.
//     If it ends in something prompt-shaped ($ # > %) we arm. If we
//     see DECSET 1049 (alternate-screen enter — vim/less/htop) we
//     disarm. After a rollback we go into a short cool-down so we
//     don't churn predictions during a TUI session.
//   - Concurrency: OnUserInput and OnDaemonOutput can race (stdin
//     pump and stdout pump are independent goroutines), so a single
//     mutex serialises all state mutation.
//
// Stage B (daemon-aware EchoConfirm) will override the arming
// heuristic with an authoritative signal from meshtermd's termios
// watcher. The state machine here doesn't change for Stage B —
// only the way `armed` gets toggled.
type PredictionEngine struct {
	mu sync.Mutex

	pending    []prediction
	armed      bool
	cooldownTo time.Time
	tail       []byte // trailing window of recent daemon output (for prompt sniffing)

	// predictTimeout bounds how long a single prediction may live
	// unconfirmed before we forcibly roll it back. Without this, a
	// prediction made just before the user hits a TUI shortcut (Ctrl-F
	// during a search, etc.) would stick on screen indefinitely.
	predictTimeout time.Duration

	// cooldown bounds how long we stay disarmed after a rollback,
	// so we don't keep predicting → mismatching → rolling back during
	// a sustained TUI session.
	cooldown time.Duration

	// disabled short-circuits everything to the pass-through path.
	// Used by the --no-predict flag.
	disabled bool
}

type prediction struct {
	ch byte
	t  time.Time
}

// NewPredictionEngine returns a default-configured engine.
func NewPredictionEngine() *PredictionEngine {
	return &PredictionEngine{
		predictTimeout: 2500 * time.Millisecond,
		cooldown:       3 * time.Second,
	}
}

// Disable turns the engine into a no-op. Used by attach's --no-predict
// flag for users who'd rather have the bytes-as-they-come-in
// experience.
func (p *PredictionEngine) Disable() {
	p.mu.Lock()
	p.disabled = true
	p.mu.Unlock()
}

// OnUserInput is called by the stdin pump after the escape-watcher
// has stripped `~.` chords. It returns bytes to mirror to the user's
// terminal as a local echo. The caller MUST still forward `b` to the
// daemon — predict doesn't replace the wire send, only the local
// rendering.
//
// Bytes that aren't predictable (controls, high-bit, DEL) reset the
// queue and disarm the engine — predicting through a newline or tab
// would corrupt cursor position assumptions and we lose more than we
// gain.
func (p *PredictionEngine) OnUserInput(b []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled {
		return nil
	}
	if !p.armed || time.Now().Before(p.cooldownTo) {
		return nil
	}
	now := time.Now()
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if !isPredictable(c) {
			// Reset queue: anything pending was based on an arm we no
			// longer trust. The user types Enter / Ctrl-X / arrow keys
			// → we cease predicting until the next prompt-shape detect.
			p.pending = p.pending[:0]
			p.armed = false
			return out
		}
		p.pending = append(p.pending, prediction{ch: c, t: now})
		out = append(out, c)
	}
	return out
}

// OnDaemonOutput is called by the stdout pump with the bytes received
// from the daemon. It returns the bytes to actually write to the
// user's terminal. May suppress bytes that match pending predictions
// (we already wrote them locally) or prepend rollback sequences
// ("\b \b" per pending prediction) when a mismatch shows the daemon
// is doing something we didn't anticipate.
//
// Also updates the armed state from the trailing 80 bytes of output.
func (p *PredictionEngine) OnDaemonOutput(b []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled {
		return b
	}

	// Garbage-collect predictions that have aged out before we try to
	// match them. A prediction we made 3 seconds ago has no echo
	// coming — it'd never confirm; better to roll back now than to
	// leave it stuck on screen.
	out := make([]byte, 0, len(b)+len(p.pending)*3)
	out = p.expireStaleLocked(out)

	for _, c := range b {
		if len(p.pending) > 0 && p.pending[0].ch == c {
			// Confirm: head prediction matches the next daemon byte.
			// Don't write c — the user already saw it via OnUserInput.
			p.pending = p.pending[1:]
			continue
		}
		if len(p.pending) > 0 {
			// Mismatch. Walk back over every styled prediction with
			// \b \b sequences, drop the queue, and enter cool-down so
			// we don't keep predicting against a TUI redraw.
			for range p.pending {
				out = append(out, '\b', ' ', '\b')
			}
			p.pending = p.pending[:0]
			p.cooldownTo = time.Now().Add(p.cooldown)
			p.armed = false
		}
		out = append(out, c)
	}

	p.updateArmedFromTailLocked(b)
	return out
}

// expireStaleLocked drops any prediction older than predictTimeout
// from the front of the queue and emits the corresponding rollback
// sequences. Called from OnDaemonOutput, where we already hold the
// lock and have an output buffer in scope.
//
// Returns the (possibly-extended) output buffer.
func (p *PredictionEngine) expireStaleLocked(out []byte) []byte {
	if len(p.pending) == 0 {
		return out
	}
	now := time.Now()
	expired := 0
	for ; expired < len(p.pending); expired++ {
		if now.Sub(p.pending[expired].t) < p.predictTimeout {
			break
		}
	}
	if expired == 0 {
		return out
	}
	for i := 0; i < expired; i++ {
		out = append(out, '\b', ' ', '\b')
	}
	p.pending = p.pending[expired:]
	if expired > 0 {
		p.cooldownTo = now.Add(p.cooldown)
		p.armed = false
	}
	return out
}

// updateArmedFromTailLocked maintains the rolling 80-byte tail of
// daemon output and flips `armed` based on what it sees.
//
// This is the v1 (Stage A) heuristic. Stage B replaces this with an
// authoritative EchoConfirm signal from the daemon.
func (p *PredictionEngine) updateArmedFromTailLocked(b []byte) {
	const tailMax = 80
	if len(b) >= tailMax {
		p.tail = append(p.tail[:0], b[len(b)-tailMax:]...)
	} else {
		p.tail = append(p.tail, b...)
		if len(p.tail) > tailMax {
			p.tail = p.tail[len(p.tail)-tailMax:]
		}
	}

	// Alternate-screen enter — TUI is taking over the screen; predicting
	// against vim/less/htop output would churn rollbacks. Disarm hard.
	if bytes.Contains(b, []byte("\x1b[?1049h")) {
		p.armed = false
		p.cooldownTo = time.Now().Add(p.cooldown)
		return
	}
	// Alternate-screen exit — we're back to the main screen. Don't
	// auto-arm here; wait for a prompt sniff. The TUI might just be
	// painting an info bar.
	if bytes.Contains(b, []byte("\x1b[?1049l")) {
		// no-op; the next prompt detect will rearm.
	}

	if time.Now().Before(p.cooldownTo) {
		return
	}

	// Look at the trimmed tail: strip trailing spaces and a possible
	// CSI cursor-position sequence the shell emits after the prompt.
	// We don't try to be exhaustive — false negatives (no arm) are
	// safer than false positives (arming inside a TUI).
	tail := stripTrailingCSI(p.tail)
	tail = bytes.TrimRight(tail, " ")
	if len(tail) == 0 {
		return
	}
	last := tail[len(tail)-1]
	switch last {
	case '$', '#', '>', '%':
		p.armed = true
	}
}

// stripTrailingCSI removes any CSI (ESC [ ...) sequence at the end
// of buf. Returns a view of buf without the trailing sequence. Used
// so a prompt like "$ \x1b[6n" (cursor-position query) still arms.
func stripTrailingCSI(buf []byte) []byte {
	// Walk backwards from the end. CSI sequences end with a final
	// byte in 0x40-0x7E. The start is ESC [ ; if we find one of
	// those, we trim from there.
	for i := len(buf) - 1; i >= 1; i-- {
		c := buf[i]
		if c >= 0x40 && c <= 0x7E {
			// Possible CSI final byte. Look backward for ESC [.
			for j := i - 1; j >= 1; j-- {
				if buf[j] == '[' && buf[j-1] == 0x1b {
					return buf[:j-1]
				}
				if !isCSIParam(buf[j]) {
					break
				}
			}
		}
		// Don't loop further; only the trailing CSI gets stripped.
		break
	}
	return buf
}

// isCSIParam reports whether c is a valid CSI parameter / intermediate
// byte (0x20-0x3F). Used by stripTrailingCSI to walk back from a
// final byte to the start of the sequence.
func isCSIParam(c byte) bool { return c >= 0x20 && c <= 0x3F }

// isPredictable reports whether `c` is a printable ASCII byte we'd
// confidently predict an echo for. Conservatively limited to
// 0x20-0x7E (printable ASCII including space, excluding DEL). High-
// bit bytes are UTF-8 continuations whose echo width is ambiguous;
// controls (Ctrl-x, arrows) trigger shell-specific responses we
// can't anticipate.
func isPredictable(c byte) bool {
	return c >= 0x20 && c <= 0x7E
}

// Armed reports whether the engine is currently predicting. For
// tests.
func (p *PredictionEngine) Armed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.armed
}

// PendingCount reports queue depth. For tests.
func (p *PredictionEngine) PendingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// ForceArm sets armed=true bypassing the prompt-sniff heuristic.
// Used by tests; production code never calls this. Stage B's
// EchoConfirm wiring will call it (or a sibling) from the
// EchoState=on handler.
func (p *PredictionEngine) ForceArm() {
	p.mu.Lock()
	p.armed = true
	p.cooldownTo = time.Time{}
	p.mu.Unlock()
}
