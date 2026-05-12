package main

import (
	"bytes"
	"sync"
	"time"
	"unicode/utf8"
)

// PredictionEngine is the client-only (Stage A) predictive local echo
// for `mtctl attach`. It sits between the stdin pump (which forwards
// bytes to the daemon) and the stdout pump (which renders daemon output
// to the user's terminal), and gives the user an instant on-keystroke
// echo without waiting for the network round-trip.
//
// Design summary (see docs/predictive-echo.md for the long form):
//
//   - We maintain a FIFO queue of pending predictions, each one a
//     UTF-8-encoded rune (1–4 bytes). When the user types a
//     "predictable" rune (printable ASCII or Latin Extended; not
//     space-affecting controls), we mirror its UTF-8 bytes to stdout
//     immediately AND queue it.
//   - When the daemon sends output, we walk the bytes against the
//     head prediction's UTF-8 byte sequence. Each daemon byte that
//     matches the next expected byte CONFIRMS that byte of the head
//     — we suppress it because we already wrote it during OnUserInput.
//     When all bytes of the head's rune are consumed, we pop. A
//     non-matching byte ROLLS BACK every pending prediction via
//     "\b \b" sequences, re-emits the matched-but-suppressed bytes
//     of the current head (they're part of the daemon's actual
//     stream), and writes the daemon byte normally.
//   - Arming heuristic: watch the trailing 80 bytes of daemon output.
//     If it ends in something prompt-shaped ($ # > %) we arm. If we
//     see DECSET 1049 (alternate-screen enter — vim/less/htop) we
//     disarm. After a rollback we go into a short cool-down so we
//     don't churn predictions during a TUI session.
//   - Concurrency: OnUserInput and OnDaemonOutput can race (stdin
//     pump and stdout pump are independent goroutines), so a single
//     mutex serialises all state mutation.
//
// Stage B (daemon-aware EchoConfirm) overrides the arming heuristic
// with an authoritative signal from meshtermd's termios watcher. The
// state machine here doesn't change for Stage B — only the way
// `armed` gets toggled (via ForceArm from the EchoConfirm dispatch).
type PredictionEngine struct {
	mu sync.Mutex

	pending []prediction
	// headMatched is the number of bytes of pending[0].runeBytes that
	// have already matched daemon output. Confirmed full-rune when
	// headMatched == len(pending[0].runeBytes); we then pop and reset
	// to 0 for the next head.
	headMatched int

	// inBuf carries partial-rune UTF-8 bytes from a prior OnUserInput
	// call that didn't terminate on a rune boundary. Decoded on the
	// next call; flushed if it grows past utf8.UTFMax without forming
	// a complete rune (we treat it as garbage and disarm).
	inBuf []byte

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

	// canonMode tracks the daemon-reported ICANON termios flag — the
	// Stage B authoritative hint for "we're in a line-buffered editing
	// context where backspace prediction is safe." Sourced from
	// protocol.EchoConfirm.CanonMode via SetCanonMode. False by default
	// so backspace prediction stays off in raw-mode apps (vim, password
	// prompts) where DEL doesn't mean "erase last printable char."
	canonMode bool

	// underline, when true, wraps each predicted rune's mirror bytes
	// in SGR 4 (underline on) / SGR 24 (underline off) so the user
	// sees unconfirmed predictions visually distinguished from
	// confirmed output. Driven by --predict=adaptive (when smoothed
	// RTT exceeds the threshold) or --predict=always. The wrap is
	// purely a render trick at OnUserInput; the daemon's byte stream
	// is unaffected and the byte-level match/rollback logic doesn't
	// change. Cosmetic quirk: confirmed predictions stay underlined
	// until the next line redraw — acceptable for the high-latency
	// regime where adaptive underline is in use.
	underline bool
}

// SGR control sequences for SGR 4 (underline on) and SGR 24 (off).
// Used by OnUserInput when underline mode is enabled.
const (
	sgrUnderlineOn  = "\x1b[4m"
	sgrUnderlineOff = "\x1b[24m"
)

// prediction is one queued speculation. runeBytes holds the UTF-8
// encoding (1–4 bytes) of the predicted rune. Matching against daemon
// output is byte-by-byte against this slice via the engine's
// headMatched counter; confirmation pops once every byte matches.
type prediction struct {
	runeBytes []byte
	t         time.Time
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

// SetCanonMode records the daemon-reported ICANON state for backspace-
// prediction gating. Called from the attach loop's EchoConfirm
// dispatch on each daemon-pushed update. False is the safe default —
// backspace prediction only fires when the daemon has positively
// observed canonical mode (i.e., the user is at a shell prompt or in
// a `read`-style line edit, not in vim / less / a password prompt).
func (p *PredictionEngine) SetCanonMode(b bool) {
	p.mu.Lock()
	p.canonMode = b
	p.mu.Unlock()
}

// CanonMode returns the cached ICANON state for tests.
func (p *PredictionEngine) CanonMode() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.canonMode
}

// ForceDisarm clears the armed flag externally. Used by the
// EchoConfirm dispatch on EchoState=off so the engine stops mirroring
// keystrokes the moment a TUI takes over. Cooldown is left alone —
// the daemon's next on-transition can re-arm via ForceArm.
func (p *PredictionEngine) ForceDisarm() {
	p.mu.Lock()
	p.armed = false
	p.mu.Unlock()
}

// SetUnderline toggles whether OnUserInput wraps each predicted
// rune's mirror bytes in SGR 4 (underline) / SGR 24. Called from the
// attach loop based on `--predict` flag value + current RTT
// (adaptive). Safe to flip mid-attach; pending predictions already
// emitted aren't retroactively styled.
func (p *PredictionEngine) SetUnderline(b bool) {
	p.mu.Lock()
	p.underline = b
	p.mu.Unlock()
}

// OnUserInput is called by the stdin pump after the escape-watcher
// has stripped `~.` chords. It returns bytes to mirror to the user's
// terminal as a local echo. The caller MUST still forward `b` to the
// daemon — predict doesn't replace the wire send, only the local
// rendering.
//
// Bytes are walked rune-by-rune. Partial-rune tails (a multi-byte
// UTF-8 sequence that doesn't complete in this call) are buffered
// for the next OnUserInput. Unpredictable runes (controls, DEL, wide
// characters, combining marks) reset the queue and disarm — predicting
// through a newline / arrow key / wide-char would corrupt cursor
// position assumptions and we lose more than we gain.
func (p *PredictionEngine) OnUserInput(b []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled {
		return nil
	}
	if !p.armed || time.Now().Before(p.cooldownTo) {
		// Not predicting; clear any straggler partial-rune buffer so a
		// stale half-sequence doesn't poison the next armed period.
		p.inBuf = p.inBuf[:0]
		return nil
	}
	now := time.Now()
	// Append new bytes to the partial-rune buffer (almost always empty).
	p.inBuf = append(p.inBuf, b...)
	out := make([]byte, 0, len(p.inBuf))
	for len(p.inBuf) > 0 {
		c0 := p.inBuf[0]
		// Backspace prediction (Stage B): in canon mode + armed, a
		// DEL (0x7f) or BS (0x08) byte from the user drops the last
		// queued prediction and emits \b \b locally. We're already
		// past the !armed early-return above, so armed is guaranteed
		// true here. canonMode is the additional safety gate: in raw
		// mode (vim, password prompts) backspace doesn't mean "erase
		// last cell" so predicting it would mismatch and churn.
		if p.canonMode && (c0 == 0x7f || c0 == 0x08) {
			if len(p.pending) > 0 {
				p.pending = p.pending[:len(p.pending)-1]
				// If we just emptied the queue, reset the head-match
				// counter so the next prediction starts from byte 0.
				if len(p.pending) == 0 {
					p.headMatched = 0
				}
				out = append(out, '\b', ' ', '\b')
			}
			p.inBuf = p.inBuf[1:]
			continue
		}

		r, sz := utf8.DecodeRune(p.inBuf)
		if r == utf8.RuneError && sz == 1 && !utf8.FullRune(p.inBuf) {
			// Incomplete tail — wait for next call. Don't disarm; the
			// rest of the rune is likely en route.
			break
		}
		if !isPredictableRune(r) {
			// Either a control char, wide char, combining mark, or an
			// outright decode error. Reset the queue and disarm.
			p.pending = p.pending[:0]
			p.headMatched = 0
			p.armed = false
			p.inBuf = p.inBuf[:0]
			return out
		}
		runeBytes := make([]byte, sz)
		copy(runeBytes, p.inBuf[:sz])
		p.pending = append(p.pending, prediction{runeBytes: runeBytes, t: now})
		if p.underline {
			out = append(out, sgrUnderlineOn...)
			out = append(out, runeBytes...)
			out = append(out, sgrUnderlineOff...)
		} else {
			out = append(out, runeBytes...)
		}
		p.inBuf = p.inBuf[sz:]
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
		if len(p.pending) > 0 {
			head := p.pending[0].runeBytes
			if head[p.headMatched] == c {
				// Byte-level match against the current expected byte.
				// Suppress: the user already saw this byte via the
				// OnUserInput mirror.
				p.headMatched++
				if p.headMatched == len(head) {
					// Rune fully confirmed — pop and reset.
					p.pending = p.pending[1:]
					p.headMatched = 0
				}
				continue
			}
			// Mismatch. Walk back over every pending prediction with
			// \b \b sequences. Then re-emit the bytes of the current
			// head that already matched and got suppressed — they ARE
			// part of the daemon's actual byte stream, so the terminal
			// needs them to render correctly. Finally drop the queue
			// and enter cool-down so we don't keep predicting against
			// a TUI redraw.
			for range p.pending {
				out = append(out, '\b', ' ', '\b')
			}
			if p.headMatched > 0 {
				out = append(out, head[:p.headMatched]...)
			}
			p.pending = p.pending[:0]
			p.headMatched = 0
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
	// If the head we're expiring had partial-byte matches, those bytes
	// were already suppressed and won't be re-emitted by the daemon
	// (we consumed them). After rollback the terminal is in a clean
	// state for whatever the daemon sends next — accepting the loss
	// of a few suppressed bytes is the right call for a 2.5s-stale
	// prediction (the daemon plainly isn't echoing them).
	p.pending = p.pending[expired:]
	p.headMatched = 0
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

// isPredictableRune reports whether `r` is a rune we'd confidently
// predict an echo for. Includes ASCII printable (0x20–0x7E) and the
// most common single-cell precomposed Latin Extended ranges
// (0xA0–0x024F: Latin-1 Supplement excluding C1 controls, Latin
// Extended-A, Latin Extended-B). Excludes: controls, DEL, C1 controls
// (0x80–0x9F), combining marks (most fall outside our range anyway),
// wide CJK / emoji (out of our range), and anything else we can't
// guarantee is single-cell.
//
// This covers everyday typing for English + most European languages.
// CJK / emoji predictive echo requires East Asian Width awareness
// and grapheme-cluster handling; deferred to a later release.
func isPredictableRune(r rune) bool {
	switch {
	case r >= 0x20 && r <= 0x7E:
		return true // ASCII printable (excl. DEL)
	case r >= 0xA0 && r <= 0x024F:
		return true // Latin-1 Supplement + Latin Extended-A/B
	}
	return false
}

// Armed reports whether the engine is currently predicting. For
// tests.
func (p *PredictionEngine) Armed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.armed
}

// PendingCount reports queue depth (in runes, not bytes — a multi-
// byte UTF-8 rune counts as one). For tests.
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
