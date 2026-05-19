package session

import "sync"

// oscTitleTracker watches the PTY byte stream for OSC (Operating
// System Command) sequences that set the terminal title:
//
//   - OSC 0 ; <title> BEL/ST — set icon name AND window title
//   - OSC 1 ; <title> BEL/ST — set icon name only
//   - OSC 2 ; <title> BEL/ST — set window title only
//
// Where the framing is:
//   ESC ]                  — OSC introducer (0x1B 0x5D)
//   Ps                     — parameter (0, 1, or 2 here)
//   ;                      — separator
//   <title bytes>          — UTF-8 string
//   ST                     — string terminator: BEL (0x07) or ESC \ (0x1B 0x5C)
//
// We capture title bytes from OSC 0 and OSC 2 — OSC 1 sets just the
// icon name (a macOS / X11 concept) which iOS-side SwiftTerm doesn't
// surface. Other OSC numbers (4 = color spec, 8 = hyperlink, 10/11
// = fg/bg color, 52 = clipboard) are explicitly skipped — they share
// the OSC introducer but aren't titles.
//
// Used by Session + persistence layer to keep "last seen title"
// reliable across daemon restarts and truncated replays, so the iOS
// TUI-pill detection (which reads SwiftTerm.terminalTitle to
// distinguish Claude from Codex from generic) doesn't lose its
// signal when the original title-setting OSC gets evicted from the
// 4 MiB ring before a client reattach. Mirrors the v1.1.2/v1.1.3
// alt-screen pattern: state observed in the byte stream, persisted
// to meta.cbor, surfaced in AttachAck for client-side priming.
//
// Title length is capped at 256 bytes (well above any plausible
// shell/TUI title — `bash` writes paths there but most TUIs use
// short fixed strings like "Claude Code") to bound memory + meta
// growth. Titles longer than the cap are recorded as the leading
// 256 bytes; the rest is silently dropped.
const maxTrackedTitleLen = 256

type oscTitleTracker struct {
	mu       sync.Mutex
	state    oscState
	param    int    // numeric Ps value being parsed
	paramRaw []byte // accumulated digit bytes (for params we don't recognise)
	collect  []byte // accumulated title bytes (for params we capture)
	capture  bool   // whether the current OSC is one we want
	title    string // most recently completed title
}

type oscState int

const (
	oscNone     oscState = iota // outside an OSC sequence
	oscEsc                       // saw ESC, waiting for ']'
	oscParam                     // collecting digits of Ps
	oscBody                      // post-';' collecting title bytes
	oscBodyEsc                   // inside body, saw ESC, waiting for '\' (ST)
)

// feed parses one byte chunk. Mutates internal state; reports
// whether a fresh title was committed during this chunk (caller can
// use this to log transitions).
func (o *oscTitleTracker) feed(buf []byte) (changed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, b := range buf {
		switch o.state {
		case oscNone:
			if b == 0x1B {
				o.state = oscEsc
			}
		case oscEsc:
			if b == ']' {
				o.state = oscParam
				o.param = 0
				o.paramRaw = o.paramRaw[:0]
				o.collect = o.collect[:0]
				o.capture = false
			} else {
				// ESC followed by something other than `]` — not
				// an OSC. Reset; the byte we just consumed may
				// itself be the start of a fresh sequence, but
				// the altScreenTracker handles those — we only
				// care about OSC.
				o.state = oscNone
			}
		case oscParam:
			if b == ';' {
				// Lock in the parameter we collected. Only OSC 0
				// and OSC 2 set the title we care about; anything
				// else we still consume to end the sequence
				// cleanly, but we won't capture the body.
				o.capture = o.param == 0 || o.param == 2
				o.state = oscBody
			} else if b >= '0' && b <= '9' {
				if len(o.paramRaw) < 8 {
					o.paramRaw = append(o.paramRaw, b)
					o.param = o.param*10 + int(b-'0')
				}
				// Param longer than 8 digits → silently truncate;
				// real titles never need it.
			} else if b == 0x07 || b == 0x1B {
				// Premature terminator — abort.
				if b == 0x1B {
					o.state = oscBodyEsc
				} else {
					o.state = oscNone
				}
			} else {
				// Non-digit, non-semicolon in param — malformed.
				// Abort the sequence; let next ESC start fresh.
				o.state = oscNone
			}
		case oscBody:
			if b == 0x07 {
				o.commitLocked()
				o.state = oscNone
				changed = changed || true
			} else if b == 0x1B {
				o.state = oscBodyEsc
			} else {
				if o.capture && len(o.collect) < maxTrackedTitleLen {
					o.collect = append(o.collect, b)
				}
			}
		case oscBodyEsc:
			if b == '\\' {
				// ESC \ = String Terminator (ST). Commit if we
				// were capturing.
				if o.capture {
					o.commitLocked()
					changed = changed || true
				}
				o.state = oscNone
			} else {
				// ESC followed by non-`\` inside body is malformed.
				// Abort the OSC; do NOT commit a partial title.
				o.state = oscNone
			}
		}
	}
	return changed
}

// commitLocked promotes the accumulated bytes to `title`. Called
// only when capture==true. Caller must hold o.mu.
func (o *oscTitleTracker) commitLocked() {
	if !o.capture {
		return
	}
	// Trust the byte stream to be valid UTF-8 — Go's string(...)
	// conversion preserves bytes verbatim. SwiftTerm on the client
	// side will likewise process the bytes as UTF-8 once we re-
	// emit them via the OSC 2 inject. If a non-UTF-8 sequence
	// slipped in, the worst case is a mojibake title on the iOS
	// side, which is no worse than the pre-fix "no title at all"
	// state.
	o.title = string(o.collect)
	o.collect = o.collect[:0]
	o.capture = false
}

// Title returns the most recently observed title, or an empty
// string if none has been seen.
func (o *oscTitleTracker) Title() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.title
}

// SetTitle seeds the tracker's last-known title from persisted
// state. Called by loadSessionFromDir after construction; pre-fix
// snapshots default to empty, which is the right "unknown" state.
func (o *oscTitleTracker) SetTitle(t string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(t) > maxTrackedTitleLen {
		t = t[:maxTrackedTitleLen]
	}
	o.title = t
}
