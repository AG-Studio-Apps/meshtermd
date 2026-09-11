package main

import (
	"strings"
	"unicode/utf8"
)

// sanitizeForDisplay neutralizes terminal control and escape bytes in a
// string that crosses a trust boundary before it is rendered into the
// operator's local terminal by a STRUCTURED (table/list/panel) command.
//
// The inputs of concern are daemon-decoded session metadata (a session
// Name or foreground command from `mtroamd list --json`, a status
// field, an attach peer/mode) and scrollback ring content from
// `mtroam search` — arbitrary bytes emitted by whatever ran in the
// remote shell. Rendered verbatim, an attacker who controls any of
// these could inject OSC 52 clipboard writes, cursor/screen spoofing,
// or title-report keystroke injection into the operator's terminal.
//
// It replaces, with the Unicode replacement character U+FFFD:
//   - C0 control characters (< 0x20) — this includes ESC (0x1b), the
//     lead byte of every ANSI/CSI/OSC escape sequence, plus BEL, CR,
//     LF, etc.
//   - DEL (0x7f)
//   - C1 control characters (0x80–0x9f) — the 8-bit CSI/OSC/DCS
//     introducers
//   - invalid UTF-8 bytes — so a raw 8-bit control byte (e.g. a lone
//     0x9b CSI) can't slip through undecoded
//
// TAB (0x09) is intentionally preserved: it is not an escape vector and
// tabwriter relies on it as the column delimiter. Ordinary printable
// text, including multibyte UTF-8, passes through unchanged so normal
// session names and match lines render exactly as before.
//
// This is display-only sanitization for the structured commands. The
// attach/tail full-relay shell byte-stream passthrough is intentionally
// NOT routed through here — that raw stream is by design.
func sanitizeForDisplay(s string) string { return sanitizeString(s, false) }

// sanitizeForCell is sanitizeForDisplay for a value written AS A FIELD
// into a tabwriter row. It ALSO neutralizes TAB (0x09): the caller
// supplies the column delimiters, so a TAB embedded in daemon-supplied
// content (a session Name, a scrollback match line) would otherwise
// inject a spurious column boundary and shift or spoof the rest of the
// row — a display-integrity hole in the very table being hardened.
func sanitizeForCell(s string) string { return sanitizeString(s, true) }

// sanitizeMultilineForDisplay sanitizes a multi-LINE daemon-supplied text
// block — the re-run `mtroamd doctor` report, a daemon stdout
// confirmation, or daemon stderr on an error path — for rendering to the
// operator's terminal. Line breaks (\n) are PRESERVED so a legitimately
// multi-line block still renders as lines; every other control/escape
// byte within each line is neutralized exactly as sanitizeForDisplay
// does (including a stray CR). TAB is preserved: these blocks go to the
// raw terminal, not a tabwriter, so a TAB is just whitespace here.
func sanitizeMultilineForDisplay(s string) string {
	if !strings.ContainsRune(s, '\n') {
		return sanitizeForDisplay(s)
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = sanitizeForDisplay(ln)
	}
	return strings.Join(lines, "\n")
}

func sanitizeString(s string, cell bool) string {
	if isDisplaySafe(s, cell) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte: replace so a raw 8-bit control can't
			// reach the terminal undecoded.
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		if isDisplayControl(r, cell) {
			b.WriteRune(utf8.RuneError)
			i += size
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// isDisplaySafe reports whether s can be rendered verbatim — no control
// runes and no invalid UTF-8. The common case (a plain name or line)
// returns true so sanitizeString can hand back the original string
// without allocating. When cell is set, TAB counts as unsafe.
func isDisplaySafe(s string, cell bool) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if isDisplayControl(r, cell) {
			return false
		}
		i += size
	}
	return true
}

// isDisplayControl reports whether r is a control character that must not
// reach an interactive terminal verbatim. TAB is a control only in cell
// mode (where the caller owns the tabwriter column delimiters); in the
// default mode it is preserved so tabwriter can align on it.
func isDisplayControl(r rune, cell bool) bool {
	switch {
	case r == '\t':
		return cell
	case r < 0x20:
		return true // C0 controls, including ESC
	case r == 0x7f:
		return true // DEL
	case r >= 0x80 && r <= 0x9f:
		return true // C1 controls
	default:
		return false
	}
}
