package main

import "testing"

func TestSanitizeForDisplay(t *testing.T) {
	// U+FFFD, the replacement char the sanitizer substitutes in.
	repl := string(rune(0xFFFD))
	// C1 control characters (built as runes so the source stays ASCII).
	c1CSI := string(rune(0x9B)) // 8-bit CSI introducer
	c1Low := string(rune(0x80))
	c1High := string(rune(0x9F))
	nbsp := string(rune(0xA0)) // just above the C1 range — must survive

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain ascii", "claude", "claude"},
		{"plain with spaces", "my dev box", "my dev box"},
		{"tab preserved (tabwriter delimiter)", "a\tb", "a\tb"},
		{"multibyte utf8 preserved", "café — 日本語", "café — 日本語"},
		// ESC is the lead byte of every ANSI/CSI/OSC sequence.
		{"esc stripped", "a\x1bb", "a" + repl + "b"},
		{"csi color sequence", "\x1b[31mred\x1b[0m", repl + "[31mred" + repl + "[0m"},
		{"osc 52 clipboard write", "\x1b]52;c;ZWls\x07", repl + "]52;c;ZWls" + repl},
		{"bel stripped", "ding\x07", "ding" + repl},
		{"newline stripped", "line1\nline2", "line1" + repl + "line2"},
		{"carriage return stripped", "a\rb", "a" + repl + "b"},
		{"del stripped", "a\x7fb", "a" + repl + "b"},
		// C1 controls delivered as valid UTF-8 (as JSON decode produces
		// from \u008x escapes).
		{"c1 csi introducer stripped", "a" + c1CSI + "31mb", "a" + repl + "31mb"},
		{"c1 range low stripped", "a" + c1Low + "b", "a" + repl + "b"},
		{"c1 range high stripped", "a" + c1High + "b", "a" + repl + "b"},
		{"nbsp preserved", "a" + nbsp + "b", "a" + nbsp + "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeForDisplay(tc.in); got != tc.want {
				t.Errorf("sanitizeForDisplay(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeForDisplayInvalidUTF8(t *testing.T) {
	// A lone 0x9b byte is not valid UTF-8; a terminal in an 8-bit mode
	// could read it as the CSI introducer, so it must be neutralized
	// rather than passed through undecoded.
	got := sanitizeForDisplay("a\x9bb")
	want := "a" + string(rune(0xFFFD)) + "b"
	if got != want {
		t.Errorf("sanitizeForDisplay(lone 0x9b) = %q, want %q", got, want)
	}
}

func TestSanitizeForDisplayNoChangeOnCleanInput(t *testing.T) {
	// Clean input round-trips as the identical string (documented
	// fast path).
	in := "perfectly-ordinary-name"
	if got := sanitizeForDisplay(in); got != in {
		t.Errorf("sanitizeForDisplay(%q) = %q, want unchanged", in, got)
	}
}

func TestSanitizeForCellNeutralizesTab(t *testing.T) {
	repl := string(rune(0xFFFD))
	// In a tabwriter cell the caller owns the column delimiters, so a
	// content-embedded TAB must be neutralized (it would otherwise
	// inject a spurious column boundary and spoof the row).
	cases := []struct{ name, in, want string }{
		{"embedded tab neutralized", "a\tb", "a" + repl + "b"},
		{"leading tab neutralized", "\tname", repl + "name"},
		{"tab plus esc both neutralized", "a\tb\x1bc", "a" + repl + "b" + repl + "c"},
		{"plain text unchanged", "session-name", "session-name"},
		{"multibyte still passes", "café", "café"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeForCell(tc.in); got != tc.want {
				t.Errorf("sanitizeForCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// The default display sanitizer must STILL preserve TAB (tabwriter
	// aligns on it): guard against a regression that collapses the two.
	if got := sanitizeForDisplay("a\tb"); got != "a\tb" {
		t.Errorf("sanitizeForDisplay must preserve TAB, got %q", got)
	}
}

func TestSanitizeMultilineForDisplay(t *testing.T) {
	repl := string(rune(0xFFFD))
	cases := []struct{ name, in, want string }{
		// Newlines are preserved so a multi-line daemon block still
		// renders as lines; escapes within each line are neutralized.
		{"newlines preserved", "line1\nline2", "line1\nline2"},
		{"esc inside a line neutralized, newline kept",
			"ok\n\x1b[31mbad\x1b[0m\ndone", "ok\n" + repl + "[31mbad" + repl + "[0m\ndone"},
		{"trailing newline kept", "one line\n", "one line\n"},
		{"stray CR within a line neutralized", "a\rb\nc", "a" + repl + "b\nc"},
		{"tab preserved (raw terminal, not tabwriter)", "col1\tcol2\nrow", "col1\tcol2\nrow"},
		{"single line delegates to sanitizeForDisplay", "\x1bx", repl + "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeMultilineForDisplay(tc.in); got != tc.want {
				t.Errorf("sanitizeMultilineForDisplay(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
