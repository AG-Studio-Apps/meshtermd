package main

import (
	"strings"
	"testing"
)

// FuzzParseMTRMLine: arbitrary strings through the bootstrap line
// parser. Should never panic; should reject every shape that
// isn't exactly `MTRM_QUIC <ver> <port> <sid_32> <fp_64> <tok_32>`.
//
// Run with:
//   go test ./cmd/mtctl/ -fuzz=FuzzParseMTRMLine -run=^$ -fuzztime=30s
func FuzzParseMTRMLine(f *testing.F) {
	good := "MTRM_QUIC 1 53321 " +
		strings.Repeat("a", 32) + " " +
		strings.Repeat("b", 64) + " " +
		strings.Repeat("c", 32)
	f.Add(good)
	f.Add("")
	f.Add("MTRM_QUIC 0 0 0 0 0")
	f.Add("WRONG_SENTINEL " + strings.Repeat("a", 32))
	f.Add("MTRM_QUIC " + strings.Repeat("XX ", 100))
	f.Add(strings.Repeat("\x00", 200))
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseMTRMLine(line)
	})
}

// FuzzPickMTRMLine: arbitrary stdout (multi-line, with potential
// noise) through the MTRM_QUIC line picker.
func FuzzPickMTRMLine(f *testing.F) {
	f.Add("")
	f.Add("Welcome to host\nMTRM_QUIC 1 100 a b c\n")
	f.Add("MTRM_QUIC")
	f.Add(strings.Repeat("\n", 100))
	f.Add("MTRM_QUIC " + strings.Repeat("MTRM_QUIC ", 50))
	f.Fuzz(func(t *testing.T, stdout string) {
		_, _ = pickMTRMLine(stdout)
	})
}

// FuzzShellQuote: arbitrary user-supplied strings through the
// single-quote escape. Output should always be wrapped in
// single quotes and survive a round-trip back through `sh -c`
// (we don't actually invoke sh here — just verify the structural
// invariants: starts with ', ends with ', no UNESCAPED ' inside).
func FuzzShellQuote(f *testing.F) {
	f.Add("simple")
	f.Add("with space")
	f.Add("can't")
	f.Add(`a'b'c`)
	f.Add("$HOME; rm -rf /")
	f.Add("\x00")
	f.Add(strings.Repeat("'", 100))
	f.Fuzz(func(t *testing.T, s string) {
		out := shellQuote(s)
		if len(out) < 2 || out[0] != '\'' || out[len(out)-1] != '\'' {
			t.Errorf("shellQuote(%q) = %q — must be wrapped in single quotes", s, out)
		}
		// Every literal ' in the input must appear in the output as
		// the POSIX-escape `'\''` sequence and never as a bare '
		// inside the outer wrapping. Check by scanning the inner
		// region (everything between the wrapping quotes) for any
		// bare ' that isn't part of a `'\''` escape sequence.
		inner := out[1 : len(out)-1]
		for i := 0; i < len(inner); i++ {
			if inner[i] != '\'' {
				continue
			}
			// At each ', the next 3 characters must be `\''`.
			if i+3 >= len(inner) ||
				inner[i+1] != '\\' || inner[i+2] != '\'' || inner[i+3] != '\'' {
				t.Errorf("shellQuote(%q) = %q — bare single quote at offset %d", s, out, i)
			}
			i += 3 // skip the escape sequence
		}
	})
}
