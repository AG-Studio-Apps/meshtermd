package main

import (
	"strings"
	"testing"
)

// MTRM_QUIC line shape: MTRM_QUIC <ver> <port> <sid_32> <fp_64> <tok_32>
const goodMTRMLine = "MTRM_QUIC 1 53321 " +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa " + // 32 hex
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb " + // 64 hex
	"cccccccccccccccccccccccccccccccc" // 32 hex

func TestParseMTRMLine(t *testing.T) {
	got, err := parseMTRMLine(goodMTRMLine)
	if err != nil {
		t.Fatalf("parseMTRMLine: %v", err)
	}
	if got.version != 1 {
		t.Errorf("version = %d, want 1", got.version)
	}
	if got.port != 53321 {
		t.Errorf("port = %d, want 53321", got.port)
	}
	if len(got.sessionID) != 16 {
		t.Errorf("sessionID len = %d, want 16", len(got.sessionID))
	}
	if len(got.certFingerprint) != 32 {
		t.Errorf("certFingerprint len = %d, want 32", len(got.certFingerprint))
	}
	if len(got.attachToken) != 16 {
		t.Errorf("attachToken len = %d, want 16", len(got.attachToken))
	}
}

func TestParseMTRMLineRejectsMalformed(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		{"missing sentinel", "WRONG 1 100 a b c d"},
		{"wrong field count", "MTRM_QUIC 1 100 a b"},
		{"bad port", "MTRM_QUIC 1 0 " + strings.Repeat("a", 32) + " " + strings.Repeat("b", 64) + " " + strings.Repeat("c", 32)},
		{"short sid hex", "MTRM_QUIC 1 100 ab " + strings.Repeat("b", 64) + " " + strings.Repeat("c", 32)},
		{"short fp hex", "MTRM_QUIC 1 100 " + strings.Repeat("a", 32) + " bb " + strings.Repeat("c", 32)},
		{"short tok hex", "MTRM_QUIC 1 100 " + strings.Repeat("a", 32) + " " + strings.Repeat("b", 64) + " cc"},
		// Note: uppercase hex IS accepted by hex.DecodeString (and by
		// iOS's parser), so the bootstrap parser doesn't reject it.
		// The daemon emits lowercase by convention but clients that
		// hand-craft a bootstrap line with uppercase are tolerated.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMTRMLine(tc.line); err == nil {
				t.Errorf("parseMTRMLine(%q) returned nil error", tc.line)
			}
		})
	}
}

func TestPickMTRMLineSkipsNoise(t *testing.T) {
	// Login banner / motd / shell-startup noise can land on stdout
	// in front of the bootstrap line. The picker scans for the
	// MTRM_QUIC sentinel and ignores everything else.
	stdout := "Welcome to host.example.com\nLast login: today\n" + goodMTRMLine + "\n"
	got, err := pickMTRMLine(stdout)
	if err != nil {
		t.Fatalf("pickMTRMLine: %v", err)
	}
	if got != goodMTRMLine {
		t.Errorf("pickMTRMLine returned wrong line: %q", got)
	}
}

func TestIsHexSessionID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"abcdef0123456789abcdef0123456789", true},
		{"main", false},
		{"new", false},
		{"ABCDEF0123456789ABCDEF0123456789", false}, // uppercase rejected
		{"abc", false},                              // too short
		{strings.Repeat("a", 33), false},            // too long
		{"abcdef0123456789abcdef012345678g", false}, // non-hex
	}
	for _, tc := range cases {
		if got := isHexSessionID(tc.in); got != tc.want {
			t.Errorf("isHexSessionID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestEscapeWatcherForwardsPlainBytes(t *testing.T) {
	w := newEscapeWatcher()
	out, detach := w.process([]byte("hello world\n"))
	if detach {
		t.Error("plain input triggered detach")
	}
	if string(out) != "hello world\n" {
		t.Errorf("out = %q, want %q", string(out), "hello world\n")
	}
}

func TestEscapeWatcherDetectsChord(t *testing.T) {
	w := newEscapeWatcher()
	// First a newline to land us at line-start, then ~. to detach.
	out1, det1 := w.process([]byte("ls\n"))
	if det1 {
		t.Fatal("ls\\n shouldn't detach")
	}
	if string(out1) != "ls\n" {
		t.Errorf("ls\\n out = %q", string(out1))
	}
	out2, det2 := w.process([]byte("~."))
	if !det2 {
		t.Fatal("~. at line-start should detach")
	}
	if len(out2) != 0 {
		t.Errorf("detach out had bytes: %q", string(out2))
	}
}

func TestEscapeWatcherTildeMidLineIsLiteral(t *testing.T) {
	// ~ that isn't at line-start is just text.
	w := newEscapeWatcher()
	out, detach := w.process([]byte("echo ~/home\n"))
	if detach {
		t.Error("mid-line ~ triggered detach")
	}
	if string(out) != "echo ~/home\n" {
		t.Errorf("out = %q", string(out))
	}
}

func TestEscapeWatcherDoubledTildeIsLiteral(t *testing.T) {
	// At line-start, `~~` should forward one literal ~ and stay
	// armed (the "escape the escape" convention from ssh/mosh).
	w := newEscapeWatcher()
	out, detach := w.process([]byte("~~"))
	if detach {
		t.Fatal("~~ shouldn't detach")
	}
	if string(out) != "~" {
		t.Errorf("~~ out = %q, want \"~\"", string(out))
	}
}

func TestEscapeWatcherSplitAcrossReads(t *testing.T) {
	// stdin can return one byte at a time on slow links; the
	// watcher must hold ~ across the read boundary and recognise
	// . arriving in the next chunk.
	w := newEscapeWatcher()
	if out, det := w.process([]byte("\n")); det || string(out) != "\n" {
		t.Fatalf("setup newline: out=%q det=%v", string(out), det)
	}
	out1, det1 := w.process([]byte("~"))
	if det1 || len(out1) != 0 {
		t.Errorf("buffered ~: out=%q det=%v", string(out1), det1)
	}
	out2, det2 := w.process([]byte("."))
	if !det2 {
		t.Errorf(". after buffered ~: det=%v (want true)", det2)
	}
	if len(out2) != 0 {
		t.Errorf("detach: out=%q (want empty)", string(out2))
	}
}

func TestEscapeWatcherUnbufferedTildeIsForwarded(t *testing.T) {
	// At line-start, `~x` (~ followed by non-., non-~) should
	// forward the buffered ~ and then x.
	w := newEscapeWatcher()
	out, det := w.process([]byte("~x"))
	if det {
		t.Fatal("~x shouldn't detach")
	}
	if string(out) != "~x" {
		t.Errorf("out = %q, want %q", string(out), "~x")
	}
}
