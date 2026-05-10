package session

import (
	"bytes"
	"testing"
)

// daResponseV5 is the Primary DA response the filter currently
// emits — a stable reference for tests so a future tweak to the
// xterm-class capability list doesn't silently change behaviour.
const (
	daPrimaryResponse   = "\x1b[?65;4;1;2;6;21;22;17;28c"
	daSecondaryResponse = "\x1b[>0;276;0c"
	dsrOKResponse       = "\x1b[0n"
)

func TestQueryFilterPassesThroughNonQueryBytes(t *testing.T) {
	f := NewQueryFilter(nil)
	got := f.Process([]byte("hello world\n"))
	if string(got) != "hello world\n" {
		t.Errorf("plain text not preserved: got %q", got)
	}
	got = f.Process([]byte("\x1b[31mred\x1b[0m"))
	if string(got) != "\x1b[31mred\x1b[0m" {
		t.Errorf("colour escape not preserved: got %q", got)
	}
	// Cursor Forward (`\x1b[5c`) — looks like DA syntactically but
	// shouldn't be intercepted. (Real query is empty params or `0`.)
	got = f.Process([]byte("\x1b[5c"))
	if string(got) != "\x1b[5c" {
		t.Errorf("cursor-forward swallowed by DA matcher: got %q", got)
	}
}

func TestQueryFilterDAPrimary(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	got := f.Process([]byte("before\x1b[cafter"))
	if string(got) != "beforeafter" {
		t.Errorf("DA query not stripped from output: got %q", got)
	}
	if pty.String() != daPrimaryResponse {
		t.Errorf("DA response not written to PTY: got %q want %q",
			pty.String(), daPrimaryResponse)
	}
}

func TestQueryFilterDAPrimaryWithExplicitZero(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	got := f.Process([]byte("\x1b[0c"))
	if string(got) != "" {
		t.Errorf("DA(0) not stripped: got %q", got)
	}
	if pty.String() != daPrimaryResponse {
		t.Errorf("DA(0) response: got %q", pty.String())
	}
}

func TestQueryFilterDASecondary(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	got := f.Process([]byte("X\x1b[>cY"))
	if string(got) != "XY" {
		t.Errorf("DA secondary not stripped: got %q", got)
	}
	if pty.String() != daSecondaryResponse {
		t.Errorf("DA secondary response: got %q", pty.String())
	}
}

func TestQueryFilterDSR5(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	got := f.Process([]byte("\x1b[5n"))
	if string(got) != "" {
		t.Errorf("DSR query not stripped: got %q", got)
	}
	if pty.String() != dsrOKResponse {
		t.Errorf("DSR response: got %q", pty.String())
	}
}

func TestQueryFilterCPRStrippedNoResponse(t *testing.T) {
	// CPR (`\x1b[6n`) is a query we recognise but can't answer —
	// the daemon doesn't track cursor state. Strip it without
	// writing a response; apps that need CPR will time out, but in
	// interactive shell flows that's vanishingly rare.
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	got := f.Process([]byte("\x1b[6n"))
	if string(got) != "" {
		t.Errorf("CPR not stripped: got %q", got)
	}
	if pty.Len() != 0 {
		t.Errorf("CPR should have no synthetic response, got %q", pty.String())
	}
}

func TestQueryFilterPartialSequenceAcrossReads(t *testing.T) {
	// PTYs deliver bytes in arbitrary chunks; an escape sequence
	// can split across reads. The filter must hold the partial
	// sequence and re-evaluate it once the rest arrives, otherwise
	// occasional queries slip through unfiltered.
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)

	got1 := f.Process([]byte("hello\x1b["))
	if string(got1) != "hello" {
		t.Errorf("first chunk should emit non-ESC prefix only: got %q", got1)
	}
	got2 := f.Process([]byte("c world"))
	if string(got2) != " world" {
		t.Errorf("query split across reads not stripped: got %q", got2)
	}
	if pty.String() != daPrimaryResponse {
		t.Errorf("response on completed query: got %q", pty.String())
	}
}

func TestQueryFilterPartialAtEndOfChunk(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	// Chunk ends mid-params.
	got1 := f.Process([]byte("a\x1b[5"))
	if string(got1) != "a" {
		t.Errorf("first chunk: got %q", got1)
	}
	// Complete with the final byte.
	got2 := f.Process([]byte("n"))
	if string(got2) != "" {
		t.Errorf("DSR completed across reads not stripped: got %q", got2)
	}
	if pty.String() != dsrOKResponse {
		t.Errorf("DSR response: got %q", pty.String())
	}
}

func TestQueryFilterBareEscNotMistakenForCSI(t *testing.T) {
	// User keystroke ESC alone (or ESC followed by something other
	// than `[`) should pass through untouched.
	f := NewQueryFilter(nil)
	got := f.Process([]byte("\x1bO"))
	if string(got) != "\x1bO" {
		t.Errorf("ESC O passed through: got %q", got)
	}
}

func TestQueryFilterMultipleQueriesInOneChunk(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	got := f.Process([]byte("X\x1b[cY\x1b[>cZ"))
	if string(got) != "XYZ" {
		t.Errorf("multiple queries in one chunk: got %q", got)
	}
	expected := daPrimaryResponse + daSecondaryResponse
	if pty.String() != expected {
		t.Errorf("two responses: got %q want %q", pty.String(), expected)
	}
}

func TestQueryFilterEchoedDAResponseIsPassedThrough(t *testing.T) {
	// A DA *response* (`\x1b[?65;4;1;2;6;21;22;17;28c`) is what bash
	// readline used to echo back when the buggy iOS client sent
	// auto-responses to old queries. The filter doesn't try to
	// strip these from the output stream — they're not queries, the
	// client doesn't generate further responses to them, and SwiftTerm
	// renders them as a no-op CSI. Passing them through keeps the
	// match logic simple (one direction only: query→response).
	f := NewQueryFilter(nil)
	got := f.Process([]byte(daPrimaryResponse))
	if string(got) != daPrimaryResponse {
		t.Errorf("response should pass through: got %q", got)
	}
}

func TestQueryFilterNonQueryCSIPassesThrough(t *testing.T) {
	// CSI sequences with finals other than c/n should be untouched.
	f := NewQueryFilter(nil)
	for _, seq := range []string{
		"\x1b[2J",         // erase screen
		"\x1b[H",          // cursor home
		"\x1b[10;20H",     // cursor position set
		"\x1b[?25h",       // show cursor
		"\x1b[?1049h",     // alternate screen on
		"\x1b[1;31m",      // SGR colour
	} {
		got := f.Process([]byte(seq))
		if string(got) != seq {
			t.Errorf("%q got mangled: %q", seq, got)
		}
	}
}
