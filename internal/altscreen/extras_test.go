package altscreen

import (
	"strings"
	"testing"
)

// TestAltBufferSeparation: ?1049h saves the cursor and switches to a cleared
// alt buffer; ?1049l restores the main buffer and cursor. Repaint of an active
// alt buffer is prefixed with ?1049h.
func TestAltBufferSeparation(t *testing.T) {
	s := feed(4, 8,
		"\x1b[H\x1b[2J\x1b[1;1Hmain", // main buffer content
		"\x1b[?1049h",                // enter alt (saves cursor, clears alt)
		"\x1b[1;1Halt")               // draw on alt
	if !s.AltActive() {
		t.Fatal("alt should be active")
	}
	if s.rowText(0) != "alt" {
		t.Fatalf("alt row0 = %q", s.rowText(0))
	}
	rp := string(s.Repaint())
	if !strings.HasPrefix(rp, "\x1b[?1049h") {
		t.Fatalf("alt repaint must start with ?1049h: %q", rp)
	}
	// Leave alt: main content + cursor restored.
	s.Feed([]byte("\x1b[?1049l"))
	if s.AltActive() {
		t.Fatal("alt should be inactive after ?1049l")
	}
	if s.rowText(0) != "main" {
		t.Fatalf("main row0 not restored = %q", s.rowText(0))
	}
}

// TestWideChars: CJK + emoji occupy two cells; the visible text round-trips and
// the following text lands at the correct column.
func TestWideChars(t *testing.T) {
	s := feed(2, 12, "\x1b[1;1H世界X") // 世 界 X (each wide) then X
	if got := s.rowText(0); got != "世界X" {
		t.Fatalf("wide row = %q", got)
	}
	// 世 at cols 0-1, 界 at 2-3, X at col 4 → cursor advanced 5 cells.
	if x, _ := s.Cursor(); x != 5 {
		t.Fatalf("cursor col after 2 wide + 1 narrow = %d, want 5", x)
	}
	// An emoji is wide too.
	e := feed(1, 6, "\x1b[1;1H\U0001F600ok") // 😀 o k
	if got := e.rowText(0); got != "\U0001F600ok" {
		t.Fatalf("emoji row = %q", got)
	}
	if x, _ := e.Cursor(); x != 4 {
		t.Fatalf("cursor after emoji+ok = %d, want 4", x)
	}
}

// TestUTF8SplitAcrossFeed: a multi-byte rune whose bytes straddle a Feed-chunk
// boundary (the live model is fed arbitrary PTY chunks) must be reassembled via
// pendingUTF, not dropped. Regression for box-drawing glyphs split mid-encoding.
func TestUTF8SplitAcrossFeed(t *testing.T) {
	s := New(2, 8)
	s.Feed([]byte("\x1b[H\x1b[2J\x1b[1;1H\xe2")) // first byte of ─ (U+2500 = e2 94 80)
	s.Feed([]byte("\x94\x80X"))                  // remaining two bytes + a char
	if got := s.rowText(0); got != "─X" {
		t.Fatalf("split rune row = %q, want %q", got, "─X")
	}
	if len(s.pendingUTF) != 0 {
		t.Fatalf("pendingUTF should be drained, got %v", s.pendingUTF)
	}
}

// TestRepaintRestoresScrollRegionAndOrigin: Repaint re-emits DECSTBM + DECOM so
// the app's region-relative scrolls/moves land correctly on a reattached client.
func TestRepaintRestoresScrollRegionAndOrigin(t *testing.T) {
	s := feed(6, 10, "\x1b[2;5r\x1b[?6h\x1b[2;1HX") // region rows 2..5, origin on, draw
	rp := string(s.Repaint())
	if !strings.Contains(rp, "\x1b[2;5r") {
		t.Fatalf("repaint missing scroll region: %q", rp)
	}
	if !strings.Contains(rp, "\x1b[?6h") {
		t.Fatalf("repaint missing origin mode: %q", rp)
	}
	// A default full-screen region must NOT emit the app-region DECSTBM at the
	// end (only the leading `\x1b[r` reset). Assert the specific region form is
	// absent.
	plain := string(feed(6, 10, "\x1b[1;1Hhi").Repaint())
	if strings.Contains(plain, ";6r") {
		t.Fatalf("default region should not emit a bottom-margin DECSTBM: %q", plain)
	}
}

// TestRepaintWideGlyphLastColumns: a wide glyph filling the final two columns
// must survive a Repaint round-trip (the trailing-EL guard must not clobber it).
func TestRepaintWideGlyphLastColumns(t *testing.T) {
	rows, cols := 2, 6
	a := feed(rows, cols, "\x1b[H\x1b[2J\x1b[1;1H1234一") // "1234" + 一 (wide) at cols 4-5
	if got := a.rowText(0); got != "1234一" {
		t.Fatalf("row0 = %q, want %q", got, "1234一")
	}
	b := feed(rows, cols, string(a.Repaint()))
	if a.rowText(0) != b.rowText(0) {
		t.Fatalf("wide-glyph round-trip: %q vs %q", a.rowText(0), b.rowText(0))
	}
}

// TestCombiningMark: a zero-width combining mark attaches to the preceding cell
// and does not consume a column.
func TestCombiningMark(t *testing.T) {
	s := feed(1, 6, "\x1b[1;1Héx") // e + combining acute + x
	if x, _ := s.Cursor(); x != 2 {
		t.Fatalf("cursor after e+combining+x = %d, want 2", x)
	}
	if s.grid[0][0].comb != "́" {
		t.Fatalf("combining not attached: %q", s.grid[0][0].comb)
	}
	rp := string(s.Repaint())
	if !strings.Contains(rp, "é") {
		t.Fatalf("repaint dropped combining mark: %q", rp)
	}
}

// TestCombiningMarkFloodIsBounded: a sustained stream of zero-width combining
// marks aimed at a single cell must not grow that cell's comb string without
// limit (memory DoS). The per-cell count is capped and further marks discarded,
// while a normal few-mark sequence still renders.
func TestCombiningMarkFloodIsBounded(t *testing.T) {
	s := feed(1, 6, "\x1b[1;1He"+strings.Repeat("́", 100000))
	if x, _ := s.Cursor(); x != 1 {
		t.Fatalf("combining flood advanced cursor to %d, want 1", x)
	}
	n := len([]rune(s.grid[0][0].comb))
	if n == 0 {
		t.Fatalf("combining marks dropped entirely: comb empty")
	}
	if n > maxCombPerCell {
		t.Fatalf("comb accumulated %d marks, want <= %d (cap)", n, maxCombPerCell)
	}
}

// TestTruecolorRoundTrip: 38;2;r;g;b and 48;2;r;g;b survive into the repaint.
func TestTruecolorRoundTrip(t *testing.T) {
	s := feed(1, 10, "\x1b[1;1H\x1b[38;2;10;20;30m\x1b[48;2;40;50;60mX\x1b[0m")
	rp := string(s.Repaint())
	if !strings.Contains(rp, "38;2;10;20;30") {
		t.Fatalf("repaint dropped truecolor fg: %q", rp)
	}
	if !strings.Contains(rp, "48;2;40;50;60") {
		t.Fatalf("repaint dropped truecolor bg: %q", rp)
	}
}

// TestColonSubparamsNoCorrupt: a colon-style underline substyle (4:3) must not
// corrupt the following character, and colon-form colors still parse.
func TestColonSubparamsNoCorrupt(t *testing.T) {
	s := feed(1, 8, "\x1b[1;1H\x1b[4:3mAB\x1b[0m")
	if s.rowText(0) != "AB" {
		t.Fatalf("colon substyle corrupted text: %q", s.rowText(0))
	}
	// Colon-form 256-indexed color.
	c := feed(1, 8, "\x1b[1;1H\x1b[38:5:196mZ\x1b[0m")
	if c.grid[0][0].a.fg.mode != colIndexed || c.grid[0][0].a.fg.v != 196 {
		t.Fatalf("colon indexed color not parsed: %+v", c.grid[0][0].a.fg)
	}
}

// TestAutowrapOff: with DECAWM off, the last column overwrites in place (no
// pending wrap to the next line).
func TestAutowrapOff(t *testing.T) {
	s := feed(2, 4, "\x1b[?7l\x1b[1;1H12345678")
	// cols=4: 123 fill 0-2, then 4,5,6,7,8 all overwrite col3 → last char '8'.
	if s.rowText(0) != "1238" {
		t.Fatalf("autowrap-off row0 = %q, want 1238", s.rowText(0))
	}
	if s.rowText(1) != "" {
		t.Fatalf("autowrap-off must not wrap to row1: %q", s.rowText(1))
	}
}

// TestBCEBackgroundErase: erase fills with the current background color, and the
// repaint re-emits it.
func TestBCEBackgroundErase(t *testing.T) {
	s := feed(2, 8, "\x1b[1;1H\x1b[41m\x1b[2K") // red bg, erase whole line
	if s.grid[0][3].a.bg.mode != colIndexed || s.grid[0][3].a.bg.v != 1 {
		t.Fatalf("BCE erase did not keep red bg: %+v", s.grid[0][3].a)
	}
	rp := string(s.Repaint())
	if !strings.Contains(rp, "48;5;1") && !strings.Contains(rp, "\x1b[41") {
		// sgrCodes emits indexed bg as 48;5;1
		t.Fatalf("repaint dropped BCE bg: %q", rp)
	}
}

// TestResize preserves top-left content and clamps the cursor.
func TestResize(t *testing.T) {
	s := feed(4, 8, "\x1b[H\x1b[2J\x1b[1;1Hhello\x1b[4;1Hbottom")
	s.Resize(6, 10)
	if r, c := s.Size(); r != 6 || c != 10 {
		t.Fatalf("size after resize = %dx%d", r, c)
	}
	if s.rowText(0) != "hello" {
		t.Fatalf("content lost on resize: %q", s.rowText(0))
	}
	// grow keeps old row3 content
	if s.rowText(3) != "bottom" {
		t.Fatalf("row3 after grow = %q", s.rowText(3))
	}
}

// TestRepaintRestoresModes: tracked modes the app set are restored by Repaint.
func TestRepaintRestoresModes(t *testing.T) {
	s := feed(3, 8, "\x1b[?7l\x1b[?2004h\x1b[?1000h\x1b[?25l\x1b[1;1Hx")
	rp := string(s.Repaint())
	for _, want := range []string{"\x1b[?7l", "\x1b[?2004h", "\x1b[?1000h", "\x1b[?25l"} {
		if !strings.Contains(rp, want) {
			t.Fatalf("repaint missing mode %q: %q", want, rp)
		}
	}
}

// TestPendingWrapReconstruct: a line filled to the last column keeps a pending
// wrap; the repaint reconstructs the same grid (regression for last-column).
func TestPendingWrapReconstruct(t *testing.T) {
	rows, cols := 3, 5
	a := feed(rows, cols, "\x1b[H\x1b[2J\x1b[1;1H12345") // exactly fills row 0
	b := feed(rows, cols, string(a.Repaint()))
	for r := 0; r < rows; r++ {
		if a.rowText(r) != b.rowText(r) {
			t.Fatalf("row %d: %q vs %q", r, a.rowText(r), b.rowText(r))
		}
	}
	if a.rowText(0) != "12345" {
		t.Fatalf("row0 = %q", a.rowText(0))
	}
}
