package altscreen

import (
	"strings"
	"testing"
)

// rowText reads row r as a right-trimmed string (test helper, same package).
func (s *Screen) rowText(r int) string {
	var b strings.Builder
	for c := 0; c < s.cols; c++ {
		g := s.grid[r][c]
		if g.width == 0 {
			continue // wide-glyph spacer — content is in the lead cell
		}
		b.WriteRune(g.r)
		b.WriteString(g.comb)
	}
	return strings.TrimRight(b.String(), " ")
}

func feed(rows, cols int, seqs ...string) *Screen {
	s := New(rows, cols)
	for _, q := range seqs {
		s.Feed([]byte(q))
	}
	return s
}

func TestCursorPositioningAndText(t *testing.T) {
	s := feed(5, 10, "\x1b[3;2HHi")
	if got := s.rowText(2); got != " Hi" {
		t.Fatalf("row2 = %q, want %q", got, " Hi")
	}
}

func TestRelativeCursorDown(t *testing.T) {
	// home, then CUD 4 → row index 4 (the relative walk Claude uses)
	s := feed(6, 10, "\x1b[H\x1b[4Bfoot")
	if got := s.rowText(4); got != "foot" {
		t.Fatalf("row4 = %q, want foot", got)
	}
}

func TestCHAColumnAbsolute(t *testing.T) {
	s := feed(2, 12, "\x1b[1;1Habc\x1b[8Gz") // CHA to col 8
	if got := s.rowText(0); got != "abc    z" {
		t.Fatalf("row0 = %q", got)
	}
}

func TestEraseLineToEnd(t *testing.T) {
	s := feed(3, 10, "\x1b[1;1Habcdef", "\x1b[1;4H\x1b[K") // EL0 from col 4
	if got := s.rowText(0); got != "abc" {
		t.Fatalf("EL0 row0 = %q, want abc", got)
	}
}

func TestEraseDisplay(t *testing.T) {
	s := feed(3, 6, "\x1b[1;1Haaa", "\x1b[2;1Hbbb", "\x1b[2J")
	if s.rowText(0) != "" || s.rowText(1) != "" {
		t.Fatalf("ED2 left content: %q %q", s.rowText(0), s.rowText(1))
	}
}

func TestAutowrap(t *testing.T) {
	s := feed(3, 5, "\x1b[1;1H1234567")
	if s.rowText(0) != "12345" || s.rowText(1) != "67" {
		t.Fatalf("wrap: row0=%q row1=%q", s.rowText(0), s.rowText(1))
	}
}

func TestSGRRoundTrip(t *testing.T) {
	s := feed(2, 12, "\x1b[1;1H\x1b[38;5;174mX\x1b[39m")
	rp := string(s.Repaint())
	if !strings.Contains(rp, "38;5;174") {
		t.Fatalf("repaint dropped the 256-color fg: %q", rp)
	}
}

// TestReconstructRoundTrips: feeding a repaint into a fresh screen yields
// the same visible grid — the invariant the daemon relies on.
func TestReconstructRoundTrips(t *testing.T) {
	rows, cols := 6, 20
	src := "\x1b[H\x1b[2J\x1b[2;3H\x1b[38;5;42mhello\x1b[39m\x1b[6;1Hfooter row"
	a := feed(rows, cols, src)
	b := feed(rows, cols, string(a.Repaint()))
	for r := 0; r < rows; r++ {
		if a.rowText(r) != b.rowText(r) {
			t.Fatalf("row %d differs: %q vs %q", r, a.rowText(r), b.rowText(r))
		}
	}
}

// TestRepaintRestoresAltActive is the invariant grid-persistence relies on:
// a Repaint of an ALT-active screen, fed into a fresh screen, restores
// AltActive()+Faithful() (via the emitted ?1049h + ED2) AND the grid — so a
// persisted Repaint reconstructs a faithful alt model across a daemon restart,
// which is what InjectAltScreenRepaint gates on.
func TestRepaintRestoresAltActive(t *testing.T) {
	rows, cols := 6, 20
	a := feed(rows, cols, "\x1b[?1049h\x1b[H\x1b[2J\x1b[2;3H\x1b[38;5;42mhello\x1b[39m\x1b[6;1Hfooter row")
	if !a.AltActive() || !a.Faithful() {
		t.Fatalf("setup: source not faithful alt (alt=%v faithful=%v)", a.AltActive(), a.Faithful())
	}
	b := feed(rows, cols, string(a.Repaint()))
	if !b.AltActive() {
		t.Fatal("restored screen lost alt-active — Repaint must emit ?1049h")
	}
	if !b.Faithful() {
		t.Fatal("restored screen not faithful after feeding a Repaint")
	}
	for r := 0; r < rows; r++ {
		if a.rowText(r) != b.rowText(r) {
			t.Fatalf("row %d differs: %q vs %q", r, a.rowText(r), b.rowText(r))
		}
	}
}

// TestRepaintPlusBackfillMatchesLive is the grid-persistence restore contract:
// a persisted Repaint (the model state at the save HeadSeq) plus the resume
// backfill (the bytes AFTER that HeadSeq) must reproduce the live model exactly.
// This is what proves the seq watermarks are consistent — if lastSidecarSeq
// lagged the Repaint, the resume would replay bytes already in the Repaint
// (double-feed), and the relative sequences (CUP/linefeeds/footer) would land on
// the wrong rows. The negative half feeds the backfill twice to show that a
// double-feed genuinely diverges (so the positive case is not vacuous).
func TestRepaintPlusBackfillMatchesLive(t *testing.T) {
	rows, cols := 8, 30
	head := "\x1b[?1049h\x1b[H\x1b[2J\x1b[1;1Hline one\x1b[2;1Hline two\x1b[3;1Hline three"
	// Arrives AFTER the save point. Starts with an absolute CUP (cursor-independent,
	// so the positive case doesn't depend on where Repaint leaves the cursor) but
	// ENDS with a linefeed at the bottom row — a RELATIVE scroll, so applying it
	// twice scrolls twice and the double-feed diverges (that's the real corruption
	// mode: relative sequences replayed on top of a Repaint that already has them).
	backfill := "\x1b[8;1Hbottom row\n"

	live := feed(rows, cols, head+backfill)                        // saw everything
	saved := feed(rows, cols, head)                                // state at the save HeadSeq
	restored := feed(rows, cols, string(saved.Repaint()), backfill) // Repaint + resume backfill (fed once)

	for r := 0; r < rows; r++ {
		if live.rowText(r) != restored.rowText(r) {
			t.Fatalf("row %d: live %q vs restored+backfill %q", r, live.rowText(r), restored.rowText(r))
		}
	}
	if !restored.AltActive() || !restored.Faithful() {
		t.Fatalf("restored not faithful alt (alt=%v faithful=%v)", restored.AltActive(), restored.Faithful())
	}

	// A double-feed (backfill applied twice) must NOT match live — proves the
	// test would catch the seq-skew regression it exists to guard.
	doubled := feed(rows, cols, string(saved.Repaint()), backfill, backfill)
	same := true
	for r := 0; r < rows; r++ {
		if live.rowText(r) != doubled.rowText(r) {
			same = false
			break
		}
	}
	if same {
		t.Fatal("double-fed backfill matched live — the test cannot distinguish a double-feed")
	}
}

// TestStableFooterSurvivesPartialRedraws is the regression for the bug:
// a footer drawn ONCE must survive reconstruction even when only the top
// of the screen is repainted afterward (Claude's spinner). The daemon's
// old byte-window replay dropped it once the footer-draw aged out.
func TestStableFooterSurvivesPartialRedraws(t *testing.T) {
	rows, cols := 8, 24
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J")
	b.WriteString("\x1b[1;1Hheader line")
	b.WriteString("\x1b[8;1H-- esc to interrupt") // footer, drawn once
	for i := 0; i < 1000; i++ {                   // spinner: only ever row 3
		b.WriteString("\x1b[3;1H\x1b[Kspinner")
	}
	rp, faithful := Reconstruct([]byte(b.String()), rows, cols)
	if !faithful {
		t.Fatal("Claude-style ops should stay faithful")
	}
	out := feed(rows, cols, string(rp))
	if got := out.rowText(7); !strings.Contains(got, "esc to interrupt") {
		t.Fatalf("footer dropped after partial redraws: row8 = %q", got)
	}
	if got := out.rowText(2); !strings.Contains(got, "spinner") {
		t.Fatalf("spinner row not reconstructed: row3 = %q", got)
	}
}

// TestRestructuringOpsStayFaithful: the content-restructuring ops real TUIs
// (vim/htop/less/fzf) emit constantly — scroll region, insert/delete line,
// insert/delete char, scroll up/down, erase char, reverse index — are now
// EMULATED, so the reconstruction stays faithful (no fallback to raw replay).
func TestRestructuringOpsStayFaithful(t *testing.T) {
	for _, seq := range []string{
		"\x1b[2;5r", // DECSTBM scroll region
		"\x1b[3L",   // insert line
		"\x1b[2M",   // delete line
		"\x1b[1@",   // insert char
		"\x1b[1P",   // delete char
		"\x1b[2S",   // scroll up
		"\x1b[2T",   // scroll down
		"\x1b[3X",   // erase char
		"\x1bM",     // RI reverse index
	} {
		_, faithful := Reconstruct([]byte("\x1b[H\x1b[2Jhi"+seq), 6, 12)
		if !faithful {
			t.Errorf("seq %q should now be emulated (faithful)", seq)
		}
	}
	// Genuinely unserializable line attributes (double-height/width) still bail.
	if _, faithful := Reconstruct([]byte("\x1b[H\x1b[2Jhi\x1b#3"), 6, 12); faithful {
		t.Error("double-height line (ESC#3) should be unfaithful")
	}
}

// TestInsertDeleteLine checks IL/DL move whole lines within the scroll region.
func TestInsertDeleteLine(t *testing.T) {
	s := feed(5, 6, "\x1b[H\x1b[2J",
		"\x1b[1;1HAAA", "\x1b[2;1HBBB", "\x1b[3;1HCCC", "\x1b[4;1HDDD",
		"\x1b[2;1H\x1b[1L") // insert 1 blank line at row 2
	if s.rowText(0) != "AAA" || s.rowText(1) != "" || s.rowText(2) != "BBB" || s.rowText(3) != "CCC" {
		t.Fatalf("IL: %q %q %q %q", s.rowText(0), s.rowText(1), s.rowText(2), s.rowText(3))
	}
	s2 := feed(5, 6, "\x1b[H\x1b[2J",
		"\x1b[1;1HAAA", "\x1b[2;1HBBB", "\x1b[3;1HCCC",
		"\x1b[2;1H\x1b[1M") // delete row 2
	if s2.rowText(0) != "AAA" || s2.rowText(1) != "CCC" || s2.rowText(2) != "" {
		t.Fatalf("DL: %q %q %q", s2.rowText(0), s2.rowText(1), s2.rowText(2))
	}
}

// TestInsertDeleteEraseChar checks ICH/DCH/ECH within a line.
func TestInsertDeleteEraseChar(t *testing.T) {
	s := feed(2, 10, "\x1b[1;1Habcdef", "\x1b[1;2H\x1b[2@") // insert 2 blanks at col 2
	if s.rowText(0) != "a  bcdef" {
		t.Fatalf("ICH: %q", s.rowText(0))
	}
	s2 := feed(2, 10, "\x1b[1;1Habcdef", "\x1b[1;2H\x1b[2P") // delete 2 at col 2
	if s2.rowText(0) != "adef" {
		t.Fatalf("DCH: %q", s2.rowText(0))
	}
	s3 := feed(2, 10, "\x1b[1;1Habcdef", "\x1b[1;2H\x1b[3X") // erase 3 at col 2 (no shift)
	if s3.rowText(0) != "a   ef" {
		t.Fatalf("ECH: %q", s3.rowText(0))
	}
}

// TestScrollRegion checks DECSTBM confines line-feed scrolling to the region.
func TestScrollRegion(t *testing.T) {
	// region rows 2..4 (1-based). Fill them, then LF at the bottom margin scrolls
	// only within the region; rows 1 and 5 are untouched.
	s := feed(5, 6, "\x1b[H\x1b[2J",
		"\x1b[1;1HTOP", "\x1b[5;1HBOT",
		"\x1b[2;4r",                     // scroll region rows 2..4
		"\x1b[2;1HL1\r\nL2\r\nL3\r\nL4") // L1,L2,L3 then LF scrolls region, L4 into row4
	if s.rowText(0) != "TOP" || s.rowText(4) != "BOT" {
		t.Fatalf("region leaked: top=%q bot=%q", s.rowText(0), s.rowText(4))
	}
	// After the scroll, region holds L2,L3,L4 (L1 scrolled out).
	if s.rowText(1) != "L2" || s.rowText(2) != "L3" || s.rowText(3) != "L4" {
		t.Fatalf("region content: %q %q %q", s.rowText(1), s.rowText(2), s.rowText(3))
	}
}

// TestReverseIndexScrollsAtTop: RI at the top margin scrolls the region down.
func TestReverseIndexScrollsAtTop(t *testing.T) {
	s := feed(4, 6, "\x1b[H\x1b[2J", "\x1b[1;1HR1", "\x1b[2;1HR2",
		"\x1b[1;1H\x1bM") // cursor at top, RI → scroll down, blank row appears at top
	if s.rowText(0) != "" || s.rowText(1) != "R1" || s.rowText(2) != "R2" {
		t.Fatalf("RI: %q %q %q", s.rowText(0), s.rowText(1), s.rowText(2))
	}
}

// TestFullScreenScrollRegionStaysFaithful is the regression for the "footer
// blank until rotation" bug. A reconstruction window can still hold pre-Claude
// SHELL output (a session whose 4 MiB ring hasn't evicted its head), and that
// shell emits a harmless full-screen scroll-region reset (ESC[r) at startup.
// Both bare and explicit scroll regions are now emulated, so they stay
// faithful and the footer re-emit keeps working.
func TestFullScreenScrollRegionStaysFaithful(t *testing.T) {
	for _, seq := range []string{
		"\x1b[r",    // bare reset to full screen
		"\x1b[;r",   // explicit empty params
		"\x1b[1r",   // top only, no bottom
		"\x1b[2;5r", // partial region — now emulated
		"\x1b[1;6r", // explicit bottom
	} {
		if _, faithful := Reconstruct([]byte("\x1b[H\x1b[2Jhi"+seq), 6, 12); !faithful {
			t.Errorf("scroll region %q must stay faithful", seq)
		}
	}
	// End to end: pre-Claude shell prompt + bare ESC[r, then Claude paints its
	// alt screen; the footer must reconstruct faithfully.
	rows, cols := 8, 24
	ring := "james@box:~$ claude\r\n\x1b[r" + // shell prompt + benign full-screen reset
		"\x1b[H\x1b[2J\x1b[1;1Hheader body\x1b[8;1H-- esc to interrupt"
	redraw, faithful := ReconstructBottomRows([]byte(ring), rows, cols, 4)
	if !faithful {
		t.Fatal("pre-Claude shell ESC[r must not disqualify the reconstruction")
	}
	if !strings.Contains(string(redraw), "esc to interrupt") {
		t.Fatalf("footer missing: %q", redraw)
	}
}

func TestRepaintRowsCursorNeutralAndScoped(t *testing.T) {
	s := feed(6, 12, "\x1b[H\x1b[2J\x1b[3;1Hbody\x1b[6;1H\x1b[38;5;9mfooter\x1b[39m")
	r := string(s.RepaintRows(4, 6)) // bottom 2 rows (indices 4,5 = 1-based 5,6)
	if !strings.HasPrefix(r, "\x1b7") || !strings.HasSuffix(r, "\x1b8") {
		t.Fatalf("not cursor-neutral (ESC7…ESC8): %q", r)
	}
	if strings.Contains(r, "\x1b[2J") {
		t.Fatalf("must not clear the screen: %q", r)
	}
	for _, want := range []string{"\x1b[6;1H", "footer", "38;5;9", "\x1b[K"} {
		if !strings.Contains(r, want) {
			t.Fatalf("footer redraw missing %q: %q", want, r)
		}
	}
	if strings.Contains(r, "body") {
		t.Fatalf("leaked a non-bottom row: %q", r)
	}
}

// TestReconstructBottomRowsRestoresFooter is the v2 core guarantee: the bottom-
// rows redraw, applied onto a screen that has the body but lost the footer,
// restores the footer WITHOUT clobbering the body (cursor-neutral, scoped).
func TestReconstructBottomRowsRestoresFooter(t *testing.T) {
	rows, cols := 8, 24
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J\x1b[8;1H-- esc to interrupt")
	for i := 0; i < 200; i++ {
		b.WriteString("\x1b[3;1H\x1b[Kspin")
	}
	redraw, faithful := ReconstructBottomRows([]byte(b.String()), rows, cols, 4)
	if !faithful {
		t.Fatal("Claude-style ops should be faithful")
	}
	if !strings.Contains(string(redraw), "esc to interrupt") {
		t.Fatalf("bottom-rows redraw missing footer: %q", redraw)
	}
	// A client screen that has the header/body but a blank footer row.
	out := feed(rows, cols, "\x1b[H\x1b[2J\x1b[1;1Hheader body", string(redraw))
	if got := out.rowText(7); !strings.Contains(got, "esc to interrupt") {
		t.Fatalf("footer not restored: row8=%q", got)
	}
	if got := out.rowText(0); !strings.Contains(got, "header body") {
		t.Fatalf("body clobbered: row1=%q", got)
	}
}

// TestOverflowCSIParamsClampCursorAndRepeat proves that a pathologically large
// CSI numeric parameter (here MaxInt64 as decimal digits) can no longer wrap
// int and corrupt the cursor row or spin the REP loop. Each case must leave the
// cursor inside the grid and return promptly. Regression for the integer-
// overflow finding on CUD (B) / CNL (E) / REP (b).
func TestOverflowCSIParamsClampCursorAndRepeat(t *testing.T) {
	const huge = "9223372036854775807" // math.MaxInt64 as decimal digits

	cases := []struct {
		name string
		seq  string
	}{
		// Start CUD/CNL from a non-zero row: on the unfixed code s.y+MaxInt64
		// then wraps to a negative int that min() keeps, corrupting the row.
		{"CUD", "\x1b[3;1H\x1b[" + huge + "B"},
		{"CNL", "\x1b[3;1H\x1b[" + huge + "E"},
		{"CUU", "\x1b[5;1H\x1b[" + huge + "A"},
		{"CPL", "\x1b[5;1H\x1b[" + huge + "F"},
		// REP repeats the last graphic char; seed one first, then a huge count
		// (the unfixed loop would spin ~forever and trip the test timeout).
		{"REP", "\x1b[H" + "x" + "\x1b[" + huge + "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := feed(6, 10, tc.seq)
			x, y := s.Cursor()
			if y < 0 || y >= s.rows {
				t.Fatalf("%s: cursor row %d out of range [0,%d)", tc.name, y, s.rows)
			}
			if x < 0 || x >= s.cols {
				t.Fatalf("%s: cursor col %d out of range [0,%d)", tc.name, x, s.cols)
			}
			// Repaint must not panic on an out-of-bounds grid index.
			_ = s.Repaint()
		})
	}
}

// TestParseParamsCapsAtMax confirms the parser caps an over-long digit run at
// csiParamMax instead of overflowing.
func TestParseParamsCapsAtMax(t *testing.T) {
	got := parseParams([]byte("9223372036854775807"))
	if len(got) != 1 || got[0] != csiParamMax {
		t.Fatalf("parseParams(huge) = %v, want [%d]", got, csiParamMax)
	}
	// A normal parameter is untouched.
	if got := parseParams([]byte("12;34")); len(got) != 2 || got[0] != 12 || got[1] != 34 {
		t.Fatalf("parseParams(\"12;34\") = %v", got)
	}
}
