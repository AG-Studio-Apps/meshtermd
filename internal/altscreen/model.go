// Package altscreen reconstructs the current visible state of a full-screen
// TUI (Claude Code, vim, htop, less, fzf…) from a window of raw pty output,
// and serializes it back into a self-contained repaint sequence.
//
// Why this exists: the reattach replay (computeReplayWindow) ships a raw byte
// window. A full-screen app draws stable content (status footer, box borders,
// panes) once and then only emits tiny relative redraws of the active region,
// so that stable content is OLDER than any bounded byte window — a reattaching
// client clears its alt-screen and rebuilds it WITHOUT the footer, or replays a
// truncated byte tail that garbles the screen. A 2-D screen cannot be rebuilt
// from a mid-stream byte offset; it must be reconstructed from the cell grid.
//
// This package is a compact but faithful VT emulator: main + alt buffers, a
// scroll region (DECSTBM), origin/autowrap modes, indexed + truecolor SGR,
// insert/delete line & char, scroll up/down, erase char, reverse index, and
// wide/combining-character handling via a self-contained wcwidth. It replays
// the retained ring through the grid and emits a deterministic full-screen
// repaint (modeled on mosh's Display::new_frame) that reproduces the exact
// present screen. The design also supports a LIVE model: keep one *Screen,
// Feed incrementally, and call Repaint on demand.
package altscreen

import (
	"strconv"
	"unicode/utf8"
)

// color is a cell/pen color. mode 0 = default, 1 = 256-indexed (v = index),
// 2 = truecolor (v = r<<16 | g<<8 | b). It is a comparable value so cells and
// pens compare with ==.
type color struct {
	mode uint8
	v    uint32
}

const (
	colDefault uint8 = 0
	colIndexed uint8 = 1
	colRGB     uint8 = 2
)

// csiParamMax bounds every parsed CSI numeric parameter, matching xterm's
// clamp. It keeps parameter arithmetic (s.y+cnt(p1), the REP loop count) far
// from int overflow while staying well above any legitimate value.
const csiParamMax = 65535

type attr struct {
	fg, bg                            color
	bold, dim, italic, underline, rev bool
}

var defaultAttr = attr{}

// cell is one grid cell. width: 1 = normal, 2 = lead half of a wide (double-
// width) glyph, 0 = trailing spacer of a wide glyph (its content lives in the
// lead cell to the left). comb holds any zero-width combining marks appended
// after r.
type cell struct {
	r     rune
	comb  string
	a     attr
	width int8
}

// cursorState is a saved cursor (DECSC/DECRC and the ?1049 save slot).
type cursorState struct {
	x, y     int
	a        attr
	wrapNext bool
	origin   bool
	set      bool
}

// Screen is a rows×cols terminal with main + alt buffers, a cursor, a scroll
// region, and tracked modes.
type Screen struct {
	rows, cols int

	main      [][]cell
	alt       [][]cell
	grid      [][]cell // == main or alt, whichever is active
	altActive bool

	x, y     int
	cur      attr
	wrapNext bool
	lastRune rune // for REP (CSI b)

	// scroll region, 0-based inclusive. Default full screen.
	top, bottom int

	// modes (tracked so Repaint can restore the app's state).
	autowrap       bool
	originMode     bool
	cursorVisible  bool
	bracketedPaste bool
	mouse1000      bool
	mouse1002      bool
	mouse1003      bool
	mouse1006      bool

	saved    cursorState // DECSC / ESC7
	altSaved cursorState // ?1049 save slot

	// pendingUTF holds a partial multi-byte UTF-8 rune whose bytes were
	// split across a Feed-chunk boundary (the live model is fed arbitrary
	// PTY chunks, unlike a one-shot Reconstruct). Prepended to the next
	// Feed so a box-drawing glyph split mid-encoding isn't dropped. At
	// most 3 bytes; owned/copied, never aliases the caller's buffer.
	pendingUTF []byte

	// faithful is cleared only on ops we genuinely cannot serialize (double-
	// height / double-width line attributes). Everything a real TUI emits —
	// insert/delete line & char, scroll region, reverse index, scroll up/down,
	// erase char — is emulated, so faithful stays true for vim/htop/less/fzf.
	// The caller uses it to fall back to the raw byte-window replay.
	faithful bool

	// knowsBufferState records whether this model has ever OBSERVED which buffer
	// the pty is on, as opposed to merely defaulting to the main buffer at
	// construction. Set by enterAlt/exitAlt, so feeding a persisted Repaint (which
	// is prefixed with ?1049h) sets it too.
	//
	// ★ Why this exists: `altActive == false` is ambiguous without it. A restored
	// session builds a fresh main-buffer model and only feeds a Repaint when one
	// was persisted — and persistence.go saves a Repaint ONLY for a faithful,
	// non-resize-dirty ALT model. So a genuinely alt session saved while
	// resize-dirty or unfaithful comes back reporting main-buffer AND faithful
	// while actually knowing nothing. Treating that as authoritative would tell
	// the client not to prime its alt buffer and spill a full-screen TUI onto the
	// main screen. Negative alt evidence is only trustworthy when this is true;
	// POSITIVE alt evidence always is. See Session.AltScreenForClient.
	knowsBufferState bool

	// resizedDirty is set when Resize() changes the geometry and cleared on the
	// next Feed. While set, the grid is top-anchored to the NEW size but the app
	// has NOT yet redrawn to it — a grow strands bottom-anchored content
	// (Claude's prompt) mid-screen; a shrink drops it — so the model must NOT be
	// injected as an authoritative frame (it would ship the misplaced grid: the
	// cold-start-grow regression that parked the prime). The heal is any output
	// after the resize: SIGWINCH makes Ink/Claude/vim/htop re-render, so the
	// first post-resize Feed restores the grid to where the app actually draws
	// (see TestResizeStrandsFooterUntilRepaint). Distinct from `faithful`, which
	// tracks un-emulatable ops and recovers only on a full clear.
	resizedDirty bool
}

// New returns a cleared rows×cols screen (main buffer active).
func New(rows, cols int) *Screen {
	if rows < 1 {
		rows = 1
	}
	if cols < 1 {
		cols = 1
	}
	s := &Screen{
		rows:          rows,
		cols:          cols,
		cur:           defaultAttr,
		top:           0,
		bottom:        rows - 1,
		autowrap:      true,
		cursorVisible: true,
		faithful:      true,
	}
	s.main = newGrid(rows, cols)
	s.alt = newGrid(rows, cols)
	s.grid = s.main
	return s
}

func newGrid(rows, cols int) [][]cell {
	g := make([][]cell, rows)
	for r := range g {
		g[r] = make([]cell, cols)
		for c := range g[r] {
			g[r][c] = cell{r: ' ', a: defaultAttr, width: 1}
		}
	}
	return g
}

// Faithful reports whether the model has stayed faithful (see the field doc).
func (s *Screen) Faithful() bool { return s.faithful }

// KnowsBufferState reports whether the model has observed a buffer switch, so a
// caller can tell "the pty is on the main buffer" from "this model has never
// been told". See the field doc.
func (s *Screen) KnowsBufferState() bool { return s.knowsBufferState }

// ResizeDirty reports whether the grid was geometry-changed but the app has not
// yet repainted to the new size (see the field doc). The attach path must not
// inject the model as an authoritative frame while this is true.
func (s *Screen) ResizeDirty() bool { return s.resizedDirty }

// MarkStale marks the grid as no longer trustworthy: the caller (the live
// session model) invokes this when the PTY byte stream had a GAP (the sidecar
// ring dropped bytes under backpressure), so the grid missed updates and can't
// be trusted for a redraw. It recovers to faithful automatically on the next
// full-screen clear (ED 2/3) or alt-buffer enter-with-clear, which re-establish
// a known-good grid regardless of the lost span. Without this, a single rare
// drop would let the model confidently serve a WRONG redraw (worse than the raw
// fallback).
func (s *Screen) MarkStale() { s.faithful = false }

// AltActive reports whether the alternate buffer is currently active.
func (s *Screen) AltActive() bool { return s.altActive }

// Size returns the current rows, cols.
func (s *Screen) Size() (rows, cols int) { return s.rows, s.cols }

// Cursor returns the current 0-based cursor column (x) and row (y).
func (s *Screen) Cursor() (x, y int) { return s.x, s.y }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Resize reallocates both buffers to rows×cols, preserving top-left content,
// resets the scroll region to full, and clamps the cursor. The live model
// calls this on a window-size change before continuing to Feed.
func (s *Screen) Resize(rows, cols int) {
	if rows < 1 {
		rows = 1
	}
	if cols < 1 {
		cols = 1
	}
	if rows == s.rows && cols == s.cols {
		return
	}
	// NOTE: this is a top-left-anchored copy, so shrinking drops the bottom rows
	// and growing strands bottom-anchored content (Claude's prompt) mid-screen —
	// neither matches where the app will redraw on the resulting SIGWINCH. The
	// model does NOT try to correct that here (it can't know the app's intent);
	// instead the ATTACH path skips the injected redraw whenever the attach
	// resized the grid and lets raw replay carry the app's post-resize repaint
	// (see protocol_handler). So no faithful mutation on resize — that was too
	// coarse (an incremental post-resize repaint left the model stuck unfaithful,
	// re-exposing the very footer loss the prime fixes).
	s.main = resizeGrid(s.main, rows, cols)
	s.alt = resizeGrid(s.alt, rows, cols)
	if s.altActive {
		s.grid = s.alt
	} else {
		s.grid = s.main
	}
	s.rows, s.cols = rows, cols
	s.top, s.bottom = 0, rows-1
	s.x = clamp(s.x, 0, cols-1)
	s.y = clamp(s.y, 0, rows-1)
	s.wrapNext = false
	// The grid is now top-anchored to the new geometry but the app hasn't
	// repainted to it yet — mark dirty so the attach path won't inject the
	// misplaced grid until the app's SIGWINCH repaint feeds us (see the field).
	s.resizedDirty = true
}

func resizeGrid(old [][]cell, rows, cols int) [][]cell {
	g := newGrid(rows, cols)
	for r := 0; r < rows && r < len(old); r++ {
		for c := 0; c < cols && c < len(old[r]); c++ {
			g[r][c] = old[r][c]
		}
	}
	return g
}

// blank returns a blank cell carrying the current background (BCE: erase and
// scroll-in cells keep the pen's background color, matching xterm/tmux).
func (s *Screen) blank() cell {
	return cell{r: ' ', a: attr{bg: s.cur.bg}, width: 1}
}

func (s *Screen) blankRow(row []cell) {
	b := s.blank()
	for c := range row {
		row[c] = b
	}
}

// isBlank reports whether a cell contributes nothing to the visible line
// (a plain space with default attributes, or a wide-glyph spacer).
func isBlank(g cell) bool {
	if g.width == 0 {
		return true // spacer: content lives in the lead cell
	}
	return g.r == ' ' && g.comb == "" && g.a == defaultAttr
}

// Feed replays a chunk of raw pty bytes into the grid.
func (s *Screen) Feed(p []byte) {
	if len(p) > 0 {
		// Output after a resize is the app responding to SIGWINCH (Ink/Claude
		// re-render the full frame; vim/htop repaint). The grid now tracks the
		// app's real post-resize screen again, so it's injectable once more.
		s.resizedDirty = false
	}
	// Reassemble a multi-byte rune split across the previous chunk boundary.
	// QueryFilter already carries partial CSI/OSC across chunks, so the only
	// partial tail the model sees is a ground-state UTF-8 rune. Copy so we
	// never alias the caller's reused chunk buffer.
	if len(s.pendingUTF) > 0 {
		p = append(append([]byte(nil), s.pendingUTF...), p...)
		s.pendingUTF = nil
	}
	i := 0
	for i < len(p) {
		b := p[i]
		switch {
		case b == 0x1b:
			i += s.escape(p[i:])
		case b == '\r':
			s.x = 0
			s.wrapNext = false
			i++
		case b == '\n', b == 0x0b, b == 0x0c: // LF, VT, FF all index
			s.lineFeed()
			i++
		case b == '\b':
			if s.x > 0 {
				s.x--
			}
			s.wrapNext = false
			i++
		case b == '\t':
			s.x = clamp((s.x/8+1)*8, 0, s.cols-1)
			i++
		case b < 0x20:
			i++ // ignore other C0 controls
		default:
			// A lead byte with missing continuations at the very end of the
			// chunk: stash and reassemble on the next Feed (see pendingUTF).
			// FullRune reports an invalid single byte as "full", so a stray
			// continuation still falls through to DecodeRune → RuneError.
			if b >= 0x80 && !utf8.FullRune(p[i:]) {
				s.pendingUTF = append([]byte(nil), p[i:]...)
				return
			}
			r, sz := utf8.DecodeRune(p[i:])
			if r == utf8.RuneError && sz <= 1 {
				i++
				continue
			}
			s.putRune(r)
			i += sz
		}
	}
}

func (s *Screen) lineFeed() {
	s.wrapNext = false
	if s.y == s.bottom {
		s.scrollUp(1)
	} else if s.y < s.rows-1 {
		s.y++
	}
}

func (s *Screen) reverseIndex() {
	s.wrapNext = false
	if s.y == s.top {
		s.scrollDown(1)
	} else if s.y > 0 {
		s.y--
	}
}

// scrollUp scrolls the scroll region up by n (content moves toward the top;
// blank lines with the current bg scroll in at the bottom margin).
func (s *Screen) scrollUp(n int) { s.scrollUpRange(s.top, s.bottom, n) }

// scrollDown scrolls the scroll region down by n.
func (s *Screen) scrollDown(n int) { s.scrollDownRange(s.top, s.bottom, n) }

func (s *Screen) scrollUpRange(top, bot, n int) {
	if top < 0 || bot >= s.rows || top > bot {
		return
	}
	h := bot - top + 1
	if n > h {
		n = h
	}
	if n <= 0 {
		return
	}
	tmp := make([][]cell, n)
	copy(tmp, s.grid[top:top+n])
	copy(s.grid[top:bot+1-n], s.grid[top+n:bot+1])
	for i := 0; i < n; i++ {
		s.blankRow(tmp[i])
		s.grid[bot+1-n+i] = tmp[i]
	}
}

func (s *Screen) scrollDownRange(top, bot, n int) {
	if top < 0 || bot >= s.rows || top > bot {
		return
	}
	h := bot - top + 1
	if n > h {
		n = h
	}
	if n <= 0 {
		return
	}
	tmp := make([][]cell, n)
	copy(tmp, s.grid[bot+1-n:bot+1])
	copy(s.grid[top+n:bot+1], s.grid[top:bot+1-n])
	for i := 0; i < n; i++ {
		s.blankRow(tmp[i])
		s.grid[top+i] = tmp[i]
	}
}

// setCell writes a glyph at (x,y), cleaning up any wide pair it partially
// overwrites so no orphaned lead/spacer is left behind.
func (s *Screen) setCell(x, y int, r rune, w int8) {
	if x < 0 || x >= s.cols || y < 0 || y >= s.rows {
		return
	}
	row := s.grid[y]
	if row[x].width == 2 && x+1 < s.cols {
		row[x+1] = s.blank() // clobbered a wide lead → clear its spacer
	}
	if row[x].width == 0 && x-1 >= 0 {
		row[x-1] = s.blank() // clobbered a spacer → clear its lead
	}
	row[x] = cell{r: r, a: s.cur, width: w}
}

func (s *Screen) advance(w int) {
	nx := s.x + w
	if nx >= s.cols {
		s.x = s.cols - 1
		s.wrapNext = s.autowrap
	} else {
		s.x = nx
	}
}

func (s *Screen) putRune(r rune) {
	w := runeWidth(r)
	if w == 0 {
		s.putCombining(r)
		return
	}
	s.lastRune = r
	if s.wrapNext && s.autowrap {
		s.x = 0
		s.lineFeed()
	}
	s.wrapNext = false
	if s.x >= s.cols {
		s.x = s.cols - 1
	}
	if w == 2 && s.x == s.cols-1 {
		if s.autowrap {
			// Wide glyph won't fit: blank the last cell and wrap.
			s.setCell(s.x, s.y, ' ', 1)
			s.x = 0
			s.lineFeed()
		} else {
			// No room and no wrap: overwrite in place as a single cell.
			s.setCell(s.x, s.y, r, 1)
			return
		}
	}
	if w == 2 {
		s.setCell(s.x, s.y, r, 2)
		if s.x+1 < s.cols {
			s.grid[s.y][s.x+1] = cell{r: ' ', a: s.cur, width: 0}
		}
		s.advance(2)
	} else {
		s.setCell(s.x, s.y, r, 1)
		s.advance(1)
	}
}

// putCombining appends a zero-width mark to the last written cell.
func (s *Screen) putCombining(r rune) {
	cx := s.x
	if !s.wrapNext {
		cx = s.x - 1
	}
	if cx < 0 {
		return
	}
	row := s.grid[s.y]
	if cx < s.cols && cx > 0 && row[cx].width == 0 {
		cx-- // point at the lead of a wide glyph
	}
	if cx >= 0 && cx < s.cols {
		row[cx].comb += string(r)
	}
}

// escape consumes one escape sequence starting at p[0]==0x1b, returns the
// number of bytes consumed.
func (s *Screen) escape(p []byte) int {
	if len(p) < 2 {
		return 1
	}
	switch p[1] {
	case '[': // CSI
		return s.csi(p)
	case ']': // OSC — skip to BEL or ST
		j := 2
		for j < len(p) && p[j] != 0x07 {
			if p[j] == 0x1b && j+1 < len(p) && p[j+1] == '\\' {
				return j + 2
			}
			j++
		}
		if j < len(p) {
			return j + 1
		}
		return j
	case 'P', 'X', '^', '_': // DCS/SOS/PM/APC — skip to ST
		j := 2
		for j < len(p) {
			if p[j] == 0x1b && j+1 < len(p) && p[j+1] == '\\' {
				return j + 2
			}
			if p[j] == 0x07 {
				return j + 1
			}
			j++
		}
		return j
	case '(', ')', '*', '+': // charset designation: ESC ( X
		return 3
	case '#': // line attributes (DECDHL/DECDWL/DECALN)
		if len(p) < 3 {
			return 2
		}
		switch p[2] {
		case '8': // DECALN — fill screen with 'E'
			s.decaln()
		case '3', '4', '5', '6': // double height/width — can't serialize
			s.faithful = false
		}
		return 3
	case '=', '>': // keypad mode
		return 2
	case '7': // DECSC — save cursor
		s.saveCursor()
		return 2
	case '8': // DECRC — restore cursor
		s.restoreCursor()
		return 2
	case 'c': // RIS — full reset
		s.reset()
		return 2
	case 'D': // IND — index (line feed)
		s.lineFeed()
		return 2
	case 'E': // NEL — next line
		s.x = 0
		s.lineFeed()
		return 2
	case 'M': // RI — reverse index
		s.reverseIndex()
		return 2
	default:
		return 2
	}
}

func (s *Screen) reset() {
	s.cur = defaultAttr
	s.x, s.y = 0, 0
	s.wrapNext = false
	s.top, s.bottom = 0, s.rows-1
	s.autowrap = true
	s.originMode = false
	s.cursorVisible = true
	s.bracketedPaste = false
	s.mouse1000, s.mouse1002, s.mouse1003, s.mouse1006 = false, false, false, false
	s.altActive = false
	s.grid = s.main
	for r := 0; r < s.rows; r++ {
		s.blankRow(s.main[r])
		s.blankRow(s.alt[r])
	}
}

func (s *Screen) decaln() {
	for r := 0; r < s.rows; r++ {
		for c := 0; c < s.cols; c++ {
			s.grid[r][c] = cell{r: 'E', a: defaultAttr, width: 1}
		}
	}
	s.x, s.y = 0, 0
	s.wrapNext = false
}

func (s *Screen) csi(p []byte) int {
	j := 2
	priv := byte(0)
	if j < len(p) && (p[j] == '?' || p[j] == '>' || p[j] == '!' || p[j] == '=') {
		priv = p[j]
		j++
	}
	ps := j
	for j < len(p) && !(p[j] >= 0x40 && p[j] <= 0x7e) {
		j++
	}
	if j >= len(p) {
		return len(p)
	}
	final := p[j]
	params := parseParams(p[ps:j])
	consumed := j + 1

	if priv == '?' {
		if final == 'h' || final == 'l' {
			set := final == 'h'
			for _, m := range params {
				s.setPrivateMode(m, set)
			}
		}
		return consumed
	}
	if priv != 0 {
		return consumed // >  ! = intermediates we don't act on
	}

	p1 := param(params, 0, 1)
	switch final {
	case 'H', 'f': // CUP row;col (1-based)
		s.moveTo(param(params, 1, 1)-1, param(params, 0, 1)-1)
	case 'A': // CUU
		lo := 0
		if s.y >= s.top {
			lo = s.top
		}
		s.y = max(s.y-cnt(p1), lo)
		s.wrapNext = false
	case 'B': // CUD
		hi := s.rows - 1
		if s.y <= s.bottom {
			hi = s.bottom
		}
		// clamp (not min): a wrapped-negative sum is pulled back to 0 rather
		// than kept as a negative row index. hi >= s.y always, so legitimate
		// moves are unchanged.
		s.y = clamp(s.y+cnt(p1), 0, hi)
		s.wrapNext = false
	case 'C': // CUF
		s.x = clamp(s.x+cnt(p1), 0, s.cols-1)
		s.wrapNext = false
	case 'D': // CUB
		s.x = clamp(s.x-cnt(p1), 0, s.cols-1)
		s.wrapNext = false
	case 'G', '`': // CHA — column absolute (1-based)
		s.x = clamp(param(params, 0, 1)-1, 0, s.cols-1)
		s.wrapNext = false
	case 'd': // VPA — row absolute (respects origin)
		s.setRow(param(params, 0, 1) - 1)
		s.wrapNext = false
	case 'E': // CNL
		s.y = clamp(s.y+cnt(p1), 0, s.rows-1) // clamp (not min): see CUD above
		s.x = 0
		s.wrapNext = false
	case 'F': // CPL
		s.y = max(s.y-cnt(p1), 0)
		s.x = 0
		s.wrapNext = false
	case 'J': // ED
		s.eraseDisplay(param(params, 0, 0))
	case 'K': // EL
		s.eraseLine(param(params, 0, 0))
	case 'L': // IL — insert lines
		s.insertLines(cnt(p1))
	case 'M': // DL — delete lines
		s.deleteLines(cnt(p1))
	case '@': // ICH — insert blanks
		s.insertChars(cnt(p1))
	case 'P': // DCH — delete chars
		s.deleteChars(cnt(p1))
	case 'X': // ECH — erase chars
		s.eraseChars(cnt(p1))
	case 'S': // SU — scroll up
		s.scrollUp(cnt(p1))
	case 'T': // SD — scroll down
		s.scrollDown(cnt(p1))
	case 'b': // REP — repeat last graphic char
		if s.lastRune != 0 {
			// Cap the repeat at the cell count: filling every cell once is the
			// most a repaint can show, so a larger count only spins the Pump
			// goroutine under screenMu (CPU DoS + lock starvation). Real REP
			// counts are tiny, so this is a no-op for legitimate input.
			n := cnt(p1)
			if cells := s.cols * s.rows; n > cells {
				n = cells
			}
			for k := 0; k < n; k++ {
				s.putRune(s.lastRune)
			}
		}
	case 'm': // SGR
		s.sgr(params)
	case 'r': // DECSTBM — set scroll region
		top := param(params, 0, 1)
		bottom := param(params, 1, 0)
		if bottom == 0 {
			bottom = s.rows
		}
		t := clamp(top-1, 0, s.rows-1)
		b := clamp(bottom-1, 0, s.rows-1)
		if t < b {
			s.top, s.bottom = t, b
		} else {
			s.top, s.bottom = 0, s.rows-1
		}
		// DECSTBM homes the cursor to the region origin.
		if s.originMode {
			s.x, s.y = 0, s.top
		} else {
			s.x, s.y = 0, 0
		}
		s.wrapNext = false
	case 's': // SCOSC — save cursor (bare)
		if len(params) == 0 {
			s.saveCursor()
		}
	case 'u': // SCORC — restore cursor
		s.restoreCursor()
	case 'h', 'l': // ANSI mode set/reset (IRM etc. — not modeled, benign)
	default:
		// Unknown finals are benign (cursor style 'q', tab clears 'g', device
		// reports…) and do not restructure content, so stay faithful.
	}
	return consumed
}

// moveTo sets the cursor to a 0-based (col,row), honoring origin mode.
func (s *Screen) moveTo(col, row int) {
	s.x = clamp(col, 0, s.cols-1)
	s.setRow(row)
	s.wrapNext = false
}

// setRow sets the 0-based cursor row (as passed by a CUP/VPA whose value has
// already had its 1 subtracted), honoring origin mode.
func (s *Screen) setRow(row int) {
	if s.originMode {
		s.y = clamp(s.top+row, s.top, s.bottom)
	} else {
		s.y = clamp(row, 0, s.rows-1)
	}
}

func (s *Screen) insertLines(n int) {
	if s.y < s.top || s.y > s.bottom {
		return
	}
	s.scrollDownRange(s.y, s.bottom, n)
}

func (s *Screen) deleteLines(n int) {
	if s.y < s.top || s.y > s.bottom {
		return
	}
	s.scrollUpRange(s.y, s.bottom, n)
}

func (s *Screen) insertChars(n int) {
	row := s.grid[s.y]
	if n > s.cols-s.x {
		n = s.cols - s.x
	}
	if n <= 0 {
		return
	}
	copy(row[s.x+n:], row[s.x:s.cols-n])
	for c := s.x; c < s.x+n; c++ {
		row[c] = s.blank()
	}
}

func (s *Screen) deleteChars(n int) {
	row := s.grid[s.y]
	if n > s.cols-s.x {
		n = s.cols - s.x
	}
	if n <= 0 {
		return
	}
	copy(row[s.x:], row[s.x+n:s.cols])
	for c := s.cols - n; c < s.cols; c++ {
		row[c] = s.blank()
	}
}

func (s *Screen) eraseChars(n int) {
	row := s.grid[s.y]
	for c := s.x; c < s.x+n && c < s.cols; c++ {
		row[c] = s.blank()
	}
}

func (s *Screen) eraseLine(mode int) {
	row := s.grid[s.y]
	switch mode {
	case 0: // cursor → end
		for c := s.x; c < s.cols; c++ {
			row[c] = s.blank()
		}
	case 1: // start → cursor
		for c := 0; c <= s.x && c < s.cols; c++ {
			row[c] = s.blank()
		}
	case 2: // whole line
		for c := 0; c < s.cols; c++ {
			row[c] = s.blank()
		}
	}
}

func (s *Screen) eraseDisplay(mode int) {
	switch mode {
	case 0: // cursor → end of screen
		s.eraseLine(0)
		for r := s.y + 1; r < s.rows; r++ {
			s.blankRow(s.grid[r])
		}
	case 1: // start → cursor
		for r := 0; r < s.y; r++ {
			s.blankRow(s.grid[r])
		}
		s.eraseLine(1)
	case 2, 3: // whole screen
		for r := 0; r < s.rows; r++ {
			s.blankRow(s.grid[r])
		}
		// A full clear re-establishes a known-good grid, so it recovers
		// faithfulness lost to an earlier gap (MarkStale) or a since-cleared
		// unfaithful op — the app repaints onto a blank slate we track exactly.
		s.faithful = true
	}
}

func (s *Screen) saveCursor() {
	s.saved = cursorState{x: s.x, y: s.y, a: s.cur, wrapNext: s.wrapNext, origin: s.originMode, set: true}
}

func (s *Screen) restoreCursor() {
	if !s.saved.set {
		s.x, s.y, s.cur, s.wrapNext = 0, 0, defaultAttr, false
		return
	}
	s.x = clamp(s.saved.x, 0, s.cols-1)
	s.y = clamp(s.saved.y, 0, s.rows-1)
	s.cur = s.saved.a
	s.wrapNext = s.saved.wrapNext
	s.originMode = s.saved.origin
}

func (s *Screen) setPrivateMode(m int, set bool) {
	switch m {
	case 1049:
		if set {
			s.enterAlt(true, true)
		} else {
			s.exitAlt(true)
		}
	case 1047:
		if set {
			s.enterAlt(true, false)
		} else {
			s.exitAlt(false)
		}
	case 47:
		if set {
			s.enterAlt(false, false)
		} else {
			s.exitAlt(false)
		}
	case 7: // DECAWM autowrap
		s.autowrap = set
		s.wrapNext = false
	case 6: // DECOM origin mode — homes cursor to region origin
		s.originMode = set
		if set {
			s.x, s.y = 0, s.top
		} else {
			s.x, s.y = 0, 0
		}
		s.wrapNext = false
	case 25:
		s.cursorVisible = set
	case 2004:
		s.bracketedPaste = set
	case 1000:
		s.mouse1000 = set
	case 1002:
		s.mouse1002 = set
	case 1003:
		s.mouse1003 = set
	case 1006:
		s.mouse1006 = set
	}
}

func (s *Screen) enterAlt(clear, saveCur bool) {
	if !s.altActive {
		if saveCur {
			s.altSaved = cursorState{x: s.x, y: s.y, a: s.cur, wrapNext: s.wrapNext, origin: s.originMode, set: true}
		}
		s.altActive = true
		s.grid = s.alt
		s.top, s.bottom = 0, s.rows-1
	}
	s.knowsBufferState = true
	if clear {
		for r := 0; r < s.rows; r++ {
			s.blankRow(s.grid[r])
		}
		s.x, s.y = 0, 0
		s.wrapNext = false
		// Entering a cleared alt buffer is a known-good slate; recover
		// faithfulness the same way a full ED 2 does (see eraseDisplay).
		s.faithful = true
	}
}

func (s *Screen) exitAlt(restoreCur bool) {
	// Observing the sequence is what counts, not whether it changed anything: a
	// ?1049l on an already-main buffer still tells us the pty is on main.
	s.knowsBufferState = true
	if !s.altActive {
		return
	}
	s.altActive = false
	s.grid = s.main
	s.top, s.bottom = 0, s.rows-1
	if restoreCur && s.altSaved.set {
		s.x = clamp(s.altSaved.x, 0, s.cols-1)
		s.y = clamp(s.altSaved.y, 0, s.rows-1)
		s.cur = s.altSaved.a
		s.wrapNext = s.altSaved.wrapNext
		s.originMode = s.altSaved.origin
	}
}

func (s *Screen) sgr(params []int) {
	if len(params) == 0 {
		s.cur = defaultAttr
		return
	}
	for i := 0; i < len(params); i++ {
		switch n := params[i]; {
		case n == 0:
			s.cur = defaultAttr
		case n == 1:
			s.cur.bold = true
		case n == 2:
			s.cur.dim = true
		case n == 3:
			s.cur.italic = true
		case n == 4:
			s.cur.underline = true
		case n == 7:
			s.cur.rev = true
		case n == 21, n == 22:
			s.cur.bold, s.cur.dim = false, false
		case n == 23:
			s.cur.italic = false
		case n == 24:
			s.cur.underline = false
		case n == 27:
			s.cur.rev = false
		case n == 38:
			if c, ni := sgrColorAt(params, i); ni > i {
				s.cur.fg = c
				i = ni
			}
		case n == 48:
			if c, ni := sgrColorAt(params, i); ni > i {
				s.cur.bg = c
				i = ni
			}
		case n == 39:
			s.cur.fg = color{}
		case n == 49:
			s.cur.bg = color{}
		case n >= 30 && n <= 37:
			s.cur.fg = color{mode: colIndexed, v: uint32(n - 30)}
		case n >= 40 && n <= 47:
			s.cur.bg = color{mode: colIndexed, v: uint32(n - 40)}
		case n >= 90 && n <= 97:
			s.cur.fg = color{mode: colIndexed, v: uint32(n - 90 + 8)}
		case n >= 100 && n <= 107:
			s.cur.bg = color{mode: colIndexed, v: uint32(n - 100 + 8)}
		}
	}
}

// sgrColorAt parses a 38/48 extended color starting at params[i] (== 38 or 48).
// Returns the parsed color and the new index (== i if it could not parse, so
// the caller leaves the pen unchanged). Handles both the 256-indexed (5;n) and
// truecolor (2;r;g;b) forms; colon sub-parameters are flattened by parseParams
// so 38:5:n / 48:2:r:g:b arrive here already split.
func sgrColorAt(params []int, i int) (color, int) {
	if i+1 >= len(params) {
		return color{}, i
	}
	switch params[i+1] {
	case 5:
		if i+2 < len(params) {
			return color{mode: colIndexed, v: uint32(clamp(params[i+2], 0, 255))}, i + 2
		}
	case 2:
		if i+4 < len(params) {
			r := uint32(clamp(params[i+2], 0, 255))
			g := uint32(clamp(params[i+3], 0, 255))
			b := uint32(clamp(params[i+4], 0, 255))
			return color{mode: colRGB, v: r<<16 | g<<8 | b}, i + 4
		}
	}
	return color{}, i
}

// parseParams splits a CSI parameter string into integers. Both ';' (parameter)
// and ':' (sub-parameter) separators split into the flat list, which keeps the
// colon color forms (38:5:n, 48:2:r:g:b) working and prevents a stray ':' from
// corrupting the following parameter (e.g. an underline-style 4:3).
func parseParams(b []byte) []int {
	if len(b) == 0 {
		return nil
	}
	out := []int{}
	cur := 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			cur = cur*10 + int(c-'0')
			// Cap each parameter at xterm's maximum so a pathologically long
			// digit run can't overflow int and wrap negative — a wrapped count
			// would defeat the min()/clamp guards downstream (CUD/CNL/REP) and
			// drive an out-of-bounds grid index. Real CSI params are tiny
			// (colors ≤255, positions ≤ screen size, modes ≤ ~2004), so this
			// only affects pathological input.
			if cur > csiParamMax {
				cur = csiParamMax
			}
		case c == ';' || c == ':':
			out = append(out, cur)
			cur = 0
		}
	}
	out = append(out, cur)
	return out
}

func param(p []int, idx, def int) int {
	if idx < len(p) {
		if p[idx] != 0 {
			return p[idx]
		}
		return p[idx] // explicit 0 stays 0
	}
	return def
}

// cnt returns a repeat count: a 0 or absent value means 1.
func cnt(v int) int {
	if v < 1 {
		return 1
	}
	return v
}

func (c color) codes(fg bool) []int {
	switch c.mode {
	case colIndexed:
		if fg {
			return []int{38, 5, int(c.v)}
		}
		return []int{48, 5, int(c.v)}
	case colRGB:
		r := int(c.v >> 16 & 0xff)
		g := int(c.v >> 8 & 0xff)
		b := int(c.v & 0xff)
		if fg {
			return []int{38, 2, r, g, b}
		}
		return []int{48, 2, r, g, b}
	}
	return nil
}

func (a attr) sgrCodes() []int {
	if a == defaultAttr {
		return []int{0}
	}
	out := []int{0}
	if a.bold {
		out = append(out, 1)
	}
	if a.dim {
		out = append(out, 2)
	}
	if a.italic {
		out = append(out, 3)
	}
	if a.underline {
		out = append(out, 4)
	}
	if a.rev {
		out = append(out, 7)
	}
	out = append(out, a.fg.codes(true)...)
	out = append(out, a.bg.codes(false)...)
	return out
}

func sgrBytes(a attr) []byte {
	codes := a.sgrCodes()
	out := make([]byte, 0, 4+2*len(codes))
	out = append(out, '\x1b', '[')
	for i, c := range codes {
		if i > 0 {
			out = append(out, ';')
		}
		out = append(out, strconv.Itoa(c)...)
	}
	return append(out, 'm')
}

func appendCell(out []byte, g cell) []byte {
	var buf [4]byte
	n := utf8.EncodeRune(buf[:], g.r)
	out = append(out, buf[:n]...)
	if g.comb != "" {
		out = append(out, g.comb...)
	}
	return out
}

func (s *Screen) rowEnd(r int) int {
	for c := s.cols - 1; c >= 0; c-- {
		if !isBlank(s.grid[r][c]) {
			return c
		}
	}
	return -1
}

// Repaint serializes the currently-active buffer into a self-contained repaint,
// modeled on mosh's Display::new_frame(initialized=false): if the alt buffer is
// active it is prefixed with ?1049h (so the client switches to a cleared alt
// screen); then SGR reset + home + clear; then each non-blank row is positioned
// and emitted as SGR runs (pen tracked, emitted only on change), using EL to
// clear a shorter row's tail rather than writing trailing blanks; wide-glyph
// lead cells are emitted and their spacer skipped. The app's tracked modes
// (autowrap, bracketed paste, mouse, cursor visibility) are restored, and it
// finishes with an absolute CUP to the real cursor.
func (s *Screen) Repaint() []byte {
	var out []byte
	if s.altActive {
		out = append(out, "\x1b[?1049h"...)
	}
	// Reset SGR, scroll region (full), and origin mode (off) before painting,
	// so a client with stale region/origin from a prior attach paints cleanly
	// and every per-row CUP below is absolute. The app's real region/origin
	// are restored at the end.
	out = append(out, "\x1b[m\x1b[r\x1b[?6l\x1b[H\x1b[2J"...)

	pen := defaultAttr
	havePen := false
	for r := 0; r < s.rows; r++ {
		end := s.rowEnd(r)
		if end < 0 {
			continue
		}
		out = append(out, "\x1b["...)
		out = append(out, strconv.Itoa(r+1)...)
		out = append(out, ";1H"...)
		for c := 0; c <= end; c++ {
			g := s.grid[r][c]
			if g.width == 0 {
				continue // spacer
			}
			if !havePen || g.a != pen {
				out = append(out, sgrBytes(g.a)...)
				pen, havePen = g.a, true
			}
			out = appendCell(out, g)
		}
		// A wide glyph leading at cols-2 fills THROUGH cols-1, so the row is
		// visually full — skip EL there: its erase-to-EOL would clobber the
		// glyph's right half when the client's cursor sits in pending-wrap.
		visEnd := end
		if s.grid[r][end].width == 2 {
			visEnd++
		}
		if visEnd < s.cols-1 {
			if !havePen || pen != defaultAttr {
				out = append(out, sgrBytes(defaultAttr)...)
				pen, havePen = defaultAttr, true
			}
			out = append(out, "\x1b[K"...)
		}
	}
	if !havePen || pen != defaultAttr {
		out = append(out, "\x1b[m"...)
	}

	// Restore the modes the app set.
	if !s.autowrap {
		out = append(out, "\x1b[?7l"...)
	}
	if s.bracketedPaste {
		out = append(out, "\x1b[?2004h"...)
	}
	if s.mouse1000 {
		out = append(out, "\x1b[?1000h"...)
	}
	if s.mouse1002 {
		out = append(out, "\x1b[?1002h"...)
	}
	if s.mouse1003 {
		out = append(out, "\x1b[?1003h"...)
	}
	if s.mouse1006 {
		out = append(out, "\x1b[?1006h"...)
	}
	if !s.cursorVisible {
		out = append(out, "\x1b[?25l"...)
	}

	// Restore the scroll region (DECSTBM) and origin mode (DECOM) the app
	// set, so its subsequent region-relative scrolls / cursor moves land
	// where it expects on the reattached client. Region first (it homes the
	// cursor and, under origin mode, frames the CUP); then origin mode; then
	// the cursor as a region-relative row when origin mode is on. The cell
	// painting above ran with the full-screen region + origin off (reset at
	// the top), so those CUPs stayed absolute.
	if s.top != 0 || s.bottom != s.rows-1 {
		out = append(out, "\x1b["...)
		out = append(out, strconv.Itoa(s.top+1)...)
		out = append(out, ';')
		out = append(out, strconv.Itoa(s.bottom+1)...)
		out = append(out, 'r')
	}
	cy := s.y
	if s.originMode {
		out = append(out, "\x1b[?6h"...)
		if cy = s.y - s.top; cy < 0 {
			cy = 0
		}
	}
	out = append(out, "\x1b["...)
	out = append(out, strconv.Itoa(cy+1)...)
	out = append(out, ';')
	out = append(out, strconv.Itoa(s.x+1)...)
	out = append(out, 'H')
	if s.cursorVisible {
		out = append(out, "\x1b[?25h"...)
	}
	return out
}

// Reconstruct replays ring through a fresh Screen and returns the repaint plus
// whether the model stayed faithful.
func Reconstruct(ring []byte, rows, cols int) (repaint []byte, faithful bool) {
	s := New(rows, cols)
	s.Feed(ring)
	return s.Repaint(), s.faithful
}

// RepaintRows serializes rows [from, to) as a CURSOR-NEUTRAL in-place redraw:
// ESC7 (save cursor + attrs), then per row `ESC[r;1H` + SGR runs + text + EL
// (erase any stale tail), then ESC8 (restore). No screen clear — it refreshes
// those rows in place, so re-emitting it into the live stream doesn't disturb
// the cursor/attrs of other attached clients. Rows are clamped to the grid.
func (s *Screen) RepaintRows(from, to int) []byte {
	from = clamp(from, 0, s.rows)
	to = clamp(to, 0, s.rows)
	if from >= to {
		return nil
	}
	out := []byte("\x1b7") // DECSC — save cursor + attributes
	pen := defaultAttr
	havePen := false
	for r := from; r < to; r++ {
		out = append(out, "\x1b["...)
		out = append(out, strconv.Itoa(r+1)...)
		out = append(out, ";1H"...)
		end := s.rowEnd(r)
		for c := 0; c <= end; c++ {
			g := s.grid[r][c]
			if g.width == 0 {
				continue
			}
			if !havePen || g.a != pen {
				out = append(out, sgrBytes(g.a)...)
				pen, havePen = g.a, true
			}
			out = appendCell(out, g)
		}
		if !havePen || pen != defaultAttr {
			out = append(out, sgrBytes(defaultAttr)...) // default bg for the erased tail
			pen, havePen = defaultAttr, true
		}
		out = append(out, "\x1b[K"...)
	}
	out = append(out, "\x1b8"...) // DECRC — restore cursor + attributes
	return out
}

// ReconstructBottomRows replays ring through a fresh Screen and returns a
// cursor-neutral redraw of the bottom n rows (the footer block), plus whether
// the model stayed faithful.
func ReconstructBottomRows(ring []byte, rows, cols, n int) (redraw []byte, faithful bool) {
	s := New(rows, cols)
	s.Feed(ring)
	if n > rows {
		n = rows
	}
	return s.RepaintRows(rows-n, rows), s.faithful
}
