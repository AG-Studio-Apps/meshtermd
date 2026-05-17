package session

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

// wedgeWatcher detects the "Claude TUI ignored SIGWINCH" failure mode
// non-invasively from the daemon's outbound PTY pipeline. The bug
// surfaces as: a SetSize completes successfully (kernel fires SIGWINCH
// at the foreground process group), but the application's renderer
// stays frozen at the old geometry — so the screen ends up split,
// half-stale, with the prompt drawn below the visible viewport.
//
// Two complementary signals are tracked per session:
//
//  1. **Silent post-resize**: a healthy TUI emits hundreds-to-thousands
//     of redraw bytes within ~200 ms of SIGWINCH. If the window after
//     SetSize is conspicuously quiet for the configured deadline and
//     the previous window was active, we flag a candidate wedge.
//     Heuristic — false positives possible when the app is genuinely
//     idle or mid-inference, so the deadline is generous.
//
//  2. **Cursor-row > current rows**: a wedged renderer keeps writing
//     CUP / HVP escape sequences (`\x1b[<row>;<col>H` or `…f`) that
//     reference rows from the OLD geometry. We parse outbound bytes
//     and any CUP whose row exceeds the current row count, observed
//     while a resize is pending, is a confirmed wedge: the app is
//     provably drawing for stale dimensions. No false positives —
//     a correctly-resized app cannot legally emit those.
//
// Detected wedges are logged via slog AND appended (best-effort) as
// de-identified JSON records to {stateDir}/wedge-events.jsonl. The
// record carries only metrics — no session ID, no name, no PTY
// content, no env, no paths — so the file is safe to attach to an
// upstream bug report.
type wedgeWatcher struct {
	mu sync.Mutex

	// Stable per-watcher random handle for correlating records within
	// the same JSONL file without leaking the real SessionID. Eight
	// hex chars = 32 bits of entropy: enough to disambiguate sessions
	// within one daemon run, not enough to identify a host or user.
	anonID string

	// logPath is {stateDir}/wedge-events.jsonl. Empty means "log via
	// slog only" — the daemon's bringup path may construct a Session
	// before the state dir is wired (tests, future code paths).
	logPath string

	// Cumulative output volume since the session started. Surfaced in
	// every wedge record so we can correlate session size with wedge
	// likelihood — the user's bug report noted the failure correlates
	// with long-running / large-context sessions.
	totalOutBytes uint64

	// Cumulative count of resize events observed and wedges raised.
	resizesObserved uint64
	silentWedges    uint64
	cursorWedges    uint64

	// resizePending is true between an ArmResize call and either
	// (a) the silent-deadline timer firing or (b) the post-resize
	// window having accumulated enough redraw bytes for us to clear
	// it. While true, ObserveBytes scans for CUP rows > pendingRows.
	resizePending bool

	resizeAt        time.Time
	oldRows         uint16
	pendingRows     uint16
	pendingCols     uint16
	bytesAtResize   uint64
	pendingTimerCh  chan struct{} // closed when the silent-deadline timer should stop early
	cursorWedgeSeen bool          // already raised cursor wedge for this resize; suppress duplicates

	// CSI scanner state — feed continues across chunks. Only mutated
	// inside ObserveBytes (which holds the lock).
	scanner csiScanner
}

// silentDeadline is the post-resize window we wait for redraw bytes
// before raising a silent-wedge candidate. Generous on purpose:
// Claude mid-inference can legitimately ignore SIGWINCH for a few
// seconds while it finishes generating, and we don't want to spam
// the JSONL with false positives during normal operation.
const silentDeadline = 2 * time.Second

// silentByteFloor is the minimum post-resize byte count we treat as
// evidence of a healthy redraw. Real wedged Claude emits zero bytes;
// bash's PS1 prompt-redraw on SIGWINCH is ~60–80 bytes; an alt-screen
// Claude redraw is hundreds-to-thousands. Setting the floor at 16
// puts a wide gap on both sides of bash's idle redraw so the bash-
// at-prompt case doesn't false-positive every keyboard toggle, while
// still catching a truly zero-byte renderer wedge.
const silentByteFloor = 16

// silentMinSessionAge skips the silent-wedge path for sessions that
// haven't existed long enough to plausibly hit the long-session bug
// we're chasing. The renderer wedge we've seen needs a Claude process
// that's accumulated real context — that can't happen in the first
// 30 seconds after `claude` is launched.
const silentMinSessionAge = 30 * time.Second

// silentMinSessionBytes skips the silent-wedge path when the session
// hasn't emitted enough output to be hosting a real TUI. A bare shell
// at the prompt emits almost nothing; Claude's welcome screen alone
// is >4 KB. So bytesAtResize below this floor means "this session
// isn't a Claude session yet" — silence is the normal state, not
// a wedge.
const silentMinSessionBytes uint64 = 4096

// scanWindow is how long after a resize we keep CSI scanning active.
// Longer than silentDeadline because a sluggish-but-not-wedged Claude
// can take many seconds to start emitting, and we want to catch a
// late-arriving cursor-row violation if it happens.
const scanWindow = 10 * time.Second

func newWedgeWatcher() *wedgeWatcher {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return &wedgeWatcher{anonID: hex.EncodeToString(b[:])}
}

// SetLogPath wires the JSONL output destination. Idempotent; safe to
// call before the first ArmResize.
func (w *wedgeWatcher) SetLogPath(path string) {
	w.mu.Lock()
	w.logPath = path
	w.mu.Unlock()
}

// ArmResize is called from Session.Resize after the PTY's SetSize has
// returned successfully. It records the new geometry, marks the
// watcher as awaiting redraw, and starts a one-shot deadline goroutine
// that raises a silent-wedge candidate if too few bytes flow in the
// window.
func (w *wedgeWatcher) ArmResize(oldRows, newRows, newCols uint16, sessionCreated time.Time) {
	w.mu.Lock()
	// Cancel any in-flight deadline from a prior resize so we don't
	// raise a stale silent wedge against the newer geometry.
	if w.pendingTimerCh != nil {
		close(w.pendingTimerCh)
		w.pendingTimerCh = nil
	}
	w.resizePending = true
	w.resizeAt = time.Now()
	w.oldRows = oldRows
	w.pendingRows = newRows
	w.pendingCols = newCols
	w.bytesAtResize = w.totalOutBytes
	w.resizesObserved++
	w.cursorWedgeSeen = false
	ch := make(chan struct{})
	w.pendingTimerCh = ch
	w.mu.Unlock()

	// One-shot silent-deadline goroutine.
	go w.runSilentDeadline(ch, oldRows, newRows, newCols, sessionCreated)
}

func (w *wedgeWatcher) runSilentDeadline(cancel <-chan struct{}, oldRows, newRows, newCols uint16, sessionCreated time.Time) {
	select {
	case <-cancel:
		return
	case <-time.After(silentDeadline):
	}

	w.mu.Lock()
	// If a newer resize displaced us, our timer channel was already
	// closed; the select above returned via cancel. The timer-fired
	// path only runs when we're still the active pending resize.
	if !w.resizePending || w.pendingRows != newRows || w.pendingCols != newCols {
		w.mu.Unlock()
		return
	}
	delta := w.totalOutBytes - w.bytesAtResize
	if delta >= silentByteFloor {
		// Healthy: enough bytes flowed. Don't clear resizePending —
		// we keep scanning for cursor-row violations during scanWindow.
		w.mu.Unlock()
		return
	}
	// Maturity gates: suppress silent-wedge candidates on sessions
	// that are too young or too small to plausibly be the long-session
	// renderer bug. Avoids the false-positive storm we saw against
	// bash's PS1 prompt redraw (~67 bytes) on a freshly-spawned shell.
	// Cursor-row detection is unaffected — that path stays armed even
	// for fresh sessions because a CUP > new_rows is unambiguous
	// regardless of session age.
	if time.Since(sessionCreated) < silentMinSessionAge || w.bytesAtResize < silentMinSessionBytes {
		w.mu.Unlock()
		return
	}
	w.silentWedges++
	totalOut := w.totalOutBytes
	resizes := w.resizesObserved
	silent := w.silentWedges
	cursor := w.cursorWedges
	anon := w.anonID
	logPath := w.logPath
	w.mu.Unlock()

	rec := wedgeEvent{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		AnonSessionID:   anon,
		WedgeType:       "silent",
		SessionAgeSec:   int64(time.Since(sessionCreated).Seconds()),
		TotalOutBytes:   totalOut,
		ResizesObserved: resizes,
		SilentWedges:    silent,
		CursorWedges:    cursor,
		OldRows:         oldRows,
		NewRows:         newRows,
		Cols:            newCols,
		BytesPostResize: delta,
		WindowMs:        int64(silentDeadline / time.Millisecond),
		Note:            "post-SetSize byte count below floor — possible SIGWINCH ignored",
	}
	w.emit(rec, logPath)
}

// ObserveBytes is called from the PTY pump for every chunk read from
// the child. Always increments the cumulative counter; scans for CUP
// row violations only while a resize is recent (within scanWindow)
// AND the new geometry is smaller than the old one (the only case
// where a stale cursor row would exceed the current row count).
func (w *wedgeWatcher) ObserveBytes(data []byte, sessionCreated time.Time) {
	if len(data) == 0 {
		return
	}
	w.mu.Lock()
	w.totalOutBytes += uint64(len(data))
	if !w.resizePending {
		w.mu.Unlock()
		return
	}
	if time.Since(w.resizeAt) > scanWindow {
		w.resizePending = false
		w.scanner.reset()
		w.mu.Unlock()
		return
	}
	// Only scan when the new geometry is strictly smaller — that's the
	// only configuration where a stale CUP row is provably illegal.
	// (A larger window would still accept old row numbers as valid.)
	if w.pendingRows >= w.oldRows {
		w.mu.Unlock()
		return
	}
	if w.cursorWedgeSeen {
		// One report per resize is enough — we've already flagged.
		w.mu.Unlock()
		return
	}
	pendingRows := w.pendingRows
	oldRows := w.oldRows
	cols := w.pendingCols
	resizes := w.resizesObserved
	silent := w.silentWedges
	totalOut := w.totalOutBytes
	anon := w.anonID
	logPath := w.logPath

	violatingRow := w.scanner.feed(data, pendingRows)
	if violatingRow == 0 {
		w.mu.Unlock()
		return
	}
	w.cursorWedges++
	w.cursorWedgeSeen = true
	cursorWedges := w.cursorWedges
	w.mu.Unlock()

	rec := wedgeEvent{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		AnonSessionID:   anon,
		WedgeType:       "cursor_row",
		SessionAgeSec:   int64(time.Since(sessionCreated).Seconds()),
		TotalOutBytes:   totalOut,
		ResizesObserved: resizes,
		SilentWedges:    silent,
		CursorWedges:    cursorWedges,
		OldRows:         oldRows,
		NewRows:         pendingRows,
		Cols:            cols,
		CursorRowSeen:   violatingRow,
		MsSinceResize:   int64(time.Since(w.resizeAt) / time.Millisecond),
		Note:            "CUP escape referenced row > new geometry — app is drawing for old size",
	}
	w.emit(rec, logPath)
}

// Snapshot returns a point-in-time copy of the watcher's counters.
// Used by status / wedge-report subcommands to render cumulative
// stats without touching internal state.
func (w *wedgeWatcher) Snapshot() (totalOut, resizes, silent, cursor uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.totalOutBytes, w.resizesObserved, w.silentWedges, w.cursorWedges
}

// emit writes one record both to slog (always) and to the JSONL file
// (when a path is configured). All write errors are swallowed — a
// disk-full or permission failure mustn't crash the pump.
func (w *wedgeWatcher) emit(rec wedgeEvent, logPath string) {
	slog.Warn("wedge: candidate detected",
		"anon", rec.AnonSessionID,
		"type", rec.WedgeType,
		"session_age_sec", rec.SessionAgeSec,
		"total_out_bytes", rec.TotalOutBytes,
		"resizes", rec.ResizesObserved,
		"old_rows", rec.OldRows,
		"new_rows", rec.NewRows,
		"bytes_post_resize", rec.BytesPostResize,
		"cursor_row_seen", rec.CursorRowSeen,
	)
	if logPath == "" {
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
	_, _ = f.Write([]byte{'\n'})
}

// wedgeEvent is one JSONL record. Every field is either a metric, a
// dimension count, or a free-form note we wrote ourselves. There is
// deliberately no SessionID, name, hostname, username, path, or PTY
// content — anyone receiving this file learns about geometry math
// and Claude's redraw behaviour, nothing about the user.
type wedgeEvent struct {
	Timestamp       string `json:"ts"`
	AnonSessionID   string `json:"anon_session"`
	WedgeType       string `json:"wedge_type"` // "silent" or "cursor_row"
	SessionAgeSec   int64  `json:"session_age_sec"`
	TotalOutBytes   uint64 `json:"total_out_bytes"`
	ResizesObserved uint64 `json:"resizes_observed"`
	SilentWedges    uint64 `json:"silent_wedges_so_far"`
	CursorWedges    uint64 `json:"cursor_wedges_so_far"`
	OldRows         uint16 `json:"old_rows"`
	NewRows         uint16 `json:"new_rows"`
	Cols            uint16 `json:"cols"`

	// Silent-wedge fields.
	BytesPostResize uint64 `json:"bytes_post_resize,omitempty"`
	WindowMs        int64  `json:"window_ms,omitempty"`

	// Cursor-row fields.
	CursorRowSeen int   `json:"cursor_row_seen,omitempty"`
	MsSinceResize int64 `json:"ms_since_resize,omitempty"`

	Note string `json:"note,omitempty"`
}

// csiScanner is a tiny resumable parser for CSI sequences. We only
// care about CUP (final `H`) and HVP (final `f`); every other CSI
// final is read and discarded. State persists across chunks because
// PTY reads can split an escape sequence anywhere.
type csiScanner struct {
	state  csiScanState
	params []byte
}

type csiScanState int

const (
	csiNone csiScanState = iota
	csiEsc
	csiParams
)

// feed consumes one byte chunk and returns the offending row (>= 1)
// if a CUP / HVP referenced a row > maxRows during this call;
// otherwise 0. Returns on the FIRST violation — callers should
// suppress duplicate reports themselves.
func (s *csiScanner) feed(buf []byte, maxRows uint16) int {
	for _, b := range buf {
		switch s.state {
		case csiNone:
			if b == 0x1b {
				s.state = csiEsc
			}
		case csiEsc:
			if b == '[' {
				s.state = csiParams
				s.params = s.params[:0]
			} else {
				s.state = csiNone
			}
		case csiParams:
			if b >= 0x40 && b <= 0x7e {
				if b == 'H' || b == 'f' {
					row, _ := parseCUPParams(s.params)
					if row > int(maxRows) {
						s.state = csiNone
						s.params = s.params[:0]
						return row
					}
				}
				s.state = csiNone
				s.params = s.params[:0]
			} else {
				s.params = append(s.params, b)
				// Defensive cap — a sane CSI param block is < 16 bytes.
				if len(s.params) > 64 {
					s.state = csiNone
					s.params = s.params[:0]
				}
			}
		}
	}
	return 0
}

func (s *csiScanner) reset() {
	s.state = csiNone
	if s.params != nil {
		s.params = s.params[:0]
	}
}

// parseCUPParams reads the optional `<row>;<col>` parameter block of
// a CSI CUP / HVP. Missing or empty fields default to 1, matching
// the ECMA-48 spec. Either field may be absent (CUP with no params =
// home; `;5H` = row 1 col 5; `5H` = row 5 col 1).
func parseCUPParams(p []byte) (row, col int) {
	row, col = 1, 1
	if len(p) == 0 {
		return
	}
	semi := bytes.IndexByte(p, ';')
	var rowStr, colStr []byte
	if semi < 0 {
		rowStr = p
	} else {
		rowStr = p[:semi]
		colStr = p[semi+1:]
	}
	if len(rowStr) > 0 {
		if r, err := strconv.Atoi(string(rowStr)); err == nil && r > 0 {
			row = r
		}
	}
	if len(colStr) > 0 {
		if c, err := strconv.Atoi(string(colStr)); err == nil && c > 0 {
			col = c
		}
	}
	return
}
