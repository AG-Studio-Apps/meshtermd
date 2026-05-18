package session

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"
)

// wedgeCaptureBytesEnvVar opts the watcher into recording the
// post-resize PTY byte stream in each JSONL record (base64-encoded).
// Off by default because the captured bytes can include rendered
// terminal content — application UI, chat messages, command output —
// and the JSONL is otherwise de-identified-by-construction. Set
// `MESHTERMD_WEDGE_CAPTURE_BYTES=1` in the daemon's env to enable for
// detection-refinement data collection. Sample the JSONL contents
// before sharing externally if the env var is on.
const wedgeCaptureBytesEnvVar = "MESHTERMD_WEDGE_CAPTURE_BYTES"

// wedgeCaptureBufferCap caps the rolling buffer of post-resize bytes
// the watcher retains for inclusion in a JSONL record on a fire.
// 4 KiB is enough to span a single typical Claude redraw frame plus
// some leading context. Per-session memory cost is negligible; we
// trim from the front as new bytes arrive past the cap.
const wedgeCaptureBufferCap = 4 * 1024

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
// WedgeNotice is the cross-package value the wedge watcher pushes to
// its onWedge subscriber on every detection. Mirrors the JSONL record
// shape but lives in the session package so callers outside protocol/
// don't depend on the wire types — the transport layer maps this to
// protocol.WedgeDetected when it pushes to the attached client.
type WedgeNotice struct {
	Kind               string // "silent" | "cursor_row" | "vertical_walk"
	SessionAgeSec      int64
	TotalOutBytes      uint64
	OldRows            uint16
	NewRows            uint16
	ResizesObserved    uint64
	SilentWedges       uint64
	CursorWedges       uint64
	VerticalWalkWedges uint64
	CudObserved        int
	CursorRowSeen      int
}

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

	// onWedge, if non-nil, is called on every wedge detection with a
	// WedgeNotice value. The transport layer installs this when an
	// exclusive client attaches so the daemon can push a
	// protocol.WedgeDetected frame to surface a recovery banner in
	// the client UI. Called outside the watcher's lock to keep the
	// callback path off the hot detection path; the callback must
	// itself be non-blocking (the transport implementation uses the
	// existing serialised frameWriter, which is mutex-guarded).
	onWedge func(WedgeNotice)

	// Cumulative output volume since the session started. Surfaced in
	// every wedge record so we can correlate session size with wedge
	// likelihood — the user's bug report noted the failure correlates
	// with long-running / large-context sessions.
	totalOutBytes uint64

	// Cumulative count of resize events observed and wedges raised.
	resizesObserved    uint64
	silentWedges       uint64
	cursorWedges       uint64
	verticalWalkWedges uint64

	// resizePending is true between an ArmResize call and either
	// (a) the silent-deadline timer firing or (b) the post-resize
	// window having accumulated enough redraw bytes for us to clear
	// it. While true, ObserveBytes scans for CUP rows > pendingRows
	// and for cumulative CUD motions exceeding pendingRows.
	resizePending bool

	resizeAt       time.Time
	oldRows        uint16
	pendingRows    uint16
	pendingCols    uint16
	bytesAtResize  uint64
	pendingTimerCh chan struct{} // closed when the silent-deadline timer should stop early
	wedgeRaised    bool          // any wedge already raised for this resize; suppress duplicates

	// suppressUntil silences ALL wedge signals (silent, cursor_row,
	// vertical_walk) until the wall-clock passes it. The recovery
	// sequencer sets this at the end of a save-restart cycle to
	// suppress the well-known false-positive storm caused by
	// `claude --resume` replaying scrollback (lots of CUDs in
	// milliseconds, no real wedge — just restoration replay). Zero
	// value = no suppression. The watcher checks via
	// time.Now().Before(suppressUntil).
	suppressUntil time.Time

	// captureBytes mirrors the MESHTERMD_WEDGE_CAPTURE_BYTES env at
	// construction time so the hot ObserveBytes path doesn't pay the
	// cost of an os.Getenv every chunk. When true, captureBuffer
	// accumulates post-ArmResize bytes (capped at wedgeCaptureBufferCap)
	// and the watcher includes a base64 slice in every JSONL record
	// on a fire. Used for detection-refinement data collection; off
	// by default because the captured bytes can include rendered
	// terminal content.
	captureBytes  bool
	captureBuffer []byte

	// CSI scanner state — feed continues across chunks. Only mutated
	// inside ObserveBytes (which holds the lock).
	scanner csiScanner

	// altScreen tracks whether the pty is currently on the alternate
	// screen buffer. Fed on every ObserveBytes chunk regardless of
	// resizePending, since apps enter alt-screen (Claude /tui, htop,
	// less, vim) at startup — long before the first iOS-driven resize.
	// The vertical_walk signal is gated on this so default-mode shells
	// don't false-positive on keyboard-induced resizes. See the
	// altScreenTracker doc comment for the full reasoning.
	altScreen altScreenTracker
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

// verticalWalkWindow is the tighter time bound that gates the
// vertical_walk signal specifically. Field-validated: real wedges
// fire sub-100ms after SIGWINCH (Claude immediately redraws the
// stale frame as a single contiguous CUD burst); healthy multi-frame
// renders accumulate CUDs across many seconds (spinner ticks, status
// bar updates, scrollback replay during `claude --resume`). 800ms
// captures the real-wedge response window with generous headroom
// without bleeding into the multi-frame false-positive territory.
//
// cursor_row keeps the full scanWindow — its threshold (CUP row
// strictly > pendingRows) is unambiguous regardless of timing, so
// the wider window doesn't bring in false positives.
const verticalWalkWindow = 800 * time.Millisecond

func newWedgeWatcher() *wedgeWatcher {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return &wedgeWatcher{
		anonID:       hex.EncodeToString(b[:]),
		captureBytes: os.Getenv(wedgeCaptureBytesEnvVar) == "1",
	}
}

// SetLogPath wires the JSONL output destination. Idempotent; safe to
// call before the first ArmResize.
func (w *wedgeWatcher) SetLogPath(path string) {
	w.mu.Lock()
	w.logPath = path
	w.mu.Unlock()
}

// SetOnWedge installs (or clears, with nil) the per-watcher callback
// invoked on every detection. The callback runs outside the watcher's
// lock; callers must keep it non-blocking. Set by the transport layer
// when an exclusive client attaches, cleared on detach.
func (w *wedgeWatcher) SetOnWedge(cb func(WedgeNotice)) {
	w.mu.Lock()
	w.onWedge = cb
	w.mu.Unlock()
}

// SuppressUntil silences ALL wedge detections until the given
// wall-clock time. Used by the recovery sequencer to gate the false-
// positive storm during `claude --resume` scrollback replay (lots of
// rapid CUDs from re-painting history, no real wedge). Pass a
// zero-value time.Time to clear suppression.
func (w *wedgeWatcher) SuppressUntil(t time.Time) {
	w.mu.Lock()
	w.suppressUntil = t
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
	w.wedgeRaised = false
	// Reset the CSI scanner's cumulative cursor-down counter so each
	// resize gets its own walk budget. Without this, a long-running
	// session would accumulate CUD across many resizes and the
	// vertical_walk signal would false-positive on the first resize
	// that happens after the cumulative count crossed the threshold.
	w.scanner.reset()
	// Reset the capture buffer too: each resize is its own diagnostic
	// frame. Allocated lazily on first append in ObserveBytes.
	if w.captureBytes {
		w.captureBuffer = w.captureBuffer[:0]
	}
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
	// Post-recovery cooldown: the sequencer sets suppressUntil at
	// the end of every save-restart cycle. While it's in the future
	// every signal — including silent — is muted. Keeps the banner
	// from re-popping during `claude --resume` scrollback replay.
	if !w.suppressUntil.IsZero() && time.Now().Before(w.suppressUntil) {
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
	// Always update alt-screen state — apps may enter/exit alt-screen
	// outside any resize window (Claude /tui starts on app launch).
	// Cheap state-machine scan; ignores everything except ?1049/?1047/?47.
	w.altScreen.feed(data)
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
	// Capture-bytes diagnostic mode: accumulate the raw post-resize
	// byte stream so we can inspect what Claude actually emitted when
	// a wedge fires. Sliding window — keep the most recent
	// wedgeCaptureBufferCap bytes so a long pre-fire history doesn't
	// blow the cap. Skipped entirely when the env var is off, so the
	// hot path stays zero-allocation in the default release.
	if w.captureBytes {
		w.captureBuffer = append(w.captureBuffer, data...)
		if len(w.captureBuffer) > wedgeCaptureBufferCap {
			// Trim from the front, keep the tail (most recent context).
			w.captureBuffer = append(w.captureBuffer[:0],
				w.captureBuffer[len(w.captureBuffer)-wedgeCaptureBufferCap:]...)
		}
	}
	// Only scan when the new geometry is strictly smaller — that's the
	// only configuration where a stale CUP row is provably illegal.
	// (A larger window would still accept old row numbers as valid.)
	if w.pendingRows >= w.oldRows {
		w.mu.Unlock()
		return
	}
	if w.wedgeRaised {
		// One report per resize is enough — we've already flagged a
		// wedge of some flavour for this resize window.
		w.mu.Unlock()
		return
	}
	// Post-recovery cooldown — same gate as the silent path. The
	// recovery sequencer sets suppressUntil at the end of every
	// save-restart so the false-positive storm during `claude
	// --resume` scrollback replay (lots of rapid CUDs from history
	// repaint) doesn't re-pop the banner the moment recovery
	// finishes. Once the cooldown expires the watcher's back to
	// normal sensitivity.
	if !w.suppressUntil.IsZero() && time.Now().Before(w.suppressUntil) {
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

	// Two complementary signals from one scanner pass:
	//   - violatingRow > 0   → CUP/HVP with row > pendingRows.
	//     Strong evidence Claude emits absolute moves for old geometry.
	//   - cudCount > pendingRows → cumulative relative cursor-down walk
	//     since the last resize already exceeds the new row count.
	//     Matches the Ink-renderer mechanism diagnosed in the upstream
	//     issue: relative-only redraw walks an old-geometry frame past
	//     the new viewport. Tighter time window than cursor_row
	//     because the cumulative-CUD signal is genuinely noisy on
	//     long-tail healthy renders (spinner ticks + status updates).
	violatingRow := w.scanner.feed(data, pendingRows)
	cudCount := w.scanner.cudCount()
	msSinceResize := time.Since(w.resizeAt)

	var (
		wedgeType     string
		note          string
		cursorRowSeen int
		cudObserved   int
	)
	switch {
	case violatingRow > 0:
		wedgeType = "cursor_row"
		note = "CUP escape referenced row > new geometry — app is drawing for old size"
		cursorRowSeen = violatingRow
	case cudCount > int(pendingRows) && msSinceResize <= verticalWalkWindow && w.altScreen.isActive():
		// Alt-screen gate (added v0.9.10): vertical_walk only holds for
		// renderers driving the alternate screen (Claude /tui, htop,
		// less, vim). Default-mode shells legitimately emit bursts of
		// CUDs after a resize — Claude in non-/tui mode walks its
		// streaming output area every time the iOS keyboard appears
		// and shrinks the pty from ~40 rows to ~18, which previously
		// fired vertical_walk constantly with no underlying wedge.
		// cursor_row stays ungated; an absolute CUP > rows is wrong
		// in any mode.
		wedgeType = "vertical_walk"
		note = "cumulative CUD motions exceed new row count — relative-only redraw painting past viewport"
		cudObserved = cudCount
	default:
		w.mu.Unlock()
		return
	}

	switch wedgeType {
	case "cursor_row":
		w.cursorWedges++
	case "vertical_walk":
		w.verticalWalkWedges++
	}
	w.wedgeRaised = true
	cursorWedges := w.cursorWedges
	verticalWedges := w.verticalWalkWedges
	// Snapshot the capture buffer under the lock so the emit path
	// outside the lock works on a stable slice. Off when capture
	// is disabled — keeps the JSONL field empty and out of the
	// way (`omitempty` on the struct tag handles serialisation).
	var captureSnapshot []byte
	if w.captureBytes && len(w.captureBuffer) > 0 {
		captureSnapshot = make([]byte, len(w.captureBuffer))
		copy(captureSnapshot, w.captureBuffer)
	}
	w.mu.Unlock()

	rec := wedgeEvent{
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		AnonSessionID:      anon,
		WedgeType:          wedgeType,
		SessionAgeSec:      int64(time.Since(sessionCreated).Seconds()),
		TotalOutBytes:      totalOut,
		ResizesObserved:    resizes,
		SilentWedges:       silent,
		CursorWedges:       cursorWedges,
		VerticalWalkWedges: verticalWedges,
		OldRows:            oldRows,
		NewRows:            pendingRows,
		Cols:               cols,
		CursorRowSeen:      cursorRowSeen,
		CudObserved:        cudObserved,
		MsSinceResize:      int64(time.Since(w.resizeAt) / time.Millisecond),
		Note:               note,
	}
	if captureSnapshot != nil {
		rec.RecentOutputB64 = base64.StdEncoding.EncodeToString(captureSnapshot)
	}
	w.emit(rec, logPath)
}

// Snapshot returns a point-in-time copy of the watcher's counters.
// Used by status / wedge-report subcommands to render cumulative
// stats without touching internal state.
func (w *wedgeWatcher) Snapshot() (totalOut, resizes, silent, cursor, verticalWalk uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.totalOutBytes, w.resizesObserved, w.silentWedges, w.cursorWedges, w.verticalWalkWedges
}

// emit writes one record to slog (always), to the JSONL file (when
// a path is configured), AND notifies the onWedge subscriber if one
// is installed. All write errors are swallowed — a disk-full or
// permission failure mustn't crash the pump. The subscriber call
// happens outside the watcher's lock; the subscriber is expected to
// be non-blocking (the transport layer's frameWriter is already
// mutex-guarded so the QUIC stream write is serialised correctly).
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
		"cud_observed", rec.CudObserved,
	)
	if logPath != "" {
		if line, err := json.Marshal(rec); err == nil {
			f, ferr := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if ferr == nil {
				_, _ = f.Write(line)
				_, _ = f.Write([]byte{'\n'})
				_ = f.Close()
			}
		}
	}

	// Notify any subscriber after the on-disk write so the receiver
	// can rely on "JSONL has this record by the time my callback
	// fires." Snapshot the callback under the lock to avoid racing
	// with a concurrent SetOnWedge clear.
	w.mu.Lock()
	cb := w.onWedge
	w.mu.Unlock()
	if cb != nil {
		cb(WedgeNotice{
			Kind:               rec.WedgeType,
			SessionAgeSec:      rec.SessionAgeSec,
			TotalOutBytes:      rec.TotalOutBytes,
			OldRows:            rec.OldRows,
			NewRows:            rec.NewRows,
			ResizesObserved:    rec.ResizesObserved,
			SilentWedges:       rec.SilentWedges,
			CursorWedges:       rec.CursorWedges,
			VerticalWalkWedges: rec.VerticalWalkWedges,
			CudObserved:        rec.CudObserved,
			CursorRowSeen:      rec.CursorRowSeen,
		})
	}
}

// wedgeEvent is one JSONL record. Every field is either a metric, a
// dimension count, or a free-form note we wrote ourselves. There is
// deliberately no SessionID, name, hostname, username, path, or PTY
// content — anyone receiving this file learns about geometry math
// and Claude's redraw behaviour, nothing about the user.
type wedgeEvent struct {
	Timestamp          string `json:"ts"`
	AnonSessionID      string `json:"anon_session"`
	WedgeType          string `json:"wedge_type"` // "silent" | "cursor_row" | "vertical_walk"
	SessionAgeSec      int64  `json:"session_age_sec"`
	TotalOutBytes      uint64 `json:"total_out_bytes"`
	ResizesObserved    uint64 `json:"resizes_observed"`
	SilentWedges       uint64 `json:"silent_wedges_so_far"`
	CursorWedges       uint64 `json:"cursor_wedges_so_far"`
	VerticalWalkWedges uint64 `json:"vertical_walk_wedges_so_far"`
	OldRows            uint16 `json:"old_rows"`
	NewRows            uint16 `json:"new_rows"`
	Cols               uint16 `json:"cols"`

	// Silent-wedge fields.
	BytesPostResize uint64 `json:"bytes_post_resize,omitempty"`
	WindowMs        int64  `json:"window_ms,omitempty"`

	// Cursor-row fields.
	CursorRowSeen int `json:"cursor_row_seen,omitempty"`

	// Vertical-walk fields. CudObserved is the cumulative CSI `B`
	// (Cursor-Down) motion count since the last resize. Exceeding the
	// new row count is the proof signal for an Ink-style relative-
	// only redraw painting past the viewport.
	CudObserved int `json:"cud_observed,omitempty"`

	MsSinceResize int64 `json:"ms_since_resize,omitempty"`

	Note string `json:"note,omitempty"`

	// RecentOutputB64 is the base64-encoded post-resize byte stream
	// captured up to the moment of firing, when the watcher was
	// constructed with MESHTERMD_WEDGE_CAPTURE_BYTES=1. Used for
	// detection-refinement analysis — a real wedge looks like a
	// single ~N-row CUD burst, scrollback replay looks like rapid
	// runs of CUDs interleaved with cell content, healthy multi-
	// frame renders look like multiple home-prefixed walks. The
	// field is `omitempty`, so default deployments emit no bytes
	// and the JSONL stays de-identified.
	RecentOutputB64 string `json:"recent_output_b64,omitempty"`
}

// csiScanner is a tiny resumable parser for CSI sequences. We track
// two patterns:
//   - CUP (final `H`) and HVP (final `f`): absolute cursor positioning.
//     We compare the row argument against maxRows on each occurrence
//     and return the offending row on the first violation.
//   - CUD (final `B`): cursor-down motion. We accumulate the parameter
//     (default 1) into cudAccumulated, exposed via cudCount(). Callers
//     use this to detect the Ink-style relative-only redraw mode where
//     the renderer walks down `N` rows of frame content past a smaller
//     viewport (see the upstream issue we filed).
//
// Alt-screen state is tracked separately by altScreenTracker — see
// the comment there for why it can't be folded into this scanner.
//
// State persists across chunks because PTY reads can split an escape
// sequence anywhere.
type csiScanner struct {
	state          csiScanState
	params         []byte
	cudAccumulated int
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
				switch b {
				case 'H', 'f':
					row, _ := parseCUPParams(s.params)
					if row > int(maxRows) {
						s.state = csiNone
						s.params = s.params[:0]
						return row
					}
				case 'B':
					// CUD — Cursor Down by Ps lines (default 1).
					// Accumulate so callers can detect a redraw that
					// walks more vertical space than the new viewport.
					//
					// NO per-frame reset on row=1 CUP. v0.9.7 added one
					// to avoid false-positives on healthy multi-frame
					// renders, but field-tested as too aggressive:
					// Claude emits `\x1b[H` mid-render more often than
					// modelled (status updates, cursor positioning
					// between content blocks), so every such CUP reset
					// the counter and silenced real wedges entirely.
					// Better an occasional false-positive the user
					// dismisses than a missed wedge with no banner.
					// Reverted in v0.9.8.
					s.cudAccumulated += parseSingleParam(s.params, 1)
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

// cudCount returns the cumulative CSI `B` (cursor-down) motion units
// accumulated since the last reset(). Used by the wedge watcher to
// raise a vertical_walk wedge when the walk exceeds the current row
// count.
func (s *csiScanner) cudCount() int { return s.cudAccumulated }

// altScreenTracker watches the PTY byte stream for DECSET/DECRST
// private-mode toggles that switch between the main and alternate
// screen buffer:
//
//   - ?1049 — modern (save cursor + switch + clear) — Claude, htop, less, vim
//   - ?1047 — older switch + clear, no cursor save
//   - ?47   — original alternate buffer
//
// Kept separate from csiScanner because:
//  1. csiScanner is fed only during the post-resize scan window (the
//     watcher returns early when !resizePending). Alt-screen toggles
//     usually happen at app startup, long before any resize — we'd
//     miss them.
//  2. csiScanner.feed() may early-return on a CUP violation, leaving
//     the rest of the chunk unparsed. We want alt-screen tracking to
//     always observe every byte regardless of other signals.
//
// The tracker is fed unconditionally on every ObserveBytes chunk,
// runs a minimal state machine that ignores everything except the
// three alt-screen DECSET markers, and exposes its current state
// to the vertical_walk gate. State persists across chunks because
// escape sequences can split anywhere in the byte stream.
type altScreenTracker struct {
	state  csiScanState
	params []byte
	active bool
}

// feed processes one byte chunk. Side effect only — flips `active`
// when an alt-screen DECSET/DECRST is observed.
func (a *altScreenTracker) feed(buf []byte) {
	for _, b := range buf {
		switch a.state {
		case csiNone:
			if b == 0x1b {
				a.state = csiEsc
			}
		case csiEsc:
			if b == '[' {
				a.state = csiParams
				a.params = a.params[:0]
			} else {
				a.state = csiNone
			}
		case csiParams:
			if b >= 0x40 && b <= 0x7e {
				if b == 'h' && isAltScreenMode(a.params) {
					a.active = true
				} else if b == 'l' && isAltScreenMode(a.params) {
					a.active = false
				}
				a.state = csiNone
				a.params = a.params[:0]
			} else {
				a.params = append(a.params, b)
				if len(a.params) > 64 {
					a.state = csiNone
					a.params = a.params[:0]
				}
			}
		}
	}
}

// isActive reports whether the most recent observed DECSET/DECRST put
// the pty on the alternate screen. Default-false on a fresh tracker —
// sessions start on the main screen.
func (a *altScreenTracker) isActive() bool { return a.active }

// isAltScreenMode reports whether the given CSI parameter slice
// corresponds to one of the alternate-screen DECSET private modes.
// Multi-param sequences (e.g. `?1049;1006h`) are not handled here:
// real-world alt-screen apps issue ?1049 in isolation. If that changes
// we'd split on ';' and check each segment.
func isAltScreenMode(params []byte) bool {
	return bytes.Equal(params, altScreenMode1049) ||
		bytes.Equal(params, altScreenMode1047) ||
		bytes.Equal(params, altScreenMode47)
}

var (
	altScreenMode1049 = []byte("?1049")
	altScreenMode1047 = []byte("?1047")
	altScreenMode47   = []byte("?47")
)

func (s *csiScanner) reset() {
	s.state = csiNone
	if s.params != nil {
		s.params = s.params[:0]
	}
	s.cudAccumulated = 0
}

// parseSingleParam reads a CSI parameter block consisting of a single
// numeric argument (the common form for CUD, CUF, CUU, CUB). Empty or
// unparseable parameters return defaultVal, matching ECMA-48.
func parseSingleParam(p []byte, defaultVal int) int {
	if len(p) == 0 {
		return defaultVal
	}
	// CUD only consults the first param; any trailing `;` are ignored.
	end := bytes.IndexByte(p, ';')
	if end < 0 {
		end = len(p)
	}
	if end == 0 {
		return defaultVal
	}
	v, err := strconv.Atoi(string(p[:end]))
	if err != nil || v <= 0 {
		return defaultVal
	}
	return v
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
