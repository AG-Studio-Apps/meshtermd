package session

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readEvents reads every JSONL record from path. Returns an empty
// slice if the file doesn't exist yet (the watcher creates lazily).
func readEvents(t *testing.T, path string) []wedgeEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open wedge log: %v", err)
	}
	defer f.Close()
	var out []wedgeEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev wedgeEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal: %v (line=%q)", err, sc.Text())
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestCSIScanner_CUP_AboveLimit(t *testing.T) {
	var s csiScanner
	// "\x1b[40;5H" — CUP to row 40 col 5. Limit is 24 rows.
	row := s.feed([]byte("\x1b[40;5H"), 24)
	if row != 40 {
		t.Fatalf("expected row=40, got %d", row)
	}
}

func TestCSIScanner_CUP_AtLimit(t *testing.T) {
	var s csiScanner
	row := s.feed([]byte("\x1b[24;1H"), 24)
	if row != 0 {
		t.Fatalf("row at limit must not trip; got %d", row)
	}
}

func TestCSIScanner_HVP_AltFinalByte(t *testing.T) {
	var s csiScanner
	// `f` is the HVP final byte, same semantics as CUP.
	row := s.feed([]byte("\x1b[33f"), 20)
	if row != 33 {
		t.Fatalf("HVP final byte should trip; got %d", row)
	}
}

func TestCSIScanner_NonPositioningCSI_Ignored(t *testing.T) {
	var s csiScanner
	// "\x1b[2J" — clear screen. Final byte J, not H/f. Must NOT trip.
	row := s.feed([]byte("\x1b[2J\x1b[1;1H"), 24)
	if row != 0 {
		t.Fatalf("CSI J should not trip; got %d", row)
	}
}

func TestCSIScanner_SplitAcrossChunks(t *testing.T) {
	var s csiScanner
	// Feed "\x1b[" then "40H" — must reassemble across chunks.
	if r := s.feed([]byte("\x1b["), 24); r != 0 {
		t.Fatalf("partial chunk should not trip; got %d", r)
	}
	r := s.feed([]byte("40H"), 24)
	if r != 40 {
		t.Fatalf("expected row=40 after rejoin, got %d", r)
	}
}

func TestCSIScanner_HomeNoParams(t *testing.T) {
	var s csiScanner
	// "\x1b[H" — home, row=1 col=1. Must not trip.
	r := s.feed([]byte("\x1b[H"), 24)
	if r != 0 {
		t.Fatalf("home should not trip; got %d", r)
	}
}

func TestCSIScanner_RowOnly(t *testing.T) {
	var s csiScanner
	// "\x1b[7H" — row 7 col 1 (col defaults).
	r := s.feed([]byte("\x1b[7H"), 5)
	if r != 7 {
		t.Fatalf("expected row=7, got %d", r)
	}
}

func TestWedgeWatcher_CursorWedge_LogsRecord(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now().Add(-time.Hour)
	// Old geometry 44 rows; new 23. ArmResize starts the silent-deadline
	// timer; we don't care about that path here.
	w.ArmResize(44, 23, 90, created)
	// Send a CUP that references row 40 (> 23). Within the scan window
	// and the new < old guard, this should flag a cursor-row wedge.
	w.ObserveBytes([]byte("\x1b[40;1Hhello"), created)

	// Give the file write a moment (synchronous append, but be safe).
	events := readEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("expected 1 cursor event, got %d (%+v)", len(events), events)
	}
	got := events[0]
	if got.WedgeType != "cursor_row" {
		t.Fatalf("type: want cursor_row, got %q", got.WedgeType)
	}
	if got.CursorRowSeen != 40 {
		t.Fatalf("cursor_row_seen: want 40, got %d", got.CursorRowSeen)
	}
	if got.OldRows != 44 || got.NewRows != 23 {
		t.Fatalf("rows: want 44→23, got %d→%d", got.OldRows, got.NewRows)
	}
	if got.SessionAgeSec < 3500 || got.SessionAgeSec > 3700 {
		t.Fatalf("session_age_sec: want ~3600, got %d", got.SessionAgeSec)
	}
	if got.AnonSessionID == "" || len(got.AnonSessionID) != 8 {
		t.Fatalf("anon id should be 8 hex chars; got %q", got.AnonSessionID)
	}
	// De-identification: there must be no obvious identifying string
	// in the JSON. (Best-effort substring check — the JSON is metric-
	// only by construction; this guards against accidental future
	// additions.)
	raw, _ := json.Marshal(got)
	for _, leaky := range []string{"/home/", "/Users/", "user@", "session_id"} {
		if strings.Contains(string(raw), leaky) {
			t.Fatalf("wedge record leaks identifying string %q: %s", leaky, raw)
		}
	}
}

func TestWedgeWatcher_CursorWedge_OnlyOncePerResize(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(44, 23, 90, created)
	// First violation triggers, second within the same resize window
	// should be suppressed.
	w.ObserveBytes([]byte("\x1b[40;1H"), created)
	w.ObserveBytes([]byte("\x1b[42;1H"), created)
	events := readEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("expected 1 event (dedup); got %d", len(events))
	}
}

func TestWedgeWatcher_NoFlag_WhenNewGeometryLarger(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	// Resize UP: 23 → 44. Even a CUP at row 30 is legal for the new
	// geometry, so we must not raise a wedge.
	w.ArmResize(23, 44, 90, created)
	w.ObserveBytes([]byte("\x1b[30;1H"), created)
	events := readEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("resize-up must not flag; got %+v", events)
	}
}

func TestWedgeWatcher_SilentWedge_AfterDeadline(t *testing.T) {
	// Mature session: long-existing AND with enough cumulative output
	// that the maturity gates in runSilentDeadline don't suppress the
	// candidate. Then go silent across the deadline.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now().Add(-time.Hour)
	// Push totalOutBytes past silentMinSessionBytes BEFORE ArmResize so
	// bytesAtResize is captured above the floor.
	w.ObserveBytes(make([]byte, silentMinSessionBytes+1000), created)
	w.ArmResize(44, 23, 90, created)
	// Wait out the silent deadline plus a small fudge.
	deadline := time.After(silentDeadline + 500*time.Millisecond)
	<-deadline

	events := readEvents(t, logPath)
	if len(events) == 0 {
		t.Fatalf("expected silent wedge after %v of inactivity", silentDeadline)
	}
	var found bool
	for _, ev := range events {
		if ev.WedgeType == "silent" {
			found = true
			if ev.BytesPostResize != 0 {
				t.Fatalf("expected zero bytes_post_resize on silent wedge; got %d", ev.BytesPostResize)
			}
		}
	}
	if !found {
		t.Fatalf("expected wedge_type=silent record; got %+v", events)
	}
}

func TestWedgeWatcher_NoSilentWedge_WhenRedrawHappens(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now().Add(-time.Hour)
	// Mature: clear both gates so the test exercises the redraw-cleared
	// path, not the suppression path.
	w.ObserveBytes(make([]byte, silentMinSessionBytes+1000), created)
	w.ArmResize(44, 23, 90, created)
	// Simulate a healthy redraw: > silentByteFloor bytes within the
	// deadline. None of them happen to be CUP > 23, so neither wedge
	// type should fire.
	w.ObserveBytes(make([]byte, silentByteFloor+50), created)

	// Wait the deadline.
	time.Sleep(silentDeadline + 200*time.Millisecond)
	events := readEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("expected no events on healthy redraw; got %+v", events)
	}
}

func TestWedgeWatcher_NoSilentWedge_OnFreshSession(t *testing.T) {
	// Both maturity gates should suppress the silent path when the
	// session is too young to be the long-session Claude bug. This
	// pins the behaviour against the false-positive storm observed
	// against bash's PS1 prompt redraw on a freshly-spawned shell:
	// every keyboard toggle on a fresh session was firing silent
	// wedges because bash's ~67-byte response was below the floor.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now() // fresh — within silentMinSessionAge
	// Emit roughly bash's PS1 payload to mimic the real false-positive
	// signature (post-resize bytes below the floor, but still > 0).
	w.ArmResize(24, 20, 90, created)
	w.ObserveBytes(make([]byte, 67), created)
	time.Sleep(silentDeadline + 200*time.Millisecond)
	events := readEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("fresh session must not silent-wedge on idle bash; got %+v", events)
	}
}

func TestWedgeWatcher_NoSilentWedge_OnLowOutputSession(t *testing.T) {
	// Age clears (older than silentMinSessionAge) but cumulative output
	// is below silentMinSessionBytes — i.e. the session has been sitting
	// at a shell prompt for an hour, not hosting Claude. Silence here
	// is normal; suppress.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now().Add(-time.Hour)
	// 200 bytes — well under silentMinSessionBytes.
	w.ObserveBytes(make([]byte, 200), created)
	w.ArmResize(24, 20, 90, created)
	time.Sleep(silentDeadline + 200*time.Millisecond)
	events := readEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("low-output session must not silent-wedge; got %+v", events)
	}
}

func TestWedgeWatcher_CursorWedge_StillFiresOnFreshSession(t *testing.T) {
	// Cursor-row detection is unconditional — a CUP referencing a row
	// beyond new geometry is unambiguous evidence regardless of session
	// age or cumulative output. Make sure the silent-path maturity gates
	// haven't accidentally suppressed it.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now() // fresh
	w.ArmResize(44, 23, 90, created)
	w.ObserveBytes([]byte("\x1b[40;1Hhello"), created)
	events := readEvents(t, logPath)
	if len(events) != 1 || events[0].WedgeType != "cursor_row" {
		t.Fatalf("cursor_row must still fire on fresh session; got %+v", events)
	}
}

func TestWedgeWatcher_TotalBytes_AccumulateAcrossResizes(t *testing.T) {
	w := newWedgeWatcher()
	created := time.Now()
	w.ObserveBytes(make([]byte, 100), created)
	w.ArmResize(44, 23, 90, created)
	w.ObserveBytes(make([]byte, 200), created)
	w.ArmResize(44, 30, 90, created) // displaces the previous pending
	w.ObserveBytes(make([]byte, 50), created)

	total, resizes, _, _, _ := w.Snapshot()
	if total != 350 {
		t.Fatalf("totalOutBytes: want 350, got %d", total)
	}
	if resizes != 2 {
		t.Fatalf("resizesObserved: want 2, got %d", resizes)
	}
}

func TestCSIScanner_CUD_Accumulates(t *testing.T) {
	var s csiScanner
	// Three CUDs: default-1, explicit 5, default-1 → 7 total.
	s.feed([]byte("\x1b[B\x1b[5B\x1b[B"), 100)
	if got := s.cudCount(); got != 7 {
		t.Fatalf("cudCount: want 7, got %d", got)
	}
}

func TestCSIScanner_CUD_ResetClearsCount(t *testing.T) {
	var s csiScanner
	s.feed([]byte("\x1b[10B"), 100)
	if got := s.cudCount(); got != 10 {
		t.Fatalf("pre-reset cudCount: want 10, got %d", got)
	}
	s.reset()
	if got := s.cudCount(); got != 0 {
		t.Fatalf("post-reset cudCount: want 0, got %d", got)
	}
}

func TestCSIScanner_CUD_IgnoresNonBFinals(t *testing.T) {
	var s csiScanner
	// CUF (right), CUU (up), CUB (left), SGR — none should add to CUD.
	s.feed([]byte("\x1b[5C\x1b[3A\x1b[2D\x1b[38;5;231m"), 100)
	if got := s.cudCount(); got != 0 {
		t.Fatalf("non-B finals must not bump CUD; got %d", got)
	}
}

func TestParseSingleParam(t *testing.T) {
	cases := []struct {
		name string
		in   string
		def  int
		want int
	}{
		{"empty", "", 1, 1},
		{"single", "5", 1, 5},
		{"with trailing semi", "7;", 1, 7},
		{"invalid", "abc", 1, 1},
		{"zero", "0", 1, 1},  // 0 is non-positive → default
		{"negative-ish", "-3", 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSingleParam([]byte(tc.in), tc.def); got != tc.want {
				t.Fatalf("parseSingleParam(%q,%d): want %d, got %d", tc.in, tc.def, tc.want, got)
			}
		})
	}
}

func TestWedgeWatcher_VerticalWalk_FiresWhenCudExceedsNewRows(t *testing.T) {
	// The Ink-renderer fingerprint: after a downward resize, the
	// renderer emits a relative-only redraw that walks down more rows
	// than the new viewport contains. CUD total > pendingRows fires
	// wedge_type=vertical_walk.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(44, 23, 90, created)
	// 25 cursor-down moves into a 23-row viewport — over by 2.
	w.ObserveBytes([]byte("\x1b[25B"), created)

	events := readEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("expected 1 vertical_walk event, got %d (%+v)", len(events), events)
	}
	got := events[0]
	if got.WedgeType != "vertical_walk" {
		t.Fatalf("type: want vertical_walk, got %q", got.WedgeType)
	}
	if got.CudObserved != 25 {
		t.Fatalf("cud_observed: want 25, got %d", got.CudObserved)
	}
	if got.NewRows != 23 || got.OldRows != 44 {
		t.Fatalf("rows: want 44→23, got %d→%d", got.OldRows, got.NewRows)
	}
}

func TestWedgeWatcher_VerticalWalk_NoFireBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(44, 23, 90, created)
	// 20 cursor-downs — under the 23-row viewport. Healthy redraw.
	w.ObserveBytes([]byte("\x1b[20B"), created)
	// Wait less than silentDeadline so the silent path doesn't fire.
	events := readEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("CUD under threshold must not flag; got %+v", events)
	}
}

func TestWedgeWatcher_VerticalWalk_CountsAcrossMultipleChunks(t *testing.T) {
	// Real PTY reads split escape sequences across chunks. Pattern from
	// the captured byte stream: many small \x1b[1B emitted one-per-chunk.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(44, 23, 90, created)
	// 24 single-line CUDs in 24 separate chunks. Total = 24 > 23.
	for i := 0; i < 24; i++ {
		w.ObserveBytes([]byte("\x1b[1B"), created)
		// Stop pushing once the wedge has been raised; the watcher
		// suppresses follow-up reports via wedgeRaised.
	}
	events := readEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("expected 1 vertical_walk event across chunks; got %d", len(events))
	}
	if events[0].CudObserved < 24 {
		t.Fatalf("cud_observed should include all 24 walks; got %d", events[0].CudObserved)
	}
}

func TestWedgeWatcher_VerticalWalk_ResetsBetweenResizes(t *testing.T) {
	// Two consecutive resizes: each should get its own CUD budget,
	// not carry state from the previous resize.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()

	// First resize: 18 CUDs into a 23-row viewport (under). No wedge.
	w.ArmResize(44, 23, 90, created)
	w.ObserveBytes([]byte("\x1b[18B"), created)
	if events := readEvents(t, logPath); len(events) != 0 {
		t.Fatalf("first resize must not flag; got %+v", events)
	}

	// Second resize: 25 fresh CUDs into a 20-row viewport. If the
	// counter reset, only 25 gets compared (fires, 25 > 20). If it
	// didn't reset, the cumulative would be 43 — also fires, but the
	// cud_observed value would be 43 instead of 25.
	w.ArmResize(44, 20, 90, created)
	w.ObserveBytes([]byte("\x1b[25B"), created)
	events := readEvents(t, logPath)
	if len(events) != 1 {
		t.Fatalf("second resize should fire one vertical_walk; got %d", len(events))
	}
	if events[0].CudObserved != 25 {
		t.Fatalf("cud_observed: want 25 (reset between resizes), got %d", events[0].CudObserved)
	}
}

func TestCSIScanner_FrameStartResetsCudCount(t *testing.T) {
	// Ink starts every frame with CUP-to-home. The scanner must reset
	// cudAccumulated whenever it sees a CUP/HVP to row 1 — otherwise
	// a healthy renderer that draws multiple frames in a single scan
	// window accumulates downward walks across frame boundaries and
	// trips the wedge threshold even when each individual frame is
	// well-formed.
	var s csiScanner
	// First "frame": 22 cursor-down walks (well under any reasonable
	// viewport). cumulative = 22.
	s.feed([]byte("\x1b[22B"), 100)
	if got := s.cudCount(); got != 22 {
		t.Fatalf("pre-home cudCount: want 22, got %d", got)
	}
	// CUP to home — frame boundary. Counter resets.
	s.feed([]byte("\x1b[H"), 100)
	if got := s.cudCount(); got != 0 {
		t.Fatalf("post-home cudCount: want 0 (reset), got %d", got)
	}
	// Second "frame": 18 more cursor-downs. Should be independent of
	// the first frame's count.
	s.feed([]byte("\x1b[18B"), 100)
	if got := s.cudCount(); got != 18 {
		t.Fatalf("second-frame cudCount: want 18, got %d", got)
	}
}

func TestCSIScanner_FrameStartHandlesAllHomeVariants(t *testing.T) {
	cases := []struct {
		name string
		seq  string
	}{
		{"bare home",     "\x1b[H"},
		{"row-only 1",    "\x1b[1H"},
		{"explicit 1;1",  "\x1b[1;1H"},
		{"semi prefix",   "\x1b[;1H"},
		{"HVP final byte", "\x1b[1;1f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s csiScanner
			s.feed([]byte("\x1b[15B"), 100) // 15 walks
			s.feed([]byte(tc.seq), 100)
			if got := s.cudCount(); got != 0 {
				t.Fatalf("%q should reset cudCount; got %d", tc.seq, got)
			}
		})
	}
}

func TestCSIScanner_NonHomeCUPDoesNotReset(t *testing.T) {
	// CUP to row 5 (NOT home) is not a frame boundary — the renderer
	// is just repositioning mid-frame. Counter should NOT reset.
	var s csiScanner
	s.feed([]byte("\x1b[10B"), 100)
	s.feed([]byte("\x1b[5;1H"), 100) // CUP to row 5
	if got := s.cudCount(); got != 10 {
		t.Fatalf("CUP to row 5 should not reset cudCount; got %d, want 10", got)
	}
}

func TestWedgeWatcher_VerticalWalk_HealthyMultipleFramesDoNotFire(t *testing.T) {
	// The bug this test pins: a healthy renderer that draws several
	// well-formed frames in a single scan window must not be flagged
	// as wedged. Each frame is `home + N-row walk` where N < new_rows.
	// Without the frame-start reset, three frames at 18 rows each
	// accumulate to 54 CUD against a 23-row viewport (54 > 23) and
	// fire vertical_walk. With the reset, each frame's walk is
	// independent and stays under threshold.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(40, 23, 90, created)
	// Three healthy frames at 18 rows each, separated by home.
	w.ObserveBytes([]byte("\x1b[H\x1b[18B"), created)
	w.ObserveBytes([]byte("\x1b[H\x1b[18B"), created)
	w.ObserveBytes([]byte("\x1b[H\x1b[18B"), created)
	events := readEvents(t, logPath)
	if len(events) != 0 {
		t.Fatalf("multiple healthy frames should not fire vertical_walk; got %+v", events)
	}
}

func TestWedgeWatcher_VerticalWalk_SingleFramePastViewportStillFires(t *testing.T) {
	// Counterpart to the healthy-multi-frame test: a SINGLE frame
	// whose downward walk exceeds the viewport is the real wedge
	// signature and must still fire. Confirms the frame-start reset
	// didn't accidentally silence the legitimate signal.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(40, 23, 90, created)
	// One frame: home + 30 cursor-downs (well past 23).
	w.ObserveBytes([]byte("\x1b[H\x1b[30B"), created)
	events := readEvents(t, logPath)
	if len(events) != 1 || events[0].WedgeType != "vertical_walk" {
		t.Fatalf("single frame past viewport must still fire vertical_walk; got %+v", events)
	}
	if events[0].CudObserved != 30 {
		t.Fatalf("cud_observed: want 30, got %d", events[0].CudObserved)
	}
}

func TestWedgeWatcher_CursorWedge_TakesPrecedenceOverVerticalWalk(t *testing.T) {
	// If both signals would fire on the same chunk, cursor_row wins
	// — it's the stronger evidence (absolute positioning is
	// unambiguous; relative walk is consequence-of).
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(44, 23, 90, created)
	// CUP to row 40 (> 23) AND 25 CUDs in the same chunk.
	w.ObserveBytes([]byte("\x1b[40;1H\x1b[25B"), created)
	events := readEvents(t, logPath)
	if len(events) != 1 || events[0].WedgeType != "cursor_row" {
		t.Fatalf("cursor_row should win; got %+v", events)
	}
}
