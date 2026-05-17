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
	// Direct test of the silent-deadline path with a tight loop —
	// we can't easily replace the package-level silentDeadline,
	// but we can drive the watcher state and call the deadline body
	// directly via a known-quiet ArmResize.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "wedge-events.jsonl")
	w := newWedgeWatcher()
	w.SetLogPath(logPath)
	created := time.Now()
	w.ArmResize(44, 23, 90, created)
	// Don't observe any bytes. Wait out the silent deadline plus a
	// small fudge for the goroutine to schedule and write.
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
	created := time.Now()
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

func TestWedgeWatcher_TotalBytes_AccumulateAcrossResizes(t *testing.T) {
	w := newWedgeWatcher()
	created := time.Now()
	w.ObserveBytes(make([]byte, 100), created)
	w.ArmResize(44, 23, 90, created)
	w.ObserveBytes(make([]byte, 200), created)
	w.ArmResize(44, 30, 90, created) // displaces the previous pending
	w.ObserveBytes(make([]byte, 50), created)

	total, resizes, _, _ := w.Snapshot()
	if total != 350 {
		t.Fatalf("totalOutBytes: want 350, got %d", total)
	}
	if resizes != 2 {
		t.Fatalf("resizesObserved: want 2, got %d", resizes)
	}
}
