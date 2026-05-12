package main

import (
	"bytes"
	"testing"
	"time"
)

func TestPredictionEngineDisarmedByDefault(t *testing.T) {
	p := NewPredictionEngine()
	if p.Armed() {
		t.Fatal("default state should be disarmed")
	}
	if got := p.OnUserInput([]byte("abc")); len(got) != 0 {
		t.Errorf("disarmed predictor mirrored %q; want nothing", got)
	}
	if p.PendingCount() != 0 {
		t.Errorf("queue grew while disarmed")
	}
}

func TestPredictionEngineArmsOnPromptDollar(t *testing.T) {
	p := NewPredictionEngine()
	// Simulate a bash prompt being drawn.
	out := p.OnDaemonOutput([]byte("james@laptop:~$ "))
	if !bytes.Equal(out, []byte("james@laptop:~$ ")) {
		t.Errorf("pass-through corrupted: %q", out)
	}
	if !p.Armed() {
		t.Errorf("$-prompt did not arm the engine")
	}
}

func TestPredictionEngineArmsOnPromptHash(t *testing.T) {
	p := NewPredictionEngine()
	p.OnDaemonOutput([]byte("root@server:/# "))
	if !p.Armed() {
		t.Errorf("#-prompt (root) did not arm the engine")
	}
}

func TestPredictionEngineMirrorsPredictableInput(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	got := p.OnUserInput([]byte("ls"))
	if !bytes.Equal(got, []byte("ls")) {
		t.Errorf("predicted echo = %q; want %q", got, "ls")
	}
	if p.PendingCount() != 2 {
		t.Errorf("queue depth = %d; want 2", p.PendingCount())
	}
}

func TestPredictionEngineSkipsControlBytes(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	// Newline disarms — too risky to predict cursor row.
	got := p.OnUserInput([]byte("a\n"))
	if !bytes.Equal(got, []byte("a")) {
		t.Errorf("mirrored %q; want only %q (newline should disarm)", got, "a")
	}
	if p.Armed() {
		t.Errorf("newline did not disarm")
	}
}

func TestPredictionEngineConfirmsMatchingEcho(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.OnUserInput([]byte("ls"))
	if p.PendingCount() != 2 {
		t.Fatalf("pre-condition: queue depth = %d", p.PendingCount())
	}
	// Daemon echoes back the same bytes. Predictor should consume
	// them entirely and emit nothing (since we already wrote them
	// locally via OnUserInput).
	out := p.OnDaemonOutput([]byte("ls"))
	if len(out) != 0 {
		t.Errorf("confirmed echo emitted %q; want nothing", out)
	}
	if p.PendingCount() != 0 {
		t.Errorf("queue depth after confirm = %d; want 0", p.PendingCount())
	}
}

func TestPredictionEngineRollsBackOnMismatch(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.OnUserInput([]byte("ls"))
	// User typed "ls" but somehow the daemon's first byte is "t" (e.g.,
	// echo was off and the daemon is showing the start of a long
	// command output). Expect rollback: "\b \b" * 2 then "t".
	out := p.OnDaemonOutput([]byte("t"))
	want := []byte("\b \b\b \bt")
	if !bytes.Equal(out, want) {
		t.Errorf("rollback emitted %q; want %q", out, want)
	}
	if p.PendingCount() != 0 {
		t.Errorf("queue not drained on rollback: depth = %d", p.PendingCount())
	}
	if p.Armed() {
		t.Errorf("rollback should disarm temporarily")
	}
}

func TestPredictionEnginePartialMatch(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.OnUserInput([]byte("abc"))
	// First two bytes match — they get suppressed. Third byte
	// mismatches — one rollback of the remaining 'c', then 'X'.
	out := p.OnDaemonOutput([]byte("abX"))
	want := []byte("\b \bX")
	if !bytes.Equal(out, want) {
		t.Errorf("partial-match output = %q; want %q", out, want)
	}
}

func TestPredictionEngineDisarmsOnAltScreenEnter(t *testing.T) {
	p := NewPredictionEngine()
	p.OnDaemonOutput([]byte("$ ")) // arm via prompt
	if !p.Armed() {
		t.Fatal("pre-condition: should be armed after prompt")
	}
	// vim entering alternate screen.
	p.OnDaemonOutput([]byte("\x1b[?1049h"))
	if p.Armed() {
		t.Errorf("alt-screen enter did not disarm")
	}
}

func TestPredictionEngineRespectsCooldownAfterRollback(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.OnUserInput([]byte("a"))
	p.OnDaemonOutput([]byte("X")) // forces rollback + cooldown
	if p.Armed() {
		t.Fatal("pre-condition: rollback disarms")
	}
	// Even a prompt-shaped daemon output during cooldown should NOT
	// rearm.
	p.OnDaemonOutput([]byte("$ "))
	if p.Armed() {
		t.Errorf("re-armed during cooldown")
	}
}

func TestPredictionEngineExpiresStalePredictions(t *testing.T) {
	p := NewPredictionEngine()
	p.predictTimeout = 50 * time.Millisecond
	p.ForceArm()
	p.OnUserInput([]byte("a"))
	time.Sleep(80 * time.Millisecond)
	// A subsequent daemon byte that doesn't relate to the stale
	// prediction triggers expiry. The expired prediction rolls back,
	// then the daemon byte passes through unchanged (no new
	// rollback — queue is empty by then).
	out := p.OnDaemonOutput([]byte("Z"))
	want := []byte("\b \bZ")
	if !bytes.Equal(out, want) {
		t.Errorf("stale-expire output = %q; want %q", out, want)
	}
	if p.PendingCount() != 0 {
		t.Errorf("queue not drained: depth = %d", p.PendingCount())
	}
}

func TestPredictionEngineDisabledShortCircuits(t *testing.T) {
	p := NewPredictionEngine()
	p.Disable()
	p.ForceArm() // shouldn't matter — disabled overrides
	if got := p.OnUserInput([]byte("ls")); len(got) != 0 {
		t.Errorf("disabled engine mirrored %q; want nothing", got)
	}
	out := p.OnDaemonOutput([]byte("hello"))
	if !bytes.Equal(out, []byte("hello")) {
		t.Errorf("disabled engine altered daemon output: %q", out)
	}
}

// TestPredictionEngineUTF8RunePredict: a French é (UTF-8: 0xC3 0xA9)
// gets queued as one rune (PendingCount==1), the daemon's full UTF-8
// echo confirms it, and the queue drains. Verifies the byte-by-byte
// match-then-pop logic works for multi-byte runes.
func TestPredictionEngineUTF8RunePredict(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	mirror := p.OnUserInput([]byte("é"))
	if !bytes.Equal(mirror, []byte("é")) {
		t.Errorf("mirror = %q, want %q", mirror, "é")
	}
	if p.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1 (one rune)", p.PendingCount())
	}
	out := p.OnDaemonOutput([]byte("é"))
	if len(out) != 0 {
		t.Errorf("confirmed echo emitted %q; want nothing", out)
	}
	if p.PendingCount() != 0 {
		t.Errorf("queue not drained: depth = %d", p.PendingCount())
	}
}

// TestPredictionEngineUTF8PartialRuneAcrossCalls: a UTF-8 rune that
// straddles two OnUserInput calls must be buffered and queued only
// once both bytes have arrived.
func TestPredictionEngineUTF8PartialRuneAcrossCalls(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	// First byte of é: 0xC3. Not a full rune yet.
	mirror1 := p.OnUserInput([]byte{0xC3})
	if len(mirror1) != 0 {
		t.Errorf("partial rune mirror = %q, want empty", mirror1)
	}
	if p.PendingCount() != 0 {
		t.Errorf("partial rune queued early: depth = %d", p.PendingCount())
	}
	// Second byte of é: 0xA9. Now the rune completes.
	mirror2 := p.OnUserInput([]byte{0xA9})
	if !bytes.Equal(mirror2, []byte("é")) {
		t.Errorf("completed mirror = %q, want %q", mirror2, "é")
	}
	if p.PendingCount() != 1 {
		t.Errorf("PendingCount after completion = %d, want 1", p.PendingCount())
	}
}

// TestPredictionEngineUTF8MidRuneMismatch: the daemon matches the
// first byte of a predicted rune but mismatches the second. Rollback
// must emit \b \b, re-emit the matched suppressed byte, then the
// mismatch byte — preserving the daemon's intended byte stream.
func TestPredictionEngineUTF8MidRuneMismatch(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.OnUserInput([]byte("é")) // queues 0xC3 0xA9 as one prediction
	// Daemon emits 0xC3 (matches first byte of head), then 0x6F (mismatch).
	out := p.OnDaemonOutput([]byte{0xC3, 0x6F})
	// Expected output: rollback (\b \b for 1 pred), then the matched
	// suppressed byte (0xC3) to give the daemon's stream back, then
	// the mismatch byte (0x6F).
	want := []byte{'\b', ' ', '\b', 0xC3, 0x6F}
	if !bytes.Equal(out, want) {
		t.Errorf("mid-rune mismatch out = %v, want %v", out, want)
	}
	if p.PendingCount() != 0 {
		t.Errorf("pending not drained: %d", p.PendingCount())
	}
}

// TestPredictionEngineUTF8DoesNotPredictWide: CJK (wide) characters,
// emoji, and combining marks must NOT be predicted — their cell width
// breaks our 1:1 \b\space\b rollback model. Encountering one resets
// the queue and disarms.
func TestPredictionEngineUTF8DoesNotPredictWide(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	// CJK Han (U+4E2D, "中") is wide — out of range, disarms.
	p.OnUserInput([]byte("ab"))
	if p.PendingCount() != 2 {
		t.Fatalf("ascii setup PendingCount = %d", p.PendingCount())
	}
	p.OnUserInput([]byte("中"))
	if p.PendingCount() != 0 {
		t.Errorf("wide-char input did not reset queue: %d pending", p.PendingCount())
	}
	if p.Armed() {
		t.Error("wide-char input did not disarm")
	}
}

// TestPredictionEngineLatinExtendedPredict: a Latin-1 supplement
// character (e.g., ñ at U+00F1) and a Latin Extended-A character
// (e.g., ł at U+0142) both within the predictable range should
// queue and confirm cleanly.
func TestPredictionEngineLatinExtendedPredict(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	mirror := p.OnUserInput([]byte("ñł"))
	if !bytes.Equal(mirror, []byte("ñł")) {
		t.Errorf("mirror = %q, want %q", mirror, "ñł")
	}
	if p.PendingCount() != 2 {
		t.Errorf("Latin Extended PendingCount = %d, want 2", p.PendingCount())
	}
	out := p.OnDaemonOutput([]byte("ñł"))
	if len(out) != 0 {
		t.Errorf("Latin echo confirm emitted %q, want nothing", out)
	}
}

// TestIsPredictableRune tabulates the rune predicate's contract for
// the ranges that matter (ASCII boundary, C1 boundary, Latin Extended
// boundary, wide chars).
func TestIsPredictableRune(t *testing.T) {
	cases := []struct {
		r    rune
		want bool
		name string
	}{
		{0x1F, false, "C0 control"},
		{0x20, true, "space (printable boundary)"},
		{'a', true, "ascii lowercase"},
		{0x7E, true, "ascii ~ (top of printable)"},
		{0x7F, false, "DEL"},
		{0x80, false, "C1 control start"},
		{0x9F, false, "C1 control end"},
		{0xA0, true, "non-breaking space (Latin-1 start)"},
		{0xE9, true, "é (Latin-1 supplement)"},
		{0x142, true, "ł (Latin Extended-A)"},
		{0x024F, true, "Latin Extended-B boundary"},
		{0x0250, false, "IPA Extensions (out of range)"},
		{0x4E2D, false, "CJK 中 (wide)"},
		{0x1F600, false, "emoji 😀"},
	}
	for _, tc := range cases {
		if got := isPredictableRune(tc.r); got != tc.want {
			t.Errorf("isPredictableRune(%#x %s) = %v, want %v", tc.r, tc.name, got, tc.want)
		}
	}
}

// TestPredictionEngineBackspacePopsLastPrediction: with canonMode
// on and armed, DEL (0x7f) drops the last queued prediction and emits
// \b \b. Mirrors the shell's expected ICANON behaviour: backspace
// erases the previous cell.
func TestPredictionEngineBackspacePopsLastPrediction(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.SetCanonMode(true)
	p.OnUserInput([]byte("ab"))
	if p.PendingCount() != 2 {
		t.Fatalf("setup PendingCount = %d", p.PendingCount())
	}
	mirror := p.OnUserInput([]byte{0x7f})
	if !bytes.Equal(mirror, []byte("\b \b")) {
		t.Errorf("backspace mirror = %q, want \\b \\b", mirror)
	}
	if p.PendingCount() != 1 {
		t.Errorf("PendingCount after backspace = %d, want 1", p.PendingCount())
	}
}

// TestPredictionEngineBackspaceCtrlH: BS (0x08, Ctrl-H) is the
// alternate byte for backspace on some terminals — behave identically.
func TestPredictionEngineBackspaceCtrlH(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.SetCanonMode(true)
	p.OnUserInput([]byte("ab"))
	mirror := p.OnUserInput([]byte{0x08})
	if !bytes.Equal(mirror, []byte("\b \b")) {
		t.Errorf("Ctrl-H mirror = %q, want \\b \\b", mirror)
	}
	if p.PendingCount() != 1 {
		t.Errorf("PendingCount after Ctrl-H = %d, want 1", p.PendingCount())
	}
}

// TestPredictionEngineBackspaceWithoutCanonMode: without canonMode,
// backspace is NOT predicted — vim and password prompts handle DEL
// differently. The DEL byte reaches the unpredictable-rune branch
// (it's < 0x20) which resets the queue + disarms.
func TestPredictionEngineBackspaceWithoutCanonMode(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	// canonMode defaults to false.
	p.OnUserInput([]byte("ab"))
	mirror := p.OnUserInput([]byte{0x7f})
	// 0x7f is unpredictable → queue reset + disarm. No mirror.
	if len(mirror) != 0 {
		t.Errorf("non-canon backspace mirror = %q, want empty", mirror)
	}
	if p.PendingCount() != 0 {
		t.Errorf("non-canon backspace did not reset queue: %d", p.PendingCount())
	}
	if p.Armed() {
		t.Errorf("non-canon backspace did not disarm")
	}
}

// TestPredictionEngineBackspaceEmptyQueue: with no pending predictions,
// a backspace byte is a no-op (queue stays empty, no mirror emitted).
// The byte is still consumed (forwarded to daemon by the stdin pump,
// not via the predictor).
func TestPredictionEngineBackspaceEmptyQueue(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.SetCanonMode(true)
	mirror := p.OnUserInput([]byte{0x7f})
	if len(mirror) != 0 {
		t.Errorf("backspace on empty queue mirror = %q, want empty", mirror)
	}
	if p.PendingCount() != 0 {
		t.Errorf("PendingCount = %d, want 0", p.PendingCount())
	}
	if !p.Armed() {
		t.Errorf("backspace on empty queue should NOT disarm")
	}
}

// TestPredictionEngineBackspaceThenType: backspace pops the last
// prediction; subsequent typing queues fresh predictions onto the
// (now-shorter) queue.
func TestPredictionEngineBackspaceThenType(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.SetCanonMode(true)
	p.OnUserInput([]byte("ab"))
	p.OnUserInput([]byte{0x7f})
	if p.PendingCount() != 1 {
		t.Fatalf("after bksp PendingCount = %d", p.PendingCount())
	}
	mirror := p.OnUserInput([]byte("c"))
	if !bytes.Equal(mirror, []byte("c")) {
		t.Errorf("post-bksp typing mirror = %q, want c", mirror)
	}
	if p.PendingCount() != 2 {
		t.Errorf("post-bksp typing PendingCount = %d, want 2", p.PendingCount())
	}
}

// TestForceDisarm: ForceDisarm clears the armed flag without
// affecting the queue (caller may want to flush the queue separately).
func TestForceDisarm(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	if !p.Armed() {
		t.Fatal("ForceArm did not arm")
	}
	p.ForceDisarm()
	if p.Armed() {
		t.Error("ForceDisarm did not disarm")
	}
}

// TestPredictionEngineUnderlineWrap: when SetUnderline(true) is set,
// each predicted rune's mirror bytes get wrapped in ESC[4m ... ESC[24m
// so the user sees an underlined preview. Confirmation suppression
// still works (the daemon's bytes match the plain rune bytes; no
// special SGR-aware comparison needed).
func TestPredictionEngineUnderlineWrap(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.SetUnderline(true)
	mirror := p.OnUserInput([]byte("a"))
	want := []byte("\x1b[4ma\x1b[24m")
	if !bytes.Equal(mirror, want) {
		t.Errorf("underlined mirror = %q, want %q", mirror, want)
	}
	out := p.OnDaemonOutput([]byte("a"))
	if len(out) != 0 {
		t.Errorf("confirmed underlined predict emitted %q, want nothing", out)
	}
}

// TestPredictionEngineUnderlineRollback: with underline on, rollback
// still emits one \b \b per pending prediction (cell-based, not byte-
// based — the terminal's underline attribute is already off because
// each prediction's SGR wrap closed it with ESC[24m).
func TestPredictionEngineUnderlineRollback(t *testing.T) {
	p := NewPredictionEngine()
	p.ForceArm()
	p.SetUnderline(true)
	p.OnUserInput([]byte("ab"))
	out := p.OnDaemonOutput([]byte("x"))
	want := []byte("\b \b\b \bx")
	if !bytes.Equal(out, want) {
		t.Errorf("underlined rollback = %q, want %q", out, want)
	}
}

func TestStripTrailingCSI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"$ ", "$ "},
		{"$ \x1b[6n", "$ "},                  // cursor-position query stripped
		{"$ \x1b[?25h", "$ "},                 // private-mode set stripped
		{"\x1b[31merror\x1b[0m", "\x1b[31merror"}, // strips only the trailing sequence
		{"no escape here", "no escape here"},
	}
	for _, c := range cases {
		got := string(stripTrailingCSI([]byte(c.in)))
		if got != c.want {
			t.Errorf("stripTrailingCSI(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
