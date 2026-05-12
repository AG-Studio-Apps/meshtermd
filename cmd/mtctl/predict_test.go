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
