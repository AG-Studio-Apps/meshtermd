package session

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeSnooper is a test TermiosSnooper whose returned state can be
// scripted between polls. Concurrent-safe so the watcher goroutine
// and the test main goroutine don't race.
type fakeSnooper struct {
	mu    sync.Mutex
	echo  bool
	canon bool
	ok    bool
}

func (f *fakeSnooper) set(echo, canon, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.echo, f.canon, f.ok = echo, canon, ok
}

func (f *fakeSnooper) TermiosState() (bool, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.echo, f.canon, f.ok
}

func TestWatchTermiosSuppressesInitialUnknownTransition(t *testing.T) {
	t.Parallel()
	snooper := &fakeSnooper{echo: true, canon: true, ok: true}
	got := make(chan TermiosSnapshot, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchTermiosOn(ctx, snooper, 10*time.Millisecond, func(s TermiosSnapshot) {
		got <- s
	})
	// Initial reading is on/on but the watcher primes `last` to
	// unknown/unknown and treats the first transition as
	// unknown→known — suppressed by the realTransition filter. No
	// emit expected within the first 150ms.
	select {
	case s := <-got:
		t.Errorf("got spurious initial emit: %+v", s)
	case <-time.After(150 * time.Millisecond):
		// expected
	}
}

func TestWatchTermiosFiresOnEchoTransition(t *testing.T) {
	t.Parallel()
	snooper := &fakeSnooper{echo: true, canon: true, ok: true}
	got := make(chan TermiosSnapshot, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchTermiosOn(ctx, snooper, 10*time.Millisecond, func(s TermiosSnapshot) {
		got <- s
	})
	time.Sleep(40 * time.Millisecond) // prime last to {on, on}

	// Flip echo off; canon stays on. Should emit with Echo=off, Canon=on.
	snooper.set(false, true, true)
	select {
	case s := <-got:
		if s.Echo != EchoStateOff {
			t.Errorf("Echo = %q, want off", s.Echo)
		}
		if s.Canon != EchoStateOn {
			t.Errorf("Canon = %q, want on (unchanged)", s.Canon)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("no emit after echo on→off")
	}
}

func TestWatchTermiosFiresOnCanonTransition(t *testing.T) {
	t.Parallel()
	snooper := &fakeSnooper{echo: true, canon: true, ok: true}
	got := make(chan TermiosSnapshot, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchTermiosOn(ctx, snooper, 10*time.Millisecond, func(s TermiosSnapshot) {
		got <- s
	})
	time.Sleep(40 * time.Millisecond) // prime to {on, on}

	// Flip canon only (raw-mode entry like vim). Echo stays on.
	snooper.set(true, false, true)
	select {
	case s := <-got:
		if s.Canon != EchoStateOff {
			t.Errorf("Canon = %q, want off", s.Canon)
		}
		if s.Echo != EchoStateOn {
			t.Errorf("Echo = %q, want on (unchanged)", s.Echo)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("no emit after canon on→off")
	}
}

func TestWatchTermiosFiresOnSimultaneousFlip(t *testing.T) {
	t.Parallel()
	snooper := &fakeSnooper{echo: true, canon: true, ok: true}
	got := make(chan TermiosSnapshot, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchTermiosOn(ctx, snooper, 10*time.Millisecond, func(s TermiosSnapshot) {
		got <- s
	})
	time.Sleep(40 * time.Millisecond) // prime

	// Flip both simultaneously (typical raw-mode entry: ECHO + ICANON
	// cleared together).
	snooper.set(false, false, true)
	select {
	case s := <-got:
		if s.Echo != EchoStateOff || s.Canon != EchoStateOff {
			t.Errorf("got %+v, want both off", s)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("no emit after simultaneous flip")
	}
}

func TestWatchTermiosSuppressesUnknownFlapping(t *testing.T) {
	t.Parallel()
	snooper := &fakeSnooper{echo: true, canon: true, ok: true}
	got := make(chan TermiosSnapshot, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchTermiosOn(ctx, snooper, 10*time.Millisecond, func(s TermiosSnapshot) {
		got <- s
	})
	time.Sleep(40 * time.Millisecond) // prime to {on, on}

	// Briefly flip both to unknown then back. The watcher should NOT
	// emit anything — on→unknown→on is dropped to avoid flap noise.
	snooper.set(true, true, false) // unknown
	time.Sleep(30 * time.Millisecond)
	snooper.set(true, true, true) // back to on
	time.Sleep(40 * time.Millisecond)

	select {
	case s := <-got:
		t.Errorf("got spurious emit during unknown flap: %+v", s)
	default:
		// expected
	}
}

func TestWatchTermiosExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	snooper := &fakeSnooper{echo: true, canon: true, ok: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		WatchTermiosOn(ctx, snooper, 10*time.Millisecond, func(TermiosSnapshot) {})
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// good
	case <-time.After(100 * time.Millisecond):
		t.Fatal("WatchTermios did not return after ctx cancel")
	}
}

func TestWatchTermiosNoOpWhenSnooperUnsupported(t *testing.T) {
	t.Parallel()
	// WatchTermios is the dispatch shim: passes PTY (no snoop method)
	// directly. Use a tiny PTY-like that satisfies neither the
	// session.PTY interface fully nor TermiosSnooper.
	type unsupportedPTY struct{ PTY }
	got := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	WatchTermios(ctx, unsupportedPTY{}, time.Millisecond, func(TermiosSnapshot) { got = true })
	if got {
		t.Error("onChange fired for a PTY that doesn't implement TermiosSnooper")
	}
}
