package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func mustNewSession(t *testing.T) *Session {
	t.Helper()
	id, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	pty := newFakePTY()
	s, err := NewSession(id, pty, 24, 80, 1024, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRegistryAddLookupRemove(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0) // all defaults
	s := mustNewSession(t)
	if err := r.Add(s); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
	got, err := r.Lookup(s.ID())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != s {
		t.Error("Lookup returned a different session pointer")
	}
	r.Remove(s.ID())
	if _, err := r.Lookup(s.ID()); !errors.Is(err, ErrUnknownSession) {
		t.Errorf("Lookup after Remove = %v, want ErrUnknownSession", err)
	}
	if !s.Closed() {
		t.Error("Remove did not Close the session")
	}
}

func TestRegistryRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	s := mustNewSession(t)
	if err := r.Add(s); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(s); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("second Add = %v, want ErrDuplicateID", err)
	}
}

func TestRegistryEnforcesCapacity(t *testing.T) {
	t.Parallel()
	r := NewRegistry(2, 0, 0, 0)
	a, b, c := mustNewSession(t), mustNewSession(t), mustNewSession(t)
	if err := r.Add(a); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(b); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(c); !errors.Is(err, ErrCapacityReached) {
		t.Errorf("third Add = %v, want ErrCapacityReached", err)
	}
}

func TestRegistryRemoveUnknownIsNoOp(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	id, _ := NewSessionID()
	r.Remove(id) // must not panic
}

func TestRegistrySweepReapsIdleSessions(t *testing.T) {
	t.Parallel()
	// Idle timeout 20ms, GC interval irrelevant since we drive Sweep
	// directly.
	r := NewRegistry(0, 20*time.Millisecond, time.Hour, 0)
	old := mustNewSession(t)
	if err := r.Add(old); err != nil {
		t.Fatal(err)
	}

	// Wait past idle threshold without touching `old`.
	time.Sleep(40 * time.Millisecond)

	fresh := mustNewSession(t)
	if err := r.Add(fresh); err != nil {
		t.Fatal(err)
	}

	reaped := r.Sweep()
	if reaped != 1 {
		t.Errorf("Sweep reaped %d, want 1 (the old session)", reaped)
	}
	if _, err := r.Lookup(old.ID()); !errors.Is(err, ErrUnknownSession) {
		t.Error("old session was not removed by Sweep")
	}
	if !old.Closed() {
		t.Error("old session was not Closed by Sweep")
	}
	if _, err := r.Lookup(fresh.ID()); err != nil {
		t.Error("fresh session was incorrectly reaped by Sweep")
	}
}

// TestSweepHonoursPerSessionIdleTimeout verifies that a session
// constructed with its own idleTimeout is reaped on its own clock,
// independent of the registry's default. Two sessions, registry
// default = 1h (so neither would be reaped under the old behaviour),
// one session is given a 20ms timeout. Sweep must reap that one and
// leave the other.
func TestSweepHonoursPerSessionIdleTimeout(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, time.Hour, time.Hour, 0)

	shortLived, err := newSessionWithTimeout(20 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(shortLived); err != nil {
		t.Fatal(err)
	}

	longLived := mustNewSession(t)
	if err := r.Add(longLived); err != nil {
		t.Fatal(err)
	}

	time.Sleep(40 * time.Millisecond)

	if reaped := r.Sweep(); reaped != 1 {
		t.Errorf("Sweep reaped %d, want 1 (the per-session timeout one)", reaped)
	}
	if _, err := r.Lookup(shortLived.ID()); !errors.Is(err, ErrUnknownSession) {
		t.Error("session with per-session timeout was not reaped")
	}
	if _, err := r.Lookup(longLived.ID()); err != nil {
		t.Error("session under registry-default timeout was incorrectly reaped")
	}
}

// TestResolveIdleTimeout exercises the precedence rules:
// client-zero falls back to registry default, client>ceiling clamps
// to ceiling, and zero ceiling means no clamp.
func TestResolveIdleTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name              string
		registryDefault   time.Duration
		registryCeiling   time.Duration
		requested         time.Duration
		want              time.Duration
	}{
		{"zero request → default", time.Hour, 0, 0, time.Hour},
		{"explicit under ceiling → as-is", time.Hour, 24 * time.Hour, 30 * time.Minute, 30 * time.Minute},
		{"explicit over ceiling → clamped", time.Hour, 24 * time.Hour, 30 * 24 * time.Hour, 24 * time.Hour},
		{"no ceiling → no clamp", time.Hour, 0, 30 * 24 * time.Hour, 30 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(0, tc.registryDefault, time.Hour, tc.registryCeiling)
			if got := r.ResolveIdleTimeout(tc.requested); got != tc.want {
				t.Errorf("ResolveIdleTimeout(%v) = %v, want %v", tc.requested, got, tc.want)
			}
		})
	}
}

func newSessionWithTimeout(idle time.Duration) (*Session, error) {
	id, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	return NewSession(id, newFakePTY(), 24, 80, 1024, idle)
}

func TestRegistryRunStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, time.Hour, 5*time.Millisecond, 0)
	s := mustNewSession(t)
	r.Add(s)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// good
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of cancel")
	}

	// Run's deferred Shutdown should have closed the session.
	if !s.Closed() {
		t.Error("Shutdown did not close the registry's session")
	}
	if r.Len() != 0 {
		t.Errorf("registry not drained on shutdown: Len = %d", r.Len())
	}
}

func TestRegistryShutdownIsIdempotent(t *testing.T) {
	t.Parallel()
	r := NewRegistry(0, 0, 0, 0)
	r.Shutdown()
	r.Shutdown()
}

func TestRegistryConcurrentAddLookup(t *testing.T) {
	t.Parallel()
	r := NewRegistry(1000, time.Hour, time.Hour, 0)
	const workers = 8
	const each = 50

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				s := mustNewSessionConcurrent()
				if err := r.Add(s); err != nil {
					t.Errorf("Add: %v", err)
					return
				}
				if _, err := r.Lookup(s.ID()); err != nil {
					t.Errorf("Lookup: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if want := workers * each; r.Len() != want {
		t.Errorf("Len = %d, want %d", r.Len(), want)
	}
}

// mustNewSessionConcurrent is a concurrency-friendly helper: it does
// not call t.Helper / t.Fatal, so it's safe to use from goroutines.
func mustNewSessionConcurrent() *Session {
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024, 0)
	return s
}

func TestRegistryDefaults(t *testing.T) {
	t.Parallel()
	r := NewRegistry(-1, -1, -1, 0)
	if r.Capacity() != DefaultMaxSessions {
		t.Errorf("Capacity = %d, want default %d", r.Capacity(), DefaultMaxSessions)
	}
	if r.IdleTimeout() != DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want default %v", r.IdleTimeout(), DefaultIdleTimeout)
	}
}
