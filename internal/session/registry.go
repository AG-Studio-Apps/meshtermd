package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Registry is the daemon's catalogue of live Sessions. It is the
// authority for "does this session_id exist", enforces a max-session
// cap, and reaps idle sessions on a GC sweep.
//
// Registry does not start any goroutines on its own — call Run from
// the daemon's main goroutine to drive the periodic GC sweep, and
// Shutdown to drain.
type Registry struct {
	maxSessions int
	idleTimeout time.Duration
	gcInterval  time.Duration

	mu       sync.Mutex
	sessions map[SessionID]*Session
}

// DefaultIdleTimeout is the time a detached session can remain idle
// before the GC sweep reaps it. One hour matches the plan default.
const DefaultIdleTimeout = time.Hour

// DefaultGCInterval is how often the Run loop ticks. Granularity
// here is fine; idle reaping is not latency-sensitive.
const DefaultGCInterval = time.Minute

// DefaultMaxSessions caps concurrent sessions per daemon. Tunable via
// `meshtermd serve --max-sessions`. The value here is intentionally
// modest — a typical user has a handful of terminals open at once;
// hundreds suggests something pathological.
const DefaultMaxSessions = 100

// ErrCapacityReached is returned by Create when adding the session
// would exceed maxSessions.
var ErrCapacityReached = errors.New("session registry at capacity")

// ErrDuplicateID is returned by Create when a session with the given
// ID already exists. Indicates a caller bug — IDs come from
// crypto/rand and the caller should never propose colliding ones.
var ErrDuplicateID = errors.New("session id already exists")

// ErrUnknownSession is returned by Lookup when no session with the
// given ID exists. Distinct from "session was just reaped" because the
// caller cares only that they should not attempt to attach.
var ErrUnknownSession = errors.New("unknown session id")

// NewRegistry constructs a Registry with the given limits. Zero or
// negative limits fall back to the Default* constants.
func NewRegistry(maxSessions int, idleTimeout, gcInterval time.Duration) *Registry {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	if gcInterval <= 0 {
		gcInterval = DefaultGCInterval
	}
	return &Registry{
		maxSessions: maxSessions,
		idleTimeout: idleTimeout,
		gcInterval:  gcInterval,
		sessions:    make(map[SessionID]*Session),
	}
}

// Add inserts an already-constructed Session into the registry. The
// caller is responsible for starting the session's Pump goroutine —
// keeping that contract outside the registry simplifies test wiring.
//
// Returns ErrCapacityReached if the registry is full,
// ErrDuplicateID if the ID is already present.
func (r *Registry) Add(s *Session) error {
	if s == nil {
		return errors.New("nil session")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sessions) >= r.maxSessions {
		return ErrCapacityReached
	}
	if _, exists := r.sessions[s.ID()]; exists {
		return ErrDuplicateID
	}
	r.sessions[s.ID()] = s
	return nil
}

// Lookup returns the session with the given ID, or ErrUnknownSession.
func (r *Registry) Lookup(id SessionID) (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, ErrUnknownSession
	}
	return s, nil
}

// Remove drops the session from the catalogue and closes it. Safe to
// call with an unknown ID (no-op).
func (r *Registry) Remove(id SessionID) {
	r.mu.Lock()
	s := r.sessions[id]
	delete(r.sessions, id)
	r.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
}

// Len returns the current session count.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// Capacity returns the configured maximum.
func (r *Registry) Capacity() int { return r.maxSessions }

// IdleTimeout returns the configured idle timeout.
func (r *Registry) IdleTimeout() time.Duration { return r.idleTimeout }

// IDs returns the session IDs currently in the registry. Order is not
// stable. Useful for diagnostics; the registry is the authority on
// what's live.
func (r *Registry) IDs() []SessionID {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionID, 0, len(r.sessions))
	for id := range r.sessions {
		out = append(out, id)
	}
	return out
}

// Sweep performs one GC pass. Sessions whose IdleFor exceeds the
// registry's idleTimeout are removed and closed. Returns the number
// reaped.
//
// Sweep is also called automatically by Run on a ticker; tests can
// invoke it directly to drive deterministic GC behaviour without
// waiting for the ticker.
//
// We collect candidates under the registry lock, then close them
// outside the lock so a slow Close (e.g., PTY shutdown) doesn't
// stall lookups.
func (r *Registry) Sweep() int {
	now := time.Now()
	var doomed []*Session

	r.mu.Lock()
	for id, s := range r.sessions {
		if now.Sub(s.lastActivityForGC()) >= r.idleTimeout {
			doomed = append(doomed, s)
			delete(r.sessions, id)
		}
	}
	r.mu.Unlock()

	for _, s := range doomed {
		_ = s.Close()
	}
	return len(doomed)
}

// Run drives the GC sweep loop until ctx is cancelled. On exit it
// calls Shutdown to drain any remaining sessions. Run is the
// expected entry point for the registry's background work; the
// daemon's serve loop should `go reg.Run(ctx)` once.
func (r *Registry) Run(ctx context.Context) {
	defer r.Shutdown()
	t := time.NewTicker(r.gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Sweep()
		}
	}
}

// Shutdown closes every live session and empties the catalogue. Safe
// to call multiple times.
func (r *Registry) Shutdown() {
	r.mu.Lock()
	all := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		all = append(all, s)
	}
	r.sessions = make(map[SessionID]*Session)
	r.mu.Unlock()

	for _, s := range all {
		_ = s.Close()
	}
}

// lastActivityForGC reads the session's lastActiveAt. Lives on
// Session but is exported only enough for the GC sweep — the public
// API is IdleFor which returns a Duration; for the sweep we want the
// raw time.Time so we can compare uniformly across many sessions
// without sampling time.Now multiple times. We expose it via this
// package-private accessor on Session so the registry can use it
// without leaking it into the public API.
func (s *Session) lastActivityForGC() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActiveAt
}
