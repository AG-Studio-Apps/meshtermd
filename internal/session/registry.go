package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Registry is the daemon's catalogue of live Sessions. It is the
// authority for "does this session_id exist", enforces a max-session
// cap, reaps idle sessions on a GC sweep, and tracks pending attach
// tokens.
//
// Registry does not start any goroutines on its own — call Run from
// the daemon's main goroutine to drive the periodic GC sweep, and
// Shutdown to drain.
type Registry struct {
	maxSessions int
	// idleTimeout is the daemon-wide *default* timeout used for any
	// session that didn't request its own (Session.idleTimeout == 0).
	// The actual GC decision is made per-session in Sweep.
	idleTimeout time.Duration
	// maxIdleTimeout is the operator's ceiling on per-session
	// timeouts. A client requesting a longer value is silently
	// clamped at allocate time. Zero means no ceiling — the
	// personal-server default; shared deployments would set this to
	// e.g. 7d to bound resource cost.
	maxIdleTimeout time.Duration
	gcInterval     time.Duration

	mu       sync.Mutex
	sessions map[SessionID]*Session
	tokens   map[AttachToken]pendingAttach
}

// pendingAttach is the registry-side state for a single in-flight
// attach. The SSH-side `meshtermd connect` invocation reserves one;
// the QUIC-side handler consumes it.
type pendingAttach struct {
	sessionID SessionID
	expiresAt time.Time
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

// AttachTokenLen is the byte length of an attach token. 16 bytes
// from a CSPRNG is overkill for guessability and matches the
// protocol spec's MTRM_QUIC <attach_token> 32-hex-char field.
const AttachTokenLen = 16

// AttachTokenTTL is the lifetime of a freshly-issued attach token.
// Per docs/SECURITY.md, 30 seconds is enough for the iOS client to
// receive the bootstrap line over SSH and open a QUIC connection
// without leaving a wide replay window.
const AttachTokenTTL = 30 * time.Second

// AttachToken is the single-use bearer token that authorises a QUIC
// attach. Issued by IssueAttachToken when an SSH-side `meshtermd
// connect` invocation reserves an attach; consumed by
// ConsumeAttachToken on the QUIC side.
type AttachToken [AttachTokenLen]byte

// String returns the lowercase hex encoding (32 chars), matching
// the bootstrap line's <attach_token> field format.
func (t AttachToken) String() string {
	return hex.EncodeToString(t[:])
}

// ParseAttachToken parses a 32-char hex AttachToken.
func ParseAttachToken(s string) (AttachToken, error) {
	var t AttachToken
	if len(s) != AttachTokenLen*2 {
		return t, errors.New("attach token must be 32 hex chars")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return t, err
	}
	copy(t[:], b)
	return t, nil
}

// ErrAttachTokenInvalid is returned by ConsumeAttachToken when the
// token is unknown, expired, or already consumed. We intentionally
// use a single error so callers can't distinguish those three cases —
// a timing-safe-equal vibe applied at the policy level.
var ErrAttachTokenInvalid = errors.New("attach token invalid or expired")

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
// negative limits fall back to the Default* constants. maxIdleTimeout
// = 0 means no operator-imposed ceiling (per-session timeouts may go
// arbitrarily large, bounded only by the time.Duration type).
func NewRegistry(maxSessions int, idleTimeout, gcInterval, maxIdleTimeout time.Duration) *Registry {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	if gcInterval <= 0 {
		gcInterval = DefaultGCInterval
	}
	if maxIdleTimeout < 0 {
		maxIdleTimeout = 0
	}
	return &Registry{
		maxSessions:    maxSessions,
		idleTimeout:    idleTimeout,
		maxIdleTimeout: maxIdleTimeout,
		gcInterval:     gcInterval,
		sessions:       make(map[SessionID]*Session),
		tokens:         make(map[AttachToken]pendingAttach),
	}
}

// ResolveIdleTimeout maps a client-requested timeout to the value the
// session will actually carry. Zero from the client means "use the
// daemon default". A non-zero value is clamped at the registry's
// MaxIdleTimeout ceiling when one is set.
func (r *Registry) ResolveIdleTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		return r.idleTimeout
	}
	if r.maxIdleTimeout > 0 && requested > r.maxIdleTimeout {
		return r.maxIdleTimeout
	}
	return requested
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

// IssueAttachToken generates a single-use attach token bound to the
// given session, valid for AttachTokenTTL. Returns the token; callers
// embed it in the bootstrap line. The session must already be in the
// registry — issuing a token for an unknown session is a caller bug.
func (r *Registry) IssueAttachToken(sessionID SessionID) (AttachToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.sessions[sessionID]; !ok {
		return AttachToken{}, ErrUnknownSession
	}

	var t AttachToken
	if _, err := rand.Read(t[:]); err != nil {
		return AttachToken{}, err
	}
	r.tokens[t] = pendingAttach{
		sessionID: sessionID,
		expiresAt: time.Now().Add(AttachTokenTTL),
	}
	return t, nil
}

// ConsumeAttachToken validates the token and returns the session it
// authorises. The token is deleted on success regardless of whether
// the caller's subsequent attach work succeeds — single-use is
// single-use. Returns ErrAttachTokenInvalid on any failure (unknown,
// expired, or session gone).
func (r *Registry) ConsumeAttachToken(t AttachToken) (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pending, ok := r.tokens[t]
	if !ok {
		return nil, ErrAttachTokenInvalid
	}
	delete(r.tokens, t)

	if time.Now().After(pending.expiresAt) {
		return nil, ErrAttachTokenInvalid
	}
	s, ok := r.sessions[pending.sessionID]
	if !ok {
		return nil, ErrAttachTokenInvalid
	}
	return s, nil
}

// SweepAttachTokens removes expired pending tokens. Called by the GC
// loop alongside session sweep so the tokens map doesn't grow
// unboundedly if clients abandon their bootstraps without attaching.
func (r *Registry) SweepAttachTokens() int {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int
	for k, p := range r.tokens {
		if now.After(p.expiresAt) {
			delete(r.tokens, k)
			n++
		}
	}
	return n
}

// PendingTokenCount is exposed for diagnostics + tests.
func (r *Registry) PendingTokenCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tokens)
}

// Sweep performs one GC pass. Sessions whose IdleFor exceeds the
// registry's idleTimeout are removed and closed; expired attach
// tokens are also removed. Returns the number of sessions reaped
// (token-only sweeps don't count).
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
		// Per-session timeout takes precedence; zero means
		// "inherit the registry default", set at NewSession time.
		timeout := s.idleTimeoutForGC()
		if timeout <= 0 {
			timeout = r.idleTimeout
		}
		if now.Sub(s.lastActivityForGC()) >= timeout {
			doomed = append(doomed, s)
			delete(r.sessions, id)
		}
	}
	for k, p := range r.tokens {
		if now.After(p.expiresAt) {
			delete(r.tokens, k)
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

// idleTimeoutForGC mirrors lastActivityForGC: a package-private
// no-lock-leak accessor for the GC sweep. Zero return means "fall
// back to the registry default" — the sweep handles that branch.
func (s *Session) idleTimeoutForGC() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idleTimeout
}
