package session

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// maxPersistedBufCapacity caps the BufCapacity field in a persisted
// meta.cbor at 100× the daemon's default. Defence-in-depth against a
// hostile state-dir writer crafting a meta.cbor with BufCapacity = 2^31
// which would crash daemon startup via an OOM on
// `make([]byte, meta.BufCapacity)`. The ceiling is generous enough
// that legitimate large-buffer deployments stay below it; the floor
// (BufCapacity > 0) is already enforced.
const maxPersistedBufCapacity = 100 * DefaultBufferCapacity

// persistenceFormatVersion identifies the on-disk schema. Bumped
// whenever the meta.cbor / scrollback.bin layout changes in a way
// that an older loader can't safely interpret. LoadPersisted drops
// entries whose format doesn't match (logs at WARN; never crashes).
const persistenceFormatVersion = 1

// sessionsSubdir is the immediate child of the daemon's state dir
// where per-session subdirectories live. Mode 0700 to match the
// cert dir's posture — `verifyStateDir` already audits the parent.
const sessionsSubdir = "sessions"

// metaFilename + scrollbackFilename are the per-session payload
// filenames inside each session's subdirectory. Both written at
// mode 0600 (owner-only) since scrollback may contain text the user
// considers private.
const (
	metaFilename       = "meta.cbor"
	scrollbackFilename = "scrollback.bin"
)

// persistedSessionMeta is the CBOR-serialised companion to
// scrollback.bin. All field tags are short to keep the on-disk
// representation compact. Time fields are nanoseconds since the
// Unix epoch — a single integer in CBOR vs the multi-byte RFC 3339
// string form `time.Time` defaults to.
type persistedSessionMeta struct {
	FormatVersion int    `cbor:"fv"`
	SessionID     []byte `cbor:"sid"`
	Name          string `cbor:"name,omitempty"`
	CreatedNs     int64  `cbor:"created"`
	LastActiveNs  int64  `cbor:"last_active"`
	Rows          uint16 `cbor:"rows"`
	Cols          uint16 `cbor:"cols"`
	IdleTimeoutNs int64  `cbor:"idle_timeout,omitempty"`
	Persist       bool   `cbor:"persist"`
	BufCapacity   int    `cbor:"buf_capacity"`
	HeadSeq       uint64 `cbor:"head_seq"`
	WritePos      int    `cbor:"write_pos"`
	Full          bool   `cbor:"full,omitempty"`

	// LastConsumedSidecarSeq is the highest sidecar-side outSeq the
	// daemon has durably committed to its session ring before this
	// snapshot. On daemon startup, the discovery path sends
	// FrameResume(LastConsumedSidecarSeq+1) to the sidecar so already-
	// committed bytes don't get replayed (and re-numbered) into the
	// daemon ring. Optional — pre-v0.6 sessions stored zero.
	LastConsumedSidecarSeq uint64 `cbor:"lcs,omitempty"`
}

// SaveTo writes the session's metadata + ring-buffer bytes to a
// per-session subdirectory under `parentDir`. Atomic per file —
// the metadata write goes through a temp-file-then-rename, so a
// reader that observes meta.cbor sees a consistent snapshot even
// if SaveTo is interrupted partway. scrollback.bin is rewritten in
// place with the same atomic dance.
//
// No-op when persist==false; the caller is expected to gate this,
// but the early return keeps the contract safe for accidents.
//
// Updates Session.lastSnapshotSeq on success so the flusher can
// skip the next tick if nothing's changed since.
func (s *Session) SaveTo(parentDir string) error {
	if !s.Persist() {
		return nil
	}

	// Capture buffer + metadata under their respective locks. We
	// don't hold both at once — buf has its own mu, session has s.mu.
	bufBytes, writePos, headSeq, full := s.buf.Snapshot()

	s.mu.Lock()
	meta := persistedSessionMeta{
		FormatVersion:          persistenceFormatVersion,
		SessionID:              append([]byte(nil), s.id[:]...),
		Name:                   s.name,
		CreatedNs:              s.created.UnixNano(),
		LastActiveNs:           s.lastActiveAt.UnixNano(),
		Rows:                   s.rows,
		Cols:                   s.cols,
		IdleTimeoutNs:          int64(s.idleTimeout),
		Persist:                s.persist,
		BufCapacity:            len(bufBytes),
		HeadSeq:                headSeq,
		WritePos:               writePos,
		Full:                   full,
		LastConsumedSidecarSeq: s.lastSidecarSeq,
	}
	s.mu.Unlock()

	dir := filepath.Join(parentDir, sessionsSubdir, s.id.String())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir session dir: %w", err)
	}

	metaBytes, err := cbor.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal session meta: %w", err)
	}

	if err := atomicWriteFile(filepath.Join(dir, scrollbackFilename), bufBytes, 0o600); err != nil {
		return fmt.Errorf("write scrollback: %w", err)
	}
	// Meta is written LAST so a partial save (scrollback present but
	// meta absent) is detectable by Load and dropped cleanly.
	if err := atomicWriteFile(filepath.Join(dir, metaFilename), metaBytes, 0o600); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	s.mu.Lock()
	s.lastSnapshotSeq = headSeq
	s.mu.Unlock()
	return nil
}

// DeletePersisted removes the on-disk subdir for this session.
// Called by the registry's idle-GC sweep + by the explicit Kill
// path so reaped sessions don't leak disk space.
//
// No-op when the dir doesn't exist (common when persist was false,
// or when the session was never flushed before being killed).
func (s *Session) DeletePersisted(parentDir string) error {
	dir := filepath.Join(parentDir, sessionsSubdir, s.id.String())
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// LoadPersisted walks the sessions subdirectory under `parentDir`,
// reconstructs every valid persisted Session, and inserts them into
// the registry. Returns the count of successfully restored sessions.
//
// Error handling posture is "log and continue" for per-entry
// failures — a corrupted meta or scrollback.bin for one session
// shouldn't keep the daemon from starting. Top-level errors
// (e.g. can't readdir the parent because it doesn't exist yet, or
// the registry rejects every insert) are returned.
//
// Restored sessions have their PTY field nil — the actual shell is
// not respawned until a client attaches. The registry treats nil PTY
// sessions as "live but quiescent" — GC sweeps still consider them
// against idleTimeout, list responses include them, etc.
func LoadPersisted(parentDir string, reg *Registry, logger *slog.Logger) (int, error) {
	if logger == nil {
		logger = slog.Default()
	}
	sessionsDir := filepath.Join(parentDir, sessionsSubdir)
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read sessions dir: %w", err)
	}

	now := time.Now()
	restored := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(sessionsDir, e.Name())
		s, err := loadSessionFromDir(dir, now, logger)
		if err != nil {
			logger.Warn("session.persistence.load_dropped",
				"dir", e.Name(),
				"err", err.Error(),
			)
			_ = os.RemoveAll(dir)
			continue
		}
		if s == nil {
			continue // legitimate skip (e.g. expired)
		}
		if err := reg.Add(s); err != nil {
			logger.Warn("session.persistence.register_failed",
				"session", s.ID().String(),
				"err", err.Error(),
			)
			_ = os.RemoveAll(dir)
			continue
		}
		restored++
	}
	return restored, nil
}

// loadSessionFromDir reads one per-session subdir's meta + scrollback
// and returns a fully-populated Session ready for registry insertion.
// Returns (nil, nil) when the session is legitimately stale by its
// own idleTimeout — caller treats that as "drop without error."
func loadSessionFromDir(dir string, now time.Time, logger *slog.Logger) (*Session, error) {
	metaBytes, err := os.ReadFile(filepath.Join(dir, metaFilename))
	if err != nil {
		return nil, fmt.Errorf("read meta: %w", err)
	}
	var meta persistedSessionMeta
	// Decode via the wire-protocol's StrictDecMode (CBOR limits:
	// MaxArrayElements=256, MaxMapPairs=64, MaxNestedLevels=8). The
	// raw cbor.Unmarshal default is unbounded — a malformed meta.cbor
	// from a hostile state-dir writer could otherwise drive a CPU /
	// memory exhaust during daemon startup before the schema-version
	// check runs.
	if err := protocol.StrictDecMode.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("decode meta: %w", err)
	}
	if meta.FormatVersion != persistenceFormatVersion {
		return nil, fmt.Errorf("unsupported format version %d (want %d)",
			meta.FormatVersion, persistenceFormatVersion)
	}
	if len(meta.SessionID) != SessionIDLen {
		return nil, fmt.Errorf("invalid session id length %d", len(meta.SessionID))
	}
	if meta.BufCapacity <= 0 {
		return nil, fmt.Errorf("invalid buffer capacity %d", meta.BufCapacity)
	}
	if meta.BufCapacity > maxPersistedBufCapacity {
		// Pre-v1.0 hardening: a crafted meta.cbor with BufCapacity
		// = 2^31 would crash daemon startup at NewRingBuffer's
		// make([]byte, …) via an out-of-memory panic. Reject up
		// front; the calling LoadPersisted treats this as a
		// dropped session (logs + removes the dir).
		return nil, fmt.Errorf("buffer capacity %d exceeds maximum %d",
			meta.BufCapacity, maxPersistedBufCapacity)
	}

	scrollBytes, err := os.ReadFile(filepath.Join(dir, scrollbackFilename))
	if err != nil {
		return nil, fmt.Errorf("read scrollback: %w", err)
	}
	if len(scrollBytes) != meta.BufCapacity {
		return nil, fmt.Errorf("scrollback length %d != meta cap %d",
			len(scrollBytes), meta.BufCapacity)
	}

	// Stale-on-load: drop sessions whose lastActiveAt has aged past
	// their idleTimeout. Treat zero idleTimeout as "registry default"
	// (caller can't know it without re-acquiring; use a generous
	// fallback of 30 days here so we don't aggressively drop on
	// load — the runtime GC sweep will re-evaluate against the real
	// default once the session is registered).
	if meta.IdleTimeoutNs > 0 {
		lastActive := time.Unix(0, meta.LastActiveNs)
		if now.Sub(lastActive) >= time.Duration(meta.IdleTimeoutNs) {
			logger.Info("session.persistence.expired_on_load",
				"session", fmt.Sprintf("%x", meta.SessionID),
				"name", meta.Name,
				"idle_for", now.Sub(lastActive).String(),
			)
			return nil, nil
		}
	}

	buf, err := NewRingBuffer(meta.BufCapacity)
	if err != nil {
		return nil, fmt.Errorf("alloc buffer: %w", err)
	}
	if err := buf.RestoreFromSnapshot(scrollBytes, meta.WritePos, meta.HeadSeq, meta.Full); err != nil {
		return nil, fmt.Errorf("restore buffer: %w", err)
	}

	var sid SessionID
	copy(sid[:], meta.SessionID)

	s := &Session{
		id:               sid,
		name:             meta.Name,
		created:          time.Unix(0, meta.CreatedNs),
		cap:              meta.BufCapacity,
		buf:              buf,
		pty:              nil, // lazy: spawned on first attach
		rows:             meta.Rows,
		cols:             meta.Cols,
		idleTimeout:      time.Duration(meta.IdleTimeoutNs),
		lastActiveAt:     time.Unix(0, meta.LastActiveNs),
		persist:          meta.Persist,
		lastSnapshotSeq:  meta.HeadSeq,
		lastSidecarSeq:   meta.LastConsumedSidecarSeq,
		restoredFromDisk: true,
		// Without this the wedge watcher is nil on restored sessions
		// and every nil-guarded call site (Resize → ArmResize, Pump →
		// ObserveBytes, OnWedge subscriber install) silently no-ops.
		// Any session that survives a daemon restart loses detection
		// for the rest of its lifetime. The watcher is per-Session
		// state by design (no on-disk persistence of counters — those
		// are diagnostic, not durable) so a fresh one is correct: we
		// start counting resizes / bytes / wedges from the moment the
		// session is rehydrated, not retroactively.
		wedge:            newWedgeWatcher(),
	}
	return s, nil
}

// atomicWriteFile is the local copy of the temp-file-then-rename
// pattern. We duplicate (vs reusing cert.writeFileAtomic) to keep
// the session package self-contained without exporting a generic
// helper. ~25 lines; if a third caller arrives, move to a shared
// internal/atomicfile package.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".meshtermd-persist-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
