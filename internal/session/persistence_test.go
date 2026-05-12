package session

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// nullLogger discards everything. We don't want test output flooded
// with the "load_dropped" warnings the negative-path tests deliberately
// trigger.
func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// makePersistedSession spawns a fresh Session, marks it persistent,
// writes some test scrollback into the buffer, and returns it. The
// caller is responsible for cleanup via the temp-dir t.TempDir.
func makePersistedSession(t *testing.T, payload []byte) *Session {
	t.Helper()
	id, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	s, err := NewSession(id, "persist-test", newFakePTY(), 24, 80, 1024, time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	s.SetPersist(true)
	if len(payload) > 0 {
		_, _ = s.buf.Write(payload)
	}
	return s
}

// TestSaveToAndLoadPersistedRoundTrip is the load-bearing positive
// test: spawn → save → load (into a fresh registry) → confirm the
// hydrated session reports the same state and replays the same bytes.
func TestSaveToAndLoadPersistedRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	payload := []byte("hello, persisted world\nthis is the scrollback the user should see on restore\n")

	original := makePersistedSession(t, payload)
	if err := original.SaveTo(dir); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	// On-disk shape sanity check.
	sessionDir := filepath.Join(dir, sessionsSubdir, original.ID().String())
	for _, f := range []string{metaFilename, scrollbackFilename} {
		info, err := os.Stat(filepath.Join(sessionDir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", f, info.Mode().Perm())
		}
	}

	// Fresh registry — simulates daemon restart.
	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	n, err := LoadPersisted(dir, reg, nullLogger())
	if err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	if n != 1 {
		t.Fatalf("LoadPersisted count = %d, want 1", n)
	}

	restored, err := reg.Lookup(original.ID())
	if err != nil {
		t.Fatalf("registry.Lookup: %v", err)
	}
	if got := restored.Name(); got != original.Name() {
		t.Errorf("Name = %q, want %q", got, original.Name())
	}
	if !restored.RestoredFromDisk() {
		t.Error("restored session should have RestoredFromDisk() == true")
	}
	if !restored.Persist() {
		t.Error("persist flag did not round-trip")
	}
	rows, cols := restored.WindowSize()
	if rows != 24 || cols != 80 {
		t.Errorf("WindowSize = %d×%d, want 24×80", rows, cols)
	}

	// Most important: replay the scrollback.
	data, _, _ := restored.Buffer().ReadSince(0, 0)
	if string(data) != string(payload) {
		t.Errorf("scrollback mismatch:\n  got:  %q\n  want: %q", data, payload)
	}
}

// TestSaveToNoOpWhenNotPersisting verifies that calling SaveTo on a
// session whose persist flag is false is harmless — no dir created.
// The flusher relies on this guard so callers don't have to.
func TestSaveToNoOpWhenNotPersisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, _ := NewSessionID()
	s, err := NewSession(id, "ephemeral", newFakePTY(), 24, 80, 1024, time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// SetPersist not called — defaults to false.
	if err := s.SaveTo(dir); err != nil {
		t.Fatalf("SaveTo on non-persisting session: %v", err)
	}
	sessionDir := filepath.Join(dir, sessionsSubdir, s.ID().String())
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Errorf("session dir created despite persist=false: %v", err)
	}
}

// TestLoadPersistedDropsCorruptMeta verifies the "log and skip"
// posture: a corrupted meta.cbor in one session shouldn't crash the
// daemon or block sibling sessions from loading.
func TestLoadPersistedDropsCorruptMeta(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	good := makePersistedSession(t, []byte("clean session"))
	if err := good.SaveTo(dir); err != nil {
		t.Fatalf("save good: %v", err)
	}

	// Plant a corrupted-meta session in a sibling directory.
	badDir := filepath.Join(dir, sessionsSubdir, "ffffffffffffffffffffffffffffffff")
	if err := os.MkdirAll(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, metaFilename),
		[]byte("not valid cbor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, scrollbackFilename),
		make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	n, err := LoadPersisted(dir, reg, nullLogger())
	if err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	if n != 1 {
		t.Errorf("loaded %d sessions, want 1 (the good one)", n)
	}
	// Corrupt dir should be removed.
	if _, err := os.Stat(badDir); !os.IsNotExist(err) {
		t.Errorf("corrupt session dir wasn't cleaned up")
	}
}

// TestLoadPersistedDropsFormatVersionMismatch verifies that a meta
// from a future / past schema is dropped without breaking the load.
// Protects against "daemon downgraded after running a newer version
// and leaving incompatible files on disk."
func TestLoadPersistedDropsFormatVersionMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	s := makePersistedSession(t, []byte("hi"))
	if err := s.SaveTo(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Manually rewrite meta with a bumped FormatVersion.
	sessionDir := filepath.Join(dir, sessionsSubdir, s.ID().String())
	metaPath := filepath.Join(sessionDir, metaFilename)
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	// Hack: flip the fv field's value byte. We know it's there;
	// rewriting via CBOR would be cleaner but this is sufficient
	// to break the version check.
	_ = metaBytes
	// Easier path: replace the whole meta with an explicit bad version.
	if err := os.WriteFile(metaPath, badFormatMeta(t, s, 9999), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	n, _ := LoadPersisted(dir, reg, nullLogger())
	if n != 0 {
		t.Errorf("loaded %d sessions, want 0 (version mismatch)", n)
	}
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Errorf("mismatched-version dir wasn't cleaned up")
	}
}

// TestLoadPersistedDropsExpiredOnLoad: a session whose idleTimeout
// has elapsed by the time the daemon restarts is dropped without
// being added to the registry. Prevents zombie sessions from
// hanging around forever just because they were persisted.
func TestLoadPersistedDropsExpiredOnLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	id, _ := NewSessionID()
	s, err := NewSession(id, "stale", newFakePTY(), 24, 80, 1024, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s.SetPersist(true)
	_, _ = s.buf.Write([]byte("old"))
	if err := s.SaveTo(dir); err != nil {
		t.Fatal(err)
	}

	time.Sleep(150 * time.Millisecond)

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	n, err := LoadPersisted(dir, reg, nullLogger())
	if err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	if n != 0 {
		t.Errorf("loaded %d sessions, want 0 (expired)", n)
	}
}

// TestDeletePersistedRemovesDirectory: GC + Kill path removes the
// on-disk dir so reaped sessions don't leak.
func TestDeletePersistedRemovesDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	s := makePersistedSession(t, []byte("delete me"))
	if err := s.SaveTo(dir); err != nil {
		t.Fatal(err)
	}
	sessionDir := filepath.Join(dir, sessionsSubdir, s.ID().String())
	if _, err := os.Stat(sessionDir); err != nil {
		t.Fatalf("pre-condition: dir should exist: %v", err)
	}

	if err := s.DeletePersisted(dir); err != nil {
		t.Fatalf("DeletePersisted: %v", err)
	}
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Errorf("DeletePersisted did not remove the dir")
	}

	// Second call is a no-op (idempotent).
	if err := s.DeletePersisted(dir); err != nil {
		t.Errorf("second DeletePersisted should be a no-op: %v", err)
	}
}

// TestLoadPersistedReturnsZeroOnMissingDir: a fresh daemon install
// (no sessions/ dir yet) should not error.
func TestLoadPersistedReturnsZeroOnMissingDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	n, err := LoadPersisted(dir, reg, nullLogger())
	if err != nil {
		t.Fatalf("LoadPersisted on empty parent: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}
}

// badFormatMeta returns a meta.cbor with a bumped format version,
// used by the version-mismatch test. Other fields copied from the
// source session so the file is syntactically valid CBOR.
func badFormatMeta(t *testing.T, s *Session, version int) []byte {
	t.Helper()
	bufBytes, writePos, headSeq, full := s.buf.Snapshot()
	s.mu.Lock()
	defer s.mu.Unlock()
	meta := persistedSessionMeta{
		FormatVersion: version,
		SessionID:     append([]byte(nil), s.id[:]...),
		Name:          s.name,
		CreatedNs:     s.created.UnixNano(),
		LastActiveNs:  s.lastActiveAt.UnixNano(),
		Rows:          s.rows,
		Cols:          s.cols,
		IdleTimeoutNs: int64(s.idleTimeout),
		Persist:       s.persist,
		BufCapacity:   len(bufBytes),
		HeadSeq:       headSeq,
		WritePos:      writePos,
		Full:          full,
	}
	out, err := cbor.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
