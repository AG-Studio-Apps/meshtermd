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

// TestLastSidecarSeqRoundTrip checks that Session.lastSidecarSeq is
// persisted to meta.cbor and restored across LoadPersisted — the
// daemon needs this watermark to send FrameResume(from_seq) on
// reattach without re-consuming bytes already in the daemon ring.
func TestLastSidecarSeqRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	original := makePersistedSession(t, []byte("x"))
	original.AdvanceSidecarSeq(987654321)
	if err := original.SaveTo(dir); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	if _, err := LoadPersisted(dir, reg, nullLogger()); err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	restored, err := reg.Lookup(original.ID())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := restored.LastSidecarSeq(); got != 987654321 {
		t.Errorf("LastSidecarSeq round-trip: want 987654321, got %d", got)
	}
}

// TestAdvanceSidecarSeqMonotonic verifies that AdvanceSidecarSeq is
// a monotonic watermark — older values do not regress lastSidecarSeq.
// The Pump's coalesced-ack flow can otherwise advance the watermark
// out of order if a stale frame slips through.
func TestAdvanceSidecarSeqMonotonic(t *testing.T) {
	t.Parallel()
	s := makePersistedSession(t, nil)
	s.AdvanceSidecarSeq(100)
	s.AdvanceSidecarSeq(50)
	if got := s.LastSidecarSeq(); got != 100 {
		t.Errorf("monotonic: regressed to %d, want 100", got)
	}
	s.AdvanceSidecarSeq(200)
	if got := s.LastSidecarSeq(); got != 200 {
		t.Errorf("advance: want 200, got %d", got)
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

// TestStartFlusherWritesOnInterval: the background goroutine fires
// on its ticker cadence, advances lastSnapshotSeq, and produces a
// readable on-disk snapshot. Uses a short interval (50ms) so the
// test wraps quickly.
func TestStartFlusherWritesOnInterval(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := makePersistedSession(t, []byte("initial"))

	// Pre-flusher: no on-disk state yet.
	sessionDir := filepath.Join(dir, sessionsSubdir, s.ID().String())
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Fatalf("pre-flusher state: dir should not exist: %v", err)
	}

	s.StartFlusher(dir, 50*time.Millisecond, nullLogger())
	t.Cleanup(func() { _ = s.Close() }) // also stops the flusher

	// Wait for at least one tick — flusher needs to fire and call
	// SaveTo. 200ms gives plenty of margin.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(sessionDir, metaFilename)); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(sessionDir, metaFilename)); err != nil {
		t.Fatalf("flusher did not write meta.cbor within 500ms: %v", err)
	}

	// Push more bytes; expect the next tick to update the file.
	_, _ = s.buf.Write([]byte("\nmore output"))
	time.Sleep(120 * time.Millisecond)

	// Verify the on-disk scrollback reflects the new content via a
	// fresh Load.
	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	if _, err := LoadPersisted(dir, reg, nullLogger()); err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	restored, err := reg.Lookup(s.ID())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	data, _, _ := restored.Buffer().ReadSince(0, 0)
	if want := "initial\nmore output"; string(data) != want {
		t.Errorf("restored buffer = %q, want %q", data, want)
	}
}

// TestFlusherFinalFlushOnClose: the ctx-done path inside the flusher
// performs one final SaveTo before exiting, so a dirty session that
// hadn't yet reached its next interval is still preserved on
// daemon shutdown.
func TestFlusherFinalFlushOnClose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := makePersistedSession(t, []byte("before-close"))

	// Long interval so the ticker never fires during the test —
	// the only write we expect is the final flush from stopFlusher.
	s.StartFlusher(dir, 1*time.Hour, nullLogger())

	// Append more after the flusher started; this is what the final
	// flush should capture.
	_, _ = s.buf.Write([]byte("-final"))

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	if _, err := LoadPersisted(dir, reg, nullLogger()); err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	restored, err := reg.Lookup(s.ID())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	data, _, _ := restored.Buffer().ReadSince(0, 0)
	if want := "before-close-final"; string(data) != want {
		t.Errorf("restored buffer after final flush = %q, want %q", data, want)
	}
}

// TestResolvePersistTriState verifies the Registry's nil/true/false
// resolution. nil → daemon default (default-on), true/false → as-is.
func TestResolvePersistTriState(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	cases := []struct {
		name      string
		def       bool
		requested *bool
		want      bool
	}{
		{"nil with default on", true, nil, true},
		{"nil with default off", false, nil, false},
		{"explicit true overrides default off", false, &yes, true},
		{"explicit false overrides default on", true, &no, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(0, time.Hour, time.Hour, 0)
			r.SetPersistenceDefault(tc.def)
			if got := r.ResolvePersist(tc.requested); got != tc.want {
				t.Errorf("ResolvePersist(%v) with default=%v = %v, want %v",
					tc.requested, tc.def, got, tc.want)
			}
		})
	}
}

// TestRemoveDeletesOnDiskState: explicit Remove (mtctl kill path)
// drops the on-disk session dir so reaped sessions don't leak disk.
func TestRemoveDeletesOnDiskState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := makePersistedSession(t, []byte("kill me"))
	if err := s.SaveTo(dir); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	reg.SetStateDir(dir)
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}

	sessionDir := filepath.Join(dir, sessionsSubdir, s.ID().String())
	if _, err := os.Stat(sessionDir); err != nil {
		t.Fatalf("pre-condition: dir should exist: %v", err)
	}

	reg.Remove(s.ID())

	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Errorf("Remove did not delete on-disk state")
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

// metaWithBufCapacity returns a meta.cbor whose BufCapacity field is
// set to the supplied value. Used to verify the pre-v1.0 cap rejects
// crafted entries before NewRingBuffer attempts a huge allocation.
func metaWithBufCapacity(t *testing.T, s *Session, capacity int) []byte {
	t.Helper()
	_, writePos, headSeq, full := s.buf.Snapshot()
	s.mu.Lock()
	defer s.mu.Unlock()
	meta := persistedSessionMeta{
		FormatVersion: persistenceFormatVersion,
		SessionID:     append([]byte(nil), s.id[:]...),
		Name:          s.name,
		CreatedNs:     s.created.UnixNano(),
		LastActiveNs:  s.lastActiveAt.UnixNano(),
		Rows:          s.rows,
		Cols:          s.cols,
		IdleTimeoutNs: int64(s.idleTimeout),
		Persist:       s.persist,
		BufCapacity:   capacity,
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

func TestLoadPersistedDropsOversizedBufCapacity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	s := makePersistedSession(t, []byte("hi"))
	if err := s.SaveTo(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Rewrite meta with a BufCapacity over the cap. Defends against a
	// crafted meta.cbor that would crash daemon startup at the
	// `make([]byte, meta.BufCapacity)` inside NewRingBuffer.
	sessionDir := filepath.Join(dir, sessionsSubdir, s.ID().String())
	metaPath := filepath.Join(sessionDir, metaFilename)
	if err := os.WriteFile(metaPath,
		metaWithBufCapacity(t, s, maxPersistedBufCapacity+1), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(0, time.Hour, time.Hour, 0)
	n, _ := LoadPersisted(dir, reg, nullLogger())
	if n != 0 {
		t.Errorf("loaded %d sessions, want 0 (BufCapacity over cap)", n)
	}
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Errorf("oversized-BufCapacity dir wasn't cleaned up")
	}
}
