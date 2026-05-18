package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// testPTY is a minimal session.PTY implementation that we can push
// bytes into from a test. Mirrors the shape of session-pkg's
// internal fakePTY but lives here because Go test helpers don't
// cross package boundaries.
type testPTY struct {
	mu      sync.Mutex
	outBuf  bytes.Buffer
	outCond *sync.Cond
	closed  bool
}

func newTestPTY() *testPTY {
	p := &testPTY{}
	p.outCond = sync.NewCond(&p.mu)
	return p
}

func (p *testPTY) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.outBuf.Len() == 0 && !p.closed {
		p.outCond.Wait()
	}
	if p.closed && p.outBuf.Len() == 0 {
		return 0, io.EOF
	}
	return p.outBuf.Read(b)
}

func (p *testPTY) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errors.New("write on closed pty")
	}
	// Discard stdin writes — the sequencer writes here, but for these
	// tests we only assert on the output-direction byte observer.
	return len(b), nil
}

func (p *testPTY) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.outCond.Broadcast()
	return nil
}

func (p *testPTY) SetSize(rows, cols uint16) error { return nil }

// Push simulates the child process emitting bytes to the PTY's
// slave side, which Pump will read.
func (p *testPTY) Push(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outBuf.Write(b)
	p.outCond.Broadcast()
}

// newTestSession spins up a Session backed by testPTY and starts
// the Pump goroutine. Caller is responsible for sess.Close().
func newTestSession(t *testing.T) (*session.Session, *testPTY) {
	t.Helper()
	pipe := newTestPTY()
	sid, err := session.NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	sess, err := session.NewSession(sid, "test", pipe, 24, 80, 0, time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	go sess.Pump()
	return sess, pipe
}

// TestWatchSaveMarkers_StartThenEnd is the happy-path: inject the
// START marker, expect startCh to close; then inject the END marker,
// expect endCh to close.
func TestWatchSaveMarkers_StartThenEnd(t *testing.T) {
	sess, pipe := newTestSession(t)
	defer func() { _ = sess.Close() }()

	startCh, endCh, stop := watchSaveMarkers(sess)
	defer stop()

	pipe.Push([]byte("foo bar Commencing Save & Restore\r\n"))
	select {
	case <-startCh:
	case <-time.After(time.Second):
		t.Fatal("start marker not signalled within 1s")
	}

	// End hasn't fired yet.
	select {
	case <-endCh:
		t.Fatal("end fired before END marker was injected")
	case <-time.After(100 * time.Millisecond):
	}

	pipe.Push([]byte("(...saving...)\r\nMemory Updated, restoring session...\r\n"))
	select {
	case <-endCh:
	case <-time.After(time.Second):
		t.Fatal("end marker not signalled within 1s")
	}
}

// TestWatchSaveMarkers_EndBeforeStartDoesNotFire pins the ordering
// guard: an END marker that arrives before any START is ignored.
func TestWatchSaveMarkers_EndBeforeStartDoesNotFire(t *testing.T) {
	sess, pipe := newTestSession(t)
	defer func() { _ = sess.Close() }()

	_, endCh, stop := watchSaveMarkers(sess)
	defer stop()

	pipe.Push([]byte("Memory Updated, restoring something — and ready\r\n"))

	select {
	case <-endCh:
		t.Fatal("end fired without START having been seen")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestWatchSaveMarkers_SplitAcrossChunks pins the cross-chunk
// behaviour: a marker split between two PTY reads still matches.
func TestWatchSaveMarkers_SplitAcrossChunks(t *testing.T) {
	sess, pipe := newTestSession(t)
	defer func() { _ = sess.Close() }()

	startCh, _, stop := watchSaveMarkers(sess)
	defer stop()

	pipe.Push([]byte("Commen"))
	time.Sleep(50 * time.Millisecond)
	pipe.Push([]byte("cing Save & Restore\r\n"))

	select {
	case <-startCh:
	case <-time.After(time.Second):
		t.Fatal("split-across-chunks marker not signalled")
	}
}

// TestWatchSaveMarkers_StopClearsObserver pins the cleanup contract:
// after stop(), a follow-up burst of marker bytes must NOT re-trigger
// the start channel.
func TestWatchSaveMarkers_StopClearsObserver(t *testing.T) {
	sess, pipe := newTestSession(t)
	defer func() { _ = sess.Close() }()

	startCh, _, stop := watchSaveMarkers(sess)
	stop()

	pipe.Push([]byte("Commencing Save & Restore\r\n"))

	select {
	case <-startCh:
		t.Fatal("start fired after stop() — observer not cleared")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestSleepCtx_HonoursDeadline checks the wait helper stops early on
// ctx cancel. Used in the sequencer's per-stage waits; without this
// a client disconnect mid-recovery would leave goroutines hanging.
func TestSleepCtx_HonoursDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- sleepCtx(ctx, 5*time.Second) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("sleepCtx returned true after cancel; expected false")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sleepCtx did not return promptly after cancel")
	}
}
