package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakePTY is an in-memory PTY for testing. Reads come from outBuf
// (typically pre-loaded by the test or appended to by Push), writes
// go to inBuf so tests can assert what the session sent toward the
// child.
type fakePTY struct {
	mu       sync.Mutex
	outBuf   bytes.Buffer
	outCond  *sync.Cond
	inBuf    bytes.Buffer
	rows     uint16
	cols     uint16
	closed   bool
	closeErr error
}

func newFakePTY() *fakePTY {
	p := &fakePTY{}
	p.outCond = sync.NewCond(&p.mu)
	return p
}

func (p *fakePTY) Read(b []byte) (int, error) {
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

func (p *fakePTY) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errors.New("write on closed pty")
	}
	return p.inBuf.Write(b)
}

func (p *fakePTY) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	p.outCond.Broadcast()
	return p.closeErr
}

func (p *fakePTY) SetSize(rows, cols uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rows, p.cols = rows, cols
	return nil
}

// Push simulates the PTY's child process emitting bytes.
func (p *fakePTY) Push(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outBuf.Write(b)
	p.outCond.Broadcast()
}

func (p *fakePTY) StdinSeen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inBuf.String()
}

func TestNewSessionIDIsRandom(t *testing.T) {
	t.Parallel()
	a, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two consecutive NewSessionID calls returned identical values: %s", a)
	}
}

func TestSessionIDStringRoundTrip(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	s := id.String()
	if len(s) != SessionIDLen*2 {
		t.Errorf("String length = %d, want %d", len(s), SessionIDLen*2)
	}
	parsed, err := ParseSessionID(s)
	if err != nil {
		t.Fatalf("ParseSessionID: %v", err)
	}
	if parsed != id {
		t.Errorf("round-trip lost data: original=%v parsed=%v", id, parsed)
	}
}

func TestParseSessionIDRejectsBadInput(t *testing.T) {
	t.Parallel()
	bads := []string{"", "abcd", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "123"}
	for _, in := range bads {
		if _, err := ParseSessionID(in); err == nil {
			t.Errorf("ParseSessionID(%q) returned nil error, want error", in)
		}
	}
}

func TestNewSessionRejectsNilPTY(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	if _, err := NewSession(id, nil, 24, 80, 0); err == nil {
		t.Error("NewSession(nil pty) returned nil error")
	}
}

func TestPumpCopiesPTYIntoBuffer(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, err := NewSession(id, pty, 24, 80, 1024)
	if err != nil {
		t.Fatal(err)
	}
	go s.Pump()

	pty.Push([]byte("hello"))
	pty.Push([]byte(", world"))
	// Close PTY so Pump exits and we can read deterministically.
	pty.Close()

	// Wait for Pump to drain.
	deadline := time.Now().Add(time.Second)
	for !s.Closed() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !s.Closed() {
		t.Fatal("session did not close within timeout")
	}

	// Buffer was nil-ed out by Close (Buffer() returns nil after
	// closure to prevent races with reads against torn-down state).
	// To verify content we have to grab Buffer() before Close —
	// reach into the unexported field for testing.
	if got := bytesAccumulated(s); !bytes.Equal(got, []byte("hello, world")) {
		t.Errorf("accumulated = %q, want %q", got, "hello, world")
	}
}

// bytesAccumulated grabs the buffer's full contents directly via the
// unexported field. Used only by tests that have closed the session.
func bytesAccumulated(s *Session) []byte {
	if s.buf == nil {
		return nil
	}
	data, _, _ := s.buf.ReadSince(0, -1)
	return data
}

func TestWriteStdinReachesPTY(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	if _, err := s.WriteStdin([]byte("ls\n")); err != nil {
		t.Fatalf("WriteStdin: %v", err)
	}
	if got := pty.StdinSeen(); got != "ls\n" {
		t.Errorf("PTY stdin = %q, want %q", got, "ls\n")
	}
}

func TestResizeUpdatesPTYAndState(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	if err := s.Resize(40, 120); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	rows, cols := s.WindowSize()
	if rows != 40 || cols != 120 {
		t.Errorf("WindowSize = %d×%d, want 40×120", rows, cols)
	}
	pty.mu.Lock()
	pr, pc := pty.rows, pty.cols
	pty.mu.Unlock()
	if pr != 40 || pc != 120 {
		t.Errorf("PTY size = %d×%d, want 40×120", pr, pc)
	}
}

func TestAcquireDisplacesPriorAttach(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	parent := context.Background()

	first, gen1, err := s.Acquire(parent)
	if err != nil {
		t.Fatal(err)
	}
	if gen1 == 0 {
		t.Error("first generation should be > 0")
	}
	if first.Err() != nil {
		t.Error("first attach context cancelled prematurely")
	}

	second, gen2, err := s.Acquire(parent)
	if err != nil {
		t.Fatal(err)
	}
	if gen2 == gen1 {
		t.Error("second generation should differ from first")
	}
	// First should now be cancelled by the displacement.
	if first.Err() == nil {
		t.Error("first attach context not cancelled when second arrived")
	}
	if second.Err() != nil {
		t.Error("second attach context cancelled prematurely")
	}
}

func TestReleaseDoesNotClearWhenDisplaced(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	parent := context.Background()

	_, gen1, _ := s.Acquire(parent)
	second, _, _ := s.Acquire(parent)
	// Old attach calls Release after seeing its ctx cancelled. With
	// the generation counter, this no-ops cleanly.
	s.Release(gen1)
	// Second attach should still be active.
	if second.Err() != nil {
		t.Error("second attach was lost after the first called Release")
	}
}

func TestReleaseStaleGenerationIsNoOp(t *testing.T) {
	t.Parallel()
	// Even if the parent ctx was independently cancelled (e.g.,
	// daemon-wide shutdown), Release(staleGen) must not touch the
	// new active slot. The previous ctx-error-as-identity heuristic
	// got this wrong.
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	parent, cancel := context.WithCancel(context.Background())
	_, gen1, _ := s.Acquire(parent)
	_, gen2, _ := s.Acquire(parent)
	cancel() // cancel the shared parent — both ctxs now have Err()
	// First's Release with the OLD gen must not clear gen2's slot.
	s.Release(gen1)
	// Inspect: activeCancel must still be set (a third Acquire
	// should still trigger displacement).
	_, gen3, _ := s.Acquire(context.Background())
	if gen3 == gen2 {
		t.Error("third Acquire didn't increment generation; second's cancel was prematurely cleared")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if !s.Closed() {
		t.Error("Closed() = false after Close")
	}
	// Operations on a closed session return ErrSessionClosed.
	if _, err := s.WriteStdin([]byte("x")); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("WriteStdin after Close = %v, want ErrSessionClosed", err)
	}
	if err := s.Resize(1, 1); !errors.Is(err, ErrSessionClosed) {
		t.Errorf("Resize after Close = %v, want ErrSessionClosed", err)
	}
}

func TestCloseCancelsActiveAttach(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	ctx, _, _ := s.Acquire(context.Background())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		// good
	case <-time.After(time.Second):
		t.Error("Close did not cancel the active attach context within 1s")
	}
}

func TestIdleForGrows(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, pty, 24, 80, 1024)
	time.Sleep(20 * time.Millisecond)
	if got := s.IdleFor(); got < 20*time.Millisecond {
		t.Errorf("IdleFor = %v, want ≥ 20ms", got)
	}
	// Touch resets it.
	s.Touch()
	if got := s.IdleFor(); got > 20*time.Millisecond {
		t.Errorf("IdleFor after Touch = %v, want < 20ms", got)
	}
}
