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
	if _, err := NewSession(id, "", nil, 24, 80, 0, 0); err == nil {
		t.Error("NewSession(nil pty) returned nil error")
	}
}

func TestPumpCopiesPTYIntoBuffer(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, err := NewSession(id, "", pty, 24, 80, 1024, 0)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	parent := context.Background()

	first, gen1, err := s.Acquire(parent, AttachExclusive)
	if err != nil {
		t.Fatal(err)
	}
	if gen1 == 0 {
		t.Error("first generation should be > 0")
	}
	if first.Err() != nil {
		t.Error("first attach context cancelled prematurely")
	}

	second, gen2, err := s.Acquire(parent, AttachExclusive)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	parent := context.Background()

	_, gen1, _ := s.Acquire(parent, AttachExclusive)
	second, _, _ := s.Acquire(parent, AttachExclusive)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	parent, cancel := context.WithCancel(context.Background())
	_, gen1, _ := s.Acquire(parent, AttachExclusive)
	_, gen2, _ := s.Acquire(parent, AttachExclusive)
	cancel() // cancel the shared parent — both ctxs now have Err()
	// First's Release with the OLD gen must not clear gen2's slot.
	s.Release(gen1)
	// Inspect: activeCancel must still be set (a third Acquire
	// should still trigger displacement).
	_, gen3, _ := s.Acquire(context.Background(), AttachExclusive)
	if gen3 == gen2 {
		t.Error("third Acquire didn't increment generation; second's cancel was prematurely cleared")
	}
}

// TestAcquireReadonlyDoesNotDisplace: a readonly attach must not
// cancel any existing client (exclusive or readonly). Multiple
// readonly + one exclusive should coexist.
func TestAcquireReadonlyDoesNotDisplace(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	exclCtx, exclGen, err := s.Acquire(context.Background(), AttachExclusive)
	if err != nil {
		t.Fatal(err)
	}
	roCtx, roGen, err := s.Acquire(context.Background(), AttachReadonly)
	if err != nil {
		t.Fatal(err)
	}

	// Neither should be cancelled.
	if exclCtx.Err() != nil {
		t.Error("exclusive context cancelled by readonly Acquire")
	}
	if roCtx.Err() != nil {
		t.Error("readonly context cancelled at acquire time")
	}
	// PeerModes(roGen) should report the exclusive client.
	peers := s.PeerModes(roGen)
	if len(peers) != 1 || peers[0] != "exclusive" {
		t.Errorf("readonly's peers = %v, want [exclusive]", peers)
	}
	// PeerModes(exclGen) should report the readonly.
	peers2 := s.PeerModes(exclGen)
	if len(peers2) != 1 || peers2[0] != "readonly" {
		t.Errorf("exclusive's peers = %v, want [readonly]", peers2)
	}
}

// TestAcquireExclusiveDisplacesPriorExclusive: a new exclusive
// attach must cancel any prior exclusive client but leave readonly
// clients alone.
func TestAcquireExclusiveDisplacesPriorExclusive(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	first, _, _ := s.Acquire(context.Background(), AttachExclusive)
	roCtx, _, _ := s.Acquire(context.Background(), AttachReadonly)

	// Now displace the exclusive.
	second, _, _ := s.Acquire(context.Background(), AttachExclusive)

	// First (displaced exclusive) must be cancelled.
	select {
	case <-first.Done():
		// good
	case <-time.After(100 * time.Millisecond):
		t.Error("displaced exclusive context not cancelled within 100ms")
	}
	// Readonly must still be alive.
	if roCtx.Err() != nil {
		t.Error("readonly context cancelled by exclusive replacement")
	}
	// Second exclusive must be alive.
	if second.Err() != nil {
		t.Error("new exclusive context already cancelled")
	}
}

// TestAcquireMultipleReadonlyCoexist: readonly clients accumulate.
// Two readonly Acquire calls leave both alive.
func TestAcquireMultipleReadonlyCoexist(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	a, genA, _ := s.Acquire(context.Background(), AttachReadonly)
	b, _, _ := s.Acquire(context.Background(), AttachReadonly)
	if a.Err() != nil || b.Err() != nil {
		t.Error("readonly Acquire cancelled a peer")
	}
	if peers := s.PeerModes(genA); len(peers) != 1 || peers[0] != "readonly" {
		t.Errorf("PeerModes after 2 readonly = %v", peers)
	}
}

// TestAcquirePassiveDoesNotDisplace: a new passive Acquire must
// neither cancel exclusive nor readonly co-attachers. Passive is the
// invisible-tap mode.
func TestAcquirePassiveDoesNotDisplace(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	exclCtx, _, _ := s.Acquire(context.Background(), AttachExclusive)
	roCtx, _, _ := s.Acquire(context.Background(), AttachReadonly)
	passCtx, _, err := s.Acquire(context.Background(), AttachPassive)
	if err != nil {
		t.Fatal(err)
	}
	if exclCtx.Err() != nil {
		t.Error("exclusive cancelled by passive Acquire")
	}
	if roCtx.Err() != nil {
		t.Error("readonly cancelled by passive Acquire")
	}
	if passCtx.Err() != nil {
		t.Error("passive context cancelled at acquire time")
	}
}

// TestAcquirePassiveInvisibleInAttachedModes: passive attachers must
// NOT appear in AttachedModes() or PeerModes(). The whole point of
// the mode is that other clients can't see the tap.
func TestAcquirePassiveInvisibleInAttachedModes(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	_, exclGen, _ := s.Acquire(context.Background(), AttachExclusive)
	_, _, _ = s.Acquire(context.Background(), AttachPassive)
	_, _, _ = s.Acquire(context.Background(), AttachPassive)

	modes := s.AttachedModes()
	if len(modes) != 1 || modes[0] != "exclusive" {
		t.Errorf("AttachedModes with 2 passive + 1 exclusive = %v, want [exclusive]", modes)
	}
	peers := s.PeerModes(exclGen)
	if len(peers) != 0 {
		t.Errorf("PeerModes(exclusive) sees passive: %v, want []", peers)
	}
}

// TestAcquirePassiveCapEnforced: MaxPassivePerSession concurrent
// passive attaches succeed; the next one returns ErrPassiveCapacity.
func TestAcquirePassiveCapEnforced(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	gens := make([]uint64, 0, MaxPassivePerSession)
	for i := 0; i < MaxPassivePerSession; i++ {
		_, g, err := s.Acquire(context.Background(), AttachPassive)
		if err != nil {
			t.Fatalf("passive #%d unexpectedly failed: %v", i, err)
		}
		gens = append(gens, g)
	}
	_, _, err := s.Acquire(context.Background(), AttachPassive)
	if !errors.Is(err, ErrPassiveCapacity) {
		t.Errorf("passive overflow err = %v, want ErrPassiveCapacity", err)
	}
	// Releasing one should free up a slot.
	s.Release(gens[0])
	_, _, err = s.Acquire(context.Background(), AttachPassive)
	if err != nil {
		t.Errorf("passive after release unexpectedly failed: %v", err)
	}
}

// TestExclusiveDoesNotDisplacePassive: replacing the exclusive client
// must leave passive watchers intact (they're invisible by design;
// turnover invisibility cuts both ways).
func TestExclusiveDoesNotDisplacePassive(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	_, _, _ = s.Acquire(context.Background(), AttachExclusive)
	passCtx, _, _ := s.Acquire(context.Background(), AttachPassive)
	// Displace the exclusive.
	_, _, _ = s.Acquire(context.Background(), AttachExclusive)
	// Passive must still be alive.
	if passCtx.Err() != nil {
		t.Error("passive context cancelled by exclusive turnover")
	}
}

// TestReleasePassive: Release(gen) on a passive attacher must remove
// it from the passive sibling slice without touching s.clients.
func TestReleasePassive(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	_, exclGen, _ := s.Acquire(context.Background(), AttachExclusive)
	_, passGen, _ := s.Acquire(context.Background(), AttachPassive)

	s.Release(passGen)

	// Acquire another passive; the slot should be free.
	_, _, err := s.Acquire(context.Background(), AttachPassive)
	if err != nil {
		t.Errorf("after Release(passive), new passive failed: %v", err)
	}
	// Exclusive still alive.
	if peers := s.PeerModes(exclGen); len(peers) != 0 {
		t.Errorf("PeerModes after Release(passive) = %v, want []", peers)
	}
}

// TestClosePassiveContextsCancelled: Session.Close must cancel the
// contexts of passive attachers, not just regular ones.
func TestClosePassiveContextsCancelled(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)

	passCtx, _, _ := s.Acquire(context.Background(), AttachPassive)
	_ = s.Close()

	select {
	case <-passCtx.Done():
		// good
	case <-time.After(100 * time.Millisecond):
		t.Error("passive context not cancelled within 100ms of Close")
	}
}

// TestReleaseRemovesSpecificClient: Release(gen) must affect only
// the matching client; others stay attached.
func TestReleaseRemovesSpecificClient(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	defer s.Close()

	_, genA, _ := s.Acquire(context.Background(), AttachReadonly)
	_, genB, _ := s.Acquire(context.Background(), AttachReadonly)
	s.Release(genA)
	// Release(genA) should leave B in place.
	if !s.IsAttached() {
		t.Error("IsAttached() false after only one Release of two readonly clients")
	}
	if peers := s.PeerModes(genB); len(peers) != 0 {
		t.Errorf("PeerModes(B) after Release(A) = %v, want []", peers)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	id, _ := NewSessionID()
	pty := newFakePTY()
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
	ctx, _, _ := s.Acquire(context.Background(), AttachExclusive)
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
	s, _ := NewSession(id, "", pty, 24, 80, 1024, 0)
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
