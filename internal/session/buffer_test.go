package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewRingBufferRejectsNonPositiveCapacity(t *testing.T) {
	t.Parallel()
	cases := []int{0, -1, -1024}
	for _, c := range cases {
		if _, err := NewRingBuffer(c); !errors.Is(err, ErrInvalidCapacity) {
			t.Errorf("NewRingBuffer(%d) = %v, want ErrInvalidCapacity", c, err)
		}
	}
}

func TestEmptyBufferReadsReturnNothing(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	data, seq, trunc := r.ReadSince(0, -1)
	if len(data) != 0 || seq != 0 || trunc {
		t.Errorf("empty read: got data=%q seq=%d trunc=%v, want empty/0/false", data, seq, trunc)
	}
	if got := r.HeadSeq(); got != 0 {
		t.Errorf("HeadSeq on empty = %d, want 0", got)
	}
	if got := r.TailSeq(); got != 0 {
		t.Errorf("TailSeq on empty = %d, want 0", got)
	}
}

func TestWriteThenReadAll(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	want := []byte("hello, world")
	n, err := r.Write(want)
	if n != len(want) || err != nil {
		t.Fatalf("Write n=%d err=%v, want %d/nil", n, err, len(want))
	}
	if got := r.HeadSeq(); got != uint64(len(want)) {
		t.Errorf("HeadSeq after write = %d, want %d", got, len(want))
	}
	data, seq, trunc := r.ReadSince(0, -1)
	if !bytes.Equal(data, want) {
		t.Errorf("ReadSince data = %q, want %q", data, want)
	}
	if seq != uint64(len(want)) || trunc {
		t.Errorf("ReadSince seq=%d trunc=%v, want %d/false", seq, trunc, len(want))
	}
}

func TestReadFromHeadIsEmpty(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	r.Write([]byte("abc"))
	data, seq, trunc := r.ReadSince(3, -1)
	if len(data) != 0 || seq != 3 || trunc {
		t.Errorf("ReadSince at head: data=%q seq=%d trunc=%v", data, seq, trunc)
	}
}

func TestReadFromMiddle(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	r.Write([]byte("hello, world"))
	data, seq, trunc := r.ReadSince(7, -1)
	if !bytes.Equal(data, []byte("world")) {
		t.Errorf("data = %q, want %q", data, "world")
	}
	if seq != 12 || trunc {
		t.Errorf("seq=%d trunc=%v, want 12/false", seq, trunc)
	}
}

func TestWriteWrapKeepsLastCapacityBytes(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(8)
	// Write 10 bytes; only the last 8 should remain accessible.
	r.Write([]byte("0123456789"))
	if got := r.HeadSeq(); got != 10 {
		t.Errorf("HeadSeq = %d, want 10", got)
	}
	if got := r.TailSeq(); got != 2 {
		t.Errorf("TailSeq after wrap = %d, want 2", got)
	}
	data, seq, trunc := r.ReadSince(0, -1)
	if !bytes.Equal(data, []byte("23456789")) {
		t.Errorf("data = %q, want %q", data, "23456789")
	}
	if !trunc {
		t.Error("expected trunc=true when reading from before tail")
	}
	if seq != 10 {
		t.Errorf("seq = %d, want 10", seq)
	}
}

func TestSingleWriteLargerThanCapacity(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(4)
	// Write 12 bytes in one go. Only the last 4 remain.
	r.Write([]byte("0123456789AB"))
	if got := r.HeadSeq(); got != 12 {
		t.Errorf("HeadSeq = %d, want 12", got)
	}
	if got := r.TailSeq(); got != 8 {
		t.Errorf("TailSeq = %d, want 8", got)
	}
	data, _, trunc := r.ReadSince(0, -1)
	if !bytes.Equal(data, []byte("89AB")) {
		t.Errorf("data = %q, want %q", data, "89AB")
	}
	if !trunc {
		t.Error("expected trunc=true")
	}
}

func TestMultipleWritesBuildUpAndWrap(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(8)
	r.Write([]byte("AAAA"))
	r.Write([]byte("BBBB"))
	// Now full but not yet wrapped: tail=0, head=8.
	if got := r.TailSeq(); got != 0 {
		t.Errorf("TailSeq before wrap = %d, want 0", got)
	}
	r.Write([]byte("CC"))
	// Wrapped: head=10, tail=2.
	if got := r.TailSeq(); got != 2 {
		t.Errorf("TailSeq after small wrap = %d, want 2", got)
	}
	data, _, _ := r.ReadSince(2, -1)
	if !bytes.Equal(data, []byte("AABBBBCC")) {
		t.Errorf("after wrap data = %q, want %q", data, "AABBBBCC")
	}
}

func TestReadMaxBytesCaps(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	r.Write([]byte("hello, world"))
	data, seq, trunc := r.ReadSince(0, 5)
	if !bytes.Equal(data, []byte("hello")) {
		t.Errorf("capped data = %q, want %q", data, "hello")
	}
	if seq != 5 || trunc {
		t.Errorf("capped seq=%d trunc=%v, want 5/false", seq, trunc)
	}
	// Continue from where the previous read left off.
	data2, seq2, _ := r.ReadSince(seq, -1)
	if !bytes.Equal(data2, []byte(", world")) {
		t.Errorf("continuation data = %q, want %q", data2, ", world")
	}
	if seq2 != 12 {
		t.Errorf("continuation seq = %d, want 12", seq2)
	}
}

func TestReadBeyondHeadIsEmpty(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(8)
	r.Write([]byte("abc"))
	data, seq, trunc := r.ReadSince(99, -1)
	if len(data) != 0 || seq != 99 || trunc {
		t.Errorf("read beyond head: data=%q seq=%d trunc=%v", data, seq, trunc)
	}
}

func TestReadDataIsACopyAndSurvivesWrite(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(8)
	r.Write([]byte("abcdefgh"))
	data, _, _ := r.ReadSince(0, -1)
	want := append([]byte(nil), data...)
	// Wrap the buffer, overwriting what was read.
	r.Write([]byte("xxxxxxxx"))
	if !bytes.Equal(data, want) {
		t.Errorf("returned slice mutated by subsequent Write; got %q, want %q", data, want)
	}
}

func TestConcurrentWriterReader(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(1024)
	var wg sync.WaitGroup
	wg.Add(2)

	const writes = 100
	const chunk = 32

	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			r.Write(bytes.Repeat([]byte{byte(i)}, chunk))
		}
	}()

	go func() {
		defer wg.Done()
		var seen uint64
		for {
			data, ns, _ := r.ReadSince(seen, -1)
			seen = ns
			if seen >= writes*chunk {
				return
			}
			_ = data
		}
	}()

	wg.Wait()
	if got := r.HeadSeq(); got != writes*chunk {
		t.Errorf("HeadSeq after concurrent run = %d, want %d", got, writes*chunk)
	}
}

func TestZeroLengthWrite(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(16)
	n, err := r.Write(nil)
	if n != 0 || err != nil {
		t.Errorf("Write(nil) = %d/%v, want 0/nil", n, err)
	}
	r.Write([]byte("hi"))
	n, err = r.Write([]byte{})
	if n != 0 || err != nil {
		t.Errorf("Write([]) after content = %d/%v, want 0/nil", n, err)
	}
	if got := r.HeadSeq(); got != 2 {
		t.Errorf("HeadSeq = %d, want 2", got)
	}
}

func TestWrapAtBoundary(t *testing.T) {
	t.Parallel()
	// Boundary case: write exactly capacity, then write one more byte.
	r, _ := NewRingBuffer(4)
	r.Write([]byte("ABCD"))
	if got := r.TailSeq(); got != 0 {
		t.Errorf("after exact-capacity write, tail = %d, want 0", got)
	}
	r.Write([]byte("E"))
	if got := r.TailSeq(); got != 1 {
		t.Errorf("after one over, tail = %d, want 1", got)
	}
	data, _, trunc := r.ReadSince(0, -1)
	if !bytes.Equal(data, []byte("BCDE")) {
		t.Errorf("data = %q, want %q", data, "BCDE")
	}
	if !trunc {
		t.Error("expected truncation indicator")
	}
}

func TestWaitForDataReturnsWhenWriteHappens(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)

	type result struct {
		head uint64
		err  error
	}
	done := make(chan result, 1)
	go func() {
		head, err := r.WaitForData(context.Background(), 0)
		done <- result{head, err}
	}()

	// Briefly wait for the goroutine to enter Wait.
	time.Sleep(20 * time.Millisecond)
	r.Write([]byte("hello"))

	select {
	case res := <-done:
		if res.err != nil {
			t.Errorf("WaitForData err = %v, want nil", res.err)
		}
		if res.head != 5 {
			t.Errorf("WaitForData head = %d, want 5", res.head)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitForData did not return after Write")
	}
}

func TestWaitForDataReturnsImmediatelyIfDataAlreadyPast(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	r.Write([]byte("abc"))

	head, err := r.WaitForData(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if head != 3 {
		t.Errorf("head = %d, want 3", head)
	}
}

func TestWaitForDataRespectsContextCancel(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		head uint64
		err  error
	}
	done := make(chan result, 1)
	go func() {
		head, err := r.WaitForData(ctx, 0)
		done <- result{head, err}
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case res := <-done:
		if !errors.Is(res.err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", res.err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitForData did not return after cancel")
	}
}

func TestWaitForDataLoopsAfterIrrelevantNotify(t *testing.T) {
	t.Parallel()
	// Edge: WaitForData with seenSeq=10 while head=5; an unrelated
	// reader's WaitForData(seenSeq=2) should NOT spuriously return.
	r, _ := NewRingBuffer(64)
	r.Write([]byte("abc")) // head = 3

	type result struct {
		head uint64
		err  error
	}
	done := make(chan result, 1)
	go func() {
		// Wait for head > 10 — must block past the next small write.
		head, err := r.WaitForData(context.Background(), 10)
		done <- result{head, err}
	}()

	// A small write that doesn't push head past 10. We expect
	// WaitForData to NOT return here.
	time.Sleep(20 * time.Millisecond)
	r.Write([]byte("d")) // head = 4
	time.Sleep(20 * time.Millisecond)

	select {
	case res := <-done:
		t.Fatalf("WaitForData returned prematurely: head=%d err=%v", res.head, res.err)
	default:
		// good — still blocked
	}

	// Now push past 10.
	r.Write(bytes.Repeat([]byte{'x'}, 10)) // head = 14
	select {
	case res := <-done:
		if res.err != nil {
			t.Errorf("err = %v, want nil", res.err)
		}
		if res.head < 11 {
			t.Errorf("head = %d, want ≥ 11", res.head)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitForData did not return after head advanced past target")
	}
}
