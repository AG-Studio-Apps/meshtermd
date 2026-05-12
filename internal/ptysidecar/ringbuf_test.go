package ptysidecar

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

func TestRingWriteThenDrain(t *testing.T) {
	r := NewRing(1024)
	in := []byte("hello world")
	n, err := r.Write(in)
	if err != nil || n != len(in) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	if r.Len() != len(in) {
		t.Errorf("Len: want %d, got %d", len(in), r.Len())
	}
	buf := make([]byte, 32)
	got := r.Drain(buf)
	if got != len(in) {
		t.Errorf("Drain: want %d, got %d", len(in), got)
	}
	if !bytes.Equal(buf[:got], in) {
		t.Errorf("Drain payload mismatch: want %q, got %q", in, buf[:got])
	}
	if r.Len() != 0 {
		t.Errorf("post-drain Len: want 0, got %d", r.Len())
	}
}

func TestRingPartialDrain(t *testing.T) {
	r := NewRing(64)
	_, _ = r.Write([]byte("abcdefghij"))
	buf := make([]byte, 4)
	if got := r.Drain(buf); got != 4 || string(buf) != "abcd" {
		t.Errorf("first drain: got %d %q", got, buf[:got])
	}
	if r.Len() != 6 {
		t.Errorf("Len after partial drain: want 6, got %d", r.Len())
	}
	buf2 := make([]byte, 16)
	if got := r.Drain(buf2); got != 6 || string(buf2[:got]) != "efghij" {
		t.Errorf("second drain: got %d %q", got, buf2[:got])
	}
}

func TestRingDropOldestOnOverflow(t *testing.T) {
	r := NewRing(8)
	_, _ = r.Write([]byte("ABCDEFGH")) // ring full, no drop
	if r.Dropped() != 0 {
		t.Errorf("Dropped after exact fill: want 0, got %d", r.Dropped())
	}
	_, _ = r.Write([]byte("12345")) // drops "ABCDE"
	if r.Dropped() != 5 {
		t.Errorf("Dropped after 5-byte overflow: want 5, got %d", r.Dropped())
	}
	if r.Len() != 8 {
		t.Errorf("Len after overflow: want 8, got %d", r.Len())
	}
	buf := make([]byte, 16)
	n := r.Drain(buf)
	if n != 8 || string(buf[:n]) != "FGH12345" {
		t.Errorf("Drain after overflow: got %d %q", n, buf[:n])
	}
}

func TestRingChunkLargerThanCap(t *testing.T) {
	r := NewRing(8)
	_, _ = r.Write([]byte("prefix-noise")) // 12 bytes; will be dropped
	_, _ = r.Write(bytes.Repeat([]byte("X"), 32))
	// All 12 prefix bytes dropped, plus first 24 bytes of the 32-byte chunk;
	// last 8 bytes of the chunk retained.
	if r.Dropped() != 12+24 {
		t.Errorf("Dropped: want %d, got %d", 12+24, r.Dropped())
	}
	if r.Len() != 8 {
		t.Errorf("Len: want 8, got %d", r.Len())
	}
	buf := make([]byte, 16)
	n := r.Drain(buf)
	if n != 8 || !bytes.Equal(buf[:n], bytes.Repeat([]byte("X"), 8)) {
		t.Errorf("Drain payload: got %d %q", n, buf[:n])
	}
}

func TestRingWrapAround(t *testing.T) {
	r := NewRing(8)
	// Fill, drain half, fill again — exercises the wrap path in Write.
	_, _ = r.Write([]byte("ABCDEFGH"))
	buf := make([]byte, 4)
	r.Drain(buf) // removes "ABCD"
	_, _ = r.Write([]byte("WXYZ"))
	// Ring should now hold "EFGHWXYZ" (E was the oldest before, Z newest).
	out := make([]byte, 8)
	if n := r.Drain(out); n != 8 || string(out) != "EFGHWXYZ" {
		t.Errorf("wrap drain: got %d %q", n, out[:n])
	}
}

func TestRingNotifyFiresOnWrite(t *testing.T) {
	r := NewRing(64)
	select {
	case <-r.NotifyCh():
		t.Fatal("notify fired before any Write")
	default:
	}
	_, _ = r.Write([]byte("hi"))
	select {
	case <-r.NotifyCh():
	default:
		t.Fatal("notify did not fire after Write")
	}
}

func TestRingNotifyCoalesces(t *testing.T) {
	r := NewRing(64)
	for i := 0; i < 10; i++ {
		_, _ = r.Write([]byte("x"))
	}
	// Only one pending notification — the channel has cap 1.
	count := 0
	for {
		select {
		case <-r.NotifyCh():
			count++
		default:
			if count != 1 {
				t.Errorf("notify count: want 1 (edge-triggered), got %d", count)
			}
			return
		}
	}
}

func TestRingSeqTrackingBasic(t *testing.T) {
	r := NewRing(64)
	if r.HeadOutSeq() != 0 || r.TailOutSeq() != 0 || r.ReadOutSeq() != 0 {
		t.Fatalf("fresh ring seqs: head=%d tail=%d read=%d", r.HeadOutSeq(), r.TailOutSeq(), r.ReadOutSeq())
	}
	_, _ = r.Write([]byte("hello"))
	if r.HeadOutSeq() != 5 {
		t.Errorf("HeadOutSeq after 5-byte write: want 5, got %d", r.HeadOutSeq())
	}
	if r.TailOutSeq() != 0 || r.ReadOutSeq() != 0 {
		t.Errorf("Tail/Read should be 0 after first write: tail=%d read=%d", r.TailOutSeq(), r.ReadOutSeq())
	}
	buf := make([]byte, 16)
	n, first, gap := r.DrainWithSeq(buf)
	if n != 5 || first != 0 || gap != 0 || string(buf[:n]) != "hello" {
		t.Errorf("DrainWithSeq: n=%d first=%d gap=%d data=%q", n, first, gap, buf[:n])
	}
	if r.ReadOutSeq() != 5 {
		t.Errorf("ReadOutSeq after DrainWithSeq: want 5, got %d", r.ReadOutSeq())
	}
	// tailOutSeq does NOT advance on DrainWithSeq — bytes remain
	// reclaimable for replay until acked.
	if r.TailOutSeq() != 0 {
		t.Errorf("TailOutSeq should NOT advance on DrainWithSeq: got %d", r.TailOutSeq())
	}
}

func TestRingDrainWithSeqReportsGap(t *testing.T) {
	// Overflow before any drain — gap should be reported on next drain.
	r := NewRing(8)
	_, _ = r.Write([]byte("ABCDEFGH")) // ring full, no drop
	_, _ = r.Write([]byte("12345"))    // drops "ABCDE" → 5 bytes
	buf := make([]byte, 16)
	n, first, gap := r.DrainWithSeq(buf)
	if n != 8 {
		t.Errorf("n: want 8, got %d", n)
	}
	if string(buf[:n]) != "FGH12345" {
		t.Errorf("data: want %q, got %q", "FGH12345", buf[:n])
	}
	if gap != 5 {
		t.Errorf("gapBefore: want 5, got %d", gap)
	}
	if first != 5 {
		t.Errorf("firstSeq: want 5 (after the 5-byte gap from seq 0), got %d", first)
	}
	// A second drain right after sees no new gap.
	n2, _, gap2 := r.DrainWithSeq(buf)
	if n2 != 0 || gap2 != 0 {
		t.Errorf("second drain: want (0,0,0), got n=%d gap=%d", n2, gap2)
	}
}

func TestRingAdvanceTailToFreesUnackedBytes(t *testing.T) {
	// Drain into the daemon-side; bytes remain in the ring until the
	// daemon acks. AdvanceTailTo simulates the ack flow.
	r := NewRing(16)
	_, _ = r.Write([]byte("0123456789ABCDEF")) // ring full (cap 16)
	buf := make([]byte, 16)
	n, first, _ := r.DrainWithSeq(buf)
	if n != 16 || first != 0 {
		t.Fatalf("drain: n=%d first=%d", n, first)
	}
	// Drained but un-acked. Resident bytes still equal cap.
	if r.Len() != 16 {
		t.Errorf("Len after DrainWithSeq (un-acked): want 16, got %d", r.Len())
	}
	// Ack half the drained bytes — those slots free up; writes won't
	// drop them on overflow.
	r.AdvanceTailTo(8)
	if r.TailOutSeq() != 8 {
		t.Errorf("TailOutSeq after AdvanceTailTo(8): want 8, got %d", r.TailOutSeq())
	}
	if r.Len() != 8 {
		t.Errorf("Len after ack of 8: want 8, got %d", r.Len())
	}
	// Ack more than was drained — clamps at readOutSeq.
	r.AdvanceTailTo(999)
	if r.TailOutSeq() != 16 {
		t.Errorf("TailOutSeq after AdvanceTailTo(999): want clamped at readOutSeq=16, got %d", r.TailOutSeq())
	}
	// Older ack is a no-op.
	r.AdvanceTailTo(4)
	if r.TailOutSeq() != 16 {
		t.Errorf("TailOutSeq after old ack: want 16 (no-op), got %d", r.TailOutSeq())
	}
}

func TestRingSeekReadRewindsToReplay(t *testing.T) {
	// Daemon crash → restart → FrameResume(from_seq) rewinds the ring
	// so un-acked bytes get re-emitted.
	r := NewRing(64)
	_, _ = r.Write([]byte("0123456789"))
	buf := make([]byte, 16)
	n, _, _ := r.DrainWithSeq(buf) // drains all 10, readOutSeq=10
	if n != 10 {
		t.Fatalf("first drain: n=%d", n)
	}
	// Daemon never acked. Simulate daemon restart resuming from seq 3.
	newRead, gap := r.SeekRead(3)
	if newRead != 3 || gap != 0 {
		t.Errorf("SeekRead(3) on still-resident bytes: want (3,0), got (%d,%d)", newRead, gap)
	}
	n2, first2, gap2 := r.DrainWithSeq(buf)
	if n2 != 7 || first2 != 3 || gap2 != 0 || string(buf[:n2]) != "3456789" {
		t.Errorf("post-rewind drain: n=%d first=%d gap=%d data=%q", n2, first2, gap2, buf[:n2])
	}
}

func TestRingSeekReadOlderThanTailReportsGap(t *testing.T) {
	r := NewRing(8)
	_, _ = r.Write([]byte("ABCDEFGH")) // head=8, tail=0
	_, _ = r.Write([]byte("123"))      // drops "ABC", head=11, tail=3
	// Daemon thinks it had bytes up through seq 1, asks to resume from
	// seq 2 — older than tail=3, so gap = 1.
	newRead, gap := r.SeekRead(2)
	if newRead != 3 {
		t.Errorf("SeekRead(2) clamped to tail=3: got %d", newRead)
	}
	if gap != 1 {
		t.Errorf("gapAdded: want 1, got %d", gap)
	}
	// gapBefore from the seek itself is reported via SeekRead's
	// return value (gapAdded=1); the post-seek DrainWithSeq should NOT
	// re-report it as gapBefore — that would double-count what the
	// caller already got from SeekRead.
	buf := make([]byte, 16)
	n, first, gapBefore := r.DrainWithSeq(buf)
	if n != 8 || first != 3 || gapBefore != 0 || string(buf[:n]) != "DEFGH123" {
		t.Errorf("post-seek drain: n=%d first=%d gap=%d data=%q", n, first, gapBefore, buf[:n])
	}
}

func TestRingSeekReadClearsPriorOverflowGap(t *testing.T) {
	// A prior overflow set gapPending; a new drainer arrives and
	// SeekReads — the seek defines a fresh starting point, so the
	// prior gap should be cleared, not delivered to the new drainer.
	r := NewRing(8)
	_, _ = r.Write([]byte("ABCDEFGH"))
	_, _ = r.Write([]byte("XYZ")) // drops "ABC" → 3 bytes of pre-existing gapPending
	// New drainer comes in fresh; resume from tail=3.
	newRead, gap := r.SeekRead(3)
	if newRead != 3 || gap != 0 {
		t.Errorf("SeekRead exactly at tail: want (3,0), got (%d,%d)", newRead, gap)
	}
	buf := make([]byte, 16)
	_, _, gapBefore := r.DrainWithSeq(buf)
	if gapBefore != 0 {
		t.Errorf("post-seek drain: stale gapPending should be cleared; got gap=%d", gapBefore)
	}
}

func TestRingOverflowAfterSeekPopulatesGap(t *testing.T) {
	// SeekRead clears gapPending; subsequent overflow that crosses the
	// new read cursor must still populate gapPending.
	r := NewRing(8)
	_, _ = r.Write([]byte("ABCDEFGH"))
	// Drainer arrives, seeks to seq 2.
	r.SeekRead(2)
	// Now write 4 more bytes — overflow drops "ABCD" (4 bytes from
	// seqs 0..3). Read cursor at 2 is below new tail 4 → gap = 2.
	_, _ = r.Write([]byte("WXYZ"))
	buf := make([]byte, 16)
	n, first, gap := r.DrainWithSeq(buf)
	if n != 8 || first != 4 || gap != 2 || string(buf[:n]) != "EFGHWXYZ" {
		t.Errorf("drain after post-seek overflow: n=%d first=%d gap=%d data=%q",
			n, first, gap, buf[:n])
	}
}

func TestRingConcurrentWriterDrainer(t *testing.T) {
	// One writer, one drainer, fixed total payload. The drainer
	// accumulates whatever it sees; the writer never blocks; we
	// assert that the drainer's view + the dropped count + leftover
	// in ring == the total bytes written.
	const cap = 1024
	const total = 64 * 1024
	r := NewRing(cap)

	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < total; i += 17 {
			end := i + 17
			if end > total {
				end = total
			}
			_, _ = r.Write(payload[i:end])
		}
	}()

	var drained int64
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		// Drain until writer is done. We don't know exactly when
		// that is, so use a simple loop that pulls until empty and
		// drains again after a brief wait.
		for {
			n := r.Drain(buf)
			if n > 0 {
				drained += int64(n)
				continue
			}
			select {
			case <-r.NotifyCh():
			default:
				// Empty — but maybe writer is done. Check size again.
				if r.Len() == 0 {
					// Writer may still be ahead; spin a bit more.
					// Use a fast check loop to avoid sleep in tests.
				}
			}
			// One last drain attempt + exit if writer is done.
			n = r.Drain(buf)
			if n > 0 {
				drained += int64(n)
				continue
			}
			// Heuristic: if Dropped + drained + Len == total, we're done.
			if uint64(drained)+r.Dropped()+uint64(r.Len()) == total {
				return
			}
		}
	}()

	wg.Wait()
	// Final drain of anything left.
	leftover := make([]byte, cap+1)
	n := r.Drain(leftover)
	drained += int64(n)
	if uint64(drained)+r.Dropped() != total {
		t.Errorf("accounting: drained=%d dropped=%d total=%d", drained, r.Dropped(), total)
	}
}
