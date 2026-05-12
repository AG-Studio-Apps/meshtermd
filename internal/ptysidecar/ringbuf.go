package ptysidecar

import (
	"sync"
	"sync/atomic"
)

// DefaultRingBytes is the default capacity of the per-sidecar drop-
// oldest output ring. 256 KiB covers ~30 seconds of typical shell
// chatter or several minutes of idle prompt; bumped via the daemon's
// --sidecar-ring-bytes (env MESHTERMD_SIDECAR_RING_BYTES) for output-
// heavy sessions.
const DefaultRingBytes = 256 * 1024

// Ring is a fixed-capacity FIFO of bytes addressed by a monotonic
// 64-bit byte counter. Writes never block: when the ring would
// overflow, the oldest still-resident bytes are silently dropped and
// `gapPending` records by how many. Drainers see the gap as a "trunc
// before next data" signal on the next DrainWithSeq.
//
// Three monotonic seq positions are maintained:
//   - headOutSeq: total bytes ever written (advances on Write)
//   - tailOutSeq: oldest byte still resident (advances on overflow + AdvanceTailTo)
//   - readOutSeq: next byte the drainer will see (advances on Drain* / SeekRead)
//
// Invariants:
//
//	tailOutSeq ≤ readOutSeq ≤ headOutSeq
//	(headOutSeq − tailOutSeq) ≤ Cap() at all times
//
// Concurrency: safe for one writer (the PTY-master reader) plus one
// drainer (the per-attached-client pump). AdvanceTailTo may be called
// from a third goroutine (the daemon-ack reader); every operation
// takes the lock for its full duration.
type Ring struct {
	mu sync.Mutex

	buf      []byte // backing slice; len == capacity; never grows
	writeIdx int    // physical index where the NEXT byte will be written

	headOutSeq uint64 // total bytes ever written
	tailOutSeq uint64 // oldest byte still resident
	readOutSeq uint64 // next byte the drainer will receive

	// gapPending counts bytes that were dropped via overflow AND that
	// the drainer hadn't yet seen (i.e. drops that crossed the read
	// cursor). Cleared when DrainWithSeq reports it back to the caller.
	gapPending uint64

	droppedCum atomic.Uint64 // lifetime cumulative drops (for logging)

	notify chan struct{} // cap 1; edge-triggered wakeup
}

// NewRing constructs a ring with capacity `cap` bytes. Capacity ≤ 0
// falls back to DefaultRingBytes.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = DefaultRingBytes
	}
	return &Ring{
		buf:    make([]byte, capacity),
		notify: make(chan struct{}, 1),
	}
}

// Cap returns the ring's fixed capacity in bytes.
func (r *Ring) Cap() int { return len(r.buf) }

// Len returns the number of bytes currently resident.
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int(r.headOutSeq - r.tailOutSeq)
}

// HeadOutSeq returns the seq just past the newest byte ever written.
func (r *Ring) HeadOutSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.headOutSeq
}

// TailOutSeq returns the seq of the oldest still-resident byte (or
// HeadOutSeq when the ring is empty).
func (r *Ring) TailOutSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tailOutSeq
}

// ReadOutSeq returns the seq of the next byte the drainer will see.
func (r *Ring) ReadOutSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.readOutSeq
}

// Dropped returns the lifetime cumulative count of bytes dropped via
// overflow. Logged on detach as a debugging aid.
func (r *Ring) Dropped() uint64 { return r.droppedCum.Load() }

// NotifyCh returns the wakeup channel. Drained by exactly one consumer
// goroutine that should call DrainWithSeq (or Drain) in response and
// loop back to re-select on this channel.
func (r *Ring) NotifyCh() <-chan struct{} { return r.notify }

// Write appends p to the ring. If p combined with the resident bytes
// exceeds capacity, the oldest bytes are silently dropped. Always
// returns (len(p), nil).
func (r *Ring) Write(p []byte) (int, error) {
	total := len(p)
	if total == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	capn := len(r.buf)

	// Case 1: chunk is larger than capacity. Drop everything resident
	// plus the chunk's overflow prefix; keep only the chunk's last
	// `cap` bytes.
	if total >= capn {
		resident := r.headOutSeq - r.tailOutSeq
		dropPrefix := uint64(total - capn)
		r.droppedCum.Add(resident + dropPrefix)
		newTail := r.headOutSeq + dropPrefix
		if newTail > r.readOutSeq {
			r.gapPending += newTail - r.readOutSeq
			r.readOutSeq = newTail
		}
		copy(r.buf, p[dropPrefix:])
		r.writeIdx = 0
		r.tailOutSeq = newTail
		r.headOutSeq = newTail + uint64(capn)
		r.signal()
		return total, nil
	}

	// Case 2: chunk fits in capacity but may force the oldest bytes
	// out to make room.
	resident := int(r.headOutSeq - r.tailOutSeq)
	if resident+total > capn {
		drop := uint64(resident + total - capn)
		r.droppedCum.Add(drop)
		newTail := r.tailOutSeq + drop
		if newTail > r.readOutSeq {
			r.gapPending += newTail - r.readOutSeq
			r.readOutSeq = newTail
		}
		r.tailOutSeq = newTail
	}

	// Copy p into the ring at writeIdx, wrapping if needed.
	if r.writeIdx+total <= capn {
		copy(r.buf[r.writeIdx:], p)
	} else {
		first := capn - r.writeIdx
		copy(r.buf[r.writeIdx:], p[:first])
		copy(r.buf[0:], p[first:])
	}
	r.writeIdx = (r.writeIdx + total) % capn
	r.headOutSeq += uint64(total)
	r.signal()
	return total, nil
}

// Drain is the legacy drain-and-ack convenience: copies up to
// len(into) bytes from the current read cursor, advances readOutSeq,
// AND advances tailOutSeq to match. Bytes copied out are immediately
// reclaimable. Gap-pending events are silently consumed.
//
// New code should prefer DrainWithSeq + explicit AdvanceTailTo so the
// daemon-side ack flow can preserve un-acked bytes for replay across
// daemon restarts.
func (r *Ring) Drain(into []byte) int {
	if len(into) == 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	avail := r.headOutSeq - r.readOutSeq
	if avail == 0 {
		return 0
	}
	nu := uint64(len(into))
	if nu > avail {
		nu = avail
	}
	r.copyOutLocked(into[:nu], r.readOutSeq)
	r.readOutSeq += nu
	r.tailOutSeq = r.readOutSeq
	r.gapPending = 0
	return int(nu)
}

// DrainWithSeq copies up to len(into) bytes from the current read
// cursor into `into`. Returns:
//
//	n         — bytes copied (0 when no new data is available)
//	firstSeq  — seq of the first byte copied (or current read cursor
//	            when n == 0)
//	gapBefore — bytes silently dropped before firstSeq that the
//	            drainer hadn't yet seen. Non-zero only when the ring
//	            overflowed past the read cursor since the previous
//	            DrainWithSeq.
//
// readOutSeq advances by n; tailOutSeq does NOT advance. Un-acked
// bytes remain in the ring (subject to overflow) until the caller
// acks them via AdvanceTailTo.
func (r *Ring) DrainWithSeq(into []byte) (n int, firstSeq uint64, gapBefore uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	gapBefore = r.gapPending
	r.gapPending = 0
	firstSeq = r.readOutSeq

	avail := r.headOutSeq - r.readOutSeq
	if avail == 0 || len(into) == 0 {
		return 0, firstSeq, gapBefore
	}
	nu := uint64(len(into))
	if nu > avail {
		nu = avail
	}
	r.copyOutLocked(into[:nu], r.readOutSeq)
	r.readOutSeq += nu
	return int(nu), firstSeq, gapBefore
}

// SeekRead repositions readOutSeq to `to`. Used on daemon reattach
// to honour a FrameResume(from_seq) without re-acking bytes the
// daemon already persisted before the crash.
//
// If `to` is older than tailOutSeq, readOutSeq is clamped at
// tailOutSeq and the gap (tailOutSeq − to) is returned in `gapAdded`
// so the caller can signal Trunc on the very first frame. If `to` is
// newer than headOutSeq the cursor is clamped at headOutSeq (drainer
// will get empty drains until more data arrives).
//
// gapPending is RESET — the seek defines a fresh "starting point" for
// the new drainer; any prior overflow gap was the previous drainer's
// concern. Post-seek overflows still populate gapPending normally.
func (r *Ring) SeekRead(to uint64) (newReadSeq, gapAdded uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if to < r.tailOutSeq {
		gapAdded = r.tailOutSeq - to
		to = r.tailOutSeq
	}
	if to > r.headOutSeq {
		to = r.headOutSeq
	}
	r.readOutSeq = to
	r.gapPending = 0
	return to, gapAdded
}

// AdvanceTailTo frees bytes with seq < `to`. No-op if `to` is older
// than the current tailOutSeq. Clamped at readOutSeq — we never free
// bytes the drainer hasn't yet seen, since those still need to be
// deliverable on a reattach.
func (r *Ring) AdvanceTailTo(to uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if to <= r.tailOutSeq {
		return
	}
	if to > r.readOutSeq {
		to = r.readOutSeq
	}
	r.tailOutSeq = to
}

// copyOutLocked copies `len(into)` bytes starting at seq `from` into
// `into`, wrapping the physical buffer as needed. Caller must hold
// r.mu and must have verified the requested span is fully resident
// (from ≥ tailOutSeq and from + len(into) ≤ headOutSeq).
func (r *Ring) copyOutLocked(into []byte, from uint64) {
	capn := len(r.buf)
	resident := int(r.headOutSeq - r.tailOutSeq)
	tailIdx := r.writeIdx - resident
	if tailIdx < 0 {
		tailIdx += capn
	}
	offset := int(from - r.tailOutSeq)
	startIdx := (tailIdx + offset) % capn
	if startIdx+len(into) <= capn {
		copy(into, r.buf[startIdx:startIdx+len(into)])
		return
	}
	first := capn - startIdx
	copy(into, r.buf[startIdx:])
	copy(into[first:], r.buf[:len(into)-first])
}

// signal wakes a parked drainer. Called with r.mu held; the select
// is non-blocking so the channel is edge-triggered — at most one
// pending notification is queued.
func (r *Ring) signal() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}
