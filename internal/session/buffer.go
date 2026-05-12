// Package session owns the per-session state for meshtermd: the output
// ring buffer, the Session value, and the concurrent registry.
//
// The ring buffer is the load-bearing piece for replay-on-reattach.
// When a client disconnects (network drop, app background, foreground
// roam), the daemon keeps writing PTY output into the buffer. On
// reattach, the client passes its last-acked sequence number and the
// buffer replays from there. If the disconnect was long enough that
// the buffer overflowed, replay starts from the buffer's tail and the
// AttachAck reports `trunc = true` so the client can render a
// "[…some output lost…]" indicator.
package session

import (
	"context"
	"errors"
	"sync"
)

// DefaultBufferCapacity is the per-session output ring buffer size when
// none is specified. 4 MiB comfortably holds ~30 seconds of even a
// fast-scrolling build log; longer disconnects truncate gracefully.
const DefaultBufferCapacity = 4 * 1024 * 1024

// ErrInvalidCapacity is returned by NewRingBuffer when capacity ≤ 0.
var ErrInvalidCapacity = errors.New("ring buffer capacity must be positive")

// RingBuffer is a fixed-capacity FIFO of bytes addressed by monotonic
// sequence numbers. Sequence numbers count bytes, not frames — if seq
// 100 covers the byte 'A', seq 101 covers the next byte. This matches
// the protocol's wire framing.
//
// All exported methods are safe for concurrent use. The expected
// access pattern is one writer (the PTY-reading goroutine) and one
// reader (the Stdout-stream-writing goroutine), but the lock is a
// plain Mutex so any pattern works.
type RingBuffer struct {
	mu sync.Mutex

	// buf is the storage. Its length is the capacity; it never grows.
	buf []byte

	// writePos is the next index in buf to write at, in [0, len(buf)).
	writePos int

	// headSeq is the seq of the next byte that will be written.
	// Equivalently: the count of all bytes ever written.
	headSeq uint64

	// full is true once the buffer has filled at least once. Until
	// then writePos doubles as both the write head and "bytes used".
	full bool

	// notify is closed every time Write advances headSeq; a fresh
	// chan is allocated immediately afterwards. WaitForData reads
	// the chan under the lock, then waits on it without holding the
	// lock — coupling with sync.Cond was clunkier (Cond doesn't
	// integrate with select/ctx).
	notify chan struct{}
}

// NewRingBuffer allocates a buffer of the given capacity in bytes.
// Returns ErrInvalidCapacity if capacity ≤ 0.
func NewRingBuffer(capacity int) (*RingBuffer, error) {
	if capacity <= 0 {
		return nil, ErrInvalidCapacity
	}
	return &RingBuffer{
		buf:    make([]byte, capacity),
		notify: make(chan struct{}),
	}, nil
}

// Capacity returns the buffer's fixed size in bytes.
func (r *RingBuffer) Capacity() int {
	return len(r.buf)
}

// HeadSeq returns the sequence number of the next byte that will be
// written. Equivalently, the total bytes ever written to the buffer.
func (r *RingBuffer) HeadSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.headSeq
}

// TailSeq returns the sequence number of the oldest byte currently
// retained. Until the buffer wraps, TailSeq is 0 (or HeadSeq if
// nothing has been written). After wrap, TailSeq = HeadSeq − capacity.
func (r *RingBuffer) TailSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tailSeqLocked()
}

func (r *RingBuffer) tailSeqLocked() uint64 {
	if !r.full {
		return 0
	}
	return r.headSeq - uint64(len(r.buf))
}

// Write appends p to the buffer. If len(p) > capacity, only the last
// `capacity` bytes of p are retained — the earlier portion is dropped
// without ever being readable. headSeq advances by len(p) regardless,
// so a future ReadSince knows how much was lost.
//
// Write never returns an error or short write; the io.Writer signature
// is preserved purely for compatibility with io.MultiWriter and
// io.Copy use cases.
func (r *RingBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	total := len(p)
	cap := len(r.buf)

	// If p is bigger than capacity, only the tail of p is useful;
	// drop everything before that.
	if total > cap {
		p = p[total-cap:]
	}

	for len(p) > 0 {
		// How many bytes can we write before wrapping the underlying
		// array?
		room := cap - r.writePos
		if room > len(p) {
			room = len(p)
		}
		copy(r.buf[r.writePos:r.writePos+room], p[:room])
		r.writePos += room
		if r.writePos == cap {
			r.writePos = 0
			r.full = true
		}
		p = p[room:]
	}

	r.headSeq += uint64(total)

	// Wake any waiting readers.
	if total > 0 {
		old := r.notify
		r.notify = make(chan struct{})
		close(old)
	}
	return total, nil
}

// WaitForData blocks until HeadSeq advances past `seenSeq` or ctx is
// cancelled. Returns the current HeadSeq on advance (always >
// seenSeq); on ctx cancel returns the current HeadSeq + ctx.Err().
//
// Used by the Stdout-stream pump: after sending all available bytes
// since seenSeq, it waits here for the next chunk to arrive instead
// of polling.
func (r *RingBuffer) WaitForData(ctx context.Context, seenSeq uint64) (uint64, error) {
	r.mu.Lock()
	if r.headSeq > seenSeq {
		head := r.headSeq
		r.mu.Unlock()
		return head, nil
	}
	ch := r.notify
	r.mu.Unlock()

	select {
	case <-ch:
		// Another writer advanced head — re-read it; we don't
		// guarantee we're "the" awakened reader, just that head
		// has advanced past seenSeq for at least one writer.
		r.mu.Lock()
		head := r.headSeq
		r.mu.Unlock()
		if head <= seenSeq {
			// Edge case: a Write with len(p) == 0 closed the chan
			// without advancing seq. Re-arm.
			return r.WaitForData(ctx, seenSeq)
		}
		return head, nil
	case <-ctx.Done():
		r.mu.Lock()
		head := r.headSeq
		r.mu.Unlock()
		return head, ctx.Err()
	}
}

// Snapshot returns the raw underlying buffer (a fresh copy, safe to
// retain across subsequent writes), the current writePos, the
// monotonic headSeq, and the `full` flag. Used by the persistence
// layer to checkpoint a session's scrollback to disk: combined with
// the buffer capacity (Capacity()) these four values fully describe
// the FIFO's state, so RestoreFromSnapshot reconstructs an identical
// buffer.
//
// The copy is intentional — callers serialise on background goroutines
// and the buffer keeps mutating in parallel. 4 MiB at 30 s flush
// intervals is ~140 KB/s of allocation churn per heavily-active
// session; well within GC budget.
func (r *RingBuffer) Snapshot() (buf []byte, writePos int, headSeq uint64, full bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out, r.writePos, r.headSeq, r.full
}

// AdvanceWithGap advances headSeq by n without writing any payload
// bytes — used when the sidecar reports a Trunc-before-frame to
// indicate bytes were silently dropped between drains. The slots
// that conceptually represent the lost span are zeroed so a future
// ReadSince in that range doesn't surface stale data; the wrapped
// tail (when full) advances naturally past the gap.
//
// n == 0 is a no-op. n >= Capacity() rotates the whole ring to a
// "fresh gap" state. WaitForData is woken so consumers stop waiting
// for a head that has now advanced.
func (r *RingBuffer) AdvanceWithGap(n uint64) {
	if n == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	capn := len(r.buf)
	if n >= uint64(capn) {
		clear(r.buf)
		r.writePos = 0
		r.full = true
		r.headSeq += n
	} else {
		remaining := int(n)
		pos := r.writePos
		for remaining > 0 {
			room := capn - pos
			if room > remaining {
				room = remaining
			}
			clear(r.buf[pos : pos+room])
			pos += room
			if pos == capn {
				pos = 0
				r.full = true
			}
			remaining -= room
		}
		r.writePos = pos
		r.headSeq += n
	}
	old := r.notify
	r.notify = make(chan struct{})
	close(old)
}

// RestoreFromSnapshot rebuilds the buffer's FIFO state from a prior
// Snapshot. The byte slice must be exactly Capacity() long — same as
// the buffer was allocated with — otherwise the geometry assertions
// in subsequent ReadSince calls would be wrong. Returns
// ErrInvalidCapacity on mismatch.
//
// Resets the notify channel since waiters from a prior life have no
// reason to fire — fresh waiters arm on the new chan.
func (r *RingBuffer) RestoreFromSnapshot(buf []byte, writePos int, headSeq uint64, full bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(buf) != len(r.buf) {
		return ErrInvalidCapacity
	}
	if writePos < 0 || writePos >= len(r.buf) {
		return ErrInvalidCapacity
	}
	copy(r.buf, buf)
	r.writePos = writePos
	r.headSeq = headSeq
	r.full = full
	r.notify = make(chan struct{})
	return nil
}

// ReadSince returns the bytes from `fromSeq` onward, up to maxBytes.
// The returned slice is a fresh copy and may be retained by the caller
// after subsequent Writes.
//
//   - data is the byte slice; may be empty if fromSeq == HeadSeq.
//   - newSeq is fromSeq + len(data); the seq the next ReadSince should
//     pass to continue.
//   - truncated is true when fromSeq was older than TailSeq, meaning
//     some bytes between fromSeq and the returned data's start are
//     lost forever. The data slice in that case starts at TailSeq.
//
// maxBytes ≤ 0 means "as much as is available".
func (r *RingBuffer) ReadSince(fromSeq uint64, maxBytes int) (data []byte, newSeq uint64, truncated bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tail := r.tailSeqLocked()
	head := r.headSeq

	// Caller has already seen everything we have.
	if fromSeq >= head {
		return nil, fromSeq, false
	}

	startSeq := fromSeq
	if startSeq < tail {
		startSeq = tail
		truncated = true
	}

	avail := head - startSeq
	if maxBytes > 0 && uint64(maxBytes) < avail {
		avail = uint64(maxBytes)
	}
	if avail == 0 {
		return nil, startSeq, truncated
	}

	cap := len(r.buf)
	// Compute the index in buf where startSeq lives. The byte at
	// startSeq is at offset (startSeq - tail) into the live data; the
	// live data starts at writePos when full, or at 0 when not.
	var dataStart int
	if r.full {
		dataStart = r.writePos
	} else {
		dataStart = 0
	}
	startIdx := (dataStart + int(startSeq-tail)) % cap

	out := make([]byte, avail)
	if startIdx+int(avail) <= cap {
		copy(out, r.buf[startIdx:startIdx+int(avail)])
	} else {
		first := cap - startIdx
		copy(out[:first], r.buf[startIdx:])
		copy(out[first:], r.buf[:int(avail)-first])
	}

	return out, startSeq + avail, truncated
}
