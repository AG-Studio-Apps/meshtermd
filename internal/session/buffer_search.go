package session

import (
	"regexp"
	"sort"
)

// DefaultSearchMaxMatches caps Search results when the caller passes
// MaxMatches=0. 10,000 is generous enough for any interactive grep
// over a 4 MiB ring (≈ 60,000 lines at 70 cols), tight enough to
// prevent a pathological pattern from allocating an unbounded slice.
const DefaultSearchMaxMatches = 10_000

// SearchOpts controls RingBuffer.Search behaviour.
type SearchOpts struct {
	// MaxMatches caps the number of returned matches. 0 = use
	// DefaultSearchMaxMatches.
	MaxMatches int
}

// SearchMatch is one regex match in the ring buffer. Byte offsets are
// in the buffer's monotonic seq space so callers can ReadSince() the
// surrounding context if they want more than the immediate line.
type SearchMatch struct {
	// StartSeq is the monotonic seq of the first matched byte.
	StartSeq uint64
	// EndSeq is the monotonic seq one past the last matched byte.
	EndSeq uint64
	// Line is the full line containing the match, with trailing
	// newline stripped. If the match spans a newline, Line is the
	// line containing the match's starting byte.
	Line string
	// LineNum is the 0-based line index within the retained
	// scrollback. Not absolute across session history — the ring
	// can't know lines that have aged out.
	LineNum int
}

// Search walks the retained scrollback for pattern matches and returns
// line-level hits. Snapshots once under the lock, then scans the
// linearised copy without holding it so writes are unimpeded.
//
// Anchors (^ and $) follow Go's regexp/RE2 semantics: by default they
// match start-of-input / end-of-input. Use the (?m) flag in the pattern
// for line-wise anchors. The truncated start of the ring is NOT treated
// as ^; the buffer's first retained byte may be mid-line.
//
// Returns nil if pattern is nil, the buffer is empty, or no matches are
// found.
func (r *RingBuffer) Search(pattern *regexp.Regexp, opts SearchOpts) []SearchMatch {
	if pattern == nil {
		return nil
	}
	data, tailSeq := r.snapshotLinear()
	if len(data) == 0 {
		return nil
	}

	cap := opts.MaxMatches
	if cap <= 0 {
		cap = DefaultSearchMaxMatches
	}

	hits := pattern.FindAllIndex(data, cap)
	if len(hits) == 0 {
		return nil
	}

	lineStarts := indexLineStarts(data)

	out := make([]SearchMatch, 0, len(hits))
	for _, h := range hits {
		start, end := h[0], h[1]
		lineNum := sort.SearchInts(lineStarts, start)
		if lineNum >= len(lineStarts) || lineStarts[lineNum] > start {
			lineNum--
		}
		lineStart := lineStarts[lineNum]
		lineEnd := len(data)
		for j := lineStart; j < len(data); j++ {
			if data[j] == '\n' {
				lineEnd = j
				break
			}
		}
		out = append(out, SearchMatch{
			StartSeq: tailSeq + uint64(start),
			EndSeq:   tailSeq + uint64(end),
			Line:     string(data[lineStart:lineEnd]),
			LineNum:  lineNum,
		})
	}
	return out
}

// snapshotLinear copies the retained bytes into a single contiguous
// slice in temporal order (oldest first). Returns the slice plus the
// seq of its first byte. Held lock window is bounded by one Cap-sized
// allocation + two memcpys; the regex scan runs unlocked.
func (r *RingBuffer) snapshotLinear() (data []byte, tailSeq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	capn := len(r.buf)
	if !r.full {
		out := make([]byte, r.writePos)
		copy(out, r.buf[:r.writePos])
		return out, 0
	}
	out := make([]byte, capn)
	n := copy(out, r.buf[r.writePos:])
	copy(out[n:], r.buf[:r.writePos])
	return out, r.headSeq - uint64(capn)
}

// indexLineStarts returns the byte offset of each line's first byte
// in data. Line 0 always starts at offset 0; subsequent entries are
// the offsets immediately after each '\n'.
func indexLineStarts(data []byte) []int {
	starts := make([]int, 1, 1+len(data)/40) // amortise; ~40-byte lines
	starts[0] = 0
	for i, b := range data {
		if b == '\n' && i+1 < len(data) {
			starts = append(starts, i+1)
		}
	}
	return starts
}
