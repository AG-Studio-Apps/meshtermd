package session

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestSearchEmptyBuffer(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	hits := r.Search(regexp.MustCompile("anything"), SearchOpts{})
	if hits != nil {
		t.Errorf("Search on empty buffer = %v, want nil", hits)
	}
}

func TestSearchNilPattern(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	_, _ = r.Write([]byte("hello\nworld\n"))
	if hits := r.Search(nil, SearchOpts{}); hits != nil {
		t.Errorf("Search with nil pattern = %v, want nil", hits)
	}
}

func TestSearchSingleMatchUnwrapped(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	_, _ = r.Write([]byte("line one\nline two has ERROR\nline three\n"))
	hits := r.Search(regexp.MustCompile("ERROR"), SearchOpts{})
	if len(hits) != 1 {
		t.Fatalf("Search hits = %d, want 1", len(hits))
	}
	h := hits[0]
	if h.Line != "line two has ERROR" {
		t.Errorf("Line = %q, want %q", h.Line, "line two has ERROR")
	}
	if h.LineNum != 1 {
		t.Errorf("LineNum = %d, want 1", h.LineNum)
	}
	if h.EndSeq-h.StartSeq != 5 {
		t.Errorf("Match span = %d bytes, want 5 (len(\"ERROR\"))", h.EndSeq-h.StartSeq)
	}
}

func TestSearchMultipleMatchesOrdered(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(128)
	_, _ = r.Write([]byte("first error here\nfine line\nsecond error here\nfine\nthird error\n"))
	hits := r.Search(regexp.MustCompile("error"), SearchOpts{})
	if len(hits) != 3 {
		t.Fatalf("hits = %d, want 3", len(hits))
	}
	wantLines := []string{"first error here", "second error here", "third error"}
	for i, h := range hits {
		if h.Line != wantLines[i] {
			t.Errorf("hit[%d].Line = %q, want %q", i, h.Line, wantLines[i])
		}
	}
	if hits[0].LineNum != 0 || hits[1].LineNum != 2 || hits[2].LineNum != 4 {
		t.Errorf("LineNums = %d/%d/%d, want 0/2/4",
			hits[0].LineNum, hits[1].LineNum, hits[2].LineNum)
	}
}

func TestSearchMaxMatchesCap(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(256)
	_, _ = r.Write([]byte(strings.Repeat("hit\n", 50)))
	hits := r.Search(regexp.MustCompile("hit"), SearchOpts{MaxMatches: 5})
	if len(hits) != 5 {
		t.Errorf("hits = %d, want 5 (capped)", len(hits))
	}
}

func TestSearchDefaultMaxApplied(t *testing.T) {
	t.Parallel()
	// MaxMatches=0 should use DefaultSearchMaxMatches (10000), not 0.
	r, _ := NewRingBuffer(4096)
	_, _ = r.Write([]byte(strings.Repeat("x\n", 100)))
	hits := r.Search(regexp.MustCompile("x"), SearchOpts{MaxMatches: 0})
	if len(hits) != 100 {
		t.Errorf("hits = %d, want 100 (default cap=10000 > 100)", len(hits))
	}
}

func TestSearchWrappedBuffer(t *testing.T) {
	t.Parallel()
	// Capacity 32; write 50 bytes so head wraps and tail advances.
	r, _ := NewRingBuffer(32)
	// 5 lines of 10 bytes each = 50 bytes; only the last 32 survive.
	_, _ = r.Write([]byte("ABCDE0001\nABCDE0002\nABCDE0003\nABCDE0004\nABCDE0005\n"))
	// Retained suffix is the last 32 bytes of that input.
	hits := r.Search(regexp.MustCompile("ABCDE"), SearchOpts{})
	if len(hits) == 0 {
		t.Fatalf("expected at least one hit in wrapped buffer, got none")
	}
	// Earliest retained match should not refer to line 0001 (lost).
	for _, h := range hits {
		if strings.Contains(h.Line, "0001") {
			t.Errorf("hit on lost line: %q", h.Line)
		}
	}
	// Seq numbers must point into the retained range.
	tail := r.TailSeq()
	head := r.HeadSeq()
	for i, h := range hits {
		if h.StartSeq < tail || h.EndSeq > head {
			t.Errorf("hit[%d] seq [%d,%d) outside retained [%d,%d)",
				i, h.StartSeq, h.EndSeq, tail, head)
		}
	}
}

func TestSearchMultilineFlag(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(128)
	_, _ = r.Write([]byte("apple banana\ncherry banana\ndate elderberry\n"))
	// Default ^/$ = start/end of input.
	plain := r.Search(regexp.MustCompile("^cherry"), SearchOpts{})
	if len(plain) != 0 {
		t.Errorf("plain ^cherry hits = %d, want 0 (no multiline)", len(plain))
	}
	// (?m) flag lets ^ match line starts.
	multi := r.Search(regexp.MustCompile("(?m)^cherry"), SearchOpts{})
	if len(multi) != 1 {
		t.Fatalf("(?m)^cherry hits = %d, want 1", len(multi))
	}
	if multi[0].Line != "cherry banana" {
		t.Errorf("(?m) hit line = %q, want %q", multi[0].Line, "cherry banana")
	}
}

func TestSearchNoNewlinesEverythingIsLineZero(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	_, _ = r.Write([]byte("one long line with hit somewhere in middle"))
	hits := r.Search(regexp.MustCompile("hit"), SearchOpts{})
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].LineNum != 0 {
		t.Errorf("LineNum = %d, want 0 (no newlines)", hits[0].LineNum)
	}
	if hits[0].Line != "one long line with hit somewhere in middle" {
		t.Errorf("Line = %q, want full content", hits[0].Line)
	}
}

func TestSearchMatchAtStart(t *testing.T) {
	t.Parallel()
	r, _ := NewRingBuffer(64)
	_, _ = r.Write([]byte("STARTHERE rest of line\n"))
	hits := r.Search(regexp.MustCompile("STARTHERE"), SearchOpts{})
	if len(hits) != 1 || hits[0].StartSeq != 0 {
		t.Errorf("hit at start: got %+v, want StartSeq=0", hits)
	}
}

func TestSearchSnapshotDoesNotBlockWriter(t *testing.T) {
	t.Parallel()
	// Establish that a concurrent Write completes while Search is
	// scanning (snapshot copies and releases the lock; the scan
	// runs unlocked).
	r, _ := NewRingBuffer(1 << 20) // 1 MiB
	_, _ = r.Write([]byte(strings.Repeat("hit\n", 10000)))
	var wg sync.WaitGroup
	wg.Add(2)
	var hits []SearchMatch
	go func() {
		defer wg.Done()
		hits = r.Search(regexp.MustCompile("hit"), SearchOpts{MaxMatches: 10000})
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_, _ = r.Write([]byte("more\n"))
		}
	}()
	wg.Wait()
	if len(hits) == 0 {
		t.Errorf("expected hits, got none")
	}
}

func TestIndexLineStarts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []int
	}{
		{"", []int{0}},
		{"abc", []int{0}},
		{"a\nb\nc", []int{0, 2, 4}},
		{"a\nb\n", []int{0, 2}}, // trailing newline doesn't start a new line
		{"\n\n\n", []int{0, 1, 2}},
	}
	for _, tc := range cases {
		got := indexLineStarts([]byte(tc.in))
		if len(got) != len(tc.want) {
			t.Errorf("indexLineStarts(%q) len = %d, want %d (%v vs %v)",
				tc.in, len(got), len(tc.want), got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("indexLineStarts(%q)[%d] = %d, want %d", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}
