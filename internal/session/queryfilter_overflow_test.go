package session

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// These tests cover the maxPending overflow guard added for finding F3:
// an unterminated CSI/OSC escape must not grow q.pending without bound
// (daemon OOM), and on overflow the parked tail must be DROPPED — never
// flushed and never discriminated — so the client can never reassemble a
// stripped query and auto-respond.

// streamCheckingPending feeds `data` through Process in fixed-size
// chunks, mimicking the daemon's Pump loop, and asserts the pending
// buffer never exceeds maxPending after any read. Returns the
// concatenated output and the largest pending size observed.
func streamCheckingPending(t *testing.T, f *QueryFilter, data []byte, chunkSize int) (out []byte, maxObserved int) {
	t.Helper()
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		out = append(out, f.Process(data[i:end])...)
		if len(f.pending) > maxPending {
			t.Fatalf("pending exceeded maxPending: %d > %d after read at offset %d",
				len(f.pending), maxPending, i)
		}
		if len(f.pending) > maxObserved {
			maxObserved = len(f.pending)
		}
	}
	return out, maxObserved
}

// (a) An unterminated CSI streamed across many reads keeps pending
// bounded by maxPending — it never grows without limit.
func TestQueryFilterUnterminatedCSIBoundsPending(t *testing.T) {
	// `\x1b[` followed by params that never reach a final byte.
	data := []byte("\x1b[" + strings.Repeat("1;", maxPending)) // > maxPending, no final
	f := NewQueryFilter(nil)
	_, maxObserved := streamCheckingPending(t, f, data, 500)
	if maxObserved == 0 {
		t.Fatal("expected the filter to buffer the partial CSI at least once")
	}
	if len(f.pending) > maxPending {
		t.Fatalf("pending left over cap at end: %d", len(f.pending))
	}
}

// (a) Same, for an unterminated OSC.
func TestQueryFilterUnterminatedOSCBoundsPending(t *testing.T) {
	data := []byte("\x1b]4;" + strings.Repeat("0;", maxPending)) // > maxPending, no terminator
	f := NewQueryFilter(nil)
	_, maxObserved := streamCheckingPending(t, f, data, 500)
	if maxObserved == 0 {
		t.Fatal("expected the filter to buffer the partial OSC at least once")
	}
	if len(f.pending) > maxPending {
		t.Fatalf("pending left over cap at end: %d", len(f.pending))
	}
}

// (b) An oversized CSI — including the ANSI DECRQM `$p` variant, split
// mid-params across the 8 KiB read boundary — is DROPPED: the query
// never appears in the output and no ESC introducer leaks to the client.
func TestQueryFilterOversizedCSIDropped(t *testing.T) {
	// ANSI DECRQM `\x1b[<n>$p`, but with a pathologically long param run
	// that overflows the cap before the `$p` final arrives.
	query := []byte("\x1b[" + strings.Repeat("1;", maxPending) + "$p") // params exceed the cap before `$p`
	f := NewQueryFilter(&bytes.Buffer{})
	// 8192-byte reads reproduce the daemon's Pump buffer: the overflow
	// (and drop) happens on read 1, before `$p` arrives on read 2.
	out, _ := streamCheckingPending(t, f, query, 8192)

	if bytes.IndexByte(out, 0x1B) != -1 {
		t.Errorf("ESC introducer leaked to the client: %q", clip(out))
	}
	if bytes.Contains(out, query) {
		t.Error("the oversized CSI query was flushed to the output instead of dropped")
	}
	if len(f.pending) != 0 {
		t.Errorf("pending should be clear after the dropped sequence, got %d bytes", len(f.pending))
	}
}

// (c) An oversized OSC 4 whose `?` query marker arrives in a LATER read,
// AFTER the cap is exceeded — the exact case that defeated the prior
// prefix-scanning fix — is DROPPED. The client-visible output contains
// no reassemblable escape, so it can never reconstruct the palette query
// and auto-respond.
func TestQueryFilterOversizedOSCLateQueryMarkerDropped(t *testing.T) {
	var b strings.Builder
	b.WriteString("\x1b]4;")
	// A long run of palette SET pairs (no `?`), enough to blow past the
	// maxPending cap so the overflow/drop happens before the `?` arrives...
	for i := 0; b.Len() <= maxPending; i++ {
		fmt.Fprintf(&b, "%d;rgb:0000/0000/0000;", i%256)
	}
	// ...then the query marker, deliberately placed at the very end so it
	// lands in a read AFTER the overflow/drop has happened.
	b.WriteString("0;?\x07")
	query := []byte(b.String())

	// Sanity: confirm the `?` really does arrive after the cap is exceeded,
	// i.e. this test actually exercises the late-marker scenario.
	if qi := bytes.IndexByte(query, '?'); qi < maxPending {
		t.Fatalf("test setup: `?` at %d must be past the %d-byte cap", qi, maxPending)
	}

	f := NewQueryFilter(&bytes.Buffer{})
	out, _ := streamCheckingPending(t, f, query, 8192)

	// The emitted bytes must not reconstruct the escape: with the
	// `\x1b]` introducer dropped, the trailing `0;?\x07` bytes are inert
	// passthrough text the client cannot interpret as an OSC query.
	if bytes.IndexByte(out, 0x1B) != -1 {
		t.Errorf("ESC introducer leaked — client could reassemble the OSC query: %q", clip(out))
	}
	if bytes.Contains(out, []byte("\x1b]")) {
		t.Error("an OSC introducer reached the output")
	}
	if bytes.Contains(out, query) {
		t.Error("the oversized OSC query was flushed to the output instead of dropped")
	}
	if len(f.pending) != 0 {
		t.Errorf("pending should be clear after the dropped sequence, got %d bytes", len(f.pending))
	}
}

// (d) A legitimate short query is still stripped byte-identically and
// still answered — the refactor through parkPending changes nothing on
// the normal path.
func TestQueryFilterShortQueryStillStripped(t *testing.T) {
	pty := &bytes.Buffer{}
	f := NewQueryFilter(pty)
	if got := string(f.Process([]byte("A\x1b[cB"))); got != "AB" {
		t.Errorf("DA query not stripped byte-identically: got %q", got)
	}
	if pty.String() != daPrimaryResponse {
		t.Errorf("DA response not written: got %q", pty.String())
	}
	f2 := NewQueryFilter(nil)
	if got := string(f2.Process([]byte("X\x1b]10;?\x07Y"))); got != "XY" {
		t.Errorf("OSC colour query not stripped: got %q", got)
	}
}

// (e) A legitimate OSC that straddles reads but stays UNDER the cap is
// buffered and processed exactly as before: a SET passes through
// byte-identically, a query is stripped.
func TestQueryFilterSubCapStraddleUnchanged(t *testing.T) {
	// ~1 KiB OSC 4 SET (no `?`), well under maxPending, split mid-pairs.
	var b strings.Builder
	b.WriteString("\x1b]4;")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "%d;rgb:1111/2222/3333;", i)
	}
	b.WriteString("\x07")
	set := []byte(b.String())
	if len(set) > maxPending {
		t.Fatalf("test setup: SET (%d) must stay under the cap (%d)", len(set), maxPending)
	}

	f := NewQueryFilter(nil)
	out, maxObserved := streamCheckingPending(t, f, set, 128)
	if !bytes.Equal(out, set) {
		t.Errorf("sub-cap OSC SET not passed through byte-identically:\n got  %q\n want %q",
			clip(out), clip(set))
	}
	if maxObserved == 0 {
		t.Fatal("expected the SET to be buffered while straddling reads")
	}

	// And a straddling query under the cap is still stripped.
	fq := NewQueryFilter(nil)
	out1 := fq.Process([]byte("Z\x1b]11;"))
	out2 := fq.Process([]byte("?\x07W"))
	if got := string(out1) + string(out2); got != "ZW" {
		t.Errorf("sub-cap OSC query straddling reads not stripped: got %q", got)
	}
}

// (f) No overflow path aliases the caller's buffer: under the cap
// parkPending stores a COPY (immune to the caller reusing its buffer),
// and on overflow it drops to nil so it retains nothing at all.
func TestParkPendingCopiesUnderCapAndDropsOnOverflow(t *testing.T) {
	f := NewQueryFilter(nil)

	// Under the cap: a COPY, not a slice of the caller's buffer.
	tail := []byte("\x1b[12;34")
	f.parkPending(tail)
	for i := range tail { // caller reuses/overwrites its read buffer
		tail[i] = 'Z'
	}
	if got := string(f.pending); got != "\x1b[12;34" {
		t.Fatalf("parkPending aliased the caller buffer: pending=%q", got)
	}

	// Exactly maxPending is still parked (boundary is inclusive).
	f.parkPending(make([]byte, maxPending))
	if len(f.pending) != maxPending {
		t.Fatalf("a tail of exactly maxPending must be parked, got %d", len(f.pending))
	}

	// Over the cap: dropped to nil — nothing retained, nothing to alias.
	f.parkPending(make([]byte, maxPending+1))
	if f.pending != nil {
		t.Fatalf("overflow must drop the tail to nil, got %d bytes", len(f.pending))
	}
}

// clip trims noisy byte dumps in failure messages.
func clip(b []byte) []byte {
	if len(b) > 64 {
		return b[:64]
	}
	return b
}
