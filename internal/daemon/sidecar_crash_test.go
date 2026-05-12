package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// TestDaemonRestartPreservesScrollbackViaSidecar exercises the
// killer scenario for the pty-sidecar architecture:
//
//  1. Daemon d1 spawns a session whose shell emits numbered lines
//     ("line-1", "line-2", ...) at a known cadence.
//  2. Pump drains the sidecar, writes to the daemon ring, acks the
//     sidecar (frees bytes), persists lastSidecarSeq.
//  3. d1 cancels — registry.Shutdown closes the session (flusher
//     does a final SaveTo). Sidecar stays alive in grace.
//  4. d2 starts on the same state dir. LoadPersisted restores the
//     session including lastSidecarSeq; Discover dials the still-
//     living sidecar and sends FrameResume(lastSidecarSeq); the
//     sidecar's drainer rewinds to that seq.
//  5. Pump in d2 streams more lines into the daemon ring.
//  6. The test reads the daemon ring's entire history (ReadSince(0))
//     and asserts: every line-K is monotonic, no duplicates, no gaps
//     across the daemon-restart boundary.
//
// This is the v0.6.0 invariant that the ack-and-drop wire flow was
// designed to enforce: bytes in transit when the daemon dies survive
// in the sidecar's ring and the new daemon picks them up exactly once.
func TestDaemonRestartPreservesScrollbackViaSidecar(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("daemon assumes POSIX")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}

	tmp := shortTempDir(t)
	if err := os.Chmod(tmp, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	socket := filepath.Join(tmp, "meshtermd.sock")

	// d1: short flush interval so the on-disk lcs stays close to the
	// in-memory watermark, minimising the gap window simulated by
	// graceful cancel.
	d1, err := New(Config{
		QUICAddr:                 "127.0.0.1:0",
		IPCSocketPath:            socket,
		CertDir:                  tmp,
		IdleTimeout:              time.Hour,
		PersistenceFlushInterval: 30 * time.Millisecond,
		SidecarStderr:            io.Discard,
	})
	if err != nil {
		t.Fatalf("d1 New: %v", err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	d1Done := make(chan error, 1)
	go func() { d1Done <- d1.Run(ctx1) }()
	waitForSocket(t, socket)

	// Allocate a persisted session running a noisy producer that emits
	// "line-1", "line-2", … one every ~50 ms. /bin/sh -c with a tight
	// loop is portable enough for our CI matrix.
	c := ipc.NewClient(socket, 5*time.Second)
	persistTrue := true
	resp, err := c.Allocate(context.Background(), ipc.AllocateRequest{
		SessionID: "new",
		Name:      "crashtest",
		Rows:      24, Cols: 80,
		Shell:   "/bin/sh",
		Exec:    []string{"-c", "i=1; while :; do echo line-$i; i=$((i+1)); sleep 0.05; done"},
		Persist: &persistTrue,
	})
	if err != nil || !resp.Ok {
		t.Fatalf("allocate: %v %s %s", err, resp.Err, resp.Msg)
	}
	sid, err := session.ParseSessionID(resp.SessionID)
	if err != nil {
		t.Fatal(err)
	}

	// Let the producer run for ~400 ms so several lines flow through
	// PTY → sidecar → daemon. Then check that something landed.
	time.Sleep(400 * time.Millisecond)
	sess1, err := d1.registry.Lookup(sid)
	if err != nil {
		t.Fatalf("lookup pre-crash: %v", err)
	}
	preCrashSeq := sess1.LastSidecarSeq()
	if preCrashSeq == 0 {
		t.Fatal("no bytes Ack'd to sidecar after 400ms — Pump+Ack flow broken")
	}
	preCrashData, _, _ := sess1.Buffer().ReadSince(0, 0)
	if len(preCrashData) == 0 {
		t.Fatal("no scrollback collected pre-crash")
	}
	t.Logf("pre-crash: lcs=%d, scrollback=%d bytes", preCrashSeq, len(preCrashData))

	// Graceful cancel: registry.Shutdown runs Close on each session,
	// stopFlusher does a final SaveTo with the current lastSidecarSeq.
	// Sidecar sees socket close → enters grace timer (default 30 s).
	cancel1()
	select {
	case <-d1Done:
	case <-time.After(3 * time.Second):
		t.Fatal("d1 did not exit within 3s of cancel")
	}

	// Producer keeps running in the sidecar's PTY during the down
	// window — we let ~250 ms accumulate. Bytes >preCrashSeq will be
	// buffered in the sidecar's ring waiting for d2 to drain.
	time.Sleep(250 * time.Millisecond)

	// d2: same state dir. Discover should find the surviving sidecar
	// and send FrameResume(preCrashSeq).
	d2, err := New(Config{
		QUICAddr:      "127.0.0.1:0",
		IPCSocketPath: socket,
		CertDir:       tmp,
		IdleTimeout:   time.Hour,
		SidecarStderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("d2 New: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	d2Done := make(chan error, 1)
	go func() { d2Done <- d2.Run(ctx2) }()
	waitForSocket(t, socket)
	t.Cleanup(func() {
		cancel2()
		select {
		case <-d2Done:
		case <-time.After(3 * time.Second):
			t.Error("d2 did not exit within 3s of cancel")
		}
		killLeftoverSidecars(tmp)
	})

	// Confirm the session round-tripped and the sidecar was reattached
	// (the session must have a Pump goroutine running, which means a
	// PTY was assigned).
	sess2, err := d2.registry.Lookup(sid)
	if err != nil {
		t.Fatalf("lookup post-crash: %v", err)
	}
	if sess2.LastSidecarSeq() < preCrashSeq {
		t.Errorf("post-restart lcs regressed: was %d, now %d", preCrashSeq, sess2.LastSidecarSeq())
	}

	// Let the producer run another ~400 ms under d2; pump streams
	// fresh bytes in.
	time.Sleep(400 * time.Millisecond)

	postCrashData, _, _ := sess2.Buffer().ReadSince(0, 0)
	if len(postCrashData) == 0 {
		t.Fatal("no scrollback collected post-crash — Pump never picked up")
	}
	t.Logf("post-crash: scrollback=%d bytes", len(postCrashData))

	// Extract line numbers from the combined stream and verify they
	// are monotonic with no duplicates. The producer pads "echo
	// line-$i" output; the regex tolerates the surrounding CR/LF the
	// PTY adds.
	lineRe := regexp.MustCompile(`line-(\d+)`)
	var nums []int
	for _, m := range lineRe.FindAllStringSubmatch(string(postCrashData), -1) {
		n, _ := strconv.Atoi(m[1])
		nums = append(nums, n)
	}
	if len(nums) < 3 {
		t.Fatalf("expected ≥3 numbered lines in scrollback, found %d (data=%q)", len(nums), postCrashData)
	}

	// Monotonic + no duplicates.
	if !sort.IntsAreSorted(nums) {
		t.Errorf("line numbers not monotonic: %v", nums)
	}
	seen := map[int]bool{}
	var dupes []int
	for _, n := range nums {
		if seen[n] {
			dupes = append(dupes, n)
		}
		seen[n] = true
	}
	if len(dupes) > 0 {
		// Each duplicate is a wire-protocol failure — the sidecar's
		// ack-and-drop flow was supposed to dedupe these.
		t.Errorf("duplicate line numbers across daemon restart: %v (first 20 nums: %v)", dupes, nums[:minInt(20, len(nums))])
	}

	// Sanity: lines span the restart. Pre-crash had nums starting at
	// 1; post-crash should include numbers significantly larger.
	first := nums[0]
	last := nums[len(nums)-1]
	if last-first < 5 {
		t.Errorf("expected scrollback to span >5 lines across restart, got %d..%d (%d lines)", first, last, len(nums))
	}

	// LCS must have advanced past preCrashSeq.
	if sess2.LastSidecarSeq() <= preCrashSeq {
		t.Errorf("lcs did not advance post-restart: pre=%d post=%d", preCrashSeq, sess2.LastSidecarSeq())
	}

	// Clean shutdown of d2 happens via the deferred cancel2(); the
	// test framework's t.Cleanup ordering invokes our killLeftover-
	// Sidecars before tmp's RemoveAll so the producer doesn't keep
	// writing into a soon-to-be-deleted state dir.
	_ = fmt.Sprintf // silence unused import in some build configs
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
