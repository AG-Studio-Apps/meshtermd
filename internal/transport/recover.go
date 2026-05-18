package transport

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// defaultSavePrompt is the natural-language instruction the daemon
// injects into Claude's stdin when the client doesn't supply one.
// Bookend markers ("Commencing Save & Restore" / "Memory Updated,
// restoring session...") are the load-bearing part — the sequencer
// scans Claude's PTY output for these substrings and advances banner
// stages on each match, falling back to the grace window if either
// never arrives. Phrased as a numbered directive so Claude's
// instruction-following stays on the rails. "Do not start new work"
// guards against an interrupted restart kicking off a long-running
// response that gets killed mid-stream.
const defaultSavePrompt = "System restart imminent. Please do these three things in order:\n" +
	"1. Print exactly this line and only this line, then a newline: Commencing Save & Restore\n" +
	"2. Save any in-flight context, decisions, or work-in-progress to memory using the memory tools.\n" +
	"3. Print exactly this line and only this line, then a newline: Memory Updated, restoring session...\n" +
	"Do not start new work. Do not explain. After step 3, await the exit signal."

// markerStart / markerEnd are the substrings the sequencer scans for
// in Claude's PTY output during the save window. Substring (not full
// line) match is forgiving against minor paraphrasing AND against
// ANSI styling that wraps but doesn't interleave with the text bytes.
var (
	markerStart = []byte("Commencing Save")
	markerEnd   = []byte("Memory Updated, restoring")
)

// defaultGrace is the upper bound on the save window when the client
// doesn't specify one. 30 s is generous on purpose — a wedged Ink
// renderer can take seconds to process input, and memory tool calls
// themselves are not instant.
const defaultGrace = 30 * time.Second

// shellSettleDelay is the rough heuristic for "/exit has returned us
// to a shell prompt" before we inject the restart command. We don't
// have a clean signal for shell-prompt-ready — pattern-matching PS1
// is brittle because users customise their prompt — so we just wait
// long enough that any reasonable shell startup will have settled.
const shellSettleDelay = 3 * time.Second

// submitSettleDelay is the gap between writing the body of a Claude
// prompt and writing the trailing '\r'. Without this delay an
// observed failure mode is Ink's input handler processing the
// carriage return before the full prompt body has landed in the
// text field — Enter fires on an empty / partial buffer, Claude
// silently drops it, and the user is left with unsubmitted text
// they have to send manually. 100ms is more than enough for the
// prompt bytes to traverse PTY → terminal → Ink's stdin reader on
// any plausible machine, and it's imperceptible inside a 30s save
// window.
const submitSettleDelay = 100 * time.Millisecond

// markerStartTimeout caps how long the sequencer will wait for the
// START marker before falling through. A healthy Claude that received
// the prompt should print "Commencing Save & Restore" within a few
// seconds. If we haven't seen it after this, Claude either ignored
// the prompt (wedged input pipeline) or chose to paraphrase past our
// substring match — either way, waiting longer doesn't help. The END
// marker watch and grace cap still run.
const markerStartTimeout = 10 * time.Second

// markerScanCap bounds the rolling buffer the marker scanner keeps
// around. Markers are short; we only need enough history to span a
// chunk boundary. 8 KiB is generous and keeps allocator pressure on
// the Pump goroutine negligible.
const markerScanCap = 8 * 1024

// watchSaveMarkers installs a PTY byte observer that scans for the
// START / END markers Claude prints during a save. Returns two
// signal channels (each closed at most once on first sight of its
// marker) and a stop function the caller must invoke to clear the
// observer when the sequencer is done.
//
// Concurrency: the observer fires from the session's Pump goroutine.
// We snapshot accumulated bytes under a local mutex, do the substring
// search outside the Pump lock, and close the result channels under
// `sync.Once` guards so a noisy scan that matches multiple times in
// the same chunk only fires each signal once.
func watchSaveMarkers(sess *session.Session) (start, end <-chan struct{}, stop func()) {
	startC := make(chan struct{})
	endC := make(chan struct{})
	var (
		mu        sync.Mutex
		accum     []byte
		startOnce sync.Once
		endOnce   sync.Once
		started   bool
	)

	sess.SetPTYByteObserver(func(data []byte) {
		mu.Lock()
		accum = append(accum, data...)
		// Keep accum bounded so a long save (lots of tool output)
		// doesn't grow it unbounded. Trim from the front but keep
		// enough tail history to span a chunk boundary.
		if len(accum) > markerScanCap {
			accum = accum[len(accum)-markerScanCap/2:]
		}
		hitStart := !started && bytes.Contains(accum, markerStart)
		if hitStart {
			started = true
		}
		hitEnd := started && bytes.Contains(accum, markerEnd)
		mu.Unlock()

		if hitStart {
			startOnce.Do(func() { close(startC) })
		}
		if hitEnd {
			endOnce.Do(func() { close(endC) })
		}
	})

	stop = func() { sess.SetPTYByteObserver(nil) }
	return startC, endC, stop
}

// runRecover drives the save-restart sequence on a session's PTY.
//
// Wire flow:
//  1. RecoverProgress {stage: "started"}
//  2. Inject ESC (0x1b) to interrupt anything mid-stream, sleep 200 ms.
//  3. Inject the save prompt + '\r'; RecoverProgress {stage: "saving"}.
//  4. Sleep grace (default 30 s) — future iteration may short-circuit
//     on observed alt-screen exit (\x1b[?1049l) in the PTY output.
//  5. Inject "/exit\r"; RecoverProgress {stage: "exiting"}.
//  6. Sleep shellSettleDelay (3 s) for the shell prompt to return.
//  7. Inject "claude --resume\r"; RecoverProgress {stage: "restarting"}.
//  8. RecoverProgress {stage: "done"} — best-effort completion signal.
//
// Errors at any injection point emit {stage: "error"} and return.
// The whole sequence honours ctx cancellation between stages so a
// client disconnect terminates the goroutine promptly without
// leaving a half-recovered session.
//
// The sequencer does NOT hold the session lock or block the read
// pump — each WriteStdin call goes through Session.WriteStdin which
// has its own locking. User input concurrent with recovery is
// possible in principle; we accept the interleave risk for v1 (the
// user is presumably waiting for the recovery to finish anyway).
func runRecover(
	ctx context.Context,
	sess *session.Session,
	req protocol.Recover,
	write frameWriter,
) {
	prompt := req.SavePrompt
	if prompt == "" {
		prompt = defaultSavePrompt
	}
	grace := time.Duration(req.GraceMillis) * time.Millisecond
	if grace <= 0 {
		grace = defaultGrace
	}

	sid := sess.ID().String()
	emit := func(stage, detail string) {
		body, err := protocol.MarshalRecoverProgress(protocol.RecoverProgress{
			Stage:  stage,
			Detail: detail,
		})
		if err != nil {
			slog.Warn("recover: marshal RecoverProgress failed",
				"sid", sid, "stage", stage, "err", err)
			return
		}
		if werr := write(protocol.FrameTypeControl, body); werr != nil {
			slog.Warn("recover: write RecoverProgress failed",
				"sid", sid, "stage", stage, "err", werr)
		}
	}

	slog.Info("recover: sequence started",
		"sid", sid,
		"grace_ms", grace/time.Millisecond,
		"save_prompt_chars", len(prompt))
	emit(protocol.RecoverStageStarted, "")

	if err := injectAndCheckCtx(ctx, sess, []byte{0x1b}); err != nil {
		emit(protocol.RecoverStageError, "interrupt failed: "+err.Error())
		return
	}
	if !sleepCtx(ctx, 200*time.Millisecond) {
		emit(protocol.RecoverStageError, "cancelled before save prompt")
		return
	}

	// Install the marker scanner BEFORE we inject the prompt so we
	// don't miss the start marker if Claude responds faster than the
	// SetPTYByteObserver call returns. Cleared via defer so a future
	// recovery starts with a fresh observer pointed at a fresh stream.
	startCh, endCh, stopWatch := watchSaveMarkers(sess)
	defer stopWatch()

	// Save prompt + Enter. The trailing '\r' submits the line in raw
	// mode (Claude's stdin doesn't translate \n → \r). The
	// submitSettleDelay between the body and the carriage return is
	// load-bearing — see the constant's docstring.
	emit(protocol.RecoverStageSaving, "Asking Claude to save…")
	if err := injectAndCheckCtx(ctx, sess, []byte(prompt)); err != nil {
		emit(protocol.RecoverStageError, "save prompt write failed: "+err.Error())
		return
	}
	if !sleepCtx(ctx, submitSettleDelay) {
		emit(protocol.RecoverStageError, "cancelled before save prompt submit")
		return
	}
	if err := injectAndCheckCtx(ctx, sess, []byte{'\r'}); err != nil {
		emit(protocol.RecoverStageError, "save prompt enter failed: "+err.Error())
		return
	}

	// Marker watch — primary timing signal for v0.9.7+.
	//
	// Phase 1: wait for the START marker (Claude acknowledged the
	// prompt). If we don't see it within markerStartTimeout, Claude
	// likely never parsed the instruction (wedged input pipeline,
	// already mid-tool-call ignoring stdin, etc.). Skip ahead to the
	// grace-only fallback rather than waiting the full window.
	graceDeadline := time.After(grace)
	select {
	case <-ctx.Done():
		emit(protocol.RecoverStageError, "cancelled while awaiting save start")
		return
	case <-startCh:
		emit(protocol.RecoverStageSaving, "Claude is saving memory…")
	case <-time.After(markerStartTimeout):
		slog.Info("recover: start marker not seen — falling through to grace window",
			"sid", sid, "timeout", markerStartTimeout)
	case <-graceDeadline:
		slog.Info("recover: grace expired before start marker", "sid", sid)
	}

	// Phase 2: wait for the END marker, capped by the remaining
	// grace window. End marker = "save complete, ready to exit."
	// If grace expires first, fire /exit anyway — Claude has had
	// long enough.
	select {
	case <-ctx.Done():
		emit(protocol.RecoverStageError, "cancelled while awaiting save end")
		return
	case <-endCh:
		emit(protocol.RecoverStageSaving, "Save complete — exiting…")
	case <-graceDeadline:
		slog.Info("recover: grace expired before end marker — exiting anyway", "sid", sid)
	}

	// /exit. Claude Code listens for this slash-command and shuts down
	// cleanly, returning control to the parent shell.
	emit(protocol.RecoverStageExiting, "")
	if err := injectAndCheckCtx(ctx, sess, []byte("/exit\r")); err != nil {
		emit(protocol.RecoverStageError, "exit command failed: "+err.Error())
		return
	}
	if !sleepCtx(ctx, shellSettleDelay) {
		emit(protocol.RecoverStageError, "cancelled before restart")
		return
	}

	// Restart Claude. `--resume` reattaches to the most recent
	// session in the cwd's project so the in-memory conversation is
	// restored from disk. If --resume fails (no prior session for
	// this cwd, package not in PATH, etc.) the user sees the shell
	// error and can manually rerun — best-effort is acceptable here.
	emit(protocol.RecoverStageRestarting, "")
	if err := injectAndCheckCtx(ctx, sess, []byte("claude --resume\r")); err != nil {
		emit(protocol.RecoverStageError, "restart command failed: "+err.Error())
		return
	}

	emit(protocol.RecoverStageDone, "")
	slog.Info("recover: sequence completed", "sid", sid)
}

// injectAndCheckCtx writes data to the session's PTY stdin and
// returns the ctx error if cancelled mid-write. Wraps WriteStdin's
// error to keep callers' error paths uniform.
func injectAndCheckCtx(ctx context.Context, sess *session.Session, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := sess.WriteStdin(data)
	return err
}

// sleepCtx sleeps for d unless ctx cancels first. Returns true on
// normal completion, false on cancellation — callers use this to
// short-circuit the sequencer when the client disconnects.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

