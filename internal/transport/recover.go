package transport

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
)

// defaultSavePrompt is the natural-language instruction the daemon
// injects into Claude's stdin when the client doesn't supply one.
// Phrased as a system-side message so Claude treats it as a directive
// rather than a request to act on. Mentions the memory tool
// specifically so Claude knows what surface to use for persistence;
// "do not start new work" guards against an interrupted restart
// kicking off a long-running response that gets killed mid-stream.
const defaultSavePrompt = "System restart imminent — please save any " +
	"in-flight context, decisions, or work-in-progress to memory using " +
	"the memory tools, then exit. Do not start new work."

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

	// Save prompt + Enter. The trailing '\r' submits the line in raw
	// mode (Claude's stdin doesn't translate \n → \r).
	emit(protocol.RecoverStageSaving,
		fmt.Sprintf("Waiting up to %s for save…", roundDuration(grace)))
	if err := injectAndCheckCtx(ctx, sess, []byte(prompt)); err != nil {
		emit(protocol.RecoverStageError, "save prompt write failed: "+err.Error())
		return
	}
	if err := injectAndCheckCtx(ctx, sess, []byte{'\r'}); err != nil {
		emit(protocol.RecoverStageError, "save prompt enter failed: "+err.Error())
		return
	}
	if !sleepCtx(ctx, grace) {
		emit(protocol.RecoverStageError, "cancelled during grace window")
		return
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

// roundDuration trims sub-second precision off a duration for
// user-facing detail strings ("Waiting up to 30s for save…", not
// "Waiting up to 30.000000123s for save…").
func roundDuration(d time.Duration) time.Duration {
	if d >= time.Second {
		return d.Round(time.Second)
	}
	return d.Round(time.Millisecond)
}
