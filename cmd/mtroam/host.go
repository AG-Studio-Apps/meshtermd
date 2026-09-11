package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// resolveHost picks the SSH target for this invocation. Precedence:
//
//  1. --host <value> flag (per-invocation override)
//  2. $MTROAM_HOST env var (per-shell convenience)
//  3. ~/.config/mtroam/host (one-time setup file, single line)
//
// Empty string + nil means "the user has to set one." Caller surfaces
// a helpful error.
func resolveHost(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv("MTROAM_HOST"); env != "" {
		return env, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".config", "mtroam", "host")
		data, err := os.ReadFile(path) // #nosec G304 -- path is under $HOME
		if err == nil {
			line := strings.TrimSpace(string(data))
			if line != "" {
				return line, nil
			}
		}
	}
	return "", errors.New(
		"mtroam: no SSH host configured. Set --host user@host, " +
			"$MTROAM_HOST, or write the target to ~/.config/mtroam/host.",
	)
}

// validateSSHHost rejects host strings that OpenSSH could interpret
// as additional options. A host beginning with `-` is the canonical
// attack: `-oProxyCommand=evil-script` becomes a local-command-exec
// gadget if it lands as an argv element. Same for short options like
// `-F /attacker-controlled-config`.
//
// We don't try to enumerate the full set of dangerous patterns — we
// just refuse anything that starts with `-` (and the empty string).
// In addition, the runRemote call site inserts `--` between options
// and the host argument as defence-in-depth: even if a future caller
// bypasses this validator, OpenSSH treats `--` as "stop parsing
// options" and any leading-`-` host would surface as a "no such
// host" error rather than be re-interpreted.
//
// Closes the MEDIUM finding from the 2026-05-19 Codex audit.
func validateSSHHost(host string) error {
	if host == "" {
		return errors.New("ssh host is empty")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf(
			"ssh host %q begins with '-'; refused to prevent option-injection " +
				"into the underlying ssh argv", host)
	}
	return nil
}

// runRemote invokes `ssh <host> <remoteCmd>` and captures stdout +
// stderr + exit code. The system `ssh` binary handles all the auth +
// known-hosts + config gymnastics — we don't reimplement them. The
// caller's `~/.ssh/config` is the policy surface.
//
// `remoteCmd` is passed as a single argv after `ssh host`; ssh
// reconstructs it as a shell command on the remote side. Callers
// MUST single-quote any user-supplied selectors / names before
// embedding them into `remoteCmd` to defend against the remote
// shell parsing names like `; rm -rf $HOME`.
func runRemote(ctx context.Context, host, remoteCmd string, timeout time.Duration) (stdout, stderr string, exitCode int, err error) {
	if err := validateSSHHost(host); err != nil {
		return "", "", -1, fmt.Errorf("mtroam: %w", err)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// -o BatchMode=yes: refuse interactive password prompts. The
	// laptop running mtroam is expected to have keys + ssh-agent;
	// a passworded host gets a clean error instead of a hung wait.
	// -o ConnectTimeout matches our overall budget.
	//
	// -o StrictHostKeyChecking=yes: fail closed on host-key trust.
	// This SSH channel bootstraps FURTHER cryptographic trust — the
	// daemon's QUIC certificate fingerprint and the attach token are
	// parsed from this stream's stdout (see attach_bootstrap.go), so
	// the SSH host key is the SOLE authenticator of the whole handshake.
	// We therefore force the strictest posture and deliberately override
	// any looser user ssh_config:
	//
	//   * NOT `accept-new`: accept-new silently auto-adds an UNKNOWN key
	//     on first use — exactly the first-use MITM we must prevent
	//     (findings F4/F7). An on-path attacker on the first connection
	//     would have its forged MTRM_QUIC line trusted.
	//   * NOT unset / user-governed: a user who set `StrictHostKeyChecking
	//     no`/`off` for this host would get warn-and-proceed on a CHANGED
	//     key (an on-path attacker substituting a key for an already
	//     trusted host), and the forged bootstrap line would then be
	//     parsed and used. `-o` here overrides that looser setting.
	//   * `yes` fails closed on BOTH cases — unknown key on first use AND
	//     a changed key — regardless of the user's ssh_config. Combined
	//     with BatchMode=yes there is no interactive prompt to auto-answer.
	//
	// The user establishes/rotates trust out-of-band (add the key to
	// ~/.ssh/known_hosts); isHostKeyVerificationFailure below turns the
	// resulting ssh abort into an actionable error.
	//
	// The `--` separator between options and the host argument is
	// defence-in-depth against host-as-option injection. validateSSHHost
	// above already rejects leading `-`; this is the belt to the
	// suspenders. OpenSSH 7.x+ honours `--` to stop option parsing.
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"--",
		host,
		remoteCmd,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...) // #nosec G204 -- host validated by validateSSHHost; remoteCmd quoted by callers
	var sout, serr bytes.Buffer
	cmd.Stdout = &sout
	cmd.Stderr = &serr
	runErr := cmd.Run()
	stdout = sout.String()
	stderr = serr.String()
	if runErr != nil {
		exitCode = -1
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		}
		// A host-key verification failure (unknown key on first use, or a
		// CHANGED key for an already-trusted host) is fatal and actionable.
		// Under StrictHostKeyChecking=yes ssh aborts (exit 255) rather than
		// trusting the key. Surface it as an explicit, guidance-bearing
		// error instead of a bare non-zero exit so the user knows to verify
		// the host key out-of-band and add it to known_hosts — this bootstrap
		// must never be silently retried or bypassed.
		if isHostKeyVerificationFailure(stderr) {
			return stdout, stderr, exitCode, fmt.Errorf(
				"host key verification failed for %q: the SSH host key is unknown "+
					"or has changed. mtroam refuses to trust it automatically because "+
					"the daemon's QUIC certificate fingerprint and attach token are "+
					"delivered over this SSH channel. Verify the host key out-of-band, "+
					"add it to ~/.ssh/known_hosts, then retry. ssh said: %s",
				host, strings.TrimSpace(stderr))
		}
		if ee != nil {
			return stdout, stderr, exitCode, nil
		}
		return stdout, stderr, -1, fmt.Errorf("ssh: %w", runErr)
	}
	return stdout, stderr, 0, nil
}

// isHostKeyVerificationFailure reports whether ssh's stderr indicates
// that host-key verification failed — either an UNKNOWN host key on
// first use (under StrictHostKeyChecking=yes) or a CHANGED key for an
// already-known host. OpenSSH emits the stable sentinel
// "Host key verification failed." and exits 255 in both cases. We match
// that sentinel case-insensitively rather than the longer human-readable
// warning banners, whose wording varies across OpenSSH versions.
func isHostKeyVerificationFailure(stderr string) bool {
	return strings.Contains(
		strings.ToLower(stderr),
		"host key verification failed",
	)
}

// shellQuote single-quotes a value so it survives the remote shell's
// argument parsing intact. POSIX single-quote escape: `'\''` (close,
// escaped quote, reopen).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
