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
//  2. $MTCTL_HOST env var (per-shell convenience)
//  3. ~/.config/mtctl/host (one-time setup file, single line)
//
// Empty string + nil means "the user has to set one." Caller surfaces
// a helpful error.
func resolveHost(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv("MTCTL_HOST"); env != "" {
		return env, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".config", "mtctl", "host")
		data, err := os.ReadFile(path) // #nosec G304 -- path is under $HOME
		if err == nil {
			line := strings.TrimSpace(string(data))
			if line != "" {
				return line, nil
			}
		}
	}
	return "", errors.New(
		"mtctl: no SSH host configured. Set --host user@host, " +
			"$MTCTL_HOST, or write the target to ~/.config/mtctl/host.",
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
		return "", "", -1, fmt.Errorf("mtctl: %w", err)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// -o BatchMode=yes: refuse interactive password prompts. The
	// laptop running mtctl is expected to have keys + ssh-agent;
	// a passworded host gets a clean error instead of a hung wait.
	// -o ConnectTimeout matches our overall budget.
	//
	// The `--` separator between options and the host argument is
	// defence-in-depth against host-as-option injection. validateSSHHost
	// above already rejects leading `-`; this is the belt to the
	// suspenders. OpenSSH 7.x+ honours `--` to stop option parsing.
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
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
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
			return stdout, stderr, exitCode, nil
		}
		return stdout, stderr, -1, fmt.Errorf("ssh: %w", runErr)
	}
	return stdout, stderr, 0, nil
}

// shellQuote single-quotes a value so it survives the remote shell's
// argument parsing intact. POSIX single-quote escape: `'\''` (close,
// escaped quote, reopen).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
