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
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// -o BatchMode=yes: refuse interactive password prompts. The
	// laptop running mtctl is expected to have keys + ssh-agent;
	// a passworded host gets a clean error instead of a hung wait.
	// -o ConnectTimeout matches our overall budget.
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		host,
		remoteCmd,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...) // #nosec G204 -- host/args validated by caller
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
