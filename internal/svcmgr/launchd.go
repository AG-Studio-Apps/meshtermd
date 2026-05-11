package svcmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// launchd drives a launchctl-managed meshtermd on macOS. Mirrors the
// systemdUser semantics: idempotent Stop, exec-via-supervisor Start,
// bootout-then-remove for Remove.
type launchd struct{}

const launchdLabel = "com.agstudio.meshtermd"

func (l *launchd) Name() string { return "launchd" }

func (l *launchd) Available(ctx context.Context) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if !commandExists("launchctl") {
		return false
	}
	// Plist must exist; otherwise we don't manage anything.
	return fileExists(l.plistPath())
}

func (l *launchd) Stop(ctx context.Context) error {
	if !l.Available(ctx) {
		return ErrUnavailable
	}
	// `bootout` on a not-loaded service returns non-zero; we ignore.
	target := fmt.Sprintf("gui/%d", os.Getuid())
	_ = exec.CommandContext(ctx, "launchctl", "bootout", target, l.plistPath()).Run()
	return nil
}

func (l *launchd) Start(ctx context.Context, binPath string) error {
	if !l.Available(ctx) {
		return ErrUnavailable
	}
	target := fmt.Sprintf("gui/%d", os.Getuid())
	cmd := exec.CommandContext(ctx, "launchctl", "bootstrap", target, l.plistPath())
	if out, err := cmd.CombinedOutput(); err != nil {
		// bootstrap exit 17 = "Service already loaded" — tolerate.
		if strings.Contains(string(out), "Service already loaded") {
			return nil
		}
		return fmt.Errorf("launchctl bootstrap: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (l *launchd) Restart(ctx context.Context, binPath string) error {
	if !l.Available(ctx) {
		return ErrUnavailable
	}
	// launchctl kickstart -k <service> kills + restarts in one go.
	service := fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel)
	cmd := exec.CommandContext(ctx, "launchctl", "kickstart", "-k", service)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (l *launchd) Remove(ctx context.Context) error {
	_ = l.Stop(ctx)
	if err := os.Remove(l.plistPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}

func (l *launchd) plistPath() string {
	return homePath("Library", "LaunchAgents", launchdLabel+".plist")
}
