package svcmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// systemdUser drives a `systemctl --user`-managed meshtermd. Its
// Stop/Start/Restart all set XDG_RUNTIME_DIR + DBUS_SESSION_BUS_ADDRESS
// explicitly so they work when invoked from a non-pam_systemd SSH
// session (the common case for our installer-spawned shells).
type systemdUser struct{}

const systemdUnitName = "meshtermd"

func (s *systemdUser) Name() string { return "systemd-user" }

func (s *systemdUser) Available(ctx context.Context) bool {
	if !commandExists("systemctl") {
		return false
	}
	// The user-bus socket is what systemctl --user actually needs;
	// pam_systemd creates it at login time. Without it, every
	// systemctl --user invocation fails with "No such file or
	// directory". Check existence rather than try-and-fail so
	// Detect can fall back to nohup cleanly.
	rd := userRuntimeDir()
	if rd == "" {
		return false
	}
	if _, err := os.Stat(rd + "/bus"); err != nil {
		return false
	}
	// Last check: the unit file we manage must be installed.
	return fileExists(s.unitPath())
}

func (s *systemdUser) Stop(ctx context.Context) error {
	if !s.Available(ctx) {
		return ErrUnavailable
	}
	// `stop` on a not-running unit returns 0 from recent systemd;
	// older versions return 5. Either way we treat any non-fatal
	// exit as "stopped".
	cmd := s.cmd(ctx, "stop", systemdUnitName)
	_ = cmd.Run()
	return nil
}

func (s *systemdUser) Start(ctx context.Context, binPath string) error {
	if !s.Available(ctx) {
		return ErrUnavailable
	}
	cmd := s.cmd(ctx, "start", systemdUnitName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user start: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *systemdUser) Restart(ctx context.Context, binPath string) error {
	if !s.Available(ctx) {
		return ErrUnavailable
	}
	// Use a single restart rather than stop-then-start; systemd
	// handles the inter-process race (port re-bind on the same
	// addr) better than we can manually.
	cmd := s.cmd(ctx, "restart", systemdUnitName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user restart: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *systemdUser) Remove(ctx context.Context) error {
	if !s.Available(ctx) {
		// Try the no-bus path: remove the unit file directly so a
		// future login that brings the user manager up won't see
		// our ghost unit.
		return os.Remove(s.unitPath())
	}
	// disable --now stops + un-enables; we follow with a daemon-reload
	// so the unit's gone from systemctl's in-memory index.
	_ = s.cmd(ctx, "disable", "--now", systemdUnitName).Run()
	if err := os.Remove(s.unitPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}
	_ = s.cmd(ctx, "daemon-reload").Run()
	return nil
}

// cmd constructs an exec.Cmd invoking `systemctl --user <args>` with
// the env vars that make the user-bus reachable from a non-pam_systemd
// session.
func (s *systemdUser) cmd(ctx context.Context, args ...string) *exec.Cmd {
	full := append([]string{"--user"}, args...)
	cmd := exec.CommandContext(ctx, "systemctl", full...)
	cmd.Env = append(os.Environ(),
		"XDG_RUNTIME_DIR="+userRuntimeDir(),
		"DBUS_SESSION_BUS_ADDRESS=unix:path="+userRuntimeDir()+"/bus",
	)
	return cmd
}

func (s *systemdUser) unitPath() string {
	return homePath(".config", "systemd", "user", "meshtermd.service")
}

// UnitPath exposes the unit-file location for the doctor command.
func (s *systemdUser) UnitPath() string { return s.unitPath() }

func userRuntimeDir() string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return v
	}
	// pam_systemd's convention. Same value the iOS installer uses.
	return fmt.Sprintf("/run/user/%d", os.Getuid())
}
