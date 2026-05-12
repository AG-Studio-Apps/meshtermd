package svcmgr

import (
	"strings"
	"testing"
)

// TestRenderUserUnitGolden pins the byte-for-byte output of the
// canonical user unit so any change goes through code review with a
// visible diff. The string is intentionally embedded inline (rather
// than read from a testdata file) so a passing test guarantees this
// file matches the regenerated output AND so reviewers see the
// expected content right next to the producing function.
//
// If you intentionally change the unit format, update both this
// constant AND the iOS-side SystemdUnitTemplate so the two stay
// byte-identical. The iOS template's own snapshot test (if added)
// would surface the drift.
func TestRenderUserUnitGolden(t *testing.T) {
	const want = `[Unit]
Description=meshtermd — meshTerm roaming daemon
Documentation=https://github.com/AG-Studio-Apps/meshtermd
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/meshtermd serve --addr 0.0.0.0:51820 --socket %h/.local/share/meshtermd/meshtermd.sock
Restart=on-failure
RestartSec=5
# KillMode=process so ` + "`systemctl restart`" + ` only SIGTERMs the main
# daemon — the per-session pty-sidecar children survive in their
# cgroup waiting for the new daemon to dial them back. The
# default (control-group) wipes every sidecar + child shell on
# unit cycle, defeating v0.6.0's restart-resilient PTY split.
KillMode=process

[Install]
WantedBy=default.target
`
	got := RenderUserUnit(nil)
	if got != want {
		t.Errorf("default unit output drifted; diff:\n--- want ---\n%s--- got ---\n%s", want, got)
	}
}

func TestRenderUserUnitContainsKillModeProcess(t *testing.T) {
	got := RenderUserUnit(nil)
	if !strings.Contains(got, "\nKillMode=process\n") {
		t.Error("emitted unit is missing KillMode=process — sidecars would not survive restart")
	}
}

func TestRenderUserUnitHonoursOverrides(t *testing.T) {
	got := RenderUserUnit(&UserUnitOptions{
		BinPath:    "/opt/meshtermd/bin/meshtermd",
		Addr:       "100.64.0.1:51820",
		SocketPath: "/run/meshtermd/meshtermd.sock",
	})
	wantExec := "ExecStart=/opt/meshtermd/bin/meshtermd serve --addr 100.64.0.1:51820 --socket /run/meshtermd/meshtermd.sock"
	if !strings.Contains(got, wantExec) {
		t.Errorf("override ExecStart line missing; got:\n%s", got)
	}
}
