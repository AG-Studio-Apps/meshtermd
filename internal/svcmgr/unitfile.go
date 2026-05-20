package svcmgr

import (
	"fmt"
	"strings"
)

// UserUnitOptions is the input to RenderUserUnit. Zero-valued fields
// fall back to the defaults a fresh install would use, so callers
// that just want the canonical file pass &UserUnitOptions{} or nil.
type UserUnitOptions struct {
	// BinPath is the absolute path to the daemon binary referenced
	// from ExecStart. Defaults to "%h/.local/bin/meshtermd" so the
	// unit file is portable across users on the same host (systemd
	// expands %h at unit-load time).
	BinPath string

	// Addr is the QUIC bind address (host:port). Defaults to
	// "0.0.0.0:49820" — chosen to avoid WireGuard (51820),
	// Tailscale (41641), and other well-known UDP services. The
	// daemon will fall through to the next free port in the
	// 49820–49919 range if the preferred port is in use, and
	// persist the bound port across restarts. Operators can pass
	// an explicit override (e.g. a Tailnet IP, or a different port
	// they've decided on) — explicit non-default ports are honoured
	// strictly without stickiness override.
	Addr string

	// SocketPath is the IPC socket the daemon binds for `connect`.
	// Defaults to "%h/.local/share/meshtermd/meshtermd.sock" matching
	// the default-path lookup in `cmd/meshtermd/connect.go`.
	SocketPath string
}

// RenderUserUnit returns the canonical `~/.config/systemd/user/
// meshtermd.service` content. This is THE source of truth for the
// systemd-user unit shipped by the project:
//   - `meshtermd unit print` writes this to stdout
//   - the iOS auto-installer's SystemdUnitTemplate is kept byte-
//     identical via a snapshot test
//   - AUR/Homebrew packaging pipes this into the package payload
//
// Edits here propagate to every install path. `KillMode=process` is
// load-bearing for v0.6+: it preserves pty-sidecar children across
// daemon restart (the default control-group kill wipes the whole
// cgroup including sidecars + their child shells).
func RenderUserUnit(opts *UserUnitOptions) string {
	o := UserUnitOptions{}
	if opts != nil {
		o = *opts
	}
	if o.BinPath == "" {
		o.BinPath = "%h/.local/bin/meshtermd"
	}
	if o.Addr == "" {
		o.Addr = "0.0.0.0:49820"
	}
	if o.SocketPath == "" {
		o.SocketPath = "%h/.local/share/meshtermd/meshtermd.sock"
	}

	var b strings.Builder
	fmt.Fprintln(&b, "[Unit]")
	fmt.Fprintln(&b, "Description=meshtermd — meshTerm roaming daemon")
	fmt.Fprintln(&b, "Documentation=https://github.com/AG-Studio-Apps/meshtermd")
	fmt.Fprintln(&b, "After=network.target")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "[Service]")
	fmt.Fprintln(&b, "Type=simple")
	fmt.Fprintf(&b, "ExecStart=%s serve --addr %s --socket %s\n", o.BinPath, o.Addr, o.SocketPath)
	fmt.Fprintln(&b, "Restart=on-failure")
	fmt.Fprintln(&b, "RestartSec=5")
	fmt.Fprintln(&b, "# KillMode=process so `systemctl restart` only SIGTERMs the main")
	fmt.Fprintln(&b, "# daemon — the per-session pty-sidecar children survive in their")
	fmt.Fprintln(&b, "# cgroup waiting for the new daemon to dial them back. The")
	fmt.Fprintln(&b, "# default (control-group) wipes every sidecar + child shell on")
	fmt.Fprintln(&b, "# unit cycle, defeating v0.6.0's restart-resilient PTY split.")
	fmt.Fprintln(&b, "KillMode=process")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "[Install]")
	fmt.Fprintln(&b, "WantedBy=default.target")
	return b.String()
}
