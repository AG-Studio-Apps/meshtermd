package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/AG-Studio-Apps/meshtermd/internal/svcmgr"
)

// runUnit dispatches `meshtermd unit <action>` subcommands.
//
// Today the only action is `print`, which writes the canonical
// systemd-user unit to stdout. A future `meshtermd unit install`
// could land the file in `~/.config/systemd/user/` + run
// `systemctl --user daemon-reload`; we keep it as a no-op stub so
// the surface is forward-compatible.
//
// Exit codes:
//
//	0  printed (or installed) cleanly
//	2  bad action / flag usage
func runUnit(args []string) int {
	if len(args) == 0 {
		unitUsage(os.Stderr)
		return 2
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "print":
		return runUnitPrint(rest, os.Stdout)
	case "help", "--help", "-h":
		unitUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "meshtermd unit: unknown action %q\n", action)
		unitUsage(os.Stderr)
		return 2
	}
}

func runUnitPrint(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("unit print", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	binPath := fs.String("bin", "",
		"absolute path baked into ExecStart (default %h/.local/bin/meshtermd)")
	addr := fs.String("addr", "",
		"QUIC bind address host:port (default 0.0.0.0:49820)")
	socket := fs.String("socket", "",
		"IPC socket path (default %h/.local/share/meshtermd/meshtermd.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	content := svcmgr.RenderUserUnit(&svcmgr.UserUnitOptions{
		BinPath:    *binPath,
		Addr:       *addr,
		SocketPath: *socket,
	})
	if _, err := io.WriteString(out, content); err != nil {
		fmt.Fprintf(os.Stderr, "meshtermd unit print: write: %v\n", err)
		return 1
	}
	return 0
}

func unitUsage(w io.Writer) {
	fmt.Fprintf(w, `meshtermd unit — emit / manage the systemd-user unit file

Usage: meshtermd unit <action> [flags]

Actions:
  print    Write the canonical unit file to stdout. Pipe to
           ~/.config/systemd/user/meshtermd.service to install.

print flags:
  --bin=PATH      override ExecStart binary path
  --addr=H:P      override QUIC bind address (default 0.0.0.0:49820)
  --socket=PATH   override IPC socket path

Example:
  meshtermd unit print > ~/.config/systemd/user/meshtermd.service
  systemctl --user daemon-reload
  systemctl --user enable --now meshtermd
`)
}
