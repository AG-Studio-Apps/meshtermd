// Command mtctl manages remote `meshtermd` sessions from a laptop /
// desktop. Each invocation either shells out to ssh once and runs the
// corresponding `meshtermd <op>` on the remote host (the management
// commands — list, kill, rename, new, session-info, status, restart,
// update, uninstall), or opens a QUIC attach via attach.go's bootstrap
// (the `attach` subcommand: SSH bootstrap → QUIC handshake → raw-mode
// terminal pumps speaking the same Roam protocol the iOS RoamTransport
// speaks).
//
// Authentication: standard SSH. Your `~/.ssh/config`, ssh-agent, and
// keys all work transparently because we invoke the system `ssh`
// binary rather than vendoring `golang.org/x/crypto/ssh`. The trust
// hop is the same one the iOS app uses to bootstrap its QUIC
// connection — if you can `ssh user@host`, you have full control
// over your daemon.
//
// See AG-Studio-Apps/meshtermd/docs/roam-protocol.md § 14a for the
// stable IPC + `meshtermd list --json` wire contract this binary
// consumes.
package main

import (
	"fmt"
	"os"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Println(build.String())
	case "list":
		os.Exit(runList(args))
	case "kill":
		os.Exit(runKill(args))
	case "rename":
		os.Exit(runRename(args))
	case "new":
		os.Exit(runNew(args))
	case "status":
		os.Exit(runStatus(args))
	case "search":
		os.Exit(runSearch(args))
	case "doctor":
		os.Exit(runDoctor(args))
	case "tail":
		os.Exit(runTail(args))
	case "session-info":
		os.Exit(runSessionInfo(args))
	case "attach":
		os.Exit(runAttach(args))
	case "update":
		os.Exit(runUpdate(args))
	case "restart":
		os.Exit(runRestart(args))
	case "uninstall":
		os.Exit(runUninstall(args))
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "mtctl: unknown subcommand %q\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `mtctl %s

Usage: mtctl <subcommand> [flags]

Subcommands:
  version            print build identifier
  list               enumerate sessions on the remote daemon
  session-info       print one session's detail (attach state, geometry, idle)
  status             print the remote daemon's operational snapshot
  search             regex-grep a session's scrollback ring
  doctor             diagnose remote daemon / supervisor / unit-file / linger health
  tail               passive-attach a session's live output (no input, no replay)
  new                create a new named session (does not attach)
  attach             attach to a session as your local terminal
  kill               reap a session by id or name
  rename             rename a session
  update             check for / apply a signed self-update from GitHub Releases
  restart            cycle the remote daemon via its supervisor (sessions survive)
  uninstall          remove the mtctl binary

Common flags (any subcommand):
  --host user@host   SSH target running meshtermd. Default: $MTCTL_HOST.
                     Falls back to ~/.config/mtctl/host if neither is set.

In an attached session, type ~. on a fresh line to detach (mosh /
ssh convention). The remote shell stays alive on the daemon; pick
it up from any other client.

Run 'mtctl <subcommand> --help' for subcommand-specific flags.
`, build.Version)
}
