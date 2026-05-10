// Command mtctl manages remote `meshtermd` sessions from a laptop /
// desktop. Each invocation shells out to ssh once, runs the
// corresponding `meshtermd <op>` on the remote host, and parses the
// response (text for human output, JSON for `--json` / piping).
//
// Tier 1 (this binary): management commands — list, kill, rename,
// new, status. No QUIC attach.
//
// Tier 3 (future): real terminal attach, which needs a Go QUIC client
// that speaks the same wire protocol the iOS RoamTransport speaks.
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
  status             print the remote daemon's operational snapshot
  new                create a new named session (does not attach)
  kill               reap a session by id or name
  rename             rename a session

Common flags (any subcommand):
  --host user@host   SSH target running meshtermd. Default: $MTCTL_HOST.
                     Falls back to ~/.config/mtctl/host if neither is set.

Tier 1 release — management only. Use the meshTerm iOS app or a
future Tier 3 build for terminal attach.

Run 'mtctl <subcommand> --help' for subcommand-specific flags.
`, build.Version)
}
