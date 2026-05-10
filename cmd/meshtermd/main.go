// Command meshtermd is the server-side helper for meshTerm's Roam mode.
//
// Five subcommands:
//
//   - version : print build identifier and exit
//   - serve   : long-running daemon that owns the session registry,
//               listens for SSH-bootstrapped connect requests over a
//               unix socket, and accepts QUIC connections from paired
//               iOS clients
//   - connect : invoked over SSH by the iOS client; talks to the local
//               serve process over the unix socket, prints the
//               MTRM_QUIC bootstrap line on stdout, exits
//   - list    : enumerate live sessions on the local daemon. JSON
//               output (--json) is the wire shape iOS consumes via
//               SSH for its session-picker UI.
//   - kill    : reap a session by hex SessionID or by Name.
//
// See docs/roam-protocol.md for the wire specification.
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
	case "serve":
		os.Exit(runServe(args))
	case "connect":
		os.Exit(runConnect(args))
	case "list":
		os.Exit(runList(args))
	case "kill":
		os.Exit(runKill(args))
	case "rename":
		os.Exit(runRename(args))
	case "status":
		os.Exit(runStatus(args))
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "meshtermd: unknown subcommand %q\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `meshtermd %s

Usage: meshtermd <subcommand> [flags]

Subcommands:
  version            print build identifier
  serve              run the long-lived daemon (owns session registry, accepts QUIC)
  connect            SSH-side bootstrap helper invoked by the meshTerm iOS app
  list               enumerate live sessions on this daemon (--json for machine-readable output)
  kill               reap a session by id or name
  rename             change a session's user-visible name (PTY + buffer unaffected)
  status             print the daemon's operational snapshot (--json for tooling)

Run 'meshtermd <subcommand> --help' for subcommand-specific flags.
`, build.Version)
}
