// Command meshtermd is the server-side helper for meshTerm's Roam mode.
//
// Three subcommands:
//
//   - version : print build identifier and exit
//   - serve   : long-running daemon that owns the session registry,
//               listens for SSH-bootstrapped connect requests over a
//               unix socket, and accepts QUIC connections from paired
//               iOS clients
//   - connect : invoked over SSH by the iOS client; talks to the local
//               serve process over the unix socket, prints the
//               MTRM_QUIC bootstrap line on stdout, exits
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

Run 'meshtermd <subcommand> --help' for subcommand-specific flags.
`, build.Version)
}
