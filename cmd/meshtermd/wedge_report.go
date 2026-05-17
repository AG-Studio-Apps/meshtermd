package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/daemon"
)

// runWedgeReport dumps the daemon's de-identified wedge-events JSONL
// log. Subcommand entry point; see usage() in main.go.
//
// The wedge watcher (internal/session/wedgewatch.go) appends one JSON
// record per detected resize wedge — geometry numbers, post-resize
// byte counts, session age in seconds, an anonymous per-session
// 8-hex tag. No SessionIDs, no names, no hostnames, no usernames, no
// PTY content. The file is therefore safe to attach to an upstream
// bug report.
//
// Default output goes to stdout so users can pipe to a file or
// `pbcopy`; `--path` instead prints the file's location (useful for
// `scp host:$(ssh host meshtermd wedge-report --path) .` style flows).
// `--clear` truncates the file after dumping so a fresh repro
// produces a clean record set.
func runWedgeReport(args []string) int {
	fs := flag.NewFlagSet("wedge-report", flag.ExitOnError)
	showPath := fs.Bool("path", false,
		"print the wedge-events.jsonl path and exit; don't dump contents")
	clear := fs.Bool("clear", false,
		"truncate the wedge-events.jsonl file after dumping (lets a "+
			"subsequent repro produce a clean record set)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Usage: meshtermd wedge-report [flags]

Print the daemon's de-identified wedge-events log. Records are
appended by the per-session resize-wedge detector when a SetSize
appears to have been ignored by the foreground application
(typically Claude Code under heavy / long-running sessions).

The output is safe to share — no session IDs, names, hostnames,
usernames, paths, or PTY content. Only geometry math, byte
counts, session age, and an anonymous per-session correlation tag.

Flags:
`)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	stateDir, err := cert.DefaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wedge-report: resolve state dir: %v\n", err)
		return 1
	}
	path := filepath.Join(stateDir, daemon.WedgeReportFilename)

	if *showPath {
		fmt.Println(path)
		return 0
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr,
				"wedge-report: no wedge events recorded yet (file %s does not exist)\n",
				path)
			return 0
		}
		fmt.Fprintf(os.Stderr, "wedge-report: open: %v\n", err)
		return 1
	}
	if _, err := io.Copy(os.Stdout, f); err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "wedge-report: copy: %v\n", err)
		return 1
	}
	_ = f.Close()

	if *clear {
		if err := os.Truncate(path, 0); err != nil {
			fmt.Fprintf(os.Stderr, "wedge-report: clear: %v\n", err)
			return 1
		}
	}
	return 0
}
