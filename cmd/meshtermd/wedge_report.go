package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
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
// PTY content under default settings.
//
// Caveat (pre-v1.0): the wedge watcher's MESHTERMD_WEDGE_CAPTURE_BYTES=1
// opt-in env writes base64-encoded post-resize PTY excerpts into a
// `recent_output_b64` field on each record. When that knob has been
// flipped, the JSONL is NOT paste-safe — it may contain rendered
// terminal content (chat messages, command output, code). We scan
// for the field before emitting and surface a loud stderr warning
// if any record carries it, so the safe-to-share claim doesn't
// quietly become a leak. Records are still emitted in full; this is
// a warning, not a redaction.
//
// Default output goes to stdout so users can pipe to a file or
// `pbcopy`; `--path` instead prints the file's location (useful for
// `scp host:$(ssh host meshtermd wedge-report --path) .` style flows).
// `--clear` truncates the file after dumping so a fresh repro
// produces a clean record set.

// captureBytesFieldMarker is the substring the JSONL scanner looks
// for when deciding whether to emit the safety warning. Matches the
// `omitempty` JSON tag on RecentOutputB64 in
// internal/session/wedgewatch.go's wedgeEvent struct.
var captureBytesFieldMarker = []byte(`"recent_output_b64":"`)
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
	// Stream the file out line-by-line so we can both copy to stdout
	// and watch for the `recent_output_b64` marker. Going line-based
	// (vs io.Copy) costs a per-record scan but each record is short
	// (~few hundred bytes) and the file as a whole is bounded by
	// session lifetime — negligible.
	scanner := bufio.NewScanner(f)
	// JSONL records can include base64-encoded PTY excerpts up to
	// ~wedgeCaptureBufferCap (4 KiB) plus framing. 64 KiB is a safe
	// per-line ceiling; the default bufio.Scanner cap is 64 KiB so
	// we just keep that.
	sawCaptureBytes := false
	for scanner.Scan() {
		line := scanner.Bytes()
		if !sawCaptureBytes && bytes.Contains(line, captureBytesFieldMarker) {
			sawCaptureBytes = true
		}
		if _, werr := os.Stdout.Write(line); werr != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "wedge-report: write: %v\n", werr)
			return 1
		}
		if _, werr := os.Stdout.Write([]byte{'\n'}); werr != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "wedge-report: write: %v\n", werr)
			return 1
		}
	}
	if serr := scanner.Err(); serr != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "wedge-report: scan: %v\n", serr)
		return 1
	}
	_ = f.Close()

	if sawCaptureBytes {
		fmt.Fprintln(os.Stderr,
			"wedge-report: WARNING — this log contains records recorded with "+
				"MESHTERMD_WEDGE_CAPTURE_BYTES=1, which embed base64-encoded "+
				"PTY excerpts (terminal content). Review before sharing.")
	}

	if *clear {
		if err := os.Truncate(path, 0); err != nil {
			fmt.Fprintf(os.Stderr, "wedge-report: clear: %v\n", err)
			return 1
		}
	}
	return 0
}
