package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

// runSearch is the mtctl wrapper around `meshtermd session-search`.
// SSH-runs the daemon CLI with --json, parses the result, and renders
// a table by default or re-emits the JSON verbatim with --json.
//
// Selector + pattern are both single-quoted before embedding into the
// remote bash so a name with shell metacharacters or a regex with
// quoting can't break out.
func runSearch(args []string) int {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the ssh round-trip")
	asJSON := fs.Bool("json", false, "emit the daemon's JSON shape verbatim on stdout")
	maxMatches := fs.Int("max", 100, "cap on returned matches (0 = daemon default, 10000)")
	anchored := fs.Bool("anchored", false, "wrap the pattern in (?m:…) so ^/$ match physical newlines")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl search [flags] <id-or-name> <regex>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "mtctl search: exactly one selector and one regex required")
		fs.Usage()
		return exitConfig
	}

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}
	selector := fs.Arg(0)
	pattern := fs.Arg(1)

	parts := []string{
		"meshtermd", "session-search", "--json",
		"--max", fmt.Sprintf("%d", *maxMatches),
	}
	if *anchored {
		parts = append(parts, "--anchored")
	}
	parts = append(parts, shellQuote(selector), shellQuote(pattern))
	remote := strings.Join(parts, " ")

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, remote, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl search: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "mtctl search: remote exited %d\n%s", code, stderr)
		return exitRemote
	}

	if *asJSON {
		fmt.Print(stdout)
		if !endsWithNewline(stdout) {
			fmt.Println()
		}
		return exitOK
	}

	var matches []ipc.SearchMatchInfo
	if err := json.Unmarshal([]byte(stdout), &matches); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl search: parse daemon output: %v\n", err)
		return exitErr
	}
	if len(matches) == 0 {
		fmt.Println("(no matches)")
		return exitOK
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LINE\tSEQ\tCONTENT")
	for _, m := range matches {
		fmt.Fprintf(w, "%d\t%d\t%s\n", m.LineNum, m.StartSeq, m.Line)
	}
	_ = w.Flush()
	return exitOK
}
