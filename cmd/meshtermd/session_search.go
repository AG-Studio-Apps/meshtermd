package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

// Exit codes for `meshtermd session-search`. Mirrors the table used by
// list / status so shell-side branching is uniform.
const (
	searchExitOK               = 0
	searchExitGenericError     = 1
	searchExitDaemonNotRunning = 2
	searchExitBadFlags         = 3
)

// runSessionSearch scans a single session's scrollback for regex
// matches and prints them. Human output is a fixed-width table; --json
// emits the SessionSearchResponse.Matches slice verbatim (the stable
// wire shape mtctl + iOS consume).
//
// Usage: meshtermd session-search [flags] <id-or-name> <regex>
//
// Anchors: pass --anchored to wrap the regex in (?m:…) so ^/$ match
// physical newlines in retained bytes. The truncated start of the
// ring is NOT treated as ^.
func runSessionSearch(args []string) int {
	fs := flag.NewFlagSet("session-search", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	asJSON := fs.Bool("json", false, "emit matches as a JSON array on stdout (stable wire shape)")
	maxMatches := fs.Int("max", 100, "cap on returned matches (0 = daemon default, 10000)")
	anchored := fs.Bool("anchored", false, "wrap the pattern in (?m:…) so ^/$ match physical newlines")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd session-search [flags] <id-or-name> <regex>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "meshtermd session-search: exactly one selector and one regex required")
		fs.Usage()
		return searchExitBadFlags
	}
	selector := fs.Arg(0)
	pattern := fs.Arg(1)

	socketPath := *socket
	if socketPath == "" {
		socketPath = discoverClientSocketPath()
	}

	client := ipc.NewClient(socketPath, *timeout)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.SessionSearch(ctx, ipc.SessionSearchRequest{
		Sel:        selector,
		Pattern:    pattern,
		MaxMatches: *maxMatches,
		Anchored:   *anchored,
	})
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintf(os.Stderr, "meshtermd session-search: daemon not running at %s.\n", socketPath)
			return searchExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd session-search: %v\n", err)
		return searchExitGenericError
	}
	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd session-search: %s: %s\n", resp.Err, resp.Msg)
		return searchExitGenericError
	}

	if *asJSON {
		// Stable contract: array form, one element per match, field
		// names matching the JSON tags on ipc.SearchMatchInfo. iOS +
		// mtctl parse this directly. An empty result is `[]`, never `null`.
		if resp.Matches == nil {
			resp.Matches = []ipc.SearchMatchInfo{}
		}
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(resp.Matches); err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd session-search: json encode: %v\n", err)
			return searchExitGenericError
		}
		return searchExitOK
	}

	// Human-readable table.
	if len(resp.Matches) == 0 {
		fmt.Println("(no matches)")
		return searchExitOK
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LINE\tSEQ\tCONTENT")
	for _, m := range resp.Matches {
		fmt.Fprintf(w, "%d\t%d\t%s\n", m.LineNum, m.StartSeq, m.Line)
	}
	_ = w.Flush()
	return searchExitOK
}
