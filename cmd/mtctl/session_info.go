package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

// runSessionInfo prints a single session's details in a tabular
// panel. Selector matches either the hex SessionID (or its
// truncated prefix as displayed in `mtctl list`) or the user-
// visible Name.
//
// Implementation: just runs `meshtermd list --json` over SSH and
// filters client-side. The remote round-trip is the same shape
// regardless of selector — keeps the daemon CLI surface small (no
// new IPC type for a query that's a 100ms list-and-filter from
// any client).
func runSessionInfo(args []string) int {
	fs := flag.NewFlagSet("session-info", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the ssh round-trip")
	asJSON := fs.Bool("json", false, "emit the matching session as a single JSON object on stdout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl session-info [flags] <id-or-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "mtctl session-info: exactly one selector required (id or name)")
		fs.Usage()
		return exitConfig
	}
	selector := fs.Arg(0)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, "meshtermd list --json", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl session-info: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "mtctl session-info: remote `meshtermd list` exited %d\n%s", code, stderr)
		return exitRemote
	}

	var sessions []ipc.SessionInfo
	if err := json.Unmarshal([]byte(stdout), &sessions); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl session-info: cannot parse daemon output: %v\n", err)
		return exitErr
	}

	match := pickSession(sessions, selector)
	if match == nil {
		fmt.Fprintf(os.Stderr, "mtctl session-info: no session matches %q\n", selector)
		return 3 // unknown_session, mirrors kill/rename's exit-code convention
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(match); err != nil {
			fmt.Fprintf(os.Stderr, "mtctl session-info: json encode: %v\n", err)
			return exitErr
		}
		return exitOK
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	now := time.Now()
	created := time.Unix(0, match.CreatedAtNs)
	lastActive := time.Unix(0, match.LastActiveAtNs)
	fmt.Fprintf(w, "Name\t%s\n", match.Name)
	fmt.Fprintf(w, "ID\t%s\n", match.ID)
	fmt.Fprintf(w, "Created\t%s ago (%s)\n",
		shortDur(now.Sub(created)),
		created.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Last active\t%s ago\n", shortDur(now.Sub(lastActive)))
	if match.Rows > 0 && match.Cols > 0 {
		fmt.Fprintf(w, "Geometry\t%d×%d\n", match.Cols, match.Rows)
	} else {
		fmt.Fprintln(w, "Geometry\t(unset)")
	}
	if match.IdleTimeoutNs > 0 {
		fmt.Fprintf(w, "Idle timeout\t%s\n", shortDur(time.Duration(match.IdleTimeoutNs)))
	} else {
		fmt.Fprintln(w, "Idle timeout\t(daemon default)")
	}
	fmt.Fprintf(w, "Attached\t%s\n", formatAttachedModes(match.AttachedModes, match.AttachedNow))
	if len(match.AttachedModes) > 1 {
		// Per-client breakdown when there's more than one. Useful
		// before deciding whether to attach (e.g., "OK to displace
		// the exclusive that's there?").
		for i, m := range match.AttachedModes {
			fmt.Fprintf(w, "  client #%d\t%s\n", i+1, m)
		}
	}
	_ = w.Flush()
	return exitOK
}

// pickSession scans `sessions` for one matching `selector`. Match
// rules:
//
//   - exact match on ID (full 32-hex-char form)
//   - exact match on Name
//   - unambiguous prefix on ID (the truncated form displayed by
//     `mtctl list`, e.g. the first 12 hex chars). Prefix must be
//     non-empty AND unambiguous; if 2+ sessions share the prefix,
//     returns nil and the caller surfaces "no match" (force the
//     user to pick a more specific selector, beats arbitrarily
//     picking one).
//
// Returns nil when no match (or ambiguous prefix, or empty
// selector).
func pickSession(sessions []ipc.SessionInfo, selector string) *ipc.SessionInfo {
	if selector == "" {
		return nil
	}
	// Exact ID first — fastest, unambiguous when full-length.
	for i := range sessions {
		if sessions[i].ID == selector {
			return &sessions[i]
		}
	}
	// Exact name.
	for i := range sessions {
		if sessions[i].Name == selector {
			return &sessions[i]
		}
	}
	// Prefix on ID. Disambiguate before returning.
	var hits []*ipc.SessionInfo
	for i := range sessions {
		if len(sessions[i].ID) >= len(selector) && sessions[i].ID[:len(selector)] == selector {
			hits = append(hits, &sessions[i])
		}
	}
	if len(hits) == 1 {
		return hits[0]
	}
	return nil
}
