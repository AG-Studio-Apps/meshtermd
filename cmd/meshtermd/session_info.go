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

// Exit codes — paralleling kill/list.
const (
	infoExitOK               = 0
	infoExitGenericError     = 1
	infoExitDaemonNotRunning = 2
	infoExitUnknownSession   = 3
)

// runSessionInfo prints a single session's details. Daemon-side
// counterpart to `mtctl session-info` — for users on the host who
// want a quick detail view without going through the SSH path.
//
// Implementation: just calls ListSessions and filters client-side.
// Same selector resolution as the IPC kill/rename path: exact ID,
// exact name, then unambiguous ID prefix.
func runSessionInfo(args []string) int {
	fs := flag.NewFlagSet("session-info", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	asJSON := fs.Bool("json", false, "emit the matching session as a JSON object")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd session-info [flags] <id-or-name>\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "meshtermd session-info: exactly one selector required (id or name)")
		fs.Usage()
		return infoExitGenericError
	}
	selector := fs.Arg(0)

	socketPath := *socket
	if socketPath == "" {
		socketPath = discoverClientSocketPath()
	}

	client := ipc.NewClient(socketPath, *timeout)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.ListSessions(ctx)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintf(os.Stderr, "meshtermd session-info: daemon not running at %s.\n", socketPath)
			return infoExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd session-info: %v\n", err)
		return infoExitGenericError
	}
	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd session-info: %s: %s\n", resp.Err, resp.Msg)
		return infoExitGenericError
	}

	match := pickSessionInfo(resp.Sessions, selector)
	if match == nil {
		fmt.Fprintf(os.Stderr, "meshtermd session-info: no session matches %q\n", selector)
		return infoExitUnknownSession
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(match); err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd session-info: json encode: %v\n", err)
			return infoExitGenericError
		}
		return infoExitOK
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
		for i, m := range match.AttachedModes {
			fmt.Fprintf(w, "  client #%d\t%s\n", i+1, m)
		}
	}
	// Wedge-watcher cumulative counters. Suppress the whole section
	// when the session has never resized — keeps the common-case
	// output clean. Once any resize has been observed we always show
	// the full set so operators can read "no wedges" as positive
	// evidence rather than absence-of-line.
	if match.WedgeResizesObserved > 0 {
		fmt.Fprintln(w, "Wedge watch\t")
		fmt.Fprintf(w, "  Output bytes\t%s\n", formatBytes(match.WedgeTotalOutBytes))
		fmt.Fprintf(w, "  Resizes seen\t%d\n", match.WedgeResizesObserved)
		fmt.Fprintf(w, "  Wedges (silent / cursor_row / vertical_walk)\t%d / %d / %d\n",
			match.WedgeSilentWedges,
			match.WedgeCursorWedges,
			match.WedgeVerticalWalkWedges)
	}
	_ = w.Flush()
	return infoExitOK
}

// formatBytes renders a byte count with a one-decimal SI suffix when
// it's large enough to make raw bytes hard to scan. We intentionally
// use 1000-based units (KB / MB) rather than 1024-based — operators
// reading wedge-watch output want order-of-magnitude at a glance, not
// precise allocator accounting.
func formatBytes(n uint64) string {
	const (
		kb = 1000
		mb = kb * 1000
		gb = mb * 1000
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.1f GB", float64(n)/gb)
	case n >= mb:
		return fmt.Sprintf("%.1f MB", float64(n)/mb)
	case n >= kb:
		return fmt.Sprintf("%.1f KB", float64(n)/kb)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// pickSessionInfo: same shape as mtctl's pickSession. Kept duplicated
// across binaries to avoid pulling cmd/* into a shared package.
func pickSessionInfo(sessions []ipc.SessionInfo, selector string) *ipc.SessionInfo {
	if selector == "" {
		return nil
	}
	for i := range sessions {
		if sessions[i].ID == selector {
			return &sessions[i]
		}
	}
	for i := range sessions {
		if sessions[i].Name == selector {
			return &sessions[i]
		}
	}
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
