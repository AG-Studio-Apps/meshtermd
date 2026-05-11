package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

// Exit codes for `meshtermd list`. Mirror the connect convention so
// shell-side branching can use a uniform table across subcommands.
const (
	listExitOK               = 0
	listExitGenericError     = 1
	listExitDaemonNotRunning = 2
)

// runList prints the daemon's live session inventory. The default
// human-readable output is a fixed-width table; --json emits the
// `ListSessionsResponse.Sessions` slice verbatim. The JSON shape is
// the stable wire contract the meshTerm iOS app consumes via SSH.
func runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	asJSON := fs.Bool("json", false, "emit sessions as a JSON array on stdout (stable wire shape)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd list [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

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
			fmt.Fprintf(os.Stderr, "meshtermd list: daemon not running at %s.\n", socketPath)
			return listExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd list: %v\n", err)
		return listExitGenericError
	}
	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd list: %s: %s\n", resp.Err, resp.Msg)
		return listExitGenericError
	}

	if *asJSON {
		// Stable contract: array form, one element per session, field
		// names matching the JSON tags on ipc.SessionInfo. iOS parses
		// this directly. An empty inventory is `[]`, never `null`.
		if resp.Sessions == nil {
			resp.Sessions = []ipc.SessionInfo{}
		}
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(resp.Sessions); err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd list: json encode: %v\n", err)
			return listExitGenericError
		}
		return listExitOK
	}

	// Human-readable: fixed-width table.
	if len(resp.Sessions) == 0 {
		fmt.Println("(no sessions)")
		return listExitOK
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tID\tCREATED\tIDLE\tATTACHED")
	now := time.Now()
	for _, s := range resp.Sessions {
		created := time.Unix(0, s.CreatedAtNs)
		lastActive := time.Unix(0, s.LastActiveAtNs)
		fmt.Fprintf(w, "%s\t%s\t%s ago\t%s\t%s\n",
			s.Name,
			truncateID(s.ID),
			shortDur(now.Sub(created)),
			shortDur(now.Sub(lastActive)),
			formatAttachedModes(s.AttachedModes, s.AttachedNow),
		)
	}
	_ = w.Flush()
	return listExitOK
}

// formatAttachedModes renders the ATTACHED column compactly:
//
//	(no clients)            → "—"
//	["exclusive"]           → "exclusive"
//	["exclusive","readonly"]→ "exclusive+readonly"
//	["readonly","readonly"] → "2× readonly"
//	mixed                   → "exclusive+2× readonly"
//
// Falls back to the legacy yes/no when the daemon didn't supply
// AttachedModes (older daemon, AttachedModes is omitted from the
// CBOR/JSON entirely; AttachedNow remains the only signal).
func formatAttachedModes(modes []string, fallback bool) string {
	if modes == nil {
		if fallback {
			return "yes"
		}
		return "—"
	}
	if len(modes) == 0 {
		return "—"
	}
	var ex, ro int
	for _, m := range modes {
		switch m {
		case "exclusive":
			ex++
		case "readonly":
			ro++
		}
	}
	switch {
	case ex == 1 && ro == 0:
		return "exclusive"
	case ex == 0 && ro == 1:
		return "readonly"
	case ex == 0 && ro > 1:
		return fmt.Sprintf("%d× readonly", ro)
	case ex == 1 && ro == 1:
		return "exclusive+readonly"
	case ex == 1 && ro > 1:
		return fmt.Sprintf("exclusive+%d× readonly", ro)
	default:
		// 0 ex / N ro / unknown modes — give a count and hope for the best.
		return fmt.Sprintf("%d clients", len(modes))
	}
}

// truncateID prints the first 12 hex chars of a SessionID — enough to
// disambiguate at a glance without filling the column.
func truncateID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12] + "…"
}

func shortDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func boolMark(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Reserved for future flag parsing helpers that may want to share
// stripping logic with `connect`. Keeping the import surface minimal
// here so the linter doesn't flag unused imports as the cmd files
// grow.
var _ = strings.TrimSpace
