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

// Exit codes (uniform across mtctl subcommands):
//
//	0  ok
//	1  generic error
//	2  configuration error (no host, bad flags)
//	3  SSH or remote command failure
const (
	exitOK      = 0
	exitErr     = 1
	exitConfig  = 2
	exitRemote  = 3
)

// runList prints the remote daemon's session inventory. Wraps
// `meshtermd list --json` over SSH; renders as a table by default or
// re-emits the raw JSON with --json (`mtctl list --json | jq` works
// because the wire shape is the same as the daemon's).
func runList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the ssh round-trip")
	asJSON := fs.Bool("json", false, "emit the daemon's JSON shape verbatim on stdout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl list [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, "meshtermd list --json", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl list: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "mtctl list: remote `meshtermd list` exited %d\n%s", code, stderr)
		return exitRemote
	}

	if *asJSON {
		// Pass-through. The daemon already emits valid JSON.
		fmt.Print(stdout)
		if !endsWithNewline(stdout) {
			fmt.Println()
		}
		return exitOK
	}

	var sessions []ipc.SessionInfo
	if err := json.Unmarshal([]byte(stdout), &sessions); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl list: cannot parse daemon output: %v\n", err)
		return exitErr
	}
	if len(sessions) == 0 {
		fmt.Println("(no sessions)")
		return exitOK
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tID\tCREATED\tIDLE\tATTACHED")
	now := time.Now()
	for _, s := range sessions {
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
	return exitOK
}

// formatAttachedModes renders the ATTACHED column compactly. See the
// daemon-side `meshtermd list` for the same logic — kept duplicated
// across binaries to avoid pulling cmd/* into a shared package.
//
// Falls back to the legacy yes/no when the daemon didn't supply
// AttachedModes (older daemon — old wire didn't carry the field).
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
		return fmt.Sprintf("%d clients", len(modes))
	}
}

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

func endsWithNewline(s string) bool {
	return len(s) > 0 && s[len(s)-1] == '\n'
}
