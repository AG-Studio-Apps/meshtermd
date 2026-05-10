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

// runStatus prints the remote daemon's operational snapshot. Wraps
// `meshtermd status --json` over SSH; renders as a table by default
// or re-emits raw JSON with --json.
func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the ssh round-trip")
	asJSON := fs.Bool("json", false, "emit the daemon's JSON shape verbatim on stdout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl status [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, "meshtermd status --json", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl status: %v\n", err)
		return exitRemote
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "mtctl status: remote `meshtermd status` exited %d\n%s", code, stderr)
		return exitRemote
	}

	if *asJSON {
		fmt.Print(stdout)
		if !endsWithNewline(stdout) {
			fmt.Println()
		}
		return exitOK
	}

	var resp ipc.StatusResponse
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl status: cannot parse daemon output: %v\n", err)
		return exitErr
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host\t%s\n", target)
	fmt.Fprintf(w, "Version\t%s\n", resp.Version)
	fmt.Fprintf(w, "Uptime\t%s\n", shortDur(time.Duration(resp.UptimeNs)))
	fmt.Fprintf(w, "QUIC addr\t%s\n", resp.QUICAddr)
	fmt.Fprintf(w, "Cert fingerprint\t%s\n", resp.CertFingerprint)
	fmt.Fprintf(w, "Sessions\t%d / %d\n", resp.SessionCount, resp.MaxSessions)
	fmt.Fprintf(w, "Idle timeout\t%s\n", shortDur(time.Duration(resp.IdleTimeoutNs)))
	if resp.MaxIdleTimeoutNs > 0 {
		fmt.Fprintf(w, "Max idle timeout\t%s\n", shortDur(time.Duration(resp.MaxIdleTimeoutNs)))
	} else {
		fmt.Fprintln(w, "Max idle timeout\t(no ceiling)")
	}
	fmt.Fprintf(w, "Pending attach tokens\t%d\n", resp.PendingTokens)
	_ = w.Flush()
	return exitOK
}
