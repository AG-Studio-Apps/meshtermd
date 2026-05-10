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

// Exit codes for `meshtermd status`:
//
//	0  ok
//	1  generic error
//	2  daemon not running
const (
	statusExitOK               = 0
	statusExitGenericError     = 1
	statusExitDaemonNotRunning = 2
)

// runStatus prints the daemon's operational snapshot. Default
// output is a fixed-width table; --json emits the
// `StatusResponse` shape verbatim — what Phase 5's install flow
// and health probes will consume.
func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	asJSON := fs.Bool("json", false, "emit the snapshot as a JSON object on stdout (stable wire shape)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd status [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	socketPath := *socket
	if socketPath == "" {
		socketPath = defaultSocketPath()
	}

	client := ipc.NewClient(socketPath, *timeout)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := client.Status(ctx)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintf(os.Stderr, "meshtermd status: daemon not running at %s.\n", socketPath)
			return statusExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd status: %v\n", err)
		return statusExitGenericError
	}
	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd status: %s: %s\n", resp.Err, resp.Msg)
		return statusExitGenericError
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(resp); err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd status: json encode: %v\n", err)
			return statusExitGenericError
		}
		return statusExitOK
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
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
	return statusExitOK
}
