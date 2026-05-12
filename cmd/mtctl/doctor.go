package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
)

// daemonDoctorReport mirrors the shape `meshtermd doctor --json`
// emits. We don't import the daemon's struct directly because mtctl
// is a client; copying the fields keeps the cross-binary surface
// explicit. If the daemon adds fields, older mtctl ignores them
// (json.Unmarshal silently drops unknowns).
//
// Field-for-field with cmd/meshtermd/doctor.go's DoctorReport.
type daemonDoctorReport struct {
	Doctor     string `json:"doctor"`
	Daemon     struct {
		Running      bool   `json:"running"`
		Version      string `json:"version,omitempty"`
		UptimeNs     int64  `json:"uptime_ns,omitempty"`
		QUICAddr     string `json:"quic_addr,omitempty"`
		CertFP       string `json:"cert_fingerprint,omitempty"`
		SessionCount int    `json:"session_count"`
		MaxSessions  int    `json:"max_sessions,omitempty"`
		IdleNs       int64  `json:"idle_timeout_ns,omitempty"`
		Socket       string `json:"socket"`
		ContactError string `json:"contact_error,omitempty"`
	} `json:"daemon"`
	Supervisor struct {
		Backend   string `json:"backend"`
		Available bool   `json:"available"`
	} `json:"supervisor"`
	UnitFile *struct {
		Backend         string `json:"backend"`
		Path            string `json:"path"`
		Present         bool   `json:"present"`
		KillModeProcess bool   `json:"kill_mode_process"`
	} `json:"unit_file,omitempty"`
	Linger *struct {
		User    string `json:"user"`
		Enabled bool   `json:"enabled"`
		Source  string `json:"source,omitempty"`
		Error   string `json:"error,omitempty"`
	} `json:"linger,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// mtctlDoctorReport extends the daemon's report with the laptop-side
// checks: SSH reachability (implicit — if we got the report, SSH is
// fine) and mtctl-vs-daemon version skew.
type mtctlDoctorReport struct {
	Mtctl struct {
		Version string `json:"version"`
	} `json:"mtctl"`
	Host    string             `json:"host"`
	Skew    *versionSkew       `json:"version_skew,omitempty"`
	Server  daemonDoctorReport `json:"server"`
}

type versionSkew struct {
	MtctlVersion  string `json:"mtctl_version"`
	DaemonVersion string `json:"daemon_version"`
	Note          string `json:"note"`
}

// runDoctor wraps `meshtermd doctor --json` over SSH and renders the
// combined report. Human output is hierarchical text; --json emits the
// mtctlDoctorReport verbatim.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running meshtermd (or set $MTCTL_HOST)")
	timeout := fs.Duration("timeout", 15*time.Second, "max time for the ssh round-trip")
	asJSON := fs.Bool("json", false, "emit the diagnostic report as JSON on stdout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl doctor [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, "meshtermd doctor --json", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtctl doctor: %v\n", err)
		return exitRemote
	}
	// Exit code 1 from `meshtermd doctor` means "warnings present" —
	// we still want to render the report. Treat anything > 1 (or a
	// non-2-non-1 unknown code) as a hard failure.
	if code > 1 {
		fmt.Fprintf(os.Stderr, "mtctl doctor: remote exited %d\n%s", code, stderr)
		return exitRemote
	}

	var server daemonDoctorReport
	if err := json.Unmarshal([]byte(stdout), &server); err != nil {
		fmt.Fprintf(os.Stderr, "mtctl doctor: parse daemon JSON: %v\nraw: %s\n", err, stdout)
		return exitErr
	}

	report := mtctlDoctorReport{Host: target, Server: server}
	report.Mtctl.Version = build.Version

	if server.Daemon.Running && server.Daemon.Version != "" {
		if !versionsMatchLoose(build.Version, server.Daemon.Version) {
			report.Skew = &versionSkew{
				MtctlVersion:  build.Version,
				DaemonVersion: server.Daemon.Version,
				Note: "mtctl and meshtermd versions differ; update the older side " +
					"with `mtctl update` or `meshtermd update`",
			}
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "mtctl doctor: json encode: %v\n", err)
			return exitErr
		}
		if code == 1 || report.Skew != nil {
			return exitErr
		}
		return exitOK
	}

	fmt.Println("mtctl doctor — combined report")
	fmt.Printf("  mtctl build:     %s\n", report.Mtctl.Version)
	fmt.Printf("  Remote host:     %s\n", report.Host)
	if report.Skew != nil {
		fmt.Printf("  Version skew:    ✘ mtctl=%s vs daemon=%s\n",
			report.Skew.MtctlVersion, report.Skew.DaemonVersion)
		fmt.Printf("                   %s\n", report.Skew.Note)
	}
	fmt.Println()
	// The daemon's report is already a well-formatted block — pipe it
	// to stdout by re-running the SSH command without --json. Cheap
	// and avoids duplicating the daemon's table-rendering logic
	// across two binaries.
	stdout2, _, _, _ := runRemote(ctx, target, "meshtermd doctor", *timeout)
	fmt.Print(stdout2)
	if !endsWithNewline(stdout2) {
		fmt.Println()
	}

	if code == 1 || report.Skew != nil {
		return exitErr
	}
	return exitOK
}

// versionsMatchLoose compares two version strings allowing the
// daemon's "vX.Y.Z (sha, built ...)" trailing detail. We compare the
// leading version token only. Returns true if the leading tokens are
// byte-equal.
func versionsMatchLoose(mtctl, daemon string) bool {
	mt := firstToken(mtctl)
	dm := firstToken(daemon)
	if mt == "" || dm == "" {
		return true // can't compare; don't false-positive a skew
	}
	return mt == dm
}

func firstToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '(' {
			return s[:i]
		}
	}
	return s
}
