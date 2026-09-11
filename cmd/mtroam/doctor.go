package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/AG-Studio-Apps/mtroamd/internal/build"
)

// daemonDoctorReport mirrors the shape `mtroamd doctor --json`
// emits. We don't import the daemon's struct directly because mtroam
// is a client; copying the fields keeps the cross-binary surface
// explicit. If the daemon adds fields, older mtroam ignores them
// (json.Unmarshal silently drops unknowns).
//
// Field-for-field with cmd/mtroamd/doctor.go's DoctorReport.
type daemonDoctorReport struct {
	Doctor     string `json:"doctor"`
	Daemon     struct {
		Running      bool   `json:"running"`
		Version      string `json:"version,omitempty"`
		UptimeNs     int64  `json:"uptime_ns,omitempty"`
		QUICAddr     string `json:"quic_addr,omitempty"`
		MTRoamTCPAddr  string `json:"mtroam_tcp_addr,omitempty"`
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

// mtroamDoctorReport extends the daemon's report with the laptop-side
// checks: SSH reachability (implicit — if we got the report, SSH is
// fine) and mtroam-vs-daemon version skew.
type mtroamDoctorReport struct {
	Mtroam struct {
		Version string `json:"version"`
	} `json:"mtroam"`
	Host    string             `json:"host"`
	Skew    *versionSkew       `json:"version_skew,omitempty"`
	Server  daemonDoctorReport `json:"server"`
}

type versionSkew struct {
	MtroamVersion  string `json:"mtroam_version"`
	DaemonVersion string `json:"daemon_version"`
	Note          string `json:"note"`
}

// runDoctor wraps `mtroamd doctor --json` over SSH and renders the
// combined report. Human output is hierarchical text; --json emits the
// mtroamDoctorReport verbatim.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	host := fs.String("host", "", "SSH target running mtroamd (or set $MTROAM_HOST)")
	timeout := fs.Duration("timeout", 15*time.Second, "max time for the ssh round-trip")
	asJSON := fs.Bool("json", false, "emit the diagnostic report as JSON on stdout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtroam doctor [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	target, err := resolveHost(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitConfig
	}

	ctx := context.Background()
	stdout, stderr, code, err := runRemote(ctx, target, "mtroamd doctor --json", *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mtroam doctor: %v\n", err)
		return exitRemote
	}
	// Exit code 1 from `mtroamd doctor` means "warnings present" —
	// we still want to render the report. Treat anything > 1 (or a
	// non-2-non-1 unknown code) as a hard failure.
	if code > 1 {
		fmt.Fprintf(os.Stderr, "mtroam doctor: remote exited %d\n%s", code, sanitizeMultilineForDisplay(stderr))
		return exitRemote
	}

	var server daemonDoctorReport
	if err := json.Unmarshal([]byte(stdout), &server); err != nil {
		fmt.Fprintf(os.Stderr, "mtroam doctor: parse daemon JSON: %v\nraw: %s\n", err, sanitizeMultilineForDisplay(stdout))
		return exitErr
	}

	report := mtroamDoctorReport{Host: target, Server: server}
	report.Mtroam.Version = build.Version

	if server.Daemon.Running && server.Daemon.Version != "" {
		if !versionsMatchLoose(build.Version, server.Daemon.Version) {
			report.Skew = &versionSkew{
				MtroamVersion:  build.Version,
				DaemonVersion: server.Daemon.Version,
				Note: "mtroam and mtroamd versions differ; update the older side " +
					"with `mtroam update` or `mtroamd update`",
			}
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "mtroam doctor: json encode: %v\n", err)
			return exitErr
		}
		if code == 1 || report.Skew != nil {
			return exitErr
		}
		return exitOK
	}

	fmt.Println("mtroam doctor — combined report")
	fmt.Printf("  mtroam build:     %s\n", report.Mtroam.Version)
	fmt.Printf("  Remote host:     %s\n", sanitizeForDisplay(report.Host))
	if report.Skew != nil {
		// DaemonVersion is daemon-supplied; MtroamVersion is our own
		// compiled-in build string.
		fmt.Printf("  Version skew:    ✘ mtroam=%s vs daemon=%s\n",
			report.Skew.MtroamVersion, sanitizeForDisplay(report.Skew.DaemonVersion))
		fmt.Printf("                   %s\n", sanitizeForDisplay(report.Skew.Note))
	}
	fmt.Println()
	// The daemon's report is already a well-formatted block — pipe it
	// to stdout by re-running the SSH command without --json. Cheap
	// and avoids duplicating the daemon's table-rendering logic
	// across two binaries. Sanitize it (line-preserving) before it
	// reaches the terminal: it is daemon-supplied and may carry
	// attacker-influenced fields (host process paths, contact errors).
	stdout2, _, _, _ := runRemote(ctx, target, "mtroamd doctor", *timeout)
	safe2 := sanitizeMultilineForDisplay(stdout2)
	fmt.Print(safe2)
	if !endsWithNewline(safe2) {
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
func versionsMatchLoose(mtroam, daemon string) bool {
	mt := firstToken(mtroam)
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
