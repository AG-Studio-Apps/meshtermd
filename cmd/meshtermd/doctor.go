package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/svcmgr"
)

// Exit codes for `meshtermd doctor`.
const (
	doctorExitOK       = 0
	doctorExitWarnings = 1
)

// DoctorReport is the JSON shape `meshtermd doctor --json` emits.
// mtctl + iOS consume this directly; field names are stable.
//
// Daemon section is populated from a Status IPC call. If the daemon
// isn't running, Daemon.Running=false and the rest of Daemon is
// zero-valued — the other sections (Supervisor, UnitFile, Linger)
// still get populated from local introspection so the doctor is useful
// for diagnosing "why isn't my daemon up?"
type DoctorReport struct {
	Doctor     string         `json:"doctor"` // build identifier of the doctor that ran
	Daemon     DaemonHealth   `json:"daemon"`
	Supervisor SupervisorInfo `json:"supervisor"`
	UnitFile   *UnitFileInfo  `json:"unit_file,omitempty"`
	Linger     *LingerInfo    `json:"linger,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
}

// DaemonHealth carries the live operational snapshot from the local
// daemon. Mirrors ipc.StatusResponse but adds a Running bool so the
// JSON consumer knows whether the rest of the fields are meaningful.
type DaemonHealth struct {
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
}

// SupervisorInfo identifies which Manager (systemd-user / launchd /
// nohup) would handle this daemon, plus whether it's Available right
// now (its tooling reachable from this process).
type SupervisorInfo struct {
	Backend   string `json:"backend"`
	Available bool   `json:"available"`
}

// UnitFileInfo describes the on-disk supervisor unit / plist. Present
// is whether the file exists. KillModeProcess is the v0.6+ load-bearing
// check — units written before 2026-05-12 lack it and lose sessions on
// `meshtermd update`. Only meaningful for systemd-user; on launchd
// the field is always false (no equivalent concept) and consumers
// should ignore it.
type UnitFileInfo struct {
	Backend         string `json:"backend"`
	Path            string `json:"path"`
	Present         bool   `json:"present"`
	KillModeProcess bool   `json:"kill_mode_process"`
}

// LingerInfo reports whether `loginctl enable-linger` is set for the
// current user. Linux only; nil on macOS / BSDs. Linger is what keeps
// a systemd-user instance running across SSH logout — without it the
// daemon dies as soon as the last login session ends, taking every
// terminal session with it.
type LingerInfo struct {
	User    string `json:"user"`
	Enabled bool   `json:"enabled"`
	Source  string `json:"source,omitempty"` // "loginctl" or "fallback"
	Error   string `json:"error,omitempty"`
}

// runDoctor compiles a DoctorReport and prints it. Default output is
// a fixed-width table; --json emits the report verbatim.
//
// Exit code: 0 if no warnings, 1 if any warning surfaced (e.g. daemon
// down, KillMode=process missing, linger disabled). Bad flags exit 2
// via flag.ExitOnError.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 3*time.Second, "max time to wait for daemon IPC")
	asJSON := fs.Bool("json", false, "emit the diagnostic report as JSON on stdout (stable wire shape)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd doctor [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	socketPath := *socket
	if socketPath == "" {
		socketPath = discoverClientSocketPath()
	}

	report := buildDoctorReport(socketPath, *timeout)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "meshtermd doctor: json encode: %v\n", err)
			return doctorExitWarnings
		}
		if len(report.Warnings) > 0 {
			return doctorExitWarnings
		}
		return doctorExitOK
	}

	printDoctorReport(os.Stdout, report)
	if len(report.Warnings) > 0 {
		return doctorExitWarnings
	}
	return doctorExitOK
}

// buildDoctorReport composes the report. Each section is best-effort:
// failures get recorded in the Warnings list rather than aborting.
func buildDoctorReport(socketPath string, timeout time.Duration) DoctorReport {
	r := DoctorReport{
		Doctor: build.Version,
		Daemon: DaemonHealth{Socket: socketPath},
	}

	// 1. Daemon health via IPC Status.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := ipc.NewClient(socketPath, timeout)
	status, err := client.Status(ctx)
	if err != nil {
		r.Daemon.Running = false
		r.Daemon.ContactError = err.Error()
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("daemon not running at %s", socketPath))
		} else {
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("daemon IPC failed: %v", err))
		}
	} else if !status.Ok {
		r.Daemon.Running = false
		r.Daemon.ContactError = status.Msg
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("daemon returned not-ok: %s", status.Msg))
	} else {
		r.Daemon.Running = true
		r.Daemon.Version = status.Version
		r.Daemon.UptimeNs = status.UptimeNs
		r.Daemon.QUICAddr = status.QUICAddr
		r.Daemon.CertFP = status.CertFingerprint
		r.Daemon.SessionCount = status.SessionCount
		r.Daemon.MaxSessions = status.MaxSessions
		r.Daemon.IdleNs = status.IdleTimeoutNs
	}

	// 2. Supervisor introspection. Detect always returns a Manager
	//    (nohup fallback); Available tells us if its tooling is
	//    reachable on this host.
	mgr := svcmgr.Detect(ctx)
	r.Supervisor = SupervisorInfo{
		Backend:   mgr.Name(),
		Available: mgr.Available(ctx),
	}

	// 3. Unit/plist file. UnitPath returns "" for nohup.
	if unitPath := mgr.UnitPath(); unitPath != "" {
		info := &UnitFileInfo{
			Backend: mgr.Name(),
			Path:    unitPath,
		}
		if data, err := os.ReadFile(unitPath); err == nil {
			info.Present = true
			if mgr.Name() == "systemd-user" {
				info.KillModeProcess = unitHasKillModeProcess(data)
				if !info.KillModeProcess {
					r.Warnings = append(r.Warnings,
						"unit file missing `KillMode=process` — sessions will be killed "+
							"when meshtermd restarts (run `meshtermd unit print > "+unitPath+
							"` to refresh)")
				}
			}
		} else if os.IsNotExist(err) {
			info.Present = false
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("supervisor backend %s but unit file missing at %s",
					mgr.Name(), unitPath))
		} else {
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("could not read unit file %s: %v", unitPath, err))
		}
		r.UnitFile = info
	}

	// 4. Linger check (Linux only; systemd-user backend).
	if runtime.GOOS == "linux" && mgr.Name() == "systemd-user" {
		r.Linger = buildLingerInfo(ctx)
		if r.Linger != nil && !r.Linger.Enabled && r.Linger.Error == "" {
			r.Warnings = append(r.Warnings,
				"linger disabled for "+r.Linger.User+"; sessions die at logout — "+
					"run `loginctl enable-linger "+r.Linger.User+"` to keep them alive")
		}
	}

	return r
}

// unitHasKillModeProcess scans a systemd unit file for the
// load-bearing-since-v0.6 `KillMode=process` directive. Comments,
// leading whitespace, and quoting are tolerated — the systemd parser
// is forgiving, so the check matches that posture.
func unitHasKillModeProcess(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		// systemd accepts `Key=value`, `Key =value`, etc.
		eq := strings.Index(s, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(s[:eq])
		if !strings.EqualFold(key, "killmode") {
			continue
		}
		val := strings.TrimSpace(strings.Trim(s[eq+1:], "\"'"))
		if strings.EqualFold(val, "process") {
			return true
		}
	}
	return false
}

// buildLingerInfo queries loginctl for the current user's linger
// status. Returns nil if user.Current fails (extremely unusual).
func buildLingerInfo(ctx context.Context) *LingerInfo {
	u, err := user.Current()
	if err != nil {
		return &LingerInfo{Error: err.Error()}
	}
	info := &LingerInfo{User: u.Username, Source: "loginctl"}
	cmd := exec.CommandContext(ctx, "loginctl", "show-user", u.Username,
		"--value", "-p", "Linger")
	out, err := cmd.Output()
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Enabled = strings.EqualFold(strings.TrimSpace(string(out)), "yes")
	return info
}

// printDoctorReport renders the human-readable form. Two-column key:
// value layout with section headers; mirrors `meshtermd status`'s
// table style for visual continuity.
func printDoctorReport(out *os.File, r DoctorReport) {
	fmt.Fprintln(out, "meshtermd doctor — diagnostic report")
	fmt.Fprintf(out, "  Doctor build:    %s\n", r.Doctor)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Daemon:")
	if r.Daemon.Running {
		fmt.Fprintf(out, "  Status:          ✓ running (%s)\n", r.Daemon.Version)
		fmt.Fprintf(out, "  Uptime:          %s\n", time.Duration(r.Daemon.UptimeNs))
		fmt.Fprintf(out, "  QUIC addr:       %s\n", r.Daemon.QUICAddr)
		fmt.Fprintf(out, "  Cert FP:         %s\n", r.Daemon.CertFP)
		fmt.Fprintf(out, "  Sessions:        %d / %d\n", r.Daemon.SessionCount, r.Daemon.MaxSessions)
		fmt.Fprintf(out, "  Idle timeout:    %s\n", time.Duration(r.Daemon.IdleNs))
	} else {
		fmt.Fprintf(out, "  Status:          ✘ not running\n")
		fmt.Fprintf(out, "  Socket:          %s\n", r.Daemon.Socket)
		if r.Daemon.ContactError != "" {
			fmt.Fprintf(out, "  Error:           %s\n", r.Daemon.ContactError)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Supervisor:")
	fmt.Fprintf(out, "  Backend:         %s\n", r.Supervisor.Backend)
	fmt.Fprintf(out, "  Available:       %s\n", boolMark(r.Supervisor.Available))
	if r.UnitFile != nil {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Unit file:")
		fmt.Fprintf(out, "  Path:            %s\n", r.UnitFile.Path)
		fmt.Fprintf(out, "  Present:         %s\n", boolMark(r.UnitFile.Present))
		if r.UnitFile.Backend == "systemd-user" && r.UnitFile.Present {
			fmt.Fprintf(out, "  KillMode=process: %s\n", boolMark(r.UnitFile.KillModeProcess))
		}
	}
	if r.Linger != nil {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Linger (systemd-user):")
		fmt.Fprintf(out, "  User:            %s\n", r.Linger.User)
		if r.Linger.Error != "" {
			fmt.Fprintf(out, "  Status:          ? %s\n", r.Linger.Error)
		} else {
			fmt.Fprintf(out, "  Enabled:         %s\n", boolMark(r.Linger.Enabled))
		}
	}
	fmt.Fprintln(out)
	if len(r.Warnings) == 0 {
		fmt.Fprintln(out, "✓ All checks passed.")
		return
	}
	fmt.Fprintf(out, "✘ %d warning(s):\n", len(r.Warnings))
	for _, w := range r.Warnings {
		fmt.Fprintf(out, "  - %s\n", w)
	}
}
