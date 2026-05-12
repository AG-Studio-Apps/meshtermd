package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

// Exit codes for `meshtermd connect`, matching docs/roam-protocol.md
// § 4.4 so iOS-side detection can branch on them deterministically.
const (
	connectExitOK              = 0
	connectExitGenericError    = 1
	connectExitDaemonNotRunning = 2
	connectExitUnknownSession  = 3
	connectExitCapacity        = 4
)

// runConnect is the SSH-side helper. It dials the daemon's unix
// socket, sends an AllocateRequest, prints the bootstrap line on
// stdout, and exits.
func runConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	sessionID := fs.String("session", "new", "session id (32 hex chars) to reattach, or 'new' for a fresh session")
	rows := fs.Uint("rows", 24, "initial PTY rows (new sessions only)")
	cols := fs.Uint("cols", 80, "initial PTY cols (new sessions only)")
	exec := fs.String("exec", "", "command to run inside the new session (default: user's $SHELL)")
	shell := fs.String("shell", "", "override the user's shell for new sessions")
	socket := fs.String("socket", "", "unix socket path (default: $XDG_RUNTIME_DIR/meshtermd.sock)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for the daemon to respond")
	idleTimeout := fs.Duration("idle-timeout", 0,
		"per-session idle timeout — how long the daemon keeps this session alive while no client is attached "+
			"and the shell is producing no output. 0 = use the daemon's default. A negative value (e.g. -1s) means "+
			"\"Never\" — the session opts out of GC and lives until the daemon dies (SIGTERM, reboot, update, or "+
			"crash). Applied on both fresh spawns AND on reattach: passing a different value than the existing "+
			"session's timeout updates it in place (this is how the iOS Keep-alive picker change reaches an "+
			"already-running session). Clamped at the daemon's --max-idle-timeout ceiling when set, including "+
			"the \"Never\" path so a shared-host operator's policy isn't bypassed.")
	name := fs.String("name", "",
		"user-visible session name. With --session=new (or omitted), enables 'create-if-missing': the daemon "+
			"reattaches to an existing session of this name, or spawns a fresh one with this name. With "+
			"--session=<hex>, --name is ignored (the session's identity is fixed at creation).")
	persist := fs.Bool("persist", false,
		"opt this session into cross-restart persistence. The daemon snapshots the scrollback + metadata to "+
			"~/.local/share/meshtermd/sessions/ so the session survives daemon updates and host reboots. "+
			"Mutually exclusive with --no-persist. When neither is set, the daemon's --persistence-default "+
			"applies. Ignored on reattach to an existing session (persistence is fixed at spawn).")
	noPersist := fs.Bool("no-persist", false,
		"opt this session OUT of cross-restart persistence. Use on hosts where --persistence-default is on "+
			"but a specific session is sensitive (e.g. one-off commands you don't want lingering on disk).")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd connect [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	socketPath := *socket
	if socketPath == "" {
		socketPath = discoverClientSocketPath()
	}

	if *rows > 65535 || *cols > 65535 {
		fmt.Fprintln(os.Stderr, "meshtermd connect: rows/cols out of range")
		return connectExitGenericError
	}

	var execArgs []string
	if *exec != "" {
		// Split on whitespace. We accept the simple case of
		// `--exec "tmux new -A -s default"` rather than asking the
		// caller to repeat the flag. Quoting beyond simple
		// whitespace is out of scope; if you need it, set $SHELL
		// to a wrapper script.
		execArgs = strings.Fields(*exec)
	}

	client := ipc.NewClient(socketPath, *timeout)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Resolve --persist / --no-persist into the tri-state *bool the
	// IPC request expects. Both set is a usage error; neither set
	// leaves the field nil so the daemon's default applies.
	if *persist && *noPersist {
		fmt.Fprintln(os.Stderr, "meshtermd connect: --persist and --no-persist are mutually exclusive")
		return connectExitGenericError
	}
	var persistPtr *bool
	if *persist {
		v := true
		persistPtr = &v
	} else if *noPersist {
		v := false
		persistPtr = &v
	}

	resp, err := client.Allocate(ctx, ipc.AllocateRequest{
		SessionID:        *sessionID,
		Rows:             uint16(*rows),
		Cols:             uint16(*cols),
		Exec:             execArgs,
		Shell:            *shell,
		IdleTimeoutNanos: int64(*idleTimeout),
		Name:             *name,
		Persist:          persistPtr,
	})
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			fmt.Fprintf(os.Stderr, "meshtermd connect: daemon not running at %s. Start it with `meshtermd serve` first.\n", socketPath)
			return connectExitDaemonNotRunning
		}
		fmt.Fprintf(os.Stderr, "meshtermd connect: %v\n", err)
		return connectExitGenericError
	}

	if !resp.Ok {
		fmt.Fprintf(os.Stderr, "meshtermd connect: %s: %s\n", resp.Err, resp.Msg)
		switch resp.Err {
		case ipc.ErrUnknownSession:
			return connectExitUnknownSession
		case ipc.ErrCapacity:
			return connectExitCapacity
		default:
			return connectExitGenericError
		}
	}

	// Print the bootstrap line per docs/roam-protocol.md § 4.2:
	//   MTRM_QUIC <version> <port> <session_id> <cert_fp> <attach_token>\n
	fmt.Printf("MTRM_QUIC 1 %d %s %s %s\n",
		resp.Port, resp.SessionID, resp.CertFP, resp.AttachToken)

	// Emit the daemon version on a second line so the iOS client (or
	// mtctl, or anything else parsing connect's stdout) can compare
	// the installed daemon to the version it pins. Forward-compat:
	// older daemons don't emit this; clients treat absence as "version
	// unknown" and skip the update banner. iOS uses this to surface
	// a "Daemon update available" affordance per host without an
	// extra SSH round-trip.
	//
	// Format is deliberately simple — one space, raw build.Version
	// (typically `vX.Y.Z` or `vX.Y.Z-dirty` for dev builds; the
	// client strips any suffix before semver comparison).
	fmt.Printf("MTRM_DAEMON_VERSION %s\n", build.Version)

	return connectExitOK
}
