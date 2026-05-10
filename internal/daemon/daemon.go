// Package daemon orchestrates the long-running pieces of meshtermd:
// the session registry, the QUIC listener, and the unix-socket IPC
// server that `meshtermd connect` talks to.
//
// One Daemon per `meshtermd serve` invocation. Run blocks until the
// passed context is cancelled, at which point everything is drained
// in dependency order: IPC server (no new attaches reservable), QUIC
// listener (no new connections), then the registry's Shutdown
// (closes every live session, freeing PTYs).
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/pty"
	"github.com/AG-Studio-Apps/meshtermd/internal/session"
	"github.com/AG-Studio-Apps/meshtermd/internal/transport"
)

// Config is the daemon's runtime configuration. Defaults are
// applied for any zero / unset fields.
type Config struct {
	// QUICAddr is the bind address for the QUIC listener. Default
	// "127.0.0.1:0" — loopback only, kernel-chosen port. Operators
	// who want the daemon reachable on a Tailnet IP / LAN address
	// should override explicitly (the systemd unit shipped with the
	// release does this for testing).
	QUICAddr string

	// IPCSocketPath is the unix socket `meshtermd connect` dials.
	// Required.
	IPCSocketPath string

	// CertDir is the directory where the daemon's self-signed cert
	// + key are persisted. Defaults to cert.DefaultDir.
	CertDir string

	// MaxSessions caps concurrent live sessions. Defaults to
	// session.DefaultMaxSessions.
	MaxSessions int

	// IdleTimeout is how long a detached session can sit before GC
	// when the client doesn't request its own value. Defaults to
	// session.DefaultIdleTimeout.
	IdleTimeout time.Duration

	// MaxIdleTimeout is the ceiling on per-session timeouts a client
	// may request. Zero means no ceiling — appropriate for the
	// personal-server deployment where one user trusts the daemon
	// they're running. Operators of multi-user / shared meshtermd
	// hosts should set this to bound resource cost from a runaway
	// client requesting a 30-day timeout on every session.
	MaxIdleTimeout time.Duration

	// Logger receives operational logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Daemon owns the lifetime of the long-running server pieces.
type Daemon struct {
	cfg      Config
	logger   *slog.Logger
	cert     tls.Certificate
	certFP   cert.Fingerprint
	registry *session.Registry
	quic     *transport.Server
	ipc      *ipc.Server
}

// New constructs a Daemon. Loads or generates the TLS cert,
// creates the session registry, builds the QUIC listener and IPC
// server. Does NOT start any goroutines — call Run for that.
func New(cfg Config) (*Daemon, error) {
	if cfg.IPCSocketPath == "" {
		return nil, errors.New("daemon: Config.IPCSocketPath is required")
	}
	if cfg.QUICAddr == "" {
		// Audit F-A (v0.0.2 review): library default is loopback so
		// embedders who forget to set QUICAddr don't accidentally
		// expose the daemon on every interface. The CLI flag's
		// own default (`serve.go --addr`) was already 127.0.0.1:0;
		// this aligns the library with that.
		cfg.QUICAddr = "127.0.0.1:0"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	mgr := &cert.Manager{Dir: cfg.CertDir}
	tlsCert, fp, err := mgr.LoadOrGenerate()
	if err != nil {
		return nil, fmt.Errorf("load/generate cert: %w", err)
	}

	reg := session.NewRegistry(cfg.MaxSessions, cfg.IdleTimeout, 0, cfg.MaxIdleTimeout)

	d := &Daemon{
		cfg:      cfg,
		logger:   logger,
		cert:     tlsCert,
		certFP:   fp,
		registry: reg,
	}

	d.quic, err = transport.New(transport.Config{
		Addr:    cfg.QUICAddr,
		Cert:    tlsCert,
		Handler: &transport.ProtocolHandler{Registry: reg, Logger: logger},
	})
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	d.ipc, err = ipc.NewServer(cfg.IPCSocketPath, d)
	if err != nil {
		_ = d.quic.Close()
		return nil, fmt.Errorf("ipc: %w", err)
	}

	return d, nil
}

// Addr returns the QUIC listener's bound UDP address. Useful for
// tests and for logging "we're ready" lines that include the
// chosen port.
func (d *Daemon) Addr() string { return d.quic.Addr().String() }

// CertFingerprint returns the SHA-256 fingerprint of the daemon's
// TLS cert — the value the iOS client pins via the bootstrap line.
func (d *Daemon) CertFingerprint() cert.Fingerprint { return d.certFP }

// IPCSocketPath returns the unix socket path the IPC server is
// bound to.
func (d *Daemon) IPCSocketPath() string { return d.ipc.Path() }

// Run drives the registry GC loop, the QUIC listener, and the IPC
// server until ctx is cancelled. Returns the first error any
// component returns, or nil on graceful shutdown.
//
// Shutdown order: cancel ctx → IPC and QUIC servers' Serve loops
// return → registry.Run's deferred Shutdown closes all sessions →
// QUIC listener and IPC socket are closed.
func (d *Daemon) Run(ctx context.Context) error {
	d.logger.InfoContext(ctx, "meshtermd starting",
		"quic_addr", d.Addr(),
		"ipc_socket", d.IPCSocketPath(),
		"cert_fp", d.certFP.String(),
	)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		d.registry.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := d.quic.Serve(ctx); err != nil {
			errCh <- fmt.Errorf("quic serve: %w", err)
			cancel()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := d.ipc.Serve(ctx); err != nil {
			errCh <- fmt.Errorf("ipc serve: %w", err)
			cancel()
		}
	}()

	<-ctx.Done()
	_ = d.ipc.Close()
	_ = d.quic.Close()
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// HandleAllocate is the IPC dispatch for AllocateRequest. It either
// looks up an existing session or creates a new one (spawning a
// PTY), then issues an attach token and returns the bootstrap line
// fields.
func (d *Daemon) HandleAllocate(ctx context.Context, req ipc.AllocateRequest) ipc.AllocateResponse {
	sess, err := d.lookupOrCreateSession(req)
	if err != nil {
		// lookupOrCreateSession returns the response-shaped error
		// already; surface it.
		return errResponse(err)
	}

	tok, err := d.registry.IssueAttachToken(sess.ID())
	if err != nil {
		return ipc.AllocateResponse{Ok: false, Err: ipc.ErrInternal, Msg: err.Error()}
	}

	return ipc.AllocateResponse{
		Ok:          true,
		SessionID:   sess.ID().String(),
		AttachToken: tok.String(),
		Port:        uint16(d.quic.Addr().Port),
		CertFP:      d.certFP.String(),
		Name:        sess.Name(),
	}
}

// HandlePing implements ipc.Handler.
func (d *Daemon) HandlePing(ctx context.Context, req ipc.PingRequest) ipc.PingResponse {
	return ipc.PingResponse{Nonce: req.Nonce}
}

// HandleListSessions returns a snapshot of every live session on
// the registry. The snapshot is taken in two passes — registry.IDs()
// under the registry's lock, then per-session Lookup + accessors —
// so a slow session reader (e.g. one whose mu is held by an Acquire
// in flight) can't stall the registry-wide enumeration. Best-effort:
// a session reaped between IDs() and Lookup is silently skipped.
func (d *Daemon) HandleListSessions(ctx context.Context, _ ipc.ListSessionsRequest) ipc.ListSessionsResponse {
	ids := d.registry.IDs()
	out := make([]ipc.SessionInfo, 0, len(ids))
	for _, id := range ids {
		sess, err := d.registry.Lookup(id)
		if err != nil {
			continue
		}
		rows, cols := sess.WindowSize()
		out = append(out, ipc.SessionInfo{
			ID:             sess.ID().String(),
			Name:           sess.Name(),
			CreatedAtNs:    sess.Created().UnixNano(),
			LastActiveAtNs: sess.LastActiveAt().UnixNano(),
			AttachedNow:    sess.IsAttached(),
			IdleTimeoutNs:  int64(sess.IdleTimeout()),
			Rows:           rows,
			Cols:           cols,
		})
	}
	return ipc.ListSessionsResponse{Ok: true, Sessions: out}
}

// HandleKillSession reaps a session by hex SessionID or by Name.
// Selector resolution: try parse as hex SessionID first; on parse
// failure, try LookupByName. Either way, the registry's Remove
// closes the session (which terminates the PTY and cancels any
// active attach).
func (d *Daemon) HandleKillSession(ctx context.Context, req ipc.KillSessionRequest) ipc.KillSessionResponse {
	if req.Sel == "" {
		return ipc.KillSessionResponse{Ok: false, Err: ipc.ErrBadRequest, Msg: "selector required"}
	}
	if sid, err := session.ParseSessionID(req.Sel); err == nil {
		// Selector parsed as a SessionID — verify the session exists
		// before reporting success, so the caller can distinguish
		// "I asked you to kill X" from "X was already gone."
		if _, lerr := d.registry.Lookup(sid); lerr != nil {
			return ipc.KillSessionResponse{Ok: false, Err: ipc.ErrUnknownSession, Msg: lerr.Error()}
		}
		d.registry.Remove(sid)
		d.logger.Info("session killed", "session", sid.String(), "by", "id")
		return ipc.KillSessionResponse{Ok: true}
	}
	// Fall through: treat as a name.
	sess, err := d.registry.LookupByName(req.Sel)
	if err != nil {
		return ipc.KillSessionResponse{Ok: false, Err: ipc.ErrUnknownSession, Msg: err.Error()}
	}
	id := sess.ID()
	d.registry.Remove(id)
	d.logger.Info("session killed", "session", id.String(), "name", req.Sel, "by", "name")
	return ipc.KillSessionResponse{Ok: true}
}

// lookupOrCreateSession returns the session referenced by req. If
// SessionID is empty or "new", a new session is spawned (which
// includes opening a PTY and starting the Pump goroutine).
//
// Errors are wrapped in allocateErr so the caller can map them to
// AllocateResponse fields.
func (d *Daemon) lookupOrCreateSession(req ipc.AllocateRequest) (*session.Session, error) {
	if req.SessionID == "" || req.SessionID == "new" {
		return d.spawnSession(req)
	}

	sid, err := session.ParseSessionID(req.SessionID)
	if err != nil {
		return nil, &allocateErr{Code: ipc.ErrBadRequest, Msg: err.Error()}
	}
	sess, err := d.registry.Lookup(sid)
	if err != nil {
		return nil, &allocateErr{Code: ipc.ErrUnknownSession, Msg: err.Error()}
	}
	// Do NOT resize the PTY on reattach. iOS sends a Resize control
	// frame after Attach with the actual terminal size; if we also
	// resize here from req.Rows/Cols, the PTY size bounces (e.g.
	// 40×45 → 24×80 from the hardcoded CLI args, then 40×45 again
	// from the QUIC Resize) and each transition fires SIGWINCH at
	// the child shell, which redraws its prompt — two extra prompt
	// bytes go into the ring buffer per cold-start.
	//
	// req.Rows/Cols are still meaningful for the spawn path above
	// (initial PTY size for new sessions). For reattach, the QUIC
	// control-frame path is the single source of truth.
	return sess, nil
}

// spawnSession opens a PTY + child shell, wraps it in a Session,
// adds to the registry, and starts the Pump.
func (d *Daemon) spawnSession(req ipc.AllocateRequest) (*session.Session, error) {
	sid, err := session.NewSessionID()
	if err != nil {
		return nil, &allocateErr{Code: ipc.ErrInternal, Msg: "generate session id: " + err.Error()}
	}

	rows, cols := req.Rows, req.Cols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	// Default-naming policy: every session has a non-empty
	// user-visible name, even when the client didn't supply one.
	// `session-<first-6-hex-of-id>` is short enough to fit a chip,
	// stable across reattaches, and impossible to collide with a
	// user-chosen name (no user picks 6 hex chars deliberately).
	name := req.Name
	if name == "" {
		name = "session-" + sid.String()[:6]
	}

	// Resolve the per-session idle timeout: client request → ceiling
	// → daemon default. Stored on the Session itself so future GC
	// sweeps consult its value rather than the daemon-wide default.
	idleTimeout := d.registry.ResolveIdleTimeout(time.Duration(req.IdleTimeoutNanos))

	spawnCfg := pty.SpawnConfig{
		Shell: req.Shell,
		Args:  req.Exec,
		Rows:  rows,
		Cols:  cols,
		ExtraEnv: []string{
			"MESHTERM_SESSION_ID=" + sid.String(),
			// MESHTERM_ROAM=1 is a guard variable user shells can
			// check to avoid auto-attaching to tmux/screen on Roam
			// sessions. Without it, a typical .bashrc / .zshrc that
			// runs `tmux attach -t main || tmux new -s main` on
			// interactive login lands the Roam shell inside the same
			// tmux session as a regular SSH client — multi-attach
			// mirrors keystrokes and breaks the user's terminal UX.
			// Recommended .bashrc guard:
			//
			//   if [[ -z "$TMUX" && -z "$MESHTERM_ROAM" && $- == *i* ]]; then
			//     tmux attach -t main || tmux new -s main
			//   fi
			//
			// The Roam shell is already persistent via meshtermd's
			// own session registry, so skipping tmux is a no-op
			// from the user's persistence perspective.
			"MESHTERM_ROAM=1",
		},
	}
	ptyHandle, err := pty.Spawn(spawnCfg)
	if err != nil {
		return nil, &allocateErr{Code: ipc.ErrSpawnFailed, Msg: err.Error()}
	}

	sess, err := session.NewSession(sid, name, ptyHandle, rows, cols, 0, idleTimeout)
	if err != nil {
		_ = ptyHandle.Close()
		return nil, &allocateErr{Code: ipc.ErrInternal, Msg: err.Error()}
	}

	if err := d.registry.Add(sess); err != nil {
		_ = sess.Close()
		code := ipc.ErrInternal
		switch {
		case errors.Is(err, session.ErrCapacityReached):
			code = ipc.ErrCapacity
		case errors.Is(err, session.ErrDuplicateName):
			code = ipc.ErrNameInUse
		}
		return nil, &allocateErr{Code: code, Msg: err.Error()}
	}

	go sess.Pump()
	d.logger.Info("session spawned",
		"session", sid.String(),
		"name", name,
		"rows", rows, "cols", cols,
	)
	return sess, nil
}

// allocateErr is a typed error carrying the wire-level error code +
// message that should appear in AllocateResponse.
type allocateErr struct {
	Code string
	Msg  string
}

func (e *allocateErr) Error() string { return e.Code + ": " + e.Msg }

func errResponse(err error) ipc.AllocateResponse {
	var ae *allocateErr
	if errors.As(err, &ae) {
		return ipc.AllocateResponse{Ok: false, Err: ae.Code, Msg: ae.Msg}
	}
	return ipc.AllocateResponse{Ok: false, Err: ipc.ErrInternal, Msg: err.Error()}
}
