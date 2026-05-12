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
	"io"
	"log/slog"
	"sync"
	"time"

	"os"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
	"github.com/AG-Studio-Apps/meshtermd/internal/ptyclient"
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

	// SessionBufferBytes overrides the per-session output ring buffer
	// capacity. Zero falls back to session.DefaultBufferCapacity
	// (4 MiB). Operators who run long, output-heavy builds and want
	// generous reattach-replay history should raise this; the trade
	// is RAM per live session (one buffer per session). 16-32 MiB is
	// reasonable on a dev box; multi-MiB hits are fine even on a Pi.
	SessionBufferBytes int

	// PersistenceDefault controls whether new sessions opt into
	// cross-restart persistence when the client didn't specify
	// (AllocateRequest.Persist == nil). True (the default-on
	// posture) matches user-mental-model "of course my work
	// survives." Operators of shared / multi-user hosts can flip
	// this to false via `meshtermd serve --persistence-default off`
	// for privacy-by-default; individual sessions still opt back in
	// with explicit `--persist`.
	//
	// Defaults to true when the field is zero-value (uses the
	// `*bool` pattern so empty Config behaves correctly).
	PersistenceDefault *bool

	// PersistenceFlushInterval is how often each persisted session's
	// background flusher checkpoints its ring buffer to disk. Zero
	// falls back to 30s, which trades durability (lose up to 30s of
	// scrollback on crash) for write amplification (4 MiB buffer × 100
	// sessions × every 30s ≈ 13 MB/s peak even at full saturation,
	// well within any SSD's budget).
	PersistenceFlushInterval time.Duration

	// Logger receives operational logs. Defaults to slog.Default().
	Logger *slog.Logger

	// SidecarStderr is the io.Writer passed through to each spawned
	// sidecar's stderr. nil → os.Stderr (production posture: sidecar
	// logs surface in the daemon's journal). Tests pass io.Discard
	// to drop sidecar stderr so the test binary's stderr fd doesn't
	// stay open past reap (which makes `go test` park at WaitDelay).
	SidecarStderr io.Writer
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
	// stateDir is the persistence root resolved at New(). Reused by
	// spawnSession when starting the per-session flusher.
	stateDir string
	// daemonBinary is os.Executable() cached at New(). Re-exec'd as
	// `meshtermd pty-sidecar` for each session's PTY-owning helper.
	daemonBinary string
	// startedAt is set once in New so HandleStatus can compute
	// uptime without keeping a separate state machine.
	startedAt time.Time
}

// sessionExtraEnvForID returns the per-session env additions the
// daemon already injected into the in-process pty.SpawnConfig before
// the sidecar split. Centralised here so spawnSession + the
// PTYSpawner closure stay in sync.
func sessionExtraEnvForID(sid session.SessionID) []string {
	return []string{
		"MESHTERM_SESSION_ID=" + sid.String(),
		// MESHTERM_ROAM=1 lets user shells short-circuit auto-tmux
		// blocks in their rc files; see the original comment in
		// spawnSession for the recommended guard form.
		"MESHTERM_ROAM=1",
	}
}

// sessionExtraEnv is the *Session-flavoured wrapper used by the
// lazy-spawn closure where the SessionID lives behind the *Session.
func sessionExtraEnv(sess *session.Session) []string {
	return sessionExtraEnvForID(sess.ID())
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
	// Surface idle-GC reap events in the operational log. Pairs
	// with the session.attach / session.detach events emitted by
	// the transport layer so operators tailing logs see the full
	// lifecycle of a session.
	reg.OnReap = func(s *session.Session) {
		logger.Info("session.reaped",
			"session", s.ID().String(),
			"name", s.Name(),
		)
	}

	// Persistence wiring. State dir lives next to the cert dir
	// (cert.DefaultDir), so a single ~/.local/share/meshtermd holds
	// everything that survives daemon restart: cert, key, IPC socket,
	// and now per-session subdirs under sessions/.
	stateDir := cfg.CertDir
	if stateDir == "" {
		stateDir, err = cert.DefaultDir()
		if err != nil {
			return nil, fmt.Errorf("resolve state dir: %w", err)
		}
	}
	reg.SetStateDir(stateDir)
	if cfg.PersistenceDefault != nil {
		reg.SetPersistenceDefault(*cfg.PersistenceDefault)
	}
	// (Zero-value Config preserves the registry's default-on posture
	// set in NewRegistry — no setter call needed.)

	d := &Daemon{
		cfg:       cfg,
		logger:    logger,
		cert:      tlsCert,
		certFP:    fp,
		registry:  reg,
		stateDir:  stateDir,
		startedAt: time.Now(),
	}

	// Hydrate sessions that were persisted by a prior daemon run.
	// PTYs are NOT spawned here — protocol_handler does that lazily
	// on the first client attach. The flushers, however, are started
	// immediately so any output that arrives once a client attaches
	// gets checkpointed on the normal cadence.
	restored, lerr := session.LoadPersisted(stateDir, reg, logger)
	if lerr != nil {
		logger.Warn("session.persistence.load_failed", "err", lerr.Error())
	}
	if restored > 0 {
		logger.Info("session.persistence.restored", "count", restored)
	}
	for _, sid := range reg.IDs() {
		if s, lookupErr := reg.Lookup(sid); lookupErr == nil && s.Persist() {
			s.StartFlusher(stateDir, cfg.PersistenceFlushInterval, logger)
		}
	}

	// Cache os.Executable() once — we re-exec it as `meshtermd
	// pty-sidecar` for every session's PTY-owning helper process.
	daemonBinary, exeErr := os.Executable()
	if exeErr != nil {
		return nil, fmt.Errorf("os.Executable: %w", exeErr)
	}
	d.daemonBinary = daemonBinary

	// Reattach any sidecars that survived the previous daemon's exit.
	// Per-session pidfile + socket in {stateDir}/sessions/<sid>/ point
	// at live processes; we dial each and inject a sidecar-backed
	// PTY into the corresponding Session. Sessions whose sidecars
	// died (or never had one) fall through to the lazy-spawn path on
	// next attach, same as v0.5.x behaviour.
	if discovered, dErr := ptyclient.Discover(context.Background(), reg, stateDir, logger); dErr != nil {
		logger.Warn("session.sidecar.discovery_failed", "err", dErr.Error())
	} else if discovered > 0 {
		logger.Info("session.sidecar.reattached", "count", discovered)
	}

	d.quic, err = transport.New(transport.Config{
		Addr: cfg.QUICAddr,
		Cert: tlsCert,
		Handler: &transport.ProtocolHandler{
			Registry: reg,
			Logger:   logger,
			// PTYSpawner gives protocol_handler a way to lazy-spawn
			// the child shell for a restored session on its first
			// attach. We spawn an out-of-process sidecar so the
			// child shell survives subsequent daemon restarts —
			// see internal/ptysidecar for the design.
			PTYSpawner: func(sess *session.Session, rows, cols uint16) (session.PTY, error) {
				// context.Background here is fine: SpawnNew only uses
				// the ctx for the bounded 3 s dial-with-backoff, and a
				// daemon-shutdown that races a fresh spawn will just
				// see the sidecar disconnect cleanly via socket-close.
				return ptyclient.SpawnNew(context.Background(), ptyclient.SpawnConfig{
					SessionID:    sess.ID().String(),
					Rows:         rows,
					Cols:         cols,
					ExtraEnv:     sessionExtraEnv(sess),
					StateDir:     stateDir,
					DaemonBinary: daemonBinary,
					Logger:       logger,
					Stderr:       cfg.SidecarStderr,
				})
			},
		},
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
// Per-field size caps on IPC inputs. Same-uid trust model says the
// caller is friendly; these are defense-in-depth against a buggy or
// compromised local helper that could otherwise feed unbounded
// strings into our registry maps + log lines.
const (
	maxNameLen      = 256        // Session.Name; echoed in every list response + every log line.
	maxShellLen     = 4 * 1024   // Path to a shell binary; longer than this is pathological.
	maxExecJoinLen  = 16 * 1024  // Total bytes across all Exec[] joined by spaces.
	maxExecArgCount = 128        // Cap individual element count too — argv length is finite in practice.
)

func (d *Daemon) HandleAllocate(ctx context.Context, req ipc.AllocateRequest) ipc.AllocateResponse {
	if msg := validateAllocateBounds(req); msg != "" {
		return ipc.AllocateResponse{Ok: false, Err: ipc.ErrBadRequest, Msg: msg}
	}
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
		modes := sess.AttachedModes()
		out = append(out, ipc.SessionInfo{
			ID:             sess.ID().String(),
			Name:           sess.Name(),
			CreatedAtNs:    sess.Created().UnixNano(),
			LastActiveAtNs: sess.LastActiveAt().UnixNano(),
			AttachedNow:    len(modes) > 0,
			AttachedModes:  modes,
			IdleTimeoutNs:  int64(sess.IdleTimeout()),
			Rows:           rows,
			Cols:           cols,
		})
	}
	return ipc.ListSessionsResponse{Ok: true, Sessions: out}
}

// HandleStatus returns the daemon's operational snapshot. Pure
// read — no side effects. Used by `meshtermd status`, by Phase 5's
// install-flow version probe, and by systemd-unit health checks.
func (d *Daemon) HandleStatus(ctx context.Context, _ ipc.StatusRequest) ipc.StatusResponse {
	now := time.Now()
	return ipc.StatusResponse{
		Ok:               true,
		Version:          build.String(),
		StartedAtNs:      d.startedAt.UnixNano(),
		UptimeNs:         now.Sub(d.startedAt).Nanoseconds(),
		QUICAddr:         d.quic.Addr().String(),
		CertFingerprint:  d.certFP.String(),
		SessionCount:     d.registry.Len(),
		MaxSessions:      d.registry.Capacity(),
		IdleTimeoutNs:    int64(d.registry.IdleTimeout()),
		MaxIdleTimeoutNs: int64(d.registry.MaxIdleTimeout()),
		PendingTokens:    d.registry.PendingTokenCount(),
	}
}

// HandleRenameSession changes a session's user-visible Name.
// Selector resolution mirrors KillSession: hex SessionID first,
// fall back to LookupByName. The PTY + ring buffer + active
// attach are unaffected — this is a pure-label change.
func (d *Daemon) HandleRenameSession(ctx context.Context, req ipc.RenameSessionRequest) ipc.RenameSessionResponse {
	if req.Sel == "" {
		return ipc.RenameSessionResponse{Ok: false, Err: ipc.ErrBadRequest, Msg: "selector required"}
	}
	if req.NewName == "" {
		return ipc.RenameSessionResponse{Ok: false, Err: ipc.ErrBadRequest, Msg: "new name required"}
	}
	if len(req.NewName) > maxNameLen {
		return ipc.RenameSessionResponse{Ok: false, Err: ipc.ErrBadRequest,
			Msg: fmt.Sprintf("new name exceeds %d bytes", maxNameLen)}
	}

	// Resolve selector → SessionID.
	var sid session.SessionID
	if parsed, err := session.ParseSessionID(req.Sel); err == nil {
		sid = parsed
	} else {
		sess, lerr := d.registry.LookupByName(req.Sel)
		if lerr != nil {
			return ipc.RenameSessionResponse{Ok: false, Err: ipc.ErrUnknownSession, Msg: lerr.Error()}
		}
		sid = sess.ID()
	}

	if err := d.registry.Rename(sid, req.NewName); err != nil {
		code := ipc.ErrInternal
		switch {
		case errors.Is(err, session.ErrUnknownSession):
			code = ipc.ErrUnknownSession
		case errors.Is(err, session.ErrDuplicateName):
			code = ipc.ErrNameInUse
		}
		return ipc.RenameSessionResponse{Ok: false, Err: code, Msg: err.Error()}
	}
	d.logger.Info("session renamed", "session", sid.String(), "name", req.NewName)
	return ipc.RenameSessionResponse{Ok: true, Name: req.NewName}
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

// lookupOrCreateSession returns the session referenced by req. The
// resolution rules cover four cases:
//
//  1. SessionID is hex (parses cleanly) → look up by ID; error
//     if missing. Reattach path; req.Name is ignored.
//  2. SessionID == "" || SessionID == "new", req.Name is set →
//     "create-if-missing": look up by name; if found, attach to
//     it. If not found, spawn a fresh session with that name.
//     Matches tmux's `new -A -s name` idiom and is what the iOS
//     picker uses for "+ New named X" + every plain-tap probe.
//  3. SessionID == "" || SessionID == "new", req.Name is empty →
//     spawn a fresh anonymous session (daemon synthesises name).
//     Legacy "any session, no preferences" allocate.
//  4. SessionID is neither "new" nor a parseable hex string →
//     ErrBadRequest. Future overload (e.g., "name:foo") would land
//     here, but we don't ship that — see B1 in the plan.
//
// Errors are wrapped in allocateErr so the caller can map them to
// AllocateResponse fields.
func (d *Daemon) lookupOrCreateSession(req ipc.AllocateRequest) (*session.Session, error) {
	if req.SessionID == "" || req.SessionID == "new" {
		// Name-driven path: prefer reattach to an existing session
		// with this name, fall back to spawn. Empty Name → plain
		// anonymous spawn (legacy).
		if req.Name != "" {
			if sess, err := d.registry.LookupByName(req.Name); err == nil {
				d.applyIdleTimeoutOnReattach(sess, req)
				return sess, nil
			}
			// Not found — fall through to spawn (which will use
			// req.Name and may collide if the name was added
			// concurrently between LookupByName and Add; in that
			// race the spawn returns ErrNameInUse, which is
			// surfaced verbatim).
		}
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
	d.applyIdleTimeoutOnReattach(sess, req)
	return sess, nil
}

// applyIdleTimeoutOnReattach updates an existing session's idle
// timeout when the client's request specifies a different value.
// Without this the session would keep its original timeout — the
// iOS-side Keep-alive picker would silently no-op on reattach,
// which historically caused sessions to be GC'd at the OLD interval
// after a user edited the host (e.g. 1h → 30d).
//
// req.IdleTimeoutNanos == 0 means "use the daemon default" and is
// applied verbatim (matches the spawn-time semantics). A non-zero
// value is clamped at the registry's --max-idle-timeout ceiling
// before being written so an operator-set bound isn't bypassed.
func (d *Daemon) applyIdleTimeoutOnReattach(sess *session.Session, req ipc.AllocateRequest) {
	resolved := d.registry.ResolveIdleTimeout(time.Duration(req.IdleTimeoutNanos))
	if resolved == sess.IdleTimeout() {
		return
	}
	prev := sess.IdleTimeout()
	sess.SetIdleTimeout(resolved)
	d.logger.Info("session.idle_timeout_updated",
		"session", sess.ID().String(),
		"name", sess.Name(),
		"prev", prev.String(),
		"new", resolved.String(),
	)
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

	// Spawn the PTY-owning sidecar process. The sidecar holds the
	// child shell as a direct subprocess and survives subsequent
	// daemon restarts; the returned *ptyclient.Conn implements
	// session.PTY and slots in everywhere a *pty.Handle used to.
	//
	// MESHTERM_ROAM=1 lets user shells short-circuit auto-tmux blocks
	// in their rc files (we don't want Roam shells to nest inside the
	// user's regular tmux session — see the recommended guard form
	// in the sidecarExtraEnv comment). The Roam shell already
	// persists via meshtermd's own session machinery, so skipping
	// tmux is a no-op from the user's persistence perspective.
	ptyHandle, err := ptyclient.SpawnNew(context.Background(), ptyclient.SpawnConfig{
		SessionID:    sid.String(),
		Shell:        req.Shell,
		ShellArgs:    req.Exec,
		Rows:         rows,
		Cols:         cols,
		ExtraEnv:     sessionExtraEnvForID(sid),
		StateDir:     d.stateDir,
		DaemonBinary: d.daemonBinary,
		Logger:       d.logger,
		Stderr:       d.cfg.SidecarStderr,
	})
	if err != nil {
		return nil, &allocateErr{Code: ipc.ErrSpawnFailed, Msg: err.Error()}
	}

	// Operator-configurable buffer cap; 0 falls back to
	// session.DefaultBufferCapacity inside NewSession.
	sess, err := session.NewSession(sid, name, ptyHandle, rows, cols, d.cfg.SessionBufferBytes, idleTimeout)
	if err != nil {
		_ = ptyHandle.Close()
		return nil, &allocateErr{Code: ipc.ErrInternal, Msg: err.Error()}
	}

	// Resolve persistence tri-state. nil → daemon default
	// (`--persistence-default`, default-on). Wire the flag before
	// the session enters the registry so a Sweep or Remove that
	// fires before we start the flusher already sees the correct
	// persist value.
	persist := d.registry.ResolvePersist(req.Persist)
	sess.SetPersist(persist)

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

	// Start the persistence flusher (no-op when persist is false).
	// Lifecycle is owned by the Session — Session.Close stops the
	// goroutine and does one final write.
	if persist {
		sess.StartFlusher(d.stateDir, d.cfg.PersistenceFlushInterval, d.logger)
	}

	go sess.Pump()
	d.logger.Info("session spawned",
		"session", sid.String(),
		"name", name,
		"rows", rows, "cols", cols,
		"persist", persist,
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

// validateAllocateBounds checks the request's string fields against
// the per-field size caps. Returns "" if all good, otherwise a
// caller-facing error message.
//
// CBOR's StrictDecMode already bounds total frame size + array/map
// fanout, but a single string field can still consume the full
// per-frame budget. These caps are the inner second line of defence.
func validateAllocateBounds(req ipc.AllocateRequest) string {
	if len(req.Name) > maxNameLen {
		return fmt.Sprintf("name exceeds %d bytes", maxNameLen)
	}
	if len(req.Shell) > maxShellLen {
		return fmt.Sprintf("shell path exceeds %d bytes", maxShellLen)
	}
	if len(req.Exec) > maxExecArgCount {
		return fmt.Sprintf("exec has %d args; max is %d", len(req.Exec), maxExecArgCount)
	}
	joined := 0
	for _, a := range req.Exec {
		joined += len(a) + 1 // +1 approximates a separator
		if joined > maxExecJoinLen {
			return fmt.Sprintf("exec args total exceed %d bytes", maxExecJoinLen)
		}
	}
	return ""
}
