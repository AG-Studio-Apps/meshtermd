package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Handler is the daemon-side dispatch for IPC requests. Each
// HandleAllocate / HandlePing call gets the typed request and
// returns the corresponding typed response.
//
// Implementations should be cheap — the IPC server holds the
// connection open only long enough to receive the request and
// send the response. Long-running work (PTY spawn, registry
// updates) happens before the response is sent.
type Handler interface {
	HandleAllocate(ctx context.Context, req AllocateRequest) AllocateResponse
	HandlePing(ctx context.Context, req PingRequest) PingResponse
	HandleListSessions(ctx context.Context, req ListSessionsRequest) ListSessionsResponse
	HandleKillSession(ctx context.Context, req KillSessionRequest) KillSessionResponse
	HandleRenameSession(ctx context.Context, req RenameSessionRequest) RenameSessionResponse
	HandleStatus(ctx context.Context, req StatusRequest) StatusResponse
	HandleSessionSearch(ctx context.Context, req SessionSearchRequest) SessionSearchResponse
}

// Server listens on a Unix socket and dispatches incoming requests
// to a Handler. One request per connection — connect helpers exit
// after their bootstrap line is printed.
type Server struct {
	listener *net.UnixListener
	handler  Handler
	socket   string
	// inflight bounds the number of concurrent in-flight handler
	// goroutines. The socket is uid-0600 so only the daemon's own
	// user can connect, but a buggy local process (or a deliberate
	// fork-bomb) could still open enough connections to spawn
	// goroutines faster than the handler returns. The semaphore
	// caps that; overflow connections are closed immediately.
	inflight chan struct{}
}

// MaxConcurrentIPCHandlers caps how many in-flight IPC handlers may
// run at once. The IPC socket is local-uid-only and each handler
// completes in microseconds in steady state, so a small cap is fine.
// Sized lower than the QUIC server's 64 because IPC has no public
// surface to defend.
const MaxConcurrentIPCHandlers = 32

// ServerOption customises NewServer. Use the With* helpers; the type
// itself is opaque so we can add fields without breaking callers.
type ServerOption func(*serverOptions)

type serverOptions struct {
	maxConcurrent int
}

// WithMaxConcurrent overrides the default in-flight handler cap. Used
// by tests to make overflow easy to trigger; production callers should
// leave it at the default.
func WithMaxConcurrent(n int) ServerOption {
	return func(o *serverOptions) { o.maxConcurrent = n }
}

// NewServer creates a Server bound to the given Unix socket path.
// The path is created with mode 0600 — only the daemon's uid can
// reach it. If the path already exists (stale socket from a
// previous crash), it's removed first.
//
// Audit F5: also verifies the socket's parent directory is owned by
// the calling uid and has mode ≤ 0700 before binding. A
// world-writable parent (e.g., a misconfigured XDG_RUNTIME_DIR)
// would let another local user race-create the socket and
// intercept `meshtermd connect` IPC.
func NewServer(socketPath string, handler Handler, opts ...ServerOption) (*Server, error) {
	if handler == nil {
		return nil, errors.New("ipc: NewServer requires a Handler")
	}
	cfg := serverOptions{maxConcurrent: MaxConcurrentIPCHandlers}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.maxConcurrent <= 0 {
		cfg.maxConcurrent = MaxConcurrentIPCHandlers
	}
	parent := filepath.Dir(socketPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	if err := VerifyParentDir(parent); err != nil {
		return nil, fmt.Errorf("socket parent dir: %w", err)
	}
	// Remove stale socket. A live `meshtermd serve` would be
	// holding the listener open; bind would fail. If it succeeds,
	// the previous one is gone. Use Lstat first so we don't follow
	// a symlink an attacker may have planted at the socket path.
	if info, lerr := os.Lstat(socketPath); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("ipc: refuse to bind: %s is a symlink", socketPath)
		}
		_ = os.Remove(socketPath)
	}

	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("resolve unix addr: %w", err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return &Server{
		listener: ln,
		handler:  handler,
		socket:   socketPath,
		inflight: make(chan struct{}, cfg.maxConcurrent),
	}, nil
}

// VerifyParentDir asserts that the directory `path` is owned by the
// current uid and has permissions no looser than 0700 (i.e. neither
// group- nor world-readable/writable/executable). This rules out the
// "$XDG_RUNTIME_DIR is misconfigured world-writable" attack where a
// local attacker pre-creates the socket file or a symlink and races
// the daemon's bind.
//
// Exported for the client-side discovery path (cmd/meshtermd/serve.go's
// `discoverClientSocketPath`) so client subcommands mirror the
// server's bind-time validation — without that mirroring a connect
// helper would happily dial a same-name socket planted under a
// world-writable XDG_RUNTIME_DIR by another local user.
func VerifyParentDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-POSIX FS; we can't verify ownership. Fail closed.
		return fmt.Errorf("cannot inspect ownership of %s", path)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d; expected %d", path, stat.Uid, os.Getuid())
	}
	// Mode check: any group or other bits set fails.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s has loose permissions %o; expected ≤ 0700", path, mode)
	}
	return nil
}

// VerifyClientSocket validates a candidate socket path before a
// client dials it. Refuses symlinks (an attacker may plant a symlink
// pointing at their own socket) and refuses anything that isn't a
// Unix socket (a regular file at the same path may be an attempt to
// trick the helper into doing protocol handshakes against
// attacker-controlled bytes).
//
// Returns os.ErrNotExist if the path doesn't exist — callers should
// treat that as "no daemon here, try the next candidate" rather than
// an error.
//
// Closes the client-side mirror of the v1.0 audit hardening that
// already covers the server-side bind path. Codex audit 2026-05-19,
// MEDIUM finding.
func VerifyClientSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a unix socket", path)
	}
	return nil
}

// Path returns the unix socket path the server is bound to.
func (s *Server) Path() string { return s.socket }

// Serve accepts connections in a loop, dispatching each to the
// Handler in a fresh goroutine. Returns nil on Close or ctx cancel.
func (s *Server) Serve(ctx context.Context) error {
	// Closing the listener when ctx is cancelled wakes Accept.
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	var wg sync.WaitGroup
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			// Wait for in-flight handlers to finish before returning;
			// otherwise tests can race on shared state.
			wg.Wait()
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		// Bound concurrent handlers. Unix sockets have no application-
		// level close-with-reason, so over-cap peers just see their
		// connection drop — the client surfaces a ReadFrame error.
		select {
		case s.inflight <- struct{}{}:
			wg.Add(1)
			go func(c *net.UnixConn) {
				defer wg.Done()
				defer func() { <-s.inflight }()
				s.handle(ctx, c)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
}

// Close removes the socket file and stops Serve. Safe to call
// multiple times.
func (s *Server) Close() error {
	err := s.listener.Close()
	_ = os.Remove(s.socket)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()

	body, err := ReadFrame(conn)
	if err != nil {
		// Peer disconnected before sending a request, or framing
		// error. Either way we have nothing to respond with.
		return
	}

	t, err := PeekType(body)
	if err != nil {
		_ = EncodeResponse(conn, AllocateResponse{
			T:   TypeAllocate,
			Ok:  false,
			Err: ErrBadRequest,
			Msg: "could not parse request discriminator",
		})
		return
	}

	switch t {
	case TypeAllocate:
		req, err := DecodeAllocateRequest(body)
		if err != nil {
			_ = EncodeResponse(conn, AllocateResponse{
				T: TypeAllocate, Ok: false,
				Err: ErrBadRequest, Msg: err.Error(),
			})
			return
		}
		resp := s.handler.HandleAllocate(ctx, req)
		resp.T = TypeAllocate
		_ = EncodeResponse(conn, resp)
	case TypePing:
		req, err := DecodePingRequest(body)
		if err != nil {
			return
		}
		resp := s.handler.HandlePing(ctx, req)
		resp.T = TypePing
		_ = EncodeResponse(conn, resp)
	case TypeListSessions:
		req, err := DecodeListSessionsRequest(body)
		if err != nil {
			_ = EncodeResponse(conn, ListSessionsResponse{
				T: TypeListSessions, Ok: false,
				Err: ErrBadRequest, Msg: err.Error(),
			})
			return
		}
		resp := s.handler.HandleListSessions(ctx, req)
		resp.T = TypeListSessions
		_ = EncodeResponse(conn, resp)
	case TypeKillSession:
		req, err := DecodeKillSessionRequest(body)
		if err != nil {
			_ = EncodeResponse(conn, KillSessionResponse{
				T: TypeKillSession, Ok: false,
				Err: ErrBadRequest, Msg: err.Error(),
			})
			return
		}
		resp := s.handler.HandleKillSession(ctx, req)
		resp.T = TypeKillSession
		_ = EncodeResponse(conn, resp)
	case TypeRenameSession:
		req, err := DecodeRenameSessionRequest(body)
		if err != nil {
			_ = EncodeResponse(conn, RenameSessionResponse{
				T: TypeRenameSession, Ok: false,
				Err: ErrBadRequest, Msg: err.Error(),
			})
			return
		}
		resp := s.handler.HandleRenameSession(ctx, req)
		resp.T = TypeRenameSession
		_ = EncodeResponse(conn, resp)
	case TypeStatus:
		req, err := DecodeStatusRequest(body)
		if err != nil {
			_ = EncodeResponse(conn, StatusResponse{
				T: TypeStatus, Ok: false,
				Err: ErrBadRequest, Msg: err.Error(),
			})
			return
		}
		resp := s.handler.HandleStatus(ctx, req)
		resp.T = TypeStatus
		_ = EncodeResponse(conn, resp)
	case TypeSessionSearch:
		req, err := DecodeSessionSearchRequest(body)
		if err != nil {
			_ = EncodeResponse(conn, SessionSearchResponse{
				T: TypeSessionSearch, Ok: false,
				Err: ErrBadRequest, Msg: err.Error(),
			})
			return
		}
		resp := s.handler.HandleSessionSearch(ctx, req)
		resp.T = TypeSessionSearch
		_ = EncodeResponse(conn, resp)
	default:
		_ = EncodeResponse(conn, AllocateResponse{
			T: TypeAllocate, Ok: false,
			Err: ErrBadRequest,
			Msg: fmt.Sprintf("unknown request type %q", t),
		})
	}
}
