package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
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
}

// Server listens on a Unix socket and dispatches incoming requests
// to a Handler. One request per connection — connect helpers exit
// after their bootstrap line is printed.
type Server struct {
	listener *net.UnixListener
	handler  Handler
	socket   string
}

// NewServer creates a Server bound to the given Unix socket path.
// The path is created with mode 0600 — only the daemon's uid can
// reach it. If the path already exists (stale socket from a
// previous crash), it's removed first.
func NewServer(socketPath string, handler Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("ipc: NewServer requires a Handler")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	// Remove stale socket. A live `meshtermd serve` would be
	// holding the listener open; bind would fail. If it succeeds,
	// the previous one is gone.
	_ = os.Remove(socketPath)

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
	return &Server{listener: ln, handler: handler, socket: socketPath}, nil
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
		wg.Add(1)
		go func(c *net.UnixConn) {
			defer wg.Done()
			s.handle(ctx, c)
		}(conn)
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
	default:
		_ = EncodeResponse(conn, AllocateResponse{
			T: TypeAllocate, Ok: false,
			Err: ErrBadRequest,
			Msg: fmt.Sprintf("unknown request type %q", t),
		})
	}
}
