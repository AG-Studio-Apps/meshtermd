package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// DefaultDialTimeout is the cap for connecting to the daemon's
// unix socket. The socket is local; if it takes more than a
// second something is very wrong.
const DefaultDialTimeout = time.Second

// Client is a one-shot IPC client. Each method dials, sends a
// single request, reads one response, and closes. The daemon
// (server) closes the connection after responding, so reuse
// across requests doesn't buy anything.
type Client struct {
	socket  string
	timeout time.Duration
}

// NewClient returns a Client targeting the given socket path.
// timeout=0 falls back to DefaultDialTimeout.
func NewClient(socketPath string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	return &Client{socket: socketPath, timeout: timeout}
}

// Allocate sends an AllocateRequest and returns the response. The
// returned response's Ok field signals success; on failure Err and
// Msg describe the cause.
func (c *Client) Allocate(ctx context.Context, req AllocateRequest) (AllocateResponse, error) {
	req.T = TypeAllocate
	conn, err := c.dial(ctx)
	if err != nil {
		return AllocateResponse{}, err
	}
	defer conn.Close()

	if err := EncodeRequest(conn, req); err != nil {
		return AllocateResponse{}, fmt.Errorf("send: %w", err)
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return AllocateResponse{}, fmt.Errorf("recv: %w", err)
	}
	return DecodeAllocateResponse(body)
}

// Ping sends a PingRequest and returns the response. Used for a
// liveness probe before any real work.
func (c *Client) Ping(ctx context.Context, nonce uint64) (PingResponse, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return PingResponse{}, err
	}
	defer conn.Close()

	if err := EncodeRequest(conn, PingRequest{T: TypePing, Nonce: nonce}); err != nil {
		return PingResponse{}, err
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return PingResponse{}, err
	}
	return DecodePingResponse(body)
}

// ListSessions enumerates every live session on the daemon.
func (c *Client) ListSessions(ctx context.Context) (ListSessionsResponse, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return ListSessionsResponse{}, err
	}
	defer conn.Close()

	if err := EncodeRequest(conn, ListSessionsRequest{T: TypeListSessions}); err != nil {
		return ListSessionsResponse{}, fmt.Errorf("send: %w", err)
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return ListSessionsResponse{}, fmt.Errorf("recv: %w", err)
	}
	return DecodeListSessionsResponse(body)
}

// Status returns the daemon's operational snapshot — uptime,
// session count, idle-timeout config, attach-token pool size, QUIC
// bound address, cert fingerprint. Read-only.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return StatusResponse{}, err
	}
	defer conn.Close()

	if err := EncodeRequest(conn, StatusRequest{T: TypeStatus}); err != nil {
		return StatusResponse{}, fmt.Errorf("send: %w", err)
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return StatusResponse{}, fmt.Errorf("recv: %w", err)
	}
	return DecodeStatusResponse(body)
}

// RenameSession changes a session's user-visible Name. Sel uses
// the same id-or-name resolution as KillSession; newName must be
// non-empty. Returns ErrNameInUse if newName is already taken by
// another session.
func (c *Client) RenameSession(ctx context.Context, idOrName, newName string) (RenameSessionResponse, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return RenameSessionResponse{}, err
	}
	defer conn.Close()

	req := RenameSessionRequest{T: TypeRenameSession, Sel: idOrName, NewName: newName}
	if err := EncodeRequest(conn, req); err != nil {
		return RenameSessionResponse{}, fmt.Errorf("send: %w", err)
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return RenameSessionResponse{}, fmt.Errorf("recv: %w", err)
	}
	return DecodeRenameSessionResponse(body)
}

// KillSession reaps a session by hex SessionID or by Name. The
// daemon resolves the selector — try-as-id-first, fall back to
// name lookup. Idempotent on already-gone sessions: returns
// ErrUnknownSession in that case.
func (c *Client) KillSession(ctx context.Context, idOrName string) (KillSessionResponse, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return KillSessionResponse{}, err
	}
	defer conn.Close()

	req := KillSessionRequest{T: TypeKillSession, Sel: idOrName}
	if err := EncodeRequest(conn, req); err != nil {
		return KillSessionResponse{}, fmt.Errorf("send: %w", err)
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return KillSessionResponse{}, fmt.Errorf("recv: %w", err)
	}
	return DecodeKillSessionResponse(body)
}

// SessionSearch scans the named session's scrollback ring for regex
// matches. Sel uses the same id-or-name resolution as KillSession.
// Pattern is raw Go RE2 source — the daemon compiles it under a
// size cap. Anchored=true wraps with (?m:…) so ^/$ match physical
// newlines. MaxMatches=0 → daemon default (10,000).
func (c *Client) SessionSearch(ctx context.Context, req SessionSearchRequest) (SessionSearchResponse, error) {
	req.T = TypeSessionSearch
	conn, err := c.dial(ctx)
	if err != nil {
		return SessionSearchResponse{}, err
	}
	defer conn.Close()

	if err := EncodeRequest(conn, req); err != nil {
		return SessionSearchResponse{}, fmt.Errorf("send: %w", err)
	}
	body, err := ReadFrame(conn)
	if err != nil {
		return SessionSearchResponse{}, fmt.Errorf("recv: %w", err)
	}
	return DecodeSessionSearchResponse(body)
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	d := &net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, classifyDialErr(err)
	}
	// If the caller didn't set a deadline on ctx, give the read+write
	// the same default so a hung daemon doesn't block forever.
	if !ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

// ErrDaemonNotRunning indicates the unix socket couldn't be reached.
// `meshtermd connect` translates this into exit code 2 per
// docs/roam-protocol.md § 4.4.
var ErrDaemonNotRunning = errors.New("ipc: daemon not running")

func classifyDialErr(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// "connection refused" / "no such file or directory" both
		// mean "no daemon on this socket".
		return fmt.Errorf("%w: %v", ErrDaemonNotRunning, err)
	}
	return err
}
