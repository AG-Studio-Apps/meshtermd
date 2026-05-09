// Package transport binds the QUIC listener to the daemon's session
// registry. The Server type owns the quic-go listener and a Handler
// that processes each accepted connection.
//
// The protocol-level work (Attach, replay, stream demux) lives on
// the Handler — see handler.go. server.go only does the QUIC plumbing
// + TLS configuration.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// Server wraps a quic-go listener configured with our ALPN, the
// daemon's pinned-fingerprint TLS cert, and a Handler that drives the
// per-connection protocol state machine.
type Server struct {
	listener *quic.Listener
	udpConn  *net.UDPConn
	handler  Handler
}

// Handler processes one accepted QUIC connection. The implementation
// is responsible for opening control / stdin / stdout streams in the
// expected order, dispatching protocol messages, and cleaning up.
//
// HandleConnection should return when the connection is finished
// (graceful Goodbye, peer close, error, or ctx done). The Server
// does not call CloseWithError on its behalf.
type Handler interface {
	HandleConnection(ctx context.Context, conn *quic.Conn)
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(ctx context.Context, conn *quic.Conn)

// HandleConnection implements Handler.
func (f HandlerFunc) HandleConnection(ctx context.Context, conn *quic.Conn) { f(ctx, conn) }

// Config tunes the QUIC + TLS layer.
type Config struct {
	// Addr to listen on (e.g. "127.0.0.1:0" for an ephemeral port).
	// Daemon convention: bind to localhost only — the bootstrap line
	// already restricts which iOS clients can attach.
	Addr string

	// Cert is the daemon's TLS certificate. The fingerprint of this
	// cert's DER body is what the iOS client pins via the bootstrap
	// line.
	Cert tls.Certificate

	// MaxIdleTimeout is the QUIC idle-timeout. After this without
	// any traffic, the connection is closed. Default 30s.
	MaxIdleTimeout time.Duration

	// KeepAlivePeriod is how often we send PING frames during idle.
	// Default 10s.
	KeepAlivePeriod time.Duration

	// Handler processes accepted connections. Required.
	Handler Handler
}

// New constructs a Server. The QUIC listener starts immediately; call
// Serve to accept connections, Close to tear down. Returns an error
// if the address can't be bound, the TLS config is invalid, or the
// quic-go listener can't be created.
func New(cfg Config) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("transport: Config.Handler is required")
	}
	if len(cfg.Cert.Certificate) == 0 {
		return nil, errors.New("transport: Config.Cert is empty")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %q: %w", cfg.Addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cfg.Cert},
		NextProtos:   []string{protocol.ALPN},
		MinVersion:   tls.VersionTLS13,
		// SNI is not used — clients reach us by IP:port, the cert is
		// identified by fingerprint not name. Refuse any handshake
		// that tries to negotiate down from TLS 1.3.
		ClientAuth: tls.NoClientCert,
		// Pin classical ECDHE only. Go 1.24+ enables X25519MLKEM768
		// (post-quantum hybrid) by default for TLS 1.3 key exchange.
		// iOS Network.framework's QUIC stack negotiates the group but
		// fails on the resulting ~1.1 KB ServerHello key_share — the
		// handshake stalls in Initial space and times out client-side.
		// Locking to X25519 + P-256 sidesteps the interop bug; both
		// give the same ~128-bit classical security and TLS 1.3 forward
		// secrecy. Re-evaluate when iOS / Go interop on MLKEM768 is
		// confirmed working.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	idle := cfg.MaxIdleTimeout
	if idle <= 0 {
		idle = 30 * time.Second
	}
	keepalive := cfg.KeepAlivePeriod
	if keepalive <= 0 {
		keepalive = 10 * time.Second
	}

	// Per-connection stream caps. The single-stream tagged-framing
	// protocol uses exactly one client-initiated bidirectional
	// stream per attach (control + stdin + stdout multiplexed via
	// 1-byte type tags). A second bidi or any uni stream is a peer
	// bug or hostile pin attempt; cap accordingly.
	//
	// Audit F-B (v0.0.2 review): previous v0.0.1 caps of 8/8 were
	// stale leftovers from the three-stream protocol — buffered
	// extra streams pinned per-conn state until idle timeout.
	// HandshakeIdleTimeout caps the cost of a peer who completes
	// ALPN but stalls before Attach.
	listener, err := quic.Listen(udpConn, tlsConfig, &quic.Config{
		EnableDatagrams:       true,
		MaxIdleTimeout:        idle,
		KeepAlivePeriod:       keepalive,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: 0,
		HandshakeIdleTimeout:  10 * time.Second,
		// Pin to the QUIC spec minimum (1200 bytes UDP payload). Reasons:
		//   1. Tailscale's tailscale0 interface has L3 MTU 1280. UDP+IPv4
		//      headers = 28 bytes, so max QUIC packet = 1252. quic-go's
		//      default InitialPacketSize is 1280, producing 1308-byte IP
		//      packets that exceed the tunnel MTU and silently drop on
		//      iPhone-side egress — server's ServerHello never arrives,
		//      iOS keeps PINGing in Initial space until 15s timeout.
		//   2. Mobile/cellular paths often carry a similar ~1280 effective
		//      MTU (PPPoE, IPv6 transition, etc.). 1200 is the QUIC v1
		//      spec floor and works on every path the protocol supports.
		// Trade-off: a few extra packets per connection vs. the default
		// 1280. Worth it for portability — Roam's whole value prop is
		// "works over flaky / tunnelled networks". PMTUD is still on so
		// quic-go can grow the packet size if the path supports it.
		InitialPacketSize: 1200,
	})
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("quic.Listen: %w", err)
	}

	return &Server{
		listener: listener,
		udpConn:  udpConn,
		handler:  cfg.Handler,
	}, nil
}

// Addr returns the actual UDP address the server is listening on.
// Useful when the caller passed Config.Addr=":0" and needs to know
// the ephemeral port that was bound.
func (s *Server) Addr() *net.UDPAddr {
	return s.udpConn.LocalAddr().(*net.UDPAddr)
}

// Serve accepts connections in a loop until ctx is cancelled or the
// listener is closed. Each accepted connection is handed to the
// Handler in a fresh goroutine so a slow handler doesn't block accept.
//
// Returns nil on graceful shutdown (ctx cancel or Close), or the
// underlying quic-go error otherwise.
func (s *Server) Serve(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			// Most operational errors (peer auth failure, ALPN
			// mismatch) surface as ApplicationError or are logged by
			// quic-go itself; we only see truly fatal listener
			// errors here.
			return fmt.Errorf("quic accept: %w", err)
		}
		go s.handler.HandleConnection(ctx, conn)
	}
}

// Close shuts down the listener and the underlying UDP socket.
// In-flight connections receive a CONNECTION_CLOSE per quic-go's
// listener.Close semantics; their HandleConnection goroutines should
// observe the closed connection and return.
func (s *Server) Close() error {
	listenerErr := s.listener.Close()
	udpErr := s.udpConn.Close()
	if listenerErr != nil {
		return listenerErr
	}
	return udpErr
}
