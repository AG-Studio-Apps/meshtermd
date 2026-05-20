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
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// DefaultQUICPort is the preferred UDP port the daemon binds when
// `--addr` doesn't specify a port (or specifies the default explicitly).
// Chosen to avoid known UDP services — clear of WireGuard's 51820,
// Tailscale's 41641, OpenVPN's 1194, IPsec 4500, mosh's 60000-61000
// range, mDNS / SSDP, and IANA-registered services in the same band.
const DefaultQUICPort uint16 = 49820

// FallbackPortSpan is the number of additional candidate ports the
// bind loop will try if the preferred port is already in use. The
// daemon walks DefaultQUICPort .. DefaultQUICPort+FallbackPortSpan,
// stopping at the first successful bind. With stickiness, the
// previously-bound port is tried first (before the default) on
// subsequent restarts, so the fallback range is only exercised on
// genuine conflict.
const FallbackPortSpan uint16 = 99

// Server wraps a quic-go listener configured with our ALPN, the
// daemon's pinned-fingerprint TLS cert, and a Handler that drives the
// per-connection protocol state machine.
type Server struct {
	listener *quic.Listener
	udpConn  *net.UDPConn
	handler  Handler
	// inflight bounds the number of concurrent in-flight handler
	// goroutines. Unbounded accept-into-goroutine lets an attacker
	// against a publicly-bound listener allocate per-conn state
	// faster than HandshakeIdleTimeout reaps it. The semaphore
	// caps that; over-capacity peers get a clean CONNECTION_CLOSE
	// from quic.CloseWithError rather than holding our state.
	inflight chan struct{}
}

// MaxConcurrentHandlers caps how many connections may be inside
// HandleConnection at once. Sized for "a few simultaneous iOS clients
// per host" with headroom for foreground/background reconnect bursts.
// On a busy multi-user box this can be raised via Config.MaxConcurrent.
const MaxConcurrentHandlers = 64

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

	// MaxConcurrent caps the number of connections inside
	// HandleConnection at once. Excess accepts are closed with a
	// CONNECTION_CLOSE before the handler runs. Default
	// MaxConcurrentHandlers.
	MaxConcurrent int

	// StateDir is the daemon data directory used for port stickiness
	// persistence (the `quic-port` file). If empty, stickiness is
	// disabled and the bind loop starts from the configured port
	// every time. Callers typically pass the resolved
	// `cert.DefaultDir()` here.
	StateDir string
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

	udpConn, err := bindUDPWithFallback(cfg.Addr, cfg.StateDir)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cfg.Cert},
		NextProtos:   []string{protocol.ALPN},
		MinVersion:   tls.VersionTLS13,
		// SNI is not used — clients reach us by IP:port, the cert is
		// identified by fingerprint not name. Refuse any handshake
		// that tries to negotiate down from TLS 1.3.
		ClientAuth: tls.NoClientCert,
		// Disable TLS session tickets. Go's TLS 1.3 implementation does
		// not invoke VerifyPeerCertificate on a resumed session — the
		// server's leaf cert isn't presented again. The client side
		// (cmd/mtctl/attach_quic.go) has no ClientSessionCache today, so
		// resumption is already inhibited; this server-side flag closes
		// the latent path that a future client-cache addition would
		// reopen, bypassing fingerprint pinning on resumption.
		SessionTicketsDisabled: true,
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

	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = MaxConcurrentHandlers
	}

	return &Server{
		listener: listener,
		udpConn:  udpConn,
		handler:  cfg.Handler,
		inflight: make(chan struct{}, maxConcurrent),
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
		// Bound concurrent handlers — a public listener can be
		// reached by anyone on the network, and the handshake itself
		// allocates per-conn state in quic-go. Without this cap a
		// flood of half-open connections can drive memory + goroutine
		// growth faster than HandshakeIdleTimeout reaps them.
		select {
		case s.inflight <- struct{}{}:
			go func() {
				defer func() { <-s.inflight }()
				s.handler.HandleConnection(ctx, conn)
			}()
		default:
			// At capacity: shed load with a server-busy signal.
			// 0x10F = arbitrary application error code; we don't
			// surface it to peers anywhere else. quic-go will send
			// a CONNECTION_CLOSE and tear down the QUIC state, so
			// the peer learns to back off and we don't accumulate
			// load.
			_ = conn.CloseWithError(0x10F, "server busy")
		}
	}
}

// bindUDPWithFallback binds the QUIC listener's UDP socket,
// honouring stickiness and falling back through a small range when
// the preferred port is taken. The flow:
//
//  1. Parse the configured `host:port`. If port == 0, the OS picks
//     ephemerally — no fallback or stickiness, return immediately.
//  2. If the configured port equals DefaultQUICPort AND a stickiness
//     state file exists with a different port, prefer the persisted
//     port first. (Non-default configured ports are honoured strictly
//     — explicit user intent overrides remembered state.)
//  3. Walk candidate ports in order. On the first success, persist
//     the chosen port to the state file (best-effort) and return.
//  4. On any non-EADDRINUSE error, surface it immediately — that's a
//     real failure (permission, malformed address, etc.) not a
//     conflict to fall back from.
func bindUDPWithFallback(addr string, stateDir string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %q: %w", addr, err)
	}

	// Ephemeral port: nothing to fall back from, no stickiness.
	if udpAddr.Port == 0 {
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, fmt.Errorf("listen udp: %w", err)
		}
		return conn, nil
	}

	prefPort := uint16(udpAddr.Port)
	candidates := buildCandidatePorts(prefPort, readPortState(stateDir))

	var lastErr error
	for _, p := range candidates {
		try := *udpAddr
		try.Port = int(p)
		conn, err := net.ListenUDP("udp", &try)
		if err == nil {
			if p != prefPort {
				slog.Info("transport: preferred UDP port unavailable, fell through",
					"preferred", prefPort, "bound", p)
			}
			writePortState(stateDir, p)
			return conn, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("listen udp %s: %w", try.String(), err)
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no free UDP port in %d-%d: %w",
		prefPort, prefPort+FallbackPortSpan, lastErr)
}

// buildCandidatePorts returns the bind-attempt order. Stickiness
// (stuck) is tried first when set, distinct from prefPort, AND only
// when prefPort equals DefaultQUICPort — otherwise an explicit user-
// configured non-default port overrides any persisted state. After
// the optional stuck port, the loop walks prefPort .. prefPort + FallbackPortSpan
// in order, skipping the already-queued stuck port.
func buildCandidatePorts(prefPort, stuck uint16) []uint16 {
	candidates := make([]uint16, 0, int(FallbackPortSpan)+2)
	useStuck := stuck != 0 && stuck != prefPort && prefPort == DefaultQUICPort
	if useStuck {
		candidates = append(candidates, stuck)
	}
	for offset := uint16(0); offset <= FallbackPortSpan; offset++ {
		p := prefPort + offset
		if useStuck && p == stuck {
			continue
		}
		candidates = append(candidates, p)
	}
	return candidates
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
