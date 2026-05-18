package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// dialDaemonQUIC opens a QUIC connection to the daemon at host:port
// and verifies the server cert's SHA-256 fingerprint matches the
// one we received over SSH bootstrap. The TLS chain validation is
// bypassed entirely — meshtermd uses self-signed certs identified
// by fingerprint, not by name. Mirrors the iOS RoamTransport's
// `sec_protocol_options_set_verify_block` posture.
//
// ALPN is the daemon's `meshterm/0`. MinVersion TLS 1.3. CurveID
// preferences match the server side (X25519 + P-256, both for the
// iOS interop reason and for classical-ECDHE compatibility).
func dialDaemonQUIC(
	ctx context.Context,
	host string,
	port uint16,
	expectedFingerprint []byte,
) (*quic.Conn, error) {
	if len(expectedFingerprint) != sha256.Size {
		return nil, fmt.Errorf("mtctl attach: cert fingerprint must be %d bytes, got %d",
			sha256.Size, len(expectedFingerprint))
	}

	// IPv6 literals need the bracket form; net.JoinHostPort handles that.
	target := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // we do our own verify below
		NextProtos:         []string{protocol.ALPN},
		MinVersion:         tls.VersionTLS13,
		// Match the server's CurvePreferences exactly. iOS interop
		// rules out post-quantum hybrid here — the daemon's
		// internal/transport/server.go has the rationale.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		// Do NOT add a ClientSessionCache here. Go's TLS 1.3 skips
		// VerifyPeerCertificate on a resumed handshake, which would
		// silently bypass the fingerprint pin below. The server sets
		// SessionTicketsDisabled defensively, but leaving this nil
		// keeps the client side honest too. If you ever need session
		// reuse, also re-run the fingerprint check in VerifyConnection.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], expectedFingerprint) != 1 {
				return fmt.Errorf("server cert fingerprint mismatch (expected %s, got %s)",
					hex.EncodeToString(expectedFingerprint),
					hex.EncodeToString(sum[:]))
			}
			return nil
		},
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}

	conn, err := quic.DialAddr(ctx, target, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial %s: %w", target, err)
	}
	return conn, nil
}

