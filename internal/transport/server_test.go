package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/protocol"
)

// freshCert generates a one-shot self-signed cert in a temp dir.
// Returns the cert and its fingerprint for client-side pinning.
func freshCert(t *testing.T) (tls.Certificate, cert.Fingerprint) {
	t.Helper()
	mgr := &cert.Manager{Dir: t.TempDir(), Validity: time.Hour}
	c, fp, err := mgr.LoadOrGenerate()
	if err != nil {
		t.Fatal(err)
	}
	return c, fp
}

// pinningClientTLS builds a tls.Config that verifies the server cert
// matches the given fingerprint, just like the iOS client will via
// sec_protocol_options_set_verify_block. We disable Go's default
// chain verification (no public CA involved) and replace it with a
// constant-time SHA-256 compare on the leaf cert's DER body.
func pinningClientTLS(want cert.Fingerprint, alpn string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // we replace it with our own verification below
		NextProtos:         []string{alpn},
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if cert.Fingerprint(got) != want {
				return fmt.Errorf("cert fingerprint mismatch: got %x, want %s",
					got, want)
			}
			return nil
		},
	}
}

// connectingClient dials the server using the same primitives the
// iOS client will (modulo Network.framework wrapping it). Returns
// the connection or an error.
func connectingClient(addr string, fp cert.Fingerprint, alpn string) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr,
		pinningClientTLS(fp, alpn),
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: 5 * time.Second})
	return conn, err
}

func TestServerNewRejectsEmptyCert(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Handler: HandlerFunc(func(ctx context.Context, c *quic.Conn) {})})
	if err == nil {
		t.Error("New accepted a Config with empty Cert")
	}
}

func TestServerNewRejectsNilHandler(t *testing.T) {
	t.Parallel()
	c, _ := freshCert(t)
	_, err := New(Config{Cert: c})
	if err == nil {
		t.Error("New accepted a Config with nil Handler")
	}
}

func TestServerAcceptsClientWithCorrectFingerprint(t *testing.T) {
	t.Parallel()
	c, fp := freshCert(t)

	var connected atomic.Int32
	srv, err := New(Config{
		Addr: "127.0.0.1:0",
		Cert: c,
		Handler: HandlerFunc(func(ctx context.Context, conn *quic.Conn) {
			connected.Add(1)
			_ = conn.CloseWithError(0, "test ok")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	conn, err := connectingClient(srv.Addr().String(), fp, protocol.ALPN)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Wait for the handler to fire.
	deadline := time.Now().Add(time.Second)
	for connected.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if connected.Load() == 0 {
		t.Fatal("handler did not fire within 1s")
	}
}

func TestServerRejectsClientWithWrongFingerprint(t *testing.T) {
	t.Parallel()
	c, _ := freshCert(t)
	wrongFP := cert.Fingerprint{0xbb, 0xbb, 0xbb} // arbitrary non-match

	srv, err := New(Config{
		Addr: "127.0.0.1:0",
		Cert: c,
		Handler: HandlerFunc(func(ctx context.Context, conn *quic.Conn) {
			t.Error("handler fired despite cert pin mismatch")
			_ = conn.CloseWithError(0, "")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	if _, err := connectingClient(srv.Addr().String(), wrongFP, protocol.ALPN); err == nil {
		t.Error("client dial succeeded against wrong fingerprint")
	}
}

func TestServerRejectsClientWithWrongALPN(t *testing.T) {
	t.Parallel()
	c, fp := freshCert(t)

	srv, err := New(Config{
		Addr: "127.0.0.1:0",
		Cert: c,
		Handler: HandlerFunc(func(ctx context.Context, conn *quic.Conn) {
			t.Error("handler fired despite ALPN mismatch")
			_ = conn.CloseWithError(0, "")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	if _, err := connectingClient(srv.Addr().String(), fp, "wrong-alpn"); err == nil {
		t.Error("client dial succeeded with wrong ALPN")
	}
}

func TestServerCloseStopsServe(t *testing.T) {
	t.Parallel()
	c, _ := freshCert(t)
	srv, err := New(Config{
		Addr:    "127.0.0.1:0",
		Cert:    c,
		Handler: HandlerFunc(func(ctx context.Context, conn *quic.Conn) {}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var serveErr error
	go func() {
		defer wg.Done()
		serveErr = srv.Serve(context.Background())
	}()

	// Give Serve a moment to enter Accept.
	time.Sleep(20 * time.Millisecond)
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
		// good
	case <-time.After(time.Second):
		t.Fatal("Serve did not return within 1s of Close")
	}
	if serveErr != nil {
		t.Errorf("Serve returned %v on graceful close, want nil", serveErr)
	}
}

func TestServerServeReturnsOnContextCancel(t *testing.T) {
	t.Parallel()
	c, _ := freshCert(t)
	srv, err := New(Config{
		Addr:    "127.0.0.1:0",
		Cert:    c,
		Handler: HandlerFunc(func(ctx context.Context, conn *quic.Conn) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() { doneCh <- srv.Serve(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-doneCh:
		if err != nil {
			t.Errorf("Serve returned %v on ctx cancel, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return within 1s of ctx cancel")
	}
}
