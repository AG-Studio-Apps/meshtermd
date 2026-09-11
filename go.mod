module github.com/AG-Studio-Apps/mtroamd

go 1.26.3

// Patched toolchain: pulls in the go1.26.5 stdlib fixes for
// GO-2026-5856 (crypto/tls ECH privacy leak — the only govulncheck
// source-reachable advisory, via the QUIC listener + release fetcher)
// and GO-2026-4970 (os.Root symlink escape); supersedes the earlier
// go1.26.4 bump for GO-2026-5039 (net/textproto) + GO-2026-5037
// (crypto/x509). The `go` directive stays at the language minimum so
// GOTOOLCHAIN=local builds (Nix) keep working.
toolchain go1.26.6

require (
	github.com/creack/pty v1.1.24
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/quic-go/quic-go v0.59.1
	golang.org/x/crypto v0.56.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.57.0 // indirect
)
