# Security policy and threat model

## Reporting vulnerabilities

**Do not file security issues as public GitHub issues.**

Email: `security@meshterm.app` (PGP key available on request).
Expected first response: within 5 business days.
Coordinated disclosure: standard 90-day window.

If we are slow to respond and the issue is being actively exploited, you may disclose responsibly via a public CVE channel.

## Trust model

`meshtermd` runs as the user's UNIX account on a host the user already owns and SSH's into. It does not elevate privileges, does not bind to privileged ports, does not run as root, and does not require any setuid bits. Its threat model is the same as `sshd`'s threat model for that user account: anyone who can already get a shell as the user can read/write the same data `meshtermd` can.

The protocol's security perimeter is the **iOS client → daemon** channel. Inside the host, the daemon is just another user process.

## What we trust

- **The user's SSH host key chain.** Bootstrap happens over an existing SSH session. If the user's known_hosts trusts the host, we inherit that trust. If SSH is being MITM'd at bootstrap time, every secret SSH carries is already compromised — this protocol cannot improve on that.
- **Apple's `Security.framework` (TLS 1.3 implementation).** Used by `Network.framework` for all QUIC TLS operations on the iOS client.
- **Go's `crypto/tls` (TLS 1.3 implementation).** Used by `quic-go` on the daemon.
- **Apple's `CryptoKit` (SHA-256, P-256).** Used by the iOS client for fingerprint computation.
- **Go's `crypto` standard library (ECDSA P-256, SHA-256, `crypto/rand`).** Used by the daemon for cert generation, fingerprint computation, and token generation.
- **The user's local filesystem.** Cert + key persist at `~/.local/share/meshtermd/{cert,key}.pem` with mode 0600.

## What we do NOT trust

- The network between the iOS client and the daemon, after bootstrap. Mitigated by TLS 1.3 with cert pinning.
- Other processes on the host that are not the user's UID. They cannot read `~/.local/share/meshtermd/key.pem` without privilege escalation, which is out of our threat model.
- The bootstrap line in transit through a non-SSH path. The protocol mandates SSH bootstrap; emitting `MTRM_QUIC ...` to any other transport is undefined behaviour.

## Cryptographic primitives — none of which we wrote

| Use | Primitive | Library |
|---|---|---|
| QUIC transport encryption | TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305 | iOS: Apple `Security.framework`. Server: Go `crypto/tls` via `quic-go`. |
| Key exchange | TLS 1.3 ECDHE (X25519, P-256, P-384) | same as above |
| Server cert | self-signed ECDSA P-256 (rationale below) | Server: Go `crypto/ecdsa` + `crypto/x509` |
| Cert fingerprint | SHA-256 of DER-encoded cert | iOS: `CryptoKit`. Server: Go `crypto/sha256`. |
| Attach token | 16 bytes from CSPRNG | Go `crypto/rand` |
| Session ID | 16 bytes from CSPRNG | Go `crypto/rand` |
| SSH bootstrap channel | SSHv2 with the user's chosen cipher suite | iOS: NIOSSH (Apple-maintained). Host: OpenSSH (or similar). |

There is no application-layer cryptography in `meshtermd` or the iOS client's Roam path. We do not invoke AES, ChaCha20, HMAC, or any AEAD construction directly. All authenticated encryption is TLS 1.3 inside QUIC.

## Threat actors and defenses

### A. Passive network observer

| | |
|---|---|
| Capability | Reads packets between iOS and daemon |
| What they see | TLS 1.3 ciphertext only. SNI is sent in the clear but reveals only the bootstrap-supplied hostname (which the attacker likely already knows). |
| What they can derive | Connection timing, packet sizes, total bytes transferred. Sufficient to fingerprint typing patterns in some cases (see § known limitations). |
| Defense | TLS 1.3 with mandatory forward secrecy. Even if the daemon's cert is later stolen, captured ciphertext remains unreadable. |

### B. Active MITM during QUIC

| | |
|---|---|
| Capability | Intercepts the QUIC handshake, presents own cert |
| Defense | Client pins the cert fingerprint received over the SSH bootstrap. Connection is rejected if the presented cert's SHA-256 doesn't match. The attacker would need to also MITM the SSH bootstrap, which is the next case. |

### C. Active MITM during SSH bootstrap

| | |
|---|---|
| Capability | Intercepts SSH, replaces the `MTRM_QUIC` line with a different fingerprint |
| Defense | This requires defeating SSH's host-key trust. If they can do that, they already have a shell as the user — Roam adds nothing to their attack surface. The bootstrap pivot is no weaker than SSH itself. |

### D. Replay of captured bootstrap line

| | |
|---|---|
| Capability | Captures `MTRM_QUIC ...` line and tries to attach later |
| Defense | The attach token is single-use. Once any QUIC client successfully attaches, the daemon invalidates the token. A captured bootstrap line is useless after first use. |

### E. Stolen `session_id`

| | |
|---|---|
| Capability | An attacker learns a victim's `session_id` |
| Defense | Useless alone. Attaching requires (1) SSH access to the host as the same user, (2) a fresh `meshtermd connect` invocation that produces a new attach token. The session ID itself confers no authority. |

### F. Compromised `meshtermd` binary in transit

| | |
|---|---|
| Capability | Attacker injects a malicious daemon binary into the SFTP upload path during install |
| Defense | The iOS client embeds a public verifying key. Before SFTP-uploading, it verifies a `minisign` signature over the binary's SHA-256. An attacker would need our private signing key. |
| Residual risk | If the signing key is compromised, attackers can ship a malicious daemon. Mitigations: hardware-backed key storage, key rotation policy, public key embedded in the iOS app updates with each app release. |

### G. Compromised host

| | |
|---|---|
| Capability | An attacker has shell as the user `meshtermd` runs as |
| Outcome | Full read of session output buffers, ability to inject input, ability to read the daemon's TLS private key. |
| Defense | None inside our perimeter. The same threat exists for `tmux`, `screen`, `sshd` on that host. Roam doesn't make this worse. |

### H. Compromised iOS device

| | |
|---|---|
| Capability | Attacker has access to the unlocked iOS device |
| Outcome | Same as today's meshTerm: SSH credentials in Keychain, all sessions accessible. |
| Defense | Outside Roam's threat model — same as the existing app. |

### I. Traffic analysis (typing inference)

| | |
|---|---|
| Capability | Passive observer correlates packet sizes and timings with keystrokes |
| Outcome | Some prior research (Song et al. 2001) showed SSH traffic can leak keystroke timing information and infer typed content. The same applies here. |
| Defense | QUIC's variable-length integer framing and packet padding partially obscure sizes. Predictive echo, when active, may make timing analysis slightly easier (client sends bytes immediately, no batching). We do not currently add explicit padding or batching. |
| Status | Known limitation. Not a regression vs SSH. |

### J. Daemon attempting to read protected files

| | |
|---|---|
| Concern | A user audits our binary and asks "does this thing exfiltrate my data" |
| Defense | Only data flowing through the active terminal session reaches the QUIC connection. The daemon does not read files outside `~/.local/share/meshtermd/` (its own state) and the PTY of its child process. The source is auditable; the binary build is reproducible (Go build flags pinned). |

## Cert lifecycle

- Generated on first daemon startup, stored at `~/.local/share/meshtermd/{cert,key}.pem` with mode 0600.
- ECDSA P-256 with SHA-256 (cert sigalg `ecdsa_secp256r1_sha256`, TLS code 0x0403). No CN/SAN required — the cert is identified by fingerprint, not name. Ed25519 was the original choice and is cryptographically equivalent, but iOS Network.framework's QUIC ClientHello does not list `ed25519` (0x0807) in its `signature_algorithms` extension, so an Ed25519 server cert is rejected with `CRYPTO_ERROR 0x128` before the client's verify block runs. P-256 sidesteps this without weakening the security posture.
- Validity: 365 days. The daemon refreshes within the last 30 days of validity (regenerates cert+key, retains old fingerprint as "previously valid" for one rotation period).
- The fingerprint is the SHA-256 of the DER-encoded certificate.
- During rotation, both fingerprints (old and new) are accepted by the daemon for one full rotation period; the bootstrap line always emits the *new* fingerprint.
- Cert rotation is automatic and silent. The iOS client picks up the new fingerprint on its next bootstrap.

## Attach token semantics

- 16 bytes, generated by `crypto/rand` per `meshtermd connect` invocation.
- Stored in-memory in the `serve` process, indexed by session ID.
- TTL: 30 seconds from emission. After 30 s with no QUIC attach, the token is purged.
- Single-use. On successful attach the token is invalidated.

## Session ID semantics

- 16 bytes, generated by `crypto/rand` on session creation.
- Stable for the session's life. Persisted in the iOS client's per-host preferences.
- Confers **no authority** on its own. An attacker who learns a session ID can do nothing with it absent SSH access.

## Logging

- The daemon logs to stderr by default; production deployments redirect via systemd's journal.
- **No session output content is ever logged.** Only:
  - Connection events (open, close, error)
  - Attach events (session ID, peer IP — last two octets masked for IPv4)
  - Resize events (rows/cols only)
  - GC events (session ID, age at reap)
- An optional `--debug-frames` flag (off by default, requires `MESHTERMD_DEBUG=1`) logs frame headers (type, length, seq) but not payloads.

## Reproducible builds

The release process pins the Go version, flags `-trimpath -ldflags="-buildid="`, and publishes a `SHA256SUMS` file signed with `minisign`. Anyone can rebuild from the source tag and verify byte-for-byte that the published binary matches.

## Known limitations

1. **Traffic analysis** — see threat I above. Not addressed in v0.
2. **No defence against a compromised host.** Same as `tmux`, `screen`, `sshd`. Roam is not a sandboxing tool.
3. **Cert pinning is per-host, not per-user.** All users on a host share the daemon's cert. If multiple users connect to the same host and one is compromised, the cert fingerprint is shared.
4. **No multi-factor for the bootstrap.** SSH's auth methods are the only gate. If you require additional factors, layer them at the SSH level (PAM, hardware tokens).
5. **No explicit defence-in-depth for the attach token.** A 30-second TTL + single-use semantics + transport over an SSH-encrypted channel is the entire protection. We deliberately do not require an additional handshake step over QUIC because the SSH bootstrap is already authenticated.

## Self-audit checklist

This is the checklist we run before each release. Contributors are encouraged to add cases.

- [ ] `govulncheck ./...` passes with no findings
- [ ] `gosec ./...` passes (acknowledge all `// #nosec` rationales)
- [ ] `go test -fuzz=Fuzz` for each fuzz target runs ≥ 1 hour with no crashes
- [ ] All CBOR decode paths tagged with `MaxArrayElements`, `MaxMapPairs`, `MaxNestedLevels`
- [ ] Frame length limit enforced *before* allocation (no `make([]byte, untrusted)`)
- [ ] No `os.Exec` or shell-out paths take user-controlled strings without escaping
- [ ] PTY child inherits clean environment (specific allowlist, not full `os.Environ()`)
- [ ] No timing-sensitive comparisons of secrets; use `crypto/subtle.ConstantTimeCompare`
- [ ] `~/.local/share/meshtermd/key.pem` written with 0600 mode atomically
- [ ] `/proc/<pid>/environ`, `/proc/<pid>/cmdline` do not contain secrets
