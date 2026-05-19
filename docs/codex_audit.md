# Codex Security Audit Notes

Date: 2026-05-19

Scope: static security review of the repository, focused on update trust, SSH/bootstrap handling, IPC/socket discovery, QUIC attach authorization, persistence, and sidecar process handling.

**Status: all findings addressed in v1.1.4 (2026-05-19).** Per-finding
commits below; see git log for diffs and tests.

| Finding | Severity | Status | Commit |
|---|---|---|---|
| Self-update signatures not bound to release tag | HIGH | Fixed | `EnforceTrustedComment` wired into both update paths |
| Client socket discovery can select a spoofed XDG socket | MEDIUM | Fixed | `VerifyParentDir` exported + `VerifyClientSocket` added |
| `mtctl` host values can be parsed as local `ssh` options | MEDIUM | Fixed | `validateSSHHost` guard + `--` separator in argv |
| First-use SSH bootstrap silently trusts new host keys | LOW | Documented | TOFU caveat added to SECURITY.md § What we trust |

## Findings

### High: self-update signatures are not bound to the requested release tag

`cmd/meshtermd/update.go` and `cmd/mtctl/update.go` verify `SHA256SUMS.minisig`, then select a checksum by filename only via `internal/release/fetcher.go`. The minisign trusted comment is printed but not enforced.

If the GitHub repo or release assets are compromised but the signing key is not, an attacker can publish a higher semver release containing an old signed `SHA256SUMS`, old `.minisig`, and old binaries under the same asset names. The anti-rollback check passes because the selected tag is newer, but the installed binary can be older and vulnerable.

Suggested fix: sign a manifest that includes the release tag, asset names, and hashes. As a shorter-term guard, require the signed trusted comment to exactly match the requested tag and verify the downloaded binary's embedded version before replacement.

### Medium: client socket discovery can select a spoofed XDG socket

`cmd/meshtermd/serve.go` chooses `$XDG_RUNTIME_DIR/meshtermd.sock` based only on `os.Stat`. The server validates socket parent ownership and permissions, but the client discovery path does not mirror that check and does not require the path to be a Unix socket.

On a misconfigured world-writable XDG runtime directory, another local user could pre-create a socket and answer IPC requests, including returning a fake `MTRM_QUIC` bootstrap for `connect`.

Suggested fix: before trusting the XDG socket path, `Lstat` the parent and require current uid ownership plus no group/other permission bits. Also require the discovered path itself to be a Unix socket. If validation fails, fall back to the persistent socket path.

### Medium: `mtctl` host values can be parsed as local `ssh` options

`cmd/mtctl/host.go` passes the configured host directly as an argv element to `ssh`. If a caller supplies a host beginning with `-`, OpenSSH can treat it as another option, such as `ProxyCommand`, which can execute local commands. This is especially relevant for scripts that pass user-controlled `--host` values or inherit `MTCTL_HOST`.

Suggested fix: reject host values beginning with `-` and/or insert `--` before the host argument. Add tests covering hostile host strings.

### Low/Medium: first-use SSH bootstrap silently trusts new host keys

`cmd/mtctl/host.go` sets `StrictHostKeyChecking=accept-new`, while the security model documents bootstrap trust as inherited from the user's SSH host key chain.

On first connection, a network MITM can supply a host key, return a fake bootstrap line, and provide a cert fingerprint that the QUIC client then pins.

Suggested fix: default to normal strict host-key behavior, or make trust-on-first-use behavior an explicit opt-in flag.

## Notes

The server-side QUIC attach path, attach-token lifecycle, CBOR and frame limits, certificate storage permissions, and sidecar env-file handling looked intentionally hardened in this pass.

This was a static review; the test suite was not run.
