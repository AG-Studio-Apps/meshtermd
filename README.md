# meshtermd

**meshtermd** is a persistent terminal daemon over QUIC. It holds shell sessions on a host across network drops, device sleep, and client reconnects — like `mosh` + `tmux` consolidated into one daemon, with real scrollback through disconnects, named multi-session, and any-client handoff between devices.

Ships with [`mtctl`](docs/mtctl.md), a laptop CLI for `attach` / `list` / `new` / `kill` / `rename` / `update`. The iOS app [meshTerm](https://meshterm.app) is one client; mtctl is another; the wire protocol is documented in [`docs/roam-protocol.md`](docs/roam-protocol.md) so others can be written.

Start a build on your phone in the morning, reattach from a laptop in the afternoon. Lose Wi-Fi mid-shell, walk to a café, reconnect — the session is still there with full scrollback.

## Status

Pre-1.0. The wire protocol is documented but not frozen; we may break it before v1.0.0 with a wire-version bump and a synchronized iOS app release. Bug reports against tagged releases are welcome and get triaged.

## Compared to

|                              | meshtermd       | mosh        | tmux        | wezterm mux | Eternal Terminal |
|------------------------------|-----------------|-------------|-------------|-------------|------------------|
| Persistent across drops      | ✅              | ✅          | ✅          | ✅          | ✅               |
| Real scrollback through drop | ✅              | ❌          | ✅          | ✅          | ✅               |
| Named multi-session per host | ✅              | ❌          | ✅          | ✅          | partial          |
| Modern UDP transport         | QUIC            | SSP/UDP     | n/a         | TCP/SSH     | TCP              |
| Mobile-native client         | ✅ (meshTerm)†  | partial     | ❌          | ❌          | ❌               |
| Same daemon, multiple clients| ✅              | ❌          | ✅          | client-specific | ✅           |
| Tab completion / man pages   | ✅              | ✅          | ✅          | ✅          | ✅               |
| Signed self-update           | ✅ (minisign)   | distro-only | distro-only | distro-only | distro-only      |

The daemon is the source of truth; the clients are interchangeable. That's the line wezterm's multiplexer can't easily cross — it requires their emulator on both ends.

† **meshTerm iOS status**: the QUIC-speaking meshTerm client is currently in TestFlight as the v2.0 release; the App Store version (v1.x) is the pre-Roam SSH client. The two ship in lockstep — when v2.0 hits the App Store, meshtermd cuts its first coordinated public release (see Install below).

## What it does

- Listens for QUIC connections from any client that speaks the Roam protocol (ALPN `meshterm/0`, single bidi stream with tagged framing).
- Owns a registry of terminal sessions: PTY + child shell + monotonic output ring buffer (4 MiB per session).
- Sessions persist across client disconnects; reattach replays buffered output from the client's last ack sequence.
- One exclusive + N readonly attachers per session. Multi-attach is for "watch a colleague" / "open the same session from a second device."
- Cert-pinning trust bootstrapped over SSH — no PSK, no custom crypto in the daemon. If you can `ssh user@host`, you have full control over your daemon.
- Self-update with minisign-signed `SHA256SUMS` plus an embedded primary + emergency public-key roster.

## Install

**Currently live (manual install only):** prebuilt binaries from [GitHub Releases](https://github.com/AG-Studio-Apps/meshtermd/releases/latest) for seven targets — linux amd64/arm64/armv7, darwin amd64/arm64, freebsd amd64/arm64. Releases include the daemon, the `mtctl` CLI, man pages, and shell completions for bash/zsh/fish.

```sh
# Pick the right asset for your platform from the latest release.
# Verify SHA-256 against the signed SHA256SUMS, then install:
install -m 755 meshtermd-<platform> ~/.local/bin/meshtermd
install -m 755 mtctl-<platform>     ~/.local/bin/mtctl
```

The minisign public key for `SHA256SUMS.minisig` verification lives in [`docs/release-public-key.txt`](docs/release-public-key.txt).

**Coming with the v2.0 coordinated release** (alongside meshTerm iOS v2.0 hitting the App Store):

- **Homebrew tap** (macOS, Linux): `brew tap AG-Studio-Apps/meshtermd && brew install meshtermd`
- **Arch Linux (AUR)**: `meshtermd-bin` (pre-built) and `meshtermd` (build-from-source)

The formula and `PKGBUILD`s are already staged under [`packaging/`](packaging/) so anyone curious can preview the install shape; the live channels go up on co-release day.

Once installed, the daemon usually runs under a supervisor — systemd-user on Linux, launchd on macOS, or a `nohup` fallback. The supervisor unit is dropped automatically by the iOS app's auto-installer on first connect, or you can write one yourself by hand.

## Companion CLI: `mtctl`

`mtctl` is the laptop/desktop counterpart to the iOS app — manages remote sessions over SSH and attaches to them as your local terminal. Same binary distribution; same release artifacts.

Full install + usage guide: [`docs/mtctl.md`](docs/mtctl.md). Man page: `man mtctl`.

```
mtctl --host me@dev-box list                       # what's alive on the daemon
mtctl --host me@dev-box new --name dev             # create without attaching
mtctl --host me@dev-box attach dev                 # land in the same shell
                                                   # your iPhone is using
mtctl --host me@dev-box attach dev --mode readonly # watch over someone's
                                                   # shoulder; can't type
mtctl --host me@dev-box rename dev staging
mtctl --host me@dev-box kill staging
mtctl --host me@dev-box status                     # daemon snapshot
```

In an attached session, type `~.` on a fresh line to detach (mosh / ssh convention). The remote shell stays alive on the daemon; pick it up from any other client.

Set `MTCTL_HOST` once per shell or write the target into `~/.config/mtctl/host` to omit `--host`.

Auth is plain SSH — we shell out to the system `ssh` binary, so your existing `~/.ssh/config`, ssh-agent, and keys work transparently. The QUIC connection that carries the attached terminal is cert-pinned to the fingerprint received over SSH (same trust hop the iOS app uses).

Transport-layer security is TLS 1.3 (provided by Go's standard library inside `quic-go`); we add cert pinning bootstrapped over SSH. There is no application-layer cryptography in this codebase.

## Reporting issues

Bugs and questions about the daemon, `mtctl`, or the wire protocol: file an issue on this repo. Templates are provided.

Bugs about the **meshTerm iOS app** (UI, host management, anything that isn't the daemon): use the in-app help/feedback channel — the meshTerm app source is private, so issues here aren't the right venue for app-side problems.

Feature requests during the v0.x phase get triaged but may get rejected on grounds of "not yet" while the wire protocol is in flux. Bug reports against released versions are always welcome.

## Reporting security issues

See [SECURITY.md](docs/SECURITY.md). **Do not file security reports as public issues.**

## License

Apache License 2.0 — see [LICENSE](LICENSE).
