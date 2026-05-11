# mtctl — the laptop CLI for meshtermd

`mtctl` is the desktop/laptop companion to `meshtermd`. It speaks the
same Roam protocol the iOS meshTerm app speaks, but renders the remote
session in your local terminal instead of an on-device view.

Use it when you want:

- Persistent shell sessions across SSH drops, sleeps, and network
  changes — the same value Roam gives iOS users
- The same sessions reachable from iOS *and* the laptop, so you can
  start a build on your phone in the morning and reattach from the
  laptop in the afternoon (or vice versa)
- Tier-1 management of remote daemons (list / kill / rename / status)
  without opening a separate SSH window

`mtctl` is **not**:

- An SSH client. It shells out to your system `ssh` for the bootstrap
  step, inheriting `~/.ssh/config`, `ssh-agent`, ProxyCommand, and
  ControlMaster multiplexing. If `ssh user@host` works, `mtctl` works.
- A replacement for `meshtermd`. The daemon still needs to be running
  on the remote host — `mtctl` is a client only.

## Install

Pick the right binary for your laptop's OS + arch from the latest
release: <https://github.com/AG-Studio-Apps/meshtermd/releases/latest>

```bash
# Linux amd64 example. Swap the asset filename for your platform.
PLATFORM=linux-amd64

cd /tmp && rm -rf mtctl-install && mkdir mtctl-install && cd mtctl-install
curl -fLO https://github.com/AG-Studio-Apps/meshtermd/releases/latest/download/mtctl-${PLATFORM}
curl -fLO https://github.com/AG-Studio-Apps/meshtermd/releases/latest/download/SHA256SUMS
curl -fLO https://github.com/AG-Studio-Apps/meshtermd/releases/latest/download/SHA256SUMS.minisig
curl -fLO https://raw.githubusercontent.com/AG-Studio-Apps/meshtermd/main/docs/release-public-key.txt

# Verify signature (one-time: sudo apt install minisign / brew install minisign)
minisign -V -p release-public-key.txt -m SHA256SUMS
# Expect: "Signature and comment signature verified — Trusted comment: meshtermd vX.Y.Z"

# Verify this asset's hash
sha256sum -c SHA256SUMS --ignore-missing 2>&1 | grep mtctl-${PLATFORM}
# Expect: "mtctl-linux-amd64: OK"

# Install
mkdir -p ~/.local/bin
install -m 755 mtctl-${PLATFORM} ~/.local/bin/mtctl
mtctl version
```

Make sure `~/.local/bin` is on your `$PATH`.

After the initial install, future upgrades are one command:

```bash
mtctl update            # check + apply if available
mtctl update --check    # check only; exit 0 = up to date, 1 = available
```

## Attach to a remote session

```bash
mtctl attach user@host new                  # spawn + attach to a fresh shell
mtctl attach user@host my-session           # attach to "my-session", create if missing
mtctl attach user@host <hex-id>             # reattach to a specific session by id
mtctl attach user@host --mode readonly <id> # watcher: see output, can't type
```

If you always attach to the same host, set `$MTCTL_HOST` (or write it
to `~/.config/mtctl/host`) and drop the `user@host` argument:

```bash
export MTCTL_HOST=user@example.com
mtctl attach my-session
```

While attached:

- **Detach**: type `~.` on a fresh line. The remote shell stays alive
  on the daemon; reattach with the same command any time.
- **Window resize**: handled automatically — your local terminal's
  size changes are forwarded as Resize frames.
- **Reconnect on drop**: if your network blips, the local pump exits
  cleanly. Re-run the same `mtctl attach` to pick up where you left
  off; the daemon replays missed output.

## Manage remote sessions

All Tier 1 commands accept the same `--host`/`$MTCTL_HOST` shape as
attach:

```bash
mtctl list user@host                # all sessions on this daemon
mtctl list user@host --json         # machine-readable; same wire shape iOS consumes
mtctl status user@host              # daemon-wide snapshot (QUIC addr, sessions, idle)
mtctl session-info user@host <id>   # one session: rows, cols, idle, attached clients
mtctl rename user@host <id> new-name
mtctl kill user@host <id-or-name>   # reap; PTY + buffer go away
mtctl new user@host --name backend  # create without attaching
```

## Self-update

`mtctl update` mirrors `meshtermd update`:

- Resolves the latest signed release (or `--tag X.Y.Z`) via the
  GitHub Releases API
- Verifies the SHA256SUMS minisign signature against the same primary
  + emergency key roster the iOS app uses
- Verifies the binary's SHA-256 against the signed manifest
- Atomically swaps your `~/.local/bin/mtctl`

Anti-rollback is on by default: `mtctl update --tag <older-version>`
refuses unless you pass `--allow-downgrade`.

Exit codes match `meshtermd update`:

| Code | Meaning                                                |
|------|--------------------------------------------------------|
| 0    | up to date OR update succeeded                         |
| 1    | update available (only with `--check`)                 |
| 2    | bad flags / user cancelled                             |
| 3    | verification failed (security event)                   |
| 4    | download / network failure                             |

## Uninstall

```bash
mtctl uninstall              # confirms y/N, removes ~/.local/bin/mtctl
mtctl uninstall --yes        # non-interactive
```

mtctl has no state directory of its own (no cert, no key, no socket),
so there's no `--purge` equivalent.

## Troubleshooting

**"command not found: mtctl"** — `~/.local/bin` isn't on your `$PATH`.
Either add it (`export PATH="$HOME/.local/bin:$PATH"` in your shell rc)
or move the binary somewhere already on `$PATH`.

**"mtctl attach: bootstrap: …"** — the SSH layer failed. Run the same
`ssh user@host` invocation manually to see why (auth failure, host
unreachable, etc.).

**"mtctl attach: bootstrap: command not found: meshtermd"** — the
daemon isn't installed on the remote host. Use the meshTerm iOS app's
"Set Up Roam on this Host" flow to install it, then try again.

**"mtctl attach: tls: certificate signed by unknown authority"** — the
daemon's TLS cert fingerprint doesn't match what the bootstrap line
declared. Likely a man-in-the-middle on the QUIC port, or the daemon
regenerated its cert between SSH bootstrap and your QUIC dial (rare).
Don't continue.

**"mtctl attach: ErrNotATerminal"** — stdin isn't a TTY. mtctl needs a
terminal to drive raw mode + window-size queries; running it from a
script with redirected stdin won't work.

## Compatibility

`mtctl` and `meshtermd` ship in the same release. Pair `mtctl-vX.Y.Z`
with a daemon at `meshtermd-vX.Y.Z` or newer — older daemons may not
understand newer wire fields. The iOS app pins its own daemon version
independently via the auto-installer's `pinnedReleaseTag`.
