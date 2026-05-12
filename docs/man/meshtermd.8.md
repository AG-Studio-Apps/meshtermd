% MESHTERMD(8) | meshtermd
% meshtermd authors
% May 2026

# NAME

meshtermd - persistent terminal session daemon over QUIC

# SYNOPSIS

**meshtermd** *command* [*options*] [*arguments*]

# DESCRIPTION

**meshtermd** holds persistent terminal sessions on a host across
network drops, device sleep, and client reconnects. Sessions live as
long as the daemon does; any number of clients (the iOS app
**meshTerm**, the **mtctl**(1) laptop CLI, or anything else that
implements the documented Roam protocol) can attach, detach, and
re-attach without losing scrollback or shell state.

A persistent shell on the host is reachable from multiple devices: a
session started on a phone in the morning can be resumed from a laptop
in the afternoon. This is the workflow **mosh**(1) + **tmux**(1)
deliver in two tools; **meshtermd** consolidates them into one daemon
with a modern transport (QUIC, with reconnect-and-replay-from-ack) and
real scrollback through every disconnect.

# COMMANDS

**version**, **\-\-version**, **-v**
:   Print the build identifier and exit.

**serve** [*options*]
:   Run the long-lived daemon. Owns the session registry, accepts
    incoming QUIC connections, and serves a local IPC socket for the
    SSH bootstrap helper. Normally launched by a supervisor (systemd-user,
    launchd, or nohup fallback) rather than directly.

    Notable flags: **\-\-addr** (QUIC bind), **\-\-socket** (IPC
    socket path), **\-\-max-sessions** (concurrent session cap),
    **\-\-idle-timeout** / **\-\-max-idle-timeout** (per-session GC
    knobs), **\-\-session-buffer-bytes** (per-session output ring
    buffer; default 4 MiB, raise for hosts where you want richer
    reattach-replay history during long output-heavy builds).

**connect** [*options*]
:   SSH-side bootstrap helper invoked by the meshTerm iOS app (or by
    **mtctl attach**). Allocates a single-use attach token, looks up
    or spawns the requested session, and prints a single bootstrap
    line on stdout:

        MTRM_QUIC 1 <port> <sid_hex_32> <fp_hex_64> <tok_hex_32>

    Then exits. Not intended for direct interactive use.

**list** [**\-\-json**]
:   Enumerate live sessions on the local daemon. JSON output is the
    wire shape iOS and **mtctl**(1) consume.

**session-info** [**\-\-json**] *id*
:   Print one session's detail (attach state, geometry, idle).

**status** [**\-\-json**]
:   Print the daemon's operational snapshot (uptime, QUIC bound
    address, session count, idle-timeout config, attach-token pool
    size, certificate fingerprint).

**kill** *id-or-name*
:   Reap a session by hex SessionID or by user-visible Name. Supports
    glob patterns and **\-\-all**.

**rename** *id-or-name* *new-name*
:   Change a session's user-visible Name. PTY and scrollback buffer
    are unaffected.

**update** [**\-\-check**] [**\-\-yes**] [**\-\-tag** *vX.Y.Z*] [**\-\-allow-downgrade**]
:   Apply a signed self-update from GitHub Releases. Same verification
    chain as **mtctl update**: minisign signature on **SHA256SUMS** via
    the embedded primary + emergency key roster, per-binary SHA-256
    against the manifest, atomic file replace, then **svcmgr.Restart**
    via the detected supervisor.

**uninstall** [**\-\-purge**] [**\-\-yes**]
:   Stop the daemon, remove the supervisor unit, remove the binary.
    **\-\-purge** also wipes **~/.local/share/meshtermd/** (certificate,
    state, logs).

**help**, **\-\-help**, **-h**
:   Print top-level usage. Per-subcommand flags via
    `meshtermd <subcommand> --help`.

# OPTIONS

Common flags accepted by most subcommands:

**\-\-json**
:   Emit machine-readable JSON instead of the human-readable table.

**\-\-yes**
:   Skip the interactive confirmation prompt (**update**, **uninstall**).

**\-\-tag** *vX.Y.Z*
:   For **update**: target a specific signed release tag instead of
    the latest. The tag is validated against
    `^v\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$` and rejected
    otherwise.

**\-\-allow-downgrade**
:   For **update**: permit installing a tag older than the running
    version. Off by default so a flipped GitHub "latest" pointer or a
    typoed **\-\-tag** can't silently roll back to a known-vulnerable
    build.

# FILES

**~/.local/bin/meshtermd**
:   Conventional install path for the daemon binary.

**~/.local/share/meshtermd/**
:   State directory: self-signed TLS cert, IPC socket, daemon PID
    file. Wiped by **uninstall \-\-purge**.

**~/.config/systemd/user/meshtermd.service** (Linux, systemd-user)
:   Supervisor unit when systemd-user is the detected backend.

**~/Library/LaunchAgents/com.agstudio.meshtermd.plist** (macOS)
:   Supervisor plist when launchd is the detected backend.

**/tmp/meshtermd.log** (nohup fallback)
:   Append-only log when neither systemd-user nor launchd is available.

# NETWORK

**meshtermd** listens for QUIC on a configurable address (default
**0.0.0.0:51820** when installed via the iOS app's nohup path,
**127.0.0.1:0** when the library defaults are used). ALPN
**meshterm/0**. TLS 1.3 only, pinned curves X25519 + P-256. Datagrams
enabled. The QUIC certificate's fingerprint is what every client pins;
no SNI, no hostname verification, no CA chain.

Default per-server concurrency cap: 64 in-flight handlers. Over-cap
peers receive CONNECTION_CLOSE with application code 0x10F.

# AUTHENTICATION

Every QUIC attach requires a single-use 16-byte attach token with a
30-second TTL. Tokens are minted by **meshtermd connect** in response
to an SSH-authenticated request from the user-controlled SSH client.
There is no separate PSK, password, or key configured in the daemon —
the trust model is "you control SSH, you control the daemon."

# EXIT STATUS

0
:   Success (or, for **update**, "already on this version").

1
:   Generic error (or, for **update \-\-check**, "update available").

2
:   Bad flags or user cancellation.

3
:   Verification failure (treat as a security event when emitted from
    **update** — signature didn't match, key not in roster, or
    SHA-256 mismatch).

4
:   Network / download failure during **update**.

5
:   For **update**: binary was swapped successfully but
    **svcmgr.Restart** failed. Restart the daemon manually to pick up
    the new build.

# SECURITY

See **docs/SECURITY.md** in the source tree for the full threat model
and trust assumptions, including:

- Attacker classes (local-user, on-path, hostile mirror, jailbroken
  client).
- Cryptographic primitives (Ed25519 for minisign, BLAKE2b-512 for
  pre-hashed mode, ECDSA P-256 for the daemon's QUIC certificate).
- Audit findings and their remediations (the **\-\-tag** validator,
  the IPC concurrent-connection cap, and the minisign parser fuzz
  target ship in this version).

# EXAMPLES

Start the daemon manually for debugging:

    meshtermd serve --addr 0.0.0.0:51820

Enumerate live sessions:

    meshtermd list --json

Self-update to the latest signed release:

    meshtermd update --yes

# SEE ALSO

**mtctl**(1), **ssh**(1), **systemd.service**(5), **launchd.plist**(5)

Source and protocol specification:
<https://github.com/AG-Studio-Apps/meshtermd>
