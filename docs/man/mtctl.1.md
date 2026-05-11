% MTCTL(1) | meshtermd
% meshtermd authors
% May 2026

# NAME

mtctl - manage and attach to remote meshtermd terminal sessions

# SYNOPSIS

**mtctl** *command* [*options*] [*arguments*]

# DESCRIPTION

**mtctl** is the laptop / desktop client for **meshtermd**(8). It speaks
the same Roam protocol the iOS meshTerm app speaks, but renders the
remote session in your local terminal instead of an on-device view.

Use **mtctl** when you want persistent shell sessions across SSH drops,
sleeps, and network changes; the same sessions reachable from iOS *and*
the laptop (start a build on your phone in the morning, reattach from
the laptop in the afternoon); or out-of-band management of remote
daemons (list / kill / rename / status) without opening a separate SSH
window.

**mtctl** is **not** an SSH client. It shells out to your system
**ssh**(1) for the bootstrap step, inheriting **~/.ssh/config**,
**ssh-agent**, **ProxyCommand**, and **ControlMaster** multiplexing. If
`ssh user@host` works, **mtctl** works.

**mtctl** is **not** a replacement for **meshtermd**. The daemon still
needs to be running on the remote host; **mtctl** is a client only.

# COMMANDS

**version**, **\-\-version**, **-v**
:   Print the build identifier and exit.

**list** [**\-\-host** *user@host*] [**\-\-json**] [**\-\-timeout** *dur*]
:   Enumerate live sessions on the remote daemon.

**session-info** [**\-\-host** *user@host*] [**\-\-json**] *id*
:   Print one session's detail (attach state, geometry, idle).

**status** [**\-\-host** *user@host*] [**\-\-json**]
:   Print the remote daemon's operational snapshot (uptime, QUIC addr,
    session count, idle policy, certificate fingerprint).

**new** [**\-\-host** *user@host*] **\-\-name** *NAME* [**\-\-idle-timeout** *DUR*]
:   Create a new named session without attaching.

**attach** [**\-\-host** *user@host*] [**\-\-mode** {*exclusive*|*readonly*}] *id-or-name*
:   Attach to a session as your local terminal. If the named session
    doesn't exist, **attach** creates it. Use **\-\-mode readonly** to
    watch without sending input. Type `~.` on a fresh line to detach;
    the remote shell stays alive on the daemon.

**kill** [**\-\-host** *user@host*] *id-or-name*
:   Reap a session by SessionID or by user-visible Name. Glob patterns
    (`*`, `?`, `[...]`) and **\-\-all** are supported.

**rename** [**\-\-host** *user@host*] *id-or-name* *new-name*
:   Change a session's user-visible name. PTY and scrollback buffer
    are unaffected.

**update** [**\-\-check**] [**\-\-yes**] [**\-\-tag** *vX.Y.Z*] [**\-\-allow-downgrade**]
:   Apply a signed self-update from GitHub Releases. Verifies the
    SHA-256 manifest's minisign signature against the embedded primary
    + emergency public-key roster, then verifies the binary's SHA-256
    against the manifest, then atomically swaps **~/.local/bin/mtctl**.
    Anti-rollback is on by default; pass **\-\-allow-downgrade** to
    install an older tag.

**uninstall** [**\-\-yes**]
:   Remove the **mtctl** binary at **~/.local/bin/mtctl**. **mtctl**
    has no state directory of its own.

**help**, **\-\-help**, **-h**
:   Print top-level usage. Per-subcommand flags are listed by
    `mtctl <subcommand> --help`.

# OPTIONS

**\-\-host** *user@host*
:   SSH target running **meshtermd**. Defaults to **$MTCTL_HOST**, then
    to the contents of **~/.config/mtctl/host**.

**\-\-json**
:   Emit machine-readable JSON instead of the default text/tabwriter
    table. Wire shape matches what the iOS app consumes.

**\-\-timeout** *DUR*
:   Per-invocation SSH dial / command timeout (e.g. `5s`, `2m`). Only
    affects management commands; **attach** holds the connection until
    detach.

**\-\-mode** *MODE*
:   For **attach**: *exclusive* (default; sends stdin) or *readonly*
    (watcher; renders output, drops local stdin).

# ENVIRONMENT

**MTCTL_HOST**
:   Default SSH target for every subcommand. Overridden by **\-\-host**.

**SSH_AUTH_SOCK**, **\-\-ssh-***\ flags
:   Inherited via the system **ssh**(1); see **ssh_config**(5).

# FILES

**~/.config/mtctl/host**
:   Fallback default for **\-\-host** when **$MTCTL_HOST** is unset.
    Single-line file containing *user@host*.

**~/.local/bin/mtctl**
:   Conventional install path. **update** and **uninstall** target
    this path.

# EXIT STATUS

0
:   Success.

1
:   Generic failure (or, for **update \-\-check**, "update available").

2
:   Bad flags, missing config, or user cancellation.

3
:   SSH / remote-command failure, or signature verification failure
    (treat as a security event when emitted from **update**).

4
:   Network / download failure during **update**.

# EXAMPLES

Attach to a session, creating it if missing:

    mtctl attach --host user@example.com my-session

Discover what's live on a host:

    MTCTL_HOST=user@example.com mtctl list
    mtctl list --json | jq '.sessions[].name'

Self-update to the latest signed release:

    mtctl update --yes

# SECURITY

The trust chain mirrors the iOS app. Authentication and host trust
piggyback on standard SSH — **mtctl** never sees your password or key.
The QUIC connection's certificate fingerprint is pinned via the
bootstrap line printed by **meshtermd connect** on the remote side; a
mismatch (MITM, regenerated cert) is hard-fail. Self-update verifies
both the minisign signature on **SHA256SUMS** and the per-binary
SHA-256 before the atomic swap; the trusted-key roster is embedded in
the binary at build time.

See **meshtermd**(8) for the daemon's threat model.

# SEE ALSO

**meshtermd**(8), **ssh**(1), **ssh_config**(5)

Source: <https://github.com/AG-Studio-Apps/meshtermd>
