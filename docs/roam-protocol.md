# Roam Protocol — wire specification (v0)

**Status**: draft. Subject to breaking changes until v1.0. Do not implement against this expecting stability.

## 1. Goals

- Persistent terminal sessions across client disconnect, foreground network roam, and iOS app backgrounding
- Server-side session ownership: the daemon (`meshtermd`) holds the PTY + child process + output ring buffer; clients reattach by ID
- Trust bootstrapped over an existing SSH session — no new credential surface
- All transport security delegated to TLS 1.3 inside QUIC; **no application-layer cryptography**
- Wire format simple enough to fuzz exhaustively and review in a day

## 2. Non-goals (v0)

- Multi-client attach to the same session (one connection per session at a time; second attach kicks the first)
- Collaborative editing / cursor sharing
- File transfer over the protocol (use SFTP)
- Authentication independent of SSH (always SSH-bootstrapped)
- Lossy mode for extreme packet loss (QUIC's reliable streams suffice for our targets)

## 3. High-level flow

```
   CLIENT (meshTerm iOS)                       SERVER (meshtermd)

   ┌─────────────────────┐                     ┌─────────────────────┐
   │ existing SSH session │                     │   meshtermd serve   │
   │ (NIOSSH)             │                     │   already running   │
   └──────────┬───────────┘                     └──────────┬──────────┘
              │                                            │
              │ ① ssh-exec: meshtermd connect              │
              │            --session <id|new>               │
              ├───────────────────────────────────────────▶│
              │                                            │ talks to local
              │                                            │ serve daemon
              │                                            │ over unix socket
              │                                            │
              │   stdout: MTRM_QUIC v1 <port>              │
              │           <session_id> <cert_fp>           │
              │           <attach_token>                   │
              │◀───────────────────────────────────────────┤
              │                                            │
              │   SSH channel closes                        │
              │                                            │
              │ ② QUIC handshake (TLS 1.3, ALPN)           │
              ├───────────────────────────────────────────▶│
              │   client verifies presented cert            │
              │   fingerprint matches <cert_fp>             │
              │                                            │
              │ ③ Open control stream, send Attach         │
              ├───────────────────────────────────────────▶│
              │                                            │
              │ ④ Receive AttachAck, then replayed         │
              │    output, then live forwarding             │
              │◀───────────────────────────────────────────┤
              │                                            │
              │ ⑤ Open stdin stream, server opens          │
              │    stdout stream                            │
              │◀══════════════════════════════════════════▶│
              │                                            │
              │ ⑥ Datagrams for echo acks, ping/pong       │
              │◀┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄▶│
              │                                            │
              │   (live operation)                          │
              │                                            │
              │ ⑦ network roam → QUIC connection            │
              │    migration handles transparently           │
              │                                            │
              │ ⑧ app backgrounds → QUIC dies →             │
              │    server-side session stays alive →         │
              │    foreground reattaches with                │
              │    new bootstrap + same session_id           │
              │                                            │
```

## 4. Bootstrap

### 4.1 SSH-side invocation

The iOS client runs the following over a one-shot SSH exec channel:

```
meshtermd connect --session <session_id|new> [--rows N] [--cols M]
```

Where `<session_id>` is the hex-encoded 16-byte session ID from a previous attach, or the literal string `new` for a fresh session.

### 4.2 Stdout response

`meshtermd connect` prints **exactly one line** to stdout, then exits 0:

```
MTRM_QUIC <version> <port> <session_id> <cert_fp> <attach_token>\n
```

Fields are space-separated ASCII. No quoting, no escaping (none of these fields contain whitespace).

| Field | Format | Meaning |
|---|---|---|
| `MTRM_QUIC` | literal | sentinel string |
| `<version>` | decimal int | bootstrap-line version, currently `1` |
| `<port>` | decimal int 1024–65535 | UDP port the daemon is listening on |
| `<session_id>` | 32 hex chars (16 bytes) | session ID, echoed if `<id>` given, freshly generated if `new` |
| `<cert_fp>` | 64 hex chars (SHA-256, no separators) | fingerprint of daemon's TLS certificate (DER-encoded form) |
| `<attach_token>` | 32 hex chars (16 bytes) | single-use token authorising the next QUIC attach |

The line is terminated by a single `\n`. The client MUST validate every field before opening QUIC.

### 4.3 Stderr

`meshtermd connect` may emit human-readable diagnostics on stderr. Stderr is for humans; the client SHOULD treat any stderr output as informational unless exit code is non-zero.

### 4.4 Exit codes

| Code | Meaning |
|---|---|
| 0 | Bootstrap succeeded; stdout line valid |
| 1 | Generic error (read stderr) |
| 2 | `meshtermd serve` not running |
| 3 | Session ID provided but session not found |
| 4 | Daemon out of capacity (max sessions reached) |

## 5. QUIC connection

### 5.1 Endpoint

Client opens a QUIC connection to `<host>:<port>` where `<host>` is the same hostname used for SSH and `<port>` is the value from the bootstrap line.

### 5.2 ALPN

Single ALPN value: `meshterm/0` (will become `meshterm/1` at protocol v1.0). The client MUST set this; the server MUST refuse connections without it.

### 5.3 TLS 1.3

QUIC mandates TLS 1.3. The daemon presents a self-signed ECDSA P-256 certificate (sigalg `ecdsa_secp256r1_sha256`, TLS code 0x0403) from `~/.local/share/meshtermd/cert.pem`. The client MUST validate the certificate's fingerprint matches `<cert_fp>` from the bootstrap line. No CA trust chain is involved. No SNI validation is required (the daemon ignores the SNI hostname). Earlier drafts of this protocol specified Ed25519; we changed to P-256 because iOS Network.framework's QUIC ClientHello does not advertise `ed25519` (0x0807) in its `signature_algorithms` extension and silently rejects Ed25519 server certs with `CRYPTO_ERROR 0x128` before the client's verify block ever runs. See SECURITY.md § Cert lifecycle.

### 5.4 Connection migration

Both sides MUST enable QUIC connection migration (RFC 9000 §9). This handles foreground network changes (LTE↔Wi-Fi) without a fresh bootstrap.

### 5.5 0-RTT

Not used in v0. Future versions may negotiate 0-RTT via TLS session tickets.

## 6. Streams

Three streams per attached connection. Stream IDs are assigned by QUIC; this protocol refers to them by role.

| Stream | Direction | Initiated by | Reliability | Purpose |
|---|---|---|---|---|
| Control | bidirectional | Client | reliable | All structured messages: Attach, Ack, Resize, Ping, Goodbye |
| Stdin | unidirectional | Client | reliable | Raw byte stream from client keyboard to PTY stdin |
| Stdout | unidirectional | Server | reliable | Framed output from PTY stdout to client (with sequence numbers for replay) |

### 6.1 Stream lifecycle

1. Client opens **Control** stream first. Client sends `Attach` (§ 7.2).
2. Server responds with `AttachAck` (§ 7.3). If `accepted = false`, both sides close.
3. If `accepted = true`, server begins sending replayed output frames on **Stdout** stream (server-initiated unidirectional). Replay continues until the buffer's tail is reached, then live forwarding resumes seamlessly (no marker).
4. Client opens **Stdin** stream and begins forwarding keyboard bytes.
5. Either side may send Control messages at any time (Resize, Ping, Goodbye).

### 6.2 Closing

- Either side sends `Goodbye{reason}` on the Control stream and closes their write side of the Control stream.
- The peer acknowledges by closing its write side, then closes the Control stream.
- Stdin/Stdout streams close when the connection closes.

## 7. Control stream messages

### 7.1 Encoding

Each message on the Control stream is framed:

```
[uint32 big-endian: length][CBOR-encoded message body]
```

CBOR (RFC 8949) was chosen over JSON for compact binary representation, over Protocol Buffers for schema-less flexibility during early iteration. Each CBOR map has a single key `t` indicating the message type, plus type-specific keys.

A maximum frame length of 64 KiB is enforced. Exceeding it is a fatal protocol violation; both sides terminate the connection.

### 7.2 `Attach` (client → server, first message)

```cbor
{
  "t": "Attach",
  "v": 1,                          // protocol version client supports
  "tok": h'…',                     // attach_token (16 bytes), must match bootstrap
  "sid": h'…',                     // session_id (16 bytes), must match bootstrap
  "ack": 0,                        // last_ack_seq; 0 for fresh attach
  "rows": 24,                      // initial PTY rows
  "cols": 80,                      // initial PTY cols
  "mode": "exclusive"              // optional: "exclusive" (default) or "readonly"
}
```

**Attach modes** (the `mode` field):

- `"exclusive"` (default; missing/empty/unknown values map here): the client receives output, sends stdin, and owns the PTY size via Resize. A new exclusive Attach **displaces** any prior exclusive client — the daemon cancels the displaced client's stream context and the client sees its connection close cleanly. Existing readonly clients are unaffected by exclusive turnover.
- `"readonly"`: the client receives output only. Stdin frames from a readonly client are silently dropped by the daemon (NOT a protocol violation — a misbehaving keystroke shouldn't tear the connection down). Resize frames are also dropped: the exclusive client owns the geometry. Multiple readonly clients can coexist with each other AND with one exclusive client.

The pre-`mode` field client posture is preserved exactly: an Attach with no `mode` field is treated as exclusive, identical to v0 behaviour.

### 7.3 `AttachAck` (server → client, response to Attach)

```cbor
{
  "t": "AttachAck",
  "v": 1,                          // protocol version server is using
  "ok": true,
  "sid": h'…',                     // confirmed session_id
  "start": 12345,                  // first seq number we'll send on Stdout (replay starts here)
  "buf_seq": 12345,                // current head of the output ring buffer (== start unless replay overflowed)
  "trunc": false,                  // true iff the requested ack point is older than the buffer's tail (replay was truncated)
  "mode": "exclusive",             // the role the daemon resolved (echoes Attach.mode; "exclusive" if unrecognised)
  "peers": ["readonly"]            // modes of OTHER clients currently attached, excluding this one. Empty when sole attach.
}
```

If `ok = false`, body contains `"err": "<short_code>"` and `"msg": "<human_msg>"`. Codes: `unknown_session`, `bad_token`, `version_unsupported`, `capacity`, `replaced` (another client attached).

If `trunc = true`, the client should display a one-line "[…some output lost during disconnect…]" indicator before rendering the replayed bytes.

`peers` is a snapshot; a client of either mode can attach or detach milliseconds later. Useful for the iOS picker / mtctl status line ("also attached: 1 readonly") but not load-bearing for any protocol invariant.

### 7.4 `Ack` (client → server, periodic)

Sent at most once per 100 ms while output is being received.

```cbor
{
  "t": "Ack",
  "seq": 12500                     // highest seq we have rendered
}
```

The server uses this to advance its ring buffer's "safely delivered" pointer. The buffer never trims past the most recent `Ack` seq.

### 7.5 `Resize` (client → server)

```cbor
{
  "t": "Resize",
  "rows": 30,
  "cols": 100
}
```

Server calls `pty.Setsize` synchronously and forwards SIGWINCH to the child.

### 7.6 `Ping` / `Pong` (bidirectional)

```cbor
{ "t": "Ping", "n": 0xdeadbeef }
{ "t": "Pong", "n": 0xdeadbeef }
```

Either side may send `Ping`. Receiver MUST echo the nonce in `Pong` immediately. Used for keepalive (recommended every 10 s during idle) and latency measurement.

### 7.7 `Goodbye` (bidirectional, last message)

```cbor
{
  "t": "Goodbye",
  "reason": "client_close"        // or "session_ended", "shutdown", "error"
}
```

Sender then closes their write half. Receiver closes Control stream.

## 8. Stdout stream framing

Stdout is **not** a raw byte stream; each chunk emitted by the PTY is wrapped with a sequence number so the client can ack and the server can replay.

```
[uint64 big-endian: seq][uint32 big-endian: len][len bytes: payload]
```

- `seq` monotonically increases per byte: if `seq=100` covers 50 bytes, the next frame's seq is `150`. **Sequence numbers count bytes, not frames.**
- `len` is the byte length of `payload`. A single frame is capped at 16 KiB; longer chunks are split.
- `payload` is the raw bytes from the PTY (UTF-8, escape sequences, anything — the daemon does not interpret).

Replay: when the client sends `Attach{ack: N}`, the server seeks its ring buffer to byte position `N` and emits frames starting from there. Frame boundaries on replay may differ from frame boundaries during original transmission.

## 9. Stdin stream

Raw bytes from the client to the PTY. No framing, no acks. QUIC's reliable delivery + ordering guarantees suffice.

The client SHOULD NOT send unbounded bursts; respect QUIC's flow control.

## 10. Datagrams

QUIC datagrams (RFC 9221) are used for low-latency unreliable signals where a stream's in-order reliability would add unnecessary latency.

### 10.1 EchoConfirm (server → client)

```cbor
{
  "t": "EchoConfirm",
  "sin": 0,                        // stdin_seq — not used in v0; reserved
  "es": "on"                       // echo_state: "on" | "off" | "unknown"
}
```

Sent when the daemon detects the shell's echo mode changed (e.g., entering a password prompt or `vim`). Client uses this to authoritatively toggle predictive local echo arming, overriding the client-side prompt-sniff heuristic.

**v0 transport: control-stream frame.** This slot was originally reserved as a QUIC datagram for lower latency; the v0 implementation uses the existing tagged-frame control stream so the same dispatch path handles it on both ends without datagram plumbing. EchoConfirm payloads are ~20 bytes CBOR; head-of-line blocking behind stdout chunks (max 16 KiB) is bounded and acceptable for the use case. A future minor-version bump may add a datagram fast path while keeping the control-stream path as fallback.

**Best-effort:** the server MAY omit EchoConfirm entirely (older daemons, daemons whose PTY implementation doesn't support tcgetattr). Clients that don't receive EchoConfirm fall back to the prompt-sniff heuristic. Clients that don't recognise EchoConfirm (older versions) silently drop the unknown control type — forward-compat is built in.

### 10.2 Heartbeat datagrams

```cbor
{ "t": "Hb", "ts": 1715260000.123 }
```

Sent every ~5 s during idle. Loss is tolerable; only used for monitoring.

## 11. Session lifecycle (server-side)

### 11.1 Creation

A session is created when `meshtermd connect --session new` is invoked. The daemon:

1. Generates a fresh random 16-byte session ID
2. Allocates an output ring buffer (default 4 MiB)
3. Forks a PTY and exec's the user's `$SHELL` (or `--exec` value)
4. Returns the bootstrap line for the iOS client to attach

### 11.2 Attached state

A session has at most one **active attach** at a time. Attach acquires a per-session lock; a second `Attach` while one is live receives `AttachAck{ok: false, err: "replaced"}` ... actually, the first attach is *displaced*: the old client receives `Goodbye{reason: "replaced"}` and the new client takes over. (Trade-off: avoids stuck "ghost attach" if a previous client dies without closing.)

### 11.3 Detached state

When the active QUIC connection drops (client close, network failure, app background), the session enters detached state. The PTY remains open, the child process keeps running, and output is buffered in the ring buffer.

### 11.4 GC

A detached session is reaped after `--idle-timeout` (default 1 h) of inactivity. On reap, the daemon sends SIGHUP to the child process and frees the PTY/buffer.

### 11.5 Ring buffer

Default capacity 4 MiB. When full, oldest bytes are dropped (FIFO). The daemon tracks `head_seq` (next seq to emit) and `tail_seq` (oldest seq still in buffer). On `Attach{ack: N}`:

- If `N >= tail_seq`: replay from `N`, no truncation
- If `N < tail_seq`: replay from `tail_seq`, set `trunc = true` in AttachAck

## 12. Versioning

- The bootstrap line carries its own integer version (`MTRM_QUIC <v> ...`); v0 always emits `1`.
- The QUIC ALPN encodes the protocol epoch: `meshterm/0` = development, `meshterm/1` = stable v1.
- Within a stable epoch, the `Attach.v` field negotiates minor version. Server SHOULD support at least the previous minor version.
- Breaking wire-format changes increment the ALPN epoch. A client built against `meshterm/2` MUST NOT attempt to talk `meshterm/1`.

## 13. Error handling

Any of the following terminate the QUIC connection with the indicated QUIC application error code:

| Condition | App error code | Notes |
|---|---|---|
| Frame longer than 64 KiB | `1001 oversized_frame` | |
| CBOR decode error | `1002 bad_frame` | |
| Unexpected message type | `1003 protocol_violation` | e.g., Attach received twice |
| Bad attach token | `1004 bad_token` | sent in AttachAck, then close |
| Stream opened in wrong order | `1005 protocol_violation` | e.g., Stdin opened before Attach |
| Datagram > 64 KiB | `1006 oversized_datagram` | |
| Internal server error | `2000 internal` | |

The server logs every termination with the error code and (where safe) the offending message bytes.

## 14. Frame size budget summary

| Stream | Max element size | Reason |
|---|---|---|
| Control | 64 KiB per frame | CBOR messages are small; this is generous |
| Stdin | per-write up to QUIC flow control | raw bytes |
| Stdout | 16 KiB per frame | balance of overhead and chunking |
| Datagrams | 64 KiB | with QUIC datagram fragmentation as path-MTU allows |

## 14a. IPC for client tooling

The unix socket between `meshtermd connect` (the SSH-side helper) and
`meshtermd serve` (the long-running daemon) carries the same CBOR
framing as the QUIC control stream. The IPC surface is intentionally
broader than what `connect` alone needs — `meshtermd list` and
`meshtermd kill` use it directly, and a future `mtctl` CLI can speak
either CBOR-over-IPC (when SSH-tunnelling the socket) or shell out to
`meshtermd list --json` over SSH.

**Auth model:** the SSH boundary is the auth boundary. Any client that
can reach the unix socket (i.e., is running as the same uid as
`meshtermd serve`) may invoke any of these. Filesystem permissions on
the socket (mode 0600, uid-owned parent) keep other local users out.

### IPC message types

| `t` discriminator | Direction | Purpose |
|---|---|---|
| `Allocate` | client → daemon | reserve an attach for an existing session, or spawn a new one. Returns `MTRM_QUIC` bootstrap fields + the session's `Name`. |
| `Ping` | client → daemon | liveness probe (echo nonce). |
| `ListSessions` | client → daemon | enumerate every live session. Returns `[]SessionInfo`. |
| `KillSession` | client → daemon | reap a session by hex SessionID or by Name. |

`SessionInfo` carries `id, name, created_at_ns, last_active_at_ns,
attached_now, idle_timeout_ns, rows, cols`. Field tags are wire-stable
short strings (`sid, name, cn, la, att, itn, rows, cols`).

### `meshtermd list --json` stable contract

Output is a JSON array of `SessionInfo` objects, one per live session,
on a single line ending with `\n`. Field names match the JSON tags on
`SessionInfo` (e.g. `created_at_ns`, not `cn`). An empty inventory is
`[]`, not `null`. iOS consumes this verbatim via the SSH exec channel.

### Session naming

Every session has a non-empty user-visible name. Clients can request
one via `Allocate.Name`; if unset, the daemon synthesises
`session-<6-hex-of-id>` so picker UIs never see blank rows. Names are
unique per daemon — colliding names on a fresh-spawn request return
`ipc.ErrNameInUse`.

### Daemon-restart semantics — explicit caveat

**Sessions do not survive a `meshtermd serve` restart.** PTY child
processes are direct children of the daemon process; killing the
daemon SIGHUPs every child and unmaps every ring buffer. There is no
disk persistence. A restarted daemon presents an empty session list;
clients with cached SessionIDs hit `ErrUnknownSession` and the iOS
flow falls back to spawning a fresh session.

This is an intentional architectural choice — meshtermd is a
transparent byte-passthrough layer, and persistent-layout-without-
processes (the Zellij approach) doesn't fit that posture. Operators
who need restart survival should run `meshtermd serve` under a
supervisor (systemd-user, launchd) so it's restarted promptly, but
must accept that any in-flight session is lost. Reattach-style
persistence works **across QUIC drops** (network roam, app
foreground/background, force-quit), not across daemon process death.

## 15. Open questions for v0 → v1

- Should `EchoConfirm` carry stdin_seq for client-side echo prediction synchronisation? (Currently reserved.)
- Should we support a "snapshot at attach" frame that includes the current cursor position, alt-screen state, etc.? Necessary for clean reattach to a vim/htop session that has scrolled past the buffer's tail.
- Multi-client attach (read-only watcher) — wire format support before we build UX.
- Compression on Stdout stream for high-throughput cases (build output, `find /` etc.). QUIC compresses nothing by default; gzip per-frame would help.

These are deferred to v1; v0 stays simple.
