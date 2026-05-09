# meshtermd

Server-side helper for the [meshTerm](https://meshterm.app) iOS app. Holds persistent terminal sessions across QUIC reconnects so your shell survives network roams, sleep/wake, and the app being backgrounded.

This is published as a separable, auditable artifact. It is **not** a general-purpose tool, has no marketing, and is paired tightly with the iOS app's release cadence. If you are not running meshTerm, this is unlikely to be useful to you.

## Status

Pre-1.0. The wire protocol is not yet stable. Do not depend on this for anything.

## Compatibility

| `meshtermd` | meshTerm iOS | Notes |
|-------------|--------------|-------|
| 0.x         | unreleased   | active development |

## What it does

- Listens for QUIC connections from a paired meshTerm iOS client
- Owns a registry of terminal sessions (PTY + child shell + output ring buffer)
- Sessions persist across client disconnects; reattach replays buffered output since last ack
- Bootstrap is performed inside an existing SSH session for trust establishment

The transport-layer security is TLS 1.3 (provided by Go's standard library inside `quic-go`); we add cert pinning bootstrapped over SSH. There is no application-layer cryptography in this codebase.

## Reporting issues

Issues are tracked at [meshTerm's repo](https://github.com/AG-Studio-Apps/meshTerm/issues) for now. Please file there with the `meshtermd:` prefix in the title.

## Reporting security issues

See [SECURITY.md](docs/SECURITY.md). Do not file security reports as public issues.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
