# Security improvements

A running log of security findings that have been **fixed** in `mtroamd`, with the
detection source for each. We publish *fixed* findings only - open or unconfirmed
issues are handled privately under our [security policy](SECURITY.md) (coordinated
disclosure) and are added here once they ship in a release. Entries are listed newest-first.

Detection sources used across the project: `govulncheck`, dependency advisories
(osv-scanner / Dependabot), static analysis (CodeQL / CI-workflow audits), binary
scans, manual code review (including adversarial multi-agent review), and
independent agent audits (e.g. Codex 5.5).

## v1.8.0 (2026-09-11)

_Post-audit hardening release, and a line in the sand. Rather than the usual diff audit, this was a **deep multi-agent Claude Security scan of the whole daemon taken at the `v1.7.11` stable tag (`5bbed5e`) as a fresh baseline** - per-component threat models, per-category researchers, and a three-lens adversarial verifier panel - alongside the full static / binary / dependency scan suite; scan report + pre-stable gate in `.security/`. **11 findings were verified and all 11 are fixed** (2 High, 6 Medium, 3 Low), grouped into five focused commits; each fix was generated and then challenged by an adversarial verifier before it landed. The static / binary suite is clean against the v1.7.11 baseline: `go vet` clean; `govulncheck` **0 in code and 0 in imports** (source + freshly rebuilt daemon+cli binaries on go1.26.6); `gosec` unchanged at the **90** prior-accepted baseline with the CI high/high gate green; `staticcheck` style/unused only; `gitleaks` clean (one prior-accepted match: the public offline release-signing key); `osv-scanner` 0; `go test -race` green across every package. This release also bumps `golang.org/x/crypto` 0.53.0 -> **0.56.0** to clear three `x/crypto/ssh` advisories (GO-2026-6355 / GO-2026-6354 / GO-2026-6303) that the vuln-watch surfaced after the baseline was taken - all were unreachable, cleared proactively for a security release (the remaining govulncheck note GO-2026-5932, `x/crypto/openpgp` unmaintained, has no fix and is not imported by the daemon)._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| **F1** - Integer overflow in the CUD (cursor-down) handler defeated the `min()` clamp: a hostile PTY-side CSI parameter (e.g. `\e[4294967296B`) wrapped to a small positive after the add, drove an out-of-bounds grid row index, and crashed the daemon | High | Claude Security scan (multi-agent) | CSI parameters are capped at 65535 in `parseParams`; CUD/CNL now compute the target as `clamp(y + count, 0, hi)` instead of `min()`, so no arithmetic can escape the grid (`5e7c253`) |
| **F2** - Same integer-overflow class in the CNL (cursor-next-line) handler | High | Claude Security scan (multi-agent) | Same param cap + `clamp` (`5e7c253`) |
| **F4** - The `mtroam` SSH bootstrap forced `StrictHostKeyChecking=accept-new`, auto-trusting the daemon host key - and therefore the QUIC cert fingerprint it delivers - on first connect | Medium | Claude Security scan (multi-agent) | Forces `StrictHostKeyChecking=yes` for the daemon dial; adds an actionable `isHostKeyVerificationFailure` classifier so a real key change surfaces a clear error instead of a silent accept (`df9a90b`) |
| **F7** - Same accept-new behaviour framed as a first-use MITM of the entire QUIC trust bootstrap | Medium | Claude Security scan (multi-agent) | Same `StrictHostKeyChecking=yes` (`df9a90b`) |
| **F5** - Unbounded CSI `REP` repeat count from attacker PTY output caused CPU exhaustion / hang | Medium | Claude Security scan (multi-agent) | `REP` count is bounded at `cols*rows` (`5e7c253`) |
| **F6** - Same unbounded `REP` (CSI `b`) iteration, CPU-DoS framing | Medium | Claude Security scan (multi-agent) | Same `REP` bound (`5e7c253`) |
| **F8** - Unbounded combining-mark accumulation grew a single cell's `comb` string without limit (memory DoS from PTY output) | Medium | Claude Security scan (multi-agent) | `maxCombPerCell = 8` guard in `putCombining` (`1daf963`) |
| **F3** - Unbounded pending buffer in `QueryFilter`: attacker PTY output (an unterminated CSI/OSC) could grow the reassembly buffer without limit, exhausting daemon memory | Medium | Claude Security scan (multi-agent) | `maxPending = 256 KiB` cap across all three park sites; on overflow the buffered tail is **dropped**, not flushed - dropping the `ESC` introducer prevents leaking a partially-stripped query (the leak that made the first cut un-shippable). Real palette/clipboard sequences (~5.8 KiB) fit far under the cap (`3108250`) |
| **F9** - Daemon-supplied session `Name` / foreground-command strings were written unsanitized to the interactive CLI terminal - control-sequence injection | Low | Claude Security scan (multi-agent) | Shared `sanitizeForDisplay` (C0/C1/`ESC`/`DEL`/invalid-UTF-8 -> U+FFFD; TAB and multibyte preserved) at the structured CLI sinks (list / search / status / session-info / attach header); the raw attach + tail relay path is left untouched (`bdd85e6`) |
| **F10** - `mtroam search` rendered raw scrollback bytes (escape sequences) to the local terminal without neutralizing them | Low | Claude Security scan (multi-agent) | Same `sanitizeForDisplay` (`bdd85e6`) |
| **F11** - Same per-cell combining-mark growth from PTY output, memory-growth framing | Low | Claude Security scan (multi-agent) | Same `maxCombPerCell` guard (`1daf963`) |

## v1.7.11 (2026-08-23)

_Dependency / toolchain security bump surfaced by the twice-daily `govulncheck` vuln-watch (PR #40). Bumped the pinned toolchain to **go1.26.6** and **`golang.org/x/net` v0.56.0**, clearing the `x/net` advisories flagged against the deployed daemon; `govulncheck` (source + binary) returned to clean. No code change to the daemon's own surface; Nix `vendorHash` re-locked for the `go.mod` bump._

## v1.7.10 (2026-08-09)

_Availability hardening from a box freeze on 2026-08-06: a leak in the `connect` client, and the cgroup cap that stops any future leak reaching the machine. Both ship together because either alone leaves a gap - the fix stops this leak, the cap bounds the next one._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| **`mtroamd connect --stdio` could never exit**, leaking one process (plus its shell, and any agent running in the session) per connection. `runStdioMode` bridged the SSH channel with two `io.Copy` goroutines sharing one cancel context. `io.Copy` is a single read→write loop, so while the daemon→stdout copier was blocked writing it was **not reading the connection** - and neither fd is deadline-capable (Go does not register std fds with the netpoller), so nothing could interrupt it. When a channel's stdout pipe filled because the far side stopped draining (phone dropped, app killed) while tailscaled still held stdin open, the client never observed the daemon's close and lived until reboot. Compounded by `KillMode=process`, which is load-bearing for sidecar survival and therefore also lets leaked clients survive every daemon restart: **844 processes** accumulated over a 31-day uptime (~275 clients, 314 shells, 143 agents), exhausting the box | Hardening (availability) | box freeze 2026-08-06 | Split the daemon→stdout path into a reader and a writer, so the connection read parks in the netpoller and a daemon close is observed **immediately** regardless of what stdout is doing (the daemon was never at fault - the journal showed 2770 attaches and 2770 detaches, perfectly balanced). A wedged stdout is bounded separately by a stall budget, and `SIGTERM`/`SIGHUP`/`SIGINT` are now handled so a stuck client is killable without `SIGKILL`. Queued output is flushed on a clean close so a disconnect does not drop the last screenful. Regression test asserts teardown with stdout deliberately wedged - it fails against the old code |
| **The daemon's cgroup was uncapped**, so a leak or a runaway session could drive the whole host into swap thrash. This is the gap left open by the v1.7.3 entry below, which named it explicitly: `oom_score_adj` only chooses *who* dies once the kernel decides someone must, and cannot prevent thrash. On 2026-08-06 the cgroup sat at 5.0G resident + 4.0G swap on a 7.7G host and the machine stopped responding **with `oom_kill` still reading 0** - the mitigation never engaged because nothing was ever killed | Hardening (availability) | box freeze 2026-08-06 | `RenderUserUnit` (the unit SSOT, inherited by deb/rpm/AUR/Nix and the iOS installer via `unit print`) now emits `MemoryHigh=40%`, `MemoryMax=55%`, `MemorySwapMax=512M`. The percentages are of installed RAM, so one value suits a 2G VPS and a 64G workstation; `MemorySwapMax` takes no percentage and is the load-bearing one - a small swap budget is what converts hours of thrashing into a prompt in-cgroup OOM kill of a **single** session. Overridable per host with a `mtroamd.service.d/*.conf` drop-in, which survives `migrate` and reinstall where an in-unit edit does not. Note existing installs only pick this up on a reinstall, `mtroamd migrate`, or a package upgrade |

## v1.7.9 (2026-08-04)

_Pre-stable security audit of the `v1.7.8..v1.7.9` diff — a single change area, the **alt-screen grid-persistence reattach**: a full-frame redraw synthesized at attach time from the daemon's own screen model + ring buffer (so a cold-start reattach to a running TUI gets a complete screen, fixing alt-screen spill), plus the `meta.cbor` restore that seeds that model on boot — with a full static / binary / dependency scan; details + pre-stable gate in `.security/security-audit-v1.7.9.md`. **Clean — no findings, nothing to fix.** `go vet`, `govulncheck` (source + freshly rebuilt daemon+cli binaries on go1.26.5), `osv-scanner`, `gosec`, `staticcheck`, and `gitleaks` were all clean or prior-accepted; `go test -race` passed on the three changed packages (altscreen / session / transport). The delta is **terminal rendering/replay logic** and touches **no** security-sensitive surface — `internal/secret`, `internal/ipc`, `internal/daemon`, `internal/release`, `internal/cert`, and the network/QUIC path are byte-unchanged since v1.7.8. The two new untrusted-input touchpoints are both bounds-checked: the `meta.cbor` restore caps a hostile blob (`maxPersistedScreenRepaint` 1 MiB, gating `Screen.Feed` on load as well as save) and geometry (`maxRestoredScreenDim` 1000, before `altscreen.New` allocates a `rows*cols` grid) — crash-loop-DoS hardening for a corrupt same-uid state dir; and the remote attach dims are gated by `dimsInBounds` before any resize, with injected bytes synthesized from the daemon's own model, never from remote input. No Critical / High / Medium / Low. No dependency change (`go.mod`/`go.sum` unchanged). (This grid-persistence work was reverted out of the v1.7.8 stable cut and re-landed here for v1.7.9.)_

## v1.7.8 (2026-08-04)

_Pre-stable security audit of the `v1.7.7..v1.7.8` diff — the headline change is the **secret broker** (deferred from v1.7.6 for its own review): an in-memory, value-hiding secret store held **RAM-only** (never persisted, never in the session snapshot), pushed per-session over the local `0600` IPC socket (`SetSessionSecrets`) and delivered to consuming tools at exec time via PATH-shadow shims + `mtroamd secret-exec`, so the value never lands in the agent's own env, in argv (`ps`), or in stdout — plus the new **doctor `--fix` / stale-daemon `/proc` census** repair path and an `update` that refuses to report success until the live daemon serves the freshly-installed tag — with a full static / binary / dependency scan; details + pre-stable gate in `.security/security-audit-v1.7.8.md`. **Clean — no findings, nothing to fix.** `go vet`, `govulncheck` (source + freshly rebuilt daemon+cli binaries on go1.26.5), `osv-scanner`, `gosec`, `staticcheck`, and `gitleaks` were all clean or prior-accepted; `go test -race` passed on the changed packages (incl. the new `secret` package); and a focused adversarial re-attack of the broker (5 hypotheses — remote/QUIC reach, shim shell-injection, secret-to-disk leak, shim self-exec loop, and cross-uid shim/`SIGTERM` reach) refuted every candidate. The broker's trust boundary is re-enforced at both the `ParsePayload` and daemon-handler sites (POSIX key charset + safe-basename command allowlist + duplicate-key reject); delivery and readout are **same-uid over the daemon's own socket** — the remote path only *attaches* and can never dispatch broker IPC — and the `/proc` census is strictly same-uid-filtered (a `SIGTERM` can only ever reach this user's own stale `mtroamd serve`). No Critical / High / Medium / Low. No dependency change (`go.mod`/`go.sum` unchanged); no network-surface change (`internal/release` / `internal/cert` untouched). (Two Info-level notes only, both same-uid: `GetSecrets` performs no session-ownership check, and `SecretEntry.Value` isn't newline/size-bounded at the merge.)_

## v1.7.7 (2026-07-20)

_Pre-stable security audit of the `v1.7.6..v1.7.7` diff — **live secret injection**: a bash/zsh prompt hook (seeded by the sidecar after the user's rc, via a generated `--rcfile` / `ZDOTDIR`) that sources+removes a `0600` `~/.mt-inject-<sessionID>` file on each prompt to deliver secrets into a **running** shell, plus the additive `MTRM_LIVE_INJECT` reporting line — with a full static / binary / dependency scan; details + pre-stable gate in `.security/security-audit-v1.7.7.md`. **Clean — no findings, nothing to fix.** `go vet`, `govulncheck` (source + freshly rebuilt daemon+cli binaries on go1.26.5), `osv-scanner`, `gosec`, `staticcheck`, and `gitleaks` were all clean or prior-accepted; `go test -race` passed on the five changed packages (incl. the new hook seeder); and a focused adversarial re-attack (5 hypotheses — shell injection into the generated rc, path traversal via an overridable `MESHTERM_SESSION_ID`, cross-uid/remote injection, `--rcfile` arg-rewrite hijack, and TOCTOU/fail-safe) refuted every candidate. The feature is a **same-uid convenience**: the drop file is delivered over the user's own authenticated SSH/SFTP, and sourcing a `$HOME` file grants nothing a same-uid actor already lacks — with correct `shSingleQuote` escaping, a strict `-l`/`-i` arg allowlist, and a fail-safe seeder that never breaks the shell. No Critical / High / Medium / Low. No dependency change (`go.mod`/`go.sum` unchanged). (Two Info-level defense-in-depth notes only, both same-uid: `req.Env` values aren't newline-sanitized, and the hook sources the drop file without a perms check — inheriting the `~/.bashrc` trust model.)_

## v1.7.6 (2026-07-18)

_Pre-stable security audit of the `v1.7.5..v1.7.6` diff (bound the displaced-client `Goodbye` push at 1s; optional additive session-reuse reporting — `AllocateResponse.Reused` / the `MTRM_SESSION_REUSED` bootstrap line) plus a full static / binary / dependency scan; details + pre-stable gate in `.security/security-audit-v1.7.6.md`. **Clean — no findings, nothing to fix.** `go vet`, `govulncheck` (source + freshly rebuilt daemon+cli binaries on go1.26.5), `osv-scanner`, `gosec`, `staticcheck`, and `gitleaks` were all clean or prior-accepted; `go test -race` passed on the changed packages; and a focused adversarial re-attack (4 hypotheses — the bounded-notify goroutine/race/DoS, and whether the reuse bit feeds any authz or leaks cross-session) refuted every candidate. The notify bound is a DoS **reduction** (an unbounded write became ≤1s); the reuse bit is purely informational and feeds no authz decision. No Critical / High / Medium / Low. No dependency change (`go.mod`/`go.sum` unchanged). (The `wip/secret-broker` feature tagged out-of-band as `v1.7.6-rc3` is NOT in this release and will get its own review before it ships.)_

## v1.7.5 (2026-07-16)

_Pre-stable security audit of the `v1.7.4..v1.7.5` diff (the `connect --env-file` session env-threading, auto-start-on-connect, and the systemd user-manager detection fix) plus a full static / binary / dependency scan; details + pre-stable gate in `.security/security-audit-v1.7.5.md`. **No findings — nothing to fix.** `go vet`, `govulncheck` (source + freshly rebuilt binaries on go1.26.5), `osv-scanner`, `gosec`, `staticcheck`, and `gitleaks` were all clean or prior-accepted, and a focused adversarial re-attack of the env-threading path (6 hypotheses) refuted every candidate boundary crossing. No Critical / High / Medium / Low. No dependency change (`go.mod`/`go.sum` unchanged)._

## v1.7.4 (2026-07-09)

_Pre-stable security audit of the `v1.7.3..v1.7.4` diff plus a full static / binary / dependency scan and a deep adversarial multi-agent review; details + pre-stable gate in `.security/security-audit-v1.7.4.md`. No Critical / High / Medium findings. Two Low items fixed below (first shipping in `v1.7.4-rc3`)._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| `crypto/tls` Encrypted Client Hello privacy leak (GO-2026-5856) linked in the binary and call-graph-reachable via the QUIC listener + the release-fetch HTTPS client. ECH is never configured, so there is no runtime exposure, but the advisory is source-reachable | Low | govulncheck (source) / osv-scanner | Bumped the pinned toolchain `go1.26.4` → `go1.26.5`. Also clears GO-2026-4970 (`os.Root` symlink escape) from the binary - itself unreachable (no `os.Root` use). `govulncheck ./...` is clean on go1.26.5. The `go` directive stays at the language minimum so `GOTOOLCHAIN=local` / Nix builds keep working |
| IPC handler read the request frame with no deadline: a same-uid process (e.g. a compromised session) could open `MaxConcurrentIPCHandlers` (32) connections to the `0600` socket and never send a request, pinning every handler goroutine - denying local allocate/list/kill IPC and stalling graceful shutdown (which waits on in-flight handlers). Symmetric write-stall on the response path (a peer that never drains a send-buffer-filling reply) | Low | adversarial multi-agent code review | Bound each one-shot exchange with two independent deadlines - one on the request read, a fresh one on each response write - so a stalled peer's slot is reclaimed (5s default) while a legitimately slow handler keeps its full write budget. Not remotely reachable (socket is uid-`0600`, parent-dir verified); the attacker already shares the daemon's uid |

## v1.7.3 (2026-07-02, hardening)

_Manual audit of the `v1.7.2..v1.7.3-rc1` diff: no findings. One availability-hardening change (details + a pre-stable release gate in `.security/security-audit-v1.7.3.md`)._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| A runaway session could push the daemon's uncapped cgroup over the box's memory and get `mtroamd` (or another session's sidecar) OOM-killed, dropping persistent sessions - or hard-crash a swapless box | Hardening (availability) | box OOM incident 2026-07-02 | Each `pty-sidecar` raises its own `oom_score_adj` (inherited by the child shell + descendants) strictly ABOVE the daemon's, so the kernel OOM-killer sacrifices the runaway **session**, never `mtroamd`. Relative (inherited baseline + 300), not absolute: a systemd user manager defaults its services to a non-zero score (200 on Ubuntu), so an absolute value below that would be backwards - caught by on-box verification before the stable cut (rc1 `+100` -> rc2 relative-raise). Unprivileged (a protective negative adjust would need `CAP_SYS_RESOURCE`); best-effort + Linux-only. |

## v1.7.2 (2026-06-27)

_Independent Codex 5.5 (gpt-5.5) security audit of the `develop` branch (the new extension-seam batch). No Critical or High findings; two Medium hardening items, first shipping in `v1.7.2-rc2`._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| Plaintext-TCP listener could bind an unspecified address (`0.0.0.0` / `::` / host-less `:N`), exposing the un-TLS'd protocol and attach tokens on every interface | Medium | Codex 5.5 audit | `guardPlaintextBind` now **fails closed** on unspecified binds (refused unless `MTROAMD_ALLOW_PLAINTEXT_UNSPECIFIED=1`); the `tailnet:<port>` sentinel and loopback/private/tailnet binds still pass, and concrete globally-routable is still refused. Extends the v1.4.11 globally-routable guard. |
| Stream-extension 64 KiB frame contract was documented but not enforced: one oversized frame slipped past the drop-oldest trim, exceeding the 4 MiB log cap and tearing down client attaches at write time | Medium | Codex 5.5 audit | `Session.PublishFrame` now returns an error and **rejects** any frame over `protocol.MaxControlFrameBytes` (never retained). Not reachable in the stock daemon (no extensions registered); hardens the generic seam the agent fork drives. |

## v1.7.0 - 2026-06-15

_Adversarial multi-agent code review of the recover / attach paths._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| Recover idle-gate could SIGTERM a silent foreground tool (risking repo corruption) | High | code review | Kill path re-reads the **live** foreground group and refuses SIGTERM unless it still matches the agent |
| Recover/kill could mislabel any foreground process as "the agent" | Medium | code review | Recover refuses unless the foreground is a recoverable agent |
| Recover reachable by any well-formed client (unconditional exclusive displacement) | Medium | code review | `IsCurrentExclusive(gen)` live-gates stdin / Resize / Recover |
| Displaced exclusive client could still inject stdin/Recover during the displacement window | Medium | code review | Live ownership check under the session lock before acting |
| Two rapid Recover frames raced the single PTY-byte-observer slot → premature kill | Medium | code review | Observer set/clear is generation-keyed |
| Stale foreground anchor + torn AttachAck reads (Cwd/Fg/FgSince) | Low | code review | `ForegroundSnapshot()` returns Fg/FgSince/FgSinceSeq/Cwd as one consistent reading |
| `ClientID` / wire strings unbounded | Low | code review | Explicit 128-byte cap on `Attach.ClientID` |
| `ClientID` match was not constant-time | Low | code review | Switched to `subtle.ConstantTimeCompare` |
| Decoded-but-unused `SavePrompt` (latent command-injection footgun) | Low | code review | Documented as reserved / never injected |

## v1.5.2 - 2026-06-04

| Finding | Severity | Source | Fix |
|---|---|---|---|
| quic-go HTTP/3 QPACK trailer memory-exhaustion (GHSA-vvgj-x9jq-8cj9; not reachable in our build) | Medium | dependency advisory | Bumped quic-go 0.59.0 → 0.59.1 |

## v1.4.11 - 2026-06-01 (hardening release)

_Combined manual audit + tooling-driven scan before the develop → main merge._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| Plaintext-TCP bind to a globally-routable address | Medium | manual review | `guardPlaintextBind` refuses globally-routable binds (allows loopback / private / link-local / tailnet) |
| No accept / bad-token throttle on the public listener | Medium | manual review | `SourceLimiter`: per-source token bucket + bad-token cooldown, shared across QUIC + TCP |
| Postremove cleanup ran root `rm`/`grep` over user `$HOME` paths (symlink / TOCTOU) | Medium | manual review | Scriptlets drop privilege to `$SUDO_USER`, with unit/state paths passed as argv (never interpolated) |
| Missing workflow permissions on the macOS install-smoke workflow | Medium | static analysis (CodeQL) | Added top-level `permissions: contents: read` |
| `x/net` advisories linked in the binary (`html.Parse`; unreachable) | Low | govulncheck (binary mode) | Bumped `golang.org/x/net` → v0.55.0 |
| Unpinned third-party CI actions | Low–Med | static analysis (workflow audit) | SHA-pinned `nix-installer-action` + `action-gh-release` |
| `loadEnvFile` could leak the daemon's full env to the child on an empty env-file path | Low | manual review | Empty env-file path now fails closed; inheritance gated behind a test-only flag |
| TLS private key swept into ordinary home backups | Low | manual review | Best-effort `FS_NODUMP` on `key.pem` (Linux) + SECURITY.md checklist line |
| `EnableDatagrams` enabled but unused on a network-reachable listener | Low | manual review | Disabled (removed unused attack surface) |

## v1.4.4 - 2026-05-29 (recover hardening)

_Manual code review (static review + follow-up)._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| Recover requests could create unbounded detached session work | Medium | manual review | Per-session recovery slot; cancel previous on new start; cap recover grace at 2 minutes |
| Recover cancellation slot could be cleared by an older canceled recovery | Medium | manual review | Generation-token identity guard frees the slot only for the matching generation |

## v1.1.4 - 2026-05-19

_Manual code review (static review)._

| Finding | Severity | Source | Fix |
|---|---|---|---|
| Self-update signatures not bound to the requested release tag | High | manual review | Trusted-comment tag binding enforced in both update paths |
| Client socket discovery could select a spoofed XDG socket | Medium | manual review | Parent-dir + client-socket ownership verification |
| `mtroam` host values could be parsed as local `ssh` options | Medium | manual review | Host-value validation guard + `--` separator in argv |
