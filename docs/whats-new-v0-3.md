# meshtermd v0.3.0 — what's new

## `mtctl` ships in the release artifacts

The laptop CLI has existed in this repo for a while but wasn't part
of the published release. v0.3.0 changes that: every signed release
now includes `mtctl-*` binaries for the same seven platforms as
`meshtermd-*`, all covered by the single `SHA256SUMS.minisig`.

Install: download → verify signature → drop in `~/.local/bin/mtctl`.
Full guide in `docs/mtctl.md`.

This unblocks attaching to a remote Roam session from your laptop's
terminal — same persistent-shell experience the iOS app gives you,
but on a real keyboard.

## `mtctl update` and `mtctl uninstall`

Mirroring `meshtermd update` / `meshtermd uninstall`:

- `mtctl update` — checks GitHub Releases, verifies the minisign
  signature on the new SHA256SUMS, verifies the binary's SHA-256,
  atomically swaps `~/.local/bin/mtctl` in place. Anti-rollback is
  on by default — `--allow-downgrade` to override.
- `mtctl uninstall` — removes the binary. No state directory to
  worry about; mtctl has no cert/key/socket of its own.

## Shared internal/release package

The semver comparison helpers (`ParseSemver`, `CompareSemver`,
`VersionsMatch`, `BaseTag`) moved from `cmd/meshtermd/update.go` to
`internal/release/version.go` so both binaries' update flows share
one implementation. No user-visible behaviour change.

## Compatibility

- `meshtermd` and `mtctl` should be paired at the same version or
  newer-`mtctl` / older-`meshtermd`. Wire protocol is unchanged in
  this release.
- iOS app version unchanged. The next iOS build will start dropping
  `mtctl` alongside `meshtermd` on auto-installed hosts, so anyone
  who SSHes into a Roam host has `mtctl` ready to go.
