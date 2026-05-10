# Release signing

Every tagged release's `SHA256SUMS` is signed with [minisign] (Ed25519).
The signature lives alongside the binaries on the GitHub Release as
`SHA256SUMS.minisig`. Verification chain:

1. Download `SHA256SUMS` and `SHA256SUMS.minisig` from the release.
2. `minisign -V -p docs/release-public-key.txt -m SHA256SUMS`
3. Once trusted, verify each binary you downloaded:
   `sha256sum -c SHA256SUMS --ignore-missing`

[minisign]: https://jedisct1.github.io/minisign/

## Key roster

The meshTerm iOS app embeds **two** trusted public keys: a **primary**
and an **emergency**. Either signature satisfies verification. This
lets us rotate the primary without shipping a new iOS build — sign the
next release with the emergency key, ship a new iOS build that swaps
in a fresh primary, then retire the old emergency.

The primary public key is in `docs/release-public-key.txt`. The
emergency public key is held offline and is NOT published in this
repo. Both halves are mirrored (encrypted) in the private
`AG-Studio-Apps/meshterm_keys` repo as `age`-encrypted backups.

## Provisioning

A one-shot script in `scripts/provision-keys.sh` generates the roster,
encrypts the private halves with age, uploads the primary unencrypted
private + passphrase to this repo's Actions secrets (`MINISIGN_KEY`,
`MINISIGN_PASSWORD`), and pushes the encrypted backups to
`meshterm_keys`. Read the script before running — it has interactive
passphrase prompts and an explicit dependency check.
