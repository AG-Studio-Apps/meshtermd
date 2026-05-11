# Homebrew packaging

This directory holds the staged copy of the Homebrew formula. The live
tap is a separate repo at `github.com/AG-Studio-Apps/homebrew-meshtermd`
(create on first publish — see "First-time setup" below).

Users install via:

```sh
brew tap AG-Studio-Apps/meshtermd
brew install meshtermd
```

## First-time setup (one-off)

1. Create an empty public GitHub repo at `AG-Studio-Apps/homebrew-meshtermd`.
   Homebrew's tap convention requires the `homebrew-` prefix.
2. Clone the empty repo, copy `meshtermd.rb` into a `Formula/` subdirectory,
   commit + push.
3. Test locally on a Mac and a Linux box: `brew tap AG-Studio-Apps/meshtermd`
   then `brew install meshtermd`; confirm `meshtermd version` and
   `mtctl version` both report the tagged version.

## Per-release maintenance

After each upstream release:

1. Bump the `version` field and every `sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"`
   to the real per-binary digest. The digests come from the published
   `SHA256SUMS` at
   `https://github.com/AG-Studio-Apps/meshtermd/releases/download/v<X.Y.Z>/SHA256SUMS`.

   Example fetch:
   ```sh
   curl -fsSL https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/SHA256SUMS \
     | awk '{print $1, $2}'
   ```

2. Copy `meshtermd.rb` into the live tap repo's `Formula/meshtermd.rb`,
   commit, push.

3. `brew update && brew upgrade meshtermd` on a test box; confirm.

## Eventually: homebrew-core

The own-tap path above sidesteps homebrew-core's gatekeeping entirely and
ships today. Promoting into homebrew-core needs:

- Build-from-source (no GitHub-release binary downloads)
- `go mod vendor`'d deps
- Passing tests on macOS arm64 / x86_64 and Linux x86_64
- Some user traction (~50+ GitHub stars, stable tags)

That's a year-out goal, not a now goal. Keep the own-tap working and let
user count grow first.
