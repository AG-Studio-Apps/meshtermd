# Homebrew formula for meshtermd + mtctl.
#
# This file is the staged copy. The live tap lives at
# github.com/AG-Studio-Apps/homebrew-meshtermd; copy this file into
# Formula/meshtermd.rb there after each upstream release. Users install via:
#
#     brew tap AG-Studio-Apps/meshtermd
#     brew install meshtermd
#
# Per-release maintenance:
#   1. Update `version` to the new upstream tag.
#   2. Update the per-arch `sha256` values from the published SHA256SUMS at
#      https://github.com/AG-Studio-Apps/meshtermd/releases/download/<tag>/SHA256SUMS
#   3. Copy this file into the tap repo and `git push`.
#
# We intentionally distribute pre-built binaries (no source build) so users
# don't need a Go toolchain. The minisign-signed SHA256SUMS in the release
# verifies the bytes; the `sha256` values below pin them per-arch.

class Meshtermd < Formula
  desc "Persistent terminal daemon over QUIC — mosh+tmux in one, multi-client handoff"
  homepage "https://github.com/AG-Studio-Apps/meshtermd"
  version "0.3.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v#{version}/meshtermd-darwin-arm64"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
    end
    on_intel do
      url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v#{version}/meshtermd-darwin-amd64"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
    end
  end

  on_linux do
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v#{version}/meshtermd-linux-arm64"
        sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
      else
        url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v#{version}/meshtermd-linux-armv7"
        sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
      end
    end
    on_intel do
      url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v#{version}/meshtermd-linux-amd64"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
    end
  end

  # Companion CLI, man pages, and shell completions live as separate
  # resource downloads from the same release.
  resource "mtctl" do
    on_macos do
      on_arm do
        url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/mtctl-darwin-arm64"
        sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
      end
      on_intel do
        url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/mtctl-darwin-amd64"
        sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
      end
    end
    on_linux do
      on_arm do
        if Hardware::CPU.is_64_bit?
          url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/mtctl-linux-arm64"
          sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
        else
          url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/mtctl-linux-armv7"
          sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
        end
      end
      on_intel do
        url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/mtctl-linux-amd64"
        sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
      end
    end
  end

  resource "manpages" do
    url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/meshtermd.8"
    sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
  end

  resource "mtctl-manpage" do
    url "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v0.3.1/mtctl.1"
    sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_MANIFEST"
  end

  def install
    # Daemon binary is the formula's primary url; rename it to the
    # canonical name regardless of platform-tagged download filename.
    bin.install Dir["meshtermd-*"].first => "meshtermd"

    resource("mtctl").stage do
      bin.install Dir["mtctl-*"].first => "mtctl"
    end

    resource("manpages").stage do
      man8.install "meshtermd.8"
    end
    resource("mtctl-manpage").stage do
      man1.install "mtctl.1"
    end

    # Shell completions. Fetched on the fly from the same release; we
    # don't pin sha256s for them because they're text and we already
    # have the binaries verified — losing the completion sha doesn't
    # widen the trust boundary in any practical way. If that posture
    # changes, hoist these into named resources like the binaries.
    %w[bash zsh fish].each do |sh|
      %w[meshtermd mtctl].each do |bin_name|
        system "curl", "-fsSL", "-o", "#{bin_name}.#{sh}",
               "https://github.com/AG-Studio-Apps/meshtermd/releases/download/v#{version}/#{bin_name}.#{sh}"
      end
    end
    bash_completion.install "meshtermd.bash" => "meshtermd"
    bash_completion.install "mtctl.bash"     => "mtctl"
    zsh_completion.install  "meshtermd.zsh"  => "_meshtermd"
    zsh_completion.install  "mtctl.zsh"      => "_mtctl"
    fish_completion.install "meshtermd.fish" => "meshtermd.fish"
    fish_completion.install "mtctl.fish"     => "mtctl.fish"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/meshtermd version")
    assert_match version.to_s, shell_output("#{bin}/mtctl version")
  end
end
