# meshtermd build targets.
#
# Notable environment variables:
#   VERSION  semantic version stamped into the binary (default: dev SHA)
#   COMMIT   short git SHA stamped into the binary (default: git rev-parse)
#   DATE     RFC 3339 build timestamp (default: now in UTC)
#
# `make dist` produces statically-linked binaries for the seven supported
# host architectures under ./dist/. Static-link is enforced via
# CGO_ENABLED=0 + -tags netgo (pure-Go DNS resolver). Symbols are
# stripped via -ldflags="-s -w" and the build path is normalised via
# -trimpath so binaries are reproducible.

GO        := go
PKG       := github.com/AG-Studio-Apps/meshtermd
# CMD_PATH is the on-disk relative path; CMD_PKG is the module-import
# path. Use CMD_PATH for `go build` so the module-aware toolchain
# never tries to resolve our own package via the module proxy.
CMD_PATH  := ./cmd/meshtermd
CMD_PKG   := $(PKG)/cmd/meshtermd

# mtctl is the laptop/desktop management CLI. Built from the same
# module as meshtermd so it shares the IPC type definitions.
MTCTL_PATH := ./cmd/mtctl

VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo v0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -buildid= \
	-X $(PKG)/internal/build.Version=$(VERSION) \
	-X $(PKG)/internal/build.Commit=$(COMMIT) \
	-X $(PKG)/internal/build.Date=$(DATE)

GOFLAGS := -trimpath -tags netgo -ldflags='$(LDFLAGS)'

# Cross-compile matrix. Each row: GOOS-GOARCH-suffix.
# armv7 needs GOARM=7; everything else uses defaults.
DIST_TARGETS := \
	linux-amd64 \
	linux-arm64 \
	linux-armv7 \
	darwin-amd64 \
	darwin-arm64 \
	freebsd-amd64 \
	freebsd-arm64

.PHONY: all build test vet lint vuln dist manpages completions aur-prep clean

all: vet test build build-mtctl

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./meshtermd $(CMD_PATH)

build-mtctl:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./mtctl $(MTCTL_PATH)

test:
	$(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

# `lint` and `vuln` are intentionally permissive about missing tooling —
# they're additive checks, not gates. Run `make lint-deps` to install.
lint:
	@command -v gosec >/dev/null && gosec ./... || echo "(gosec not installed; skipping)"
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "(staticcheck not installed; skipping)"

vuln:
	@command -v govulncheck >/dev/null && govulncheck ./... || echo "(govulncheck not installed; skipping)"

lint-deps:
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	$(GO) install honnef.co/go/tools/cmd/staticcheck@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

dist-linux-amd64:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-linux-amd64 $(CMD_PATH)

dist-linux-arm64:
	@mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-linux-arm64 $(CMD_PATH)

dist-linux-armv7:
	@mkdir -p dist
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-linux-armv7 $(CMD_PATH)

dist-darwin-amd64:
	@mkdir -p dist
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-darwin-amd64 $(CMD_PATH)

dist-darwin-arm64:
	@mkdir -p dist
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-darwin-arm64 $(CMD_PATH)

dist-freebsd-amd64:
	@mkdir -p dist
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-freebsd-amd64 $(CMD_PATH)

dist-freebsd-arm64:
	@mkdir -p dist
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/meshtermd-freebsd-arm64 $(CMD_PATH)

# mtctl cross-compile rows. Mirrors the meshtermd matrix exactly —
# someone running the daemon on a freebsd-arm64 box presumably
# wants the matching CLI on their laptop.
dist-mtctl-linux-amd64:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-linux-amd64 $(MTCTL_PATH)

dist-mtctl-linux-arm64:
	@mkdir -p dist
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-linux-arm64 $(MTCTL_PATH)

dist-mtctl-linux-armv7:
	@mkdir -p dist
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-linux-armv7 $(MTCTL_PATH)

dist-mtctl-darwin-amd64:
	@mkdir -p dist
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-darwin-amd64 $(MTCTL_PATH)

dist-mtctl-darwin-arm64:
	@mkdir -p dist
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-darwin-arm64 $(MTCTL_PATH)

dist-mtctl-freebsd-amd64:
	@mkdir -p dist
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-freebsd-amd64 $(MTCTL_PATH)

dist-mtctl-freebsd-arm64:
	@mkdir -p dist
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./dist/mtctl-freebsd-arm64 $(MTCTL_PATH)

# Man pages. Source: docs/man/*.md (pandoc-flavored markdown).
# Output: dist/man/<name>.<section>. Run `make manpages` to build;
# `make dist` also produces them so release artifacts include them
# alongside the binaries.
manpages: dist/man/mtctl.1 dist/man/meshtermd.8

dist/man/mtctl.1: docs/man/mtctl.1.md
	@mkdir -p dist/man
	pandoc -s -t man $< -o $@

dist/man/meshtermd.8: docs/man/meshtermd.8.md
	@mkdir -p dist/man
	pandoc -s -t man $< -o $@

# Shell completions. Generated from internal/completions/spec.go via
# cmd/gen-completions. One file per (shell, binary) pair; the
# Homebrew formula and AUR PKGBUILDs install these to the canonical
# locations for each shell.
COMPLETION_BINS   := mtctl meshtermd
COMPLETION_SHELLS := bash zsh fish

completions: $(foreach bin,$(COMPLETION_BINS),$(foreach sh,$(COMPLETION_SHELLS),dist/completions/$(bin).$(sh)))

dist/completions/%.bash: cmd/gen-completions/main.go internal/completions/spec.go
	@mkdir -p dist/completions
	$(GO) run ./cmd/gen-completions -shell bash -binary $* > $@

dist/completions/%.zsh: cmd/gen-completions/main.go internal/completions/spec.go
	@mkdir -p dist/completions
	$(GO) run ./cmd/gen-completions -shell zsh -binary $* > $@

dist/completions/%.fish: cmd/gen-completions/main.go internal/completions/spec.go
	@mkdir -p dist/completions
	$(GO) run ./cmd/gen-completions -shell fish -binary $* > $@

# `make dist` builds binaries, man pages, and shell completions so
# release artifacts are self-contained for distro packagers.
dist: $(addprefix dist-,$(DIST_TARGETS)) $(addprefix dist-mtctl-,$(DIST_TARGETS)) manpages completions

# AUR release prep. Rewrites pkgver in both PKGBUILDs and pulls down
# the published SHA256SUMS to populate the binary package's per-arch
# hash arrays.
#
# Usage: `make aur-prep VERSION=vX.Y.Z`
#
# After this runs, regenerate .SRCINFO in each PKGBUILD dir via
# `makepkg --printsrcinfo > .SRCINFO`. See packaging/aur/README.md.
aur-prep:
	@if [ -z "$(VERSION)" ]; then echo "usage: make aur-prep VERSION=vX.Y.Z"; exit 2; fi
	@bare=$$(echo "$(VERSION)" | sed 's/^v//'); \
	sed -i "s/^pkgver=.*/pkgver=$$bare/" packaging/aur/meshtermd/PKGBUILD; \
	sed -i "s/^pkgver=.*/pkgver=$$bare/" packaging/aur/meshtermd-bin/PKGBUILD; \
	echo "pkgver bumped to $$bare in both PKGBUILDs."; \
	echo; \
	echo "Next steps:"; \
	echo "  1. cd packaging/aur/meshtermd        && makepkg --printsrcinfo > .SRCINFO"; \
	echo "  2. cd packaging/aur/meshtermd-bin    && makepkg --printsrcinfo > .SRCINFO"; \
	echo "  3. Populate sha256sums_<arch> in meshtermd-bin/PKGBUILD from"; \
	echo "     https://github.com/AG-Studio-Apps/meshtermd/releases/download/$(VERSION)/SHA256SUMS"

clean:
	rm -rf dist meshtermd mtctl
