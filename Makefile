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

.PHONY: all build test vet lint vuln dist clean

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o ./meshtermd $(CMD_PATH)

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

dist: $(addprefix dist-,$(DIST_TARGETS))

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

clean:
	rm -rf dist meshtermd
