# gbounce — make targets
#
# `make build`     compile the binary into ./bin/gbounce (gitignored)
#                  with version + commit + buildTime stamped via -ldflags
# `make install`   `go install` with the same -ldflags into $GOPATH/bin
# `make vet`       go vet ./...
# `make test`      unit tests
#
# Canonical end-user install path stays
# `go install github.com/trsreagan3/gbounce/cmd/gbounce@latest`; the
# `install` target below is for source-tree iteration only. Go 1.18+
# auto-stamps VCS info into binaries built from a checkout, so even an
# unflagged `go install` reports a real commit SHA (see
# internal/cli/cli.go::resolveBuildInfo). The explicit ldflags here
# override that auto-stamp with the values the operator's checkout
# claims, which is what release builds want.
#
# See docs/LOCAL-TEST-INFRA.md in iam-roles for the cross-repo plan.

# Build metadata. Override on the command line for release builds:
#   make build VERSION=v1.0.0
# Fallbacks keep the recipe runnable in a non-git tarball.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Single source of truth for the -X flags. Mirrors the Dockerfile +
# .github/workflows/docker-publish.yml exactly so operators get the
# same shape from every supported install path.
LDFLAGS := -X github.com/trsreagan3/gbounce/internal/cli.version=$(VERSION) \
           -X github.com/trsreagan3/gbounce/internal/cli.commit=$(COMMIT) \
           -X github.com/trsreagan3/gbounce/internal/cli.buildTime=$(BUILD_TIME)

.PHONY: build install vet test version

# Local-dev build — drops the binary into ./bin/ which is gitignored.
# NEVER commit the contents of bin/. The canonical install path for
# end users is `go install github.com/trsreagan3/gbounce/cmd/gbounce@latest`
# per README; this target exists for source-tree iteration only.
build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/gbounce ./cmd/gbounce

# Source-tree equivalent of the canonical end-user install — drops
# the binary into $GOPATH/bin (or $HOME/go/bin), with the same
# version-stamping ldflags so `gbounce --version` reports a real SHA.
install:
	go install -ldflags "$(LDFLAGS)" ./cmd/gbounce

vet:
	go vet ./...

test:
	go test ./...

# Print the ldflags shape the build would use. Useful for debugging
# canary update flows + for the version-stamping integration test.
version:
	@echo "VERSION=$(VERSION)"
	@echo "COMMIT=$(COMMIT)"
	@echo "BUILD_TIME=$(BUILD_TIME)"
