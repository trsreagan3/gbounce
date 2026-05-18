# syntax=docker/dockerfile:1.7
#
# gbounce — generic HTTP/HTTPS forward proxy with audit-export.
#
# Multi-stage build:
#   1. golang:1.26-alpine builds a static CGO-free binary with version
#      stamping via -ldflags. Matches go.mod's `go 1.26.0` directive so
#      the toolchain doesn't have to auto-download.
#   2. gcr.io/distroless/static-debian12:nonroot runs the binary as a
#      non-root user with no shell, no package manager, ~2MB base.
#
# Image is a packaging CONVENIENCE — same binary as `go install`,
# no extra features, no telemetry. The version-check subcommand only
# contacts the network when an operator runs `gbounce version-check`
# explicitly. See [[ibounce-honest-positioning]].

# ---- builder ---------------------------------------------------------------
FROM golang:1.26-alpine AS builder

# git is needed for `go build` to read VCS info when --buildvcs=auto fires.
# ca-certificates is needed by `go mod download` for TLS to proxy.golang.org.
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# Stamp version from build arg (passed in by CI from `git describe`);
# fall back to "docker" when built locally without --build-arg VERSION=...
ARG VERSION=docker
ARG COMMIT=none
ARG BUILD_TIME=unknown

# Predefined by BuildKit per the --platform flag; declared here WITHOUT
# defaults so BuildKit's auto-population isn't masked. With Docker 28.x
# + BuildKit v0.24, a default value on these specific ARGs WINS over
# the auto-populated value, silently producing wrong-arch binaries
# (e.g. --platform linux/arm64 emitting GOARCH=amd64). See the kbouncer
# #246 fix + docker/docs#5077.
ARG TARGETOS
ARG TARGETARCH

# Static binary: CGO_ENABLED=0 + -trimpath + -s -w for size + ldflags
# to populate the version/commit/buildTime vars in internal/cli/cli.go.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/trsreagan3/gbounce/internal/cli.version=${VERSION} \
            -X github.com/trsreagan3/gbounce/internal/cli.commit=${COMMIT} \
            -X github.com/trsreagan3/gbounce/internal/cli.buildTime=${BUILD_TIME}" \
        -o /out/gbounce \
        ./cmd/gbounce

# ---- runtime ---------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# OCI metadata — surfaced on GHCR + by `docker inspect`.
LABEL org.opencontainers.image.source="https://github.com/trsreagan3/gbounce" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="gbounce" \
      org.opencontainers.image.description="Generic HTTP/HTTPS forward proxy with audit-export"

COPY --from=builder /out/gbounce /usr/local/bin/gbounce

# Document the default ports:
#   8080 — proxy listener
#   8769 — management HTTP listener for /healthz (distinct from
#          kbounce's 8766, ibounce's 8767, dbounce's 8768 so all four
#          products coexist).
# The binary refuses non-loopback binds without
# --i-know-this-binds-externally, so EXPOSE here is purely
# documentation — the operator still has to pass --host 0.0.0.0 + the
# acknowledgement flag for the port to be reachable from outside the
# container.
EXPOSE 8080
EXPOSE 8769

# Distroless has no shell, so HEALTHCHECK NONE — operators hit
# /healthz externally (kubelet liveness probe, monit, systemd watchdog).
HEALTHCHECK NONE

# nonroot user (uid 65532) is the default in the :nonroot variant.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/gbounce"]
CMD ["--help"]
