# Build Caddy with the caddy-waf module.
#
# The build context IS the source. This previously ran `git clone` against
# GitHub, so `docker build .` ignored your checkout entirely and compiled
# whatever happened to be on main at that moment: not reproducible, unable to
# build a specific version, and it would make a CI image build test the wrong
# code.
#
# Cross-compilation is done by Go on the build platform rather than by emulating
# the target, so an arm64 image does not cost a QEMU-emulated compile.

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

# go.mod declares go 1.25.1 (propagated from caddy/v2, which requires it), so
# the toolchain here has to be at least that. It was pinned to 1.24 and only
# worked because GOTOOLCHAIN=auto silently downloaded a newer one mid-build.

# xcaddy is pinned so the tool that assembles the artefact is fixed; bump it via
# a tracked change rather than resolving @latest at build time.
RUN apk add --no-cache git && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7

WORKDIR /src

# Warm the module cache before copying the rest, so a source-only edit does not
# re-download the dependency tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# GeoLite2 is NOT baked into the image: it was fetched from a community mirror of
# uncertain freshness at build time, which made the artefact vary by build date
# and embedded a data file of unknown provenance. Country/ASN filtering is
# optional; mount an operator-supplied, versioned GeoLite2 database at runtime
# instead (see docs/geoblocking.md and docs/docker.md).

ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    xcaddy build --with github.com/fabriziosalmi/caddy-waf=/src

# --- Runtime ---
# Pin the runtime base so the shipped image's base layer is part of what the
# commit describes; bump deliberately. For stronger reproducibility pin by digest
# (FROM alpine:3.21@sha256:...).
FROM alpine:3.21

RUN apk add --no-cache ca-certificates && \
    addgroup -S caddy && adduser -S -G caddy caddy

WORKDIR /app

COPY --from=builder /src/caddy /usr/bin/caddy
COPY --from=builder /src/rules.json /app/
COPY --from=builder /src/ip_blacklist.txt /app/
COPY --from=builder /src/dns_blacklist.txt /app/
COPY Caddyfile /app/

RUN chown -R caddy:caddy /app

USER caddy

EXPOSE 8080

CMD ["caddy", "run", "--config", "/app/Caddyfile"]
