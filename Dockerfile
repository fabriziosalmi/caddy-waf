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

RUN apk add --no-cache git wget && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /src

# Warm the module cache before copying the rest, so a source-only edit does not
# re-download the dependency tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# GeoLite2 is optional at runtime, and this URL is a community mirror of
# uncertain freshness (see docs/geoblocking.md). It is baked in so the country
# and ASN examples work out of the box.
RUN wget -q https://git.io/GeoLite2-Country.mmdb

ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    xcaddy build --with github.com/fabriziosalmi/caddy-waf=/src

# --- Runtime ---
FROM alpine:latest

RUN apk add --no-cache ca-certificates && \
    addgroup -S caddy && adduser -S -G caddy caddy

WORKDIR /app

COPY --from=builder /src/caddy /usr/bin/caddy
COPY --from=builder /src/GeoLite2-Country.mmdb /app/
COPY --from=builder /src/rules.json /app/
COPY --from=builder /src/ip_blacklist.txt /app/
COPY --from=builder /src/dns_blacklist.txt /app/
COPY Caddyfile /app/

RUN chown -R caddy:caddy /app

USER caddy

EXPOSE 8080

CMD ["caddy", "run", "--config", "/app/Caddyfile"]
