---
title: "Build Caddy with plugins: xcaddy, Docker, add-package"
description: "How to build a Caddy binary with extra modules such as caddy-waf: install xcaddy, pin versions, combine several plugins, and build a Docker image."
---

# Build Caddy with plugins

Caddy is a single static binary, and third-party modules (plugins) such as caddy-waf are compiled into it. There is no plugin folder to drop files into: adding a module means building a new binary. This page shows the three ways to do that, using caddy-waf as the example. The xcaddy and Docker commands on this page were run with xcaddy v0.4.7 and Caddy v2.11.

| Way | Needs Go | Reproducible | Use it for |
|---|---|---|---|
| [`xcaddy`](#xcaddy) | yes | yes, with pinned versions | servers, CI, anything you deploy |
| [Docker](#docker) | no (it runs in the builder image) | yes, with pinned tags | container deployments |
| [`caddy add-package`](#caddy-add-package) | no | no | a quick one-off on a machine you operate by hand |

## xcaddy

[`xcaddy`](https://github.com/caddyserver/xcaddy) is Caddy's official build tool. It needs a Go toolchain: Caddy v2.11 and caddy-waf require **Go 1.26 or newer** (`go version` to check).

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

The binary lands in `$(go env GOPATH)/bin` (or `GOBIN` if set); add that directory to your `PATH` if `xcaddy` is not found.

Build Caddy with caddy-waf:

```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
./caddy list-modules | grep waf     # http.handlers.waf
```

### Pin the versions

Without arguments xcaddy picks the latest Caddy release and the latest version of each module, so two builds a week apart can differ. Pin both for anything you deploy:

```bash
xcaddy build v2.11.7 \
    --with github.com/fabriziosalmi/caddy-waf@v0.4.18
```

The first argument is the Caddy version (when omitted, xcaddy uses the `CADDY_VERSION` environment variable, or the latest release); `@version` pins a module.

### Several plugins in one binary

Repeat `--with` once per module. For example caddy-waf together with the Cloudflare DNS provider, needed for ACME DNS challenges on Cloudflare-hosted zones:

```bash
xcaddy build v2.11.7 \
    --with github.com/fabriziosalmi/caddy-waf@v0.4.18 \
    --with github.com/caddy-dns/cloudflare
./caddy list-modules | grep -E 'http.handlers.waf|dns.providers.cloudflare'
```

### Build for another platform

xcaddy honours `GOOS` and `GOARCH`, so a Linux server binary can be built on a Mac:

```bash
GOOS=linux GOARCH=amd64 xcaddy build v2.11.7 \
    --with github.com/fabriziosalmi/caddy-waf@v0.4.18
```

### Build from a local checkout

To test a change to a module, point `--with` at its directory with `=`:

```bash
git clone https://github.com/fabriziosalmi/caddy-waf.git
cd caddy-waf
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./
```

## Docker

The official `caddy` images come in a `-builder` variant that already contains Go and xcaddy. A two-stage Dockerfile builds the binary in the builder and copies it into the regular image:

```dockerfile
FROM caddy:2.11-builder AS builder
RUN xcaddy build \
    --with github.com/fabriziosalmi/caddy-waf@v0.4.18

FROM caddy:2.11
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

```bash
docker build -t caddy-with-waf .
docker run --rm caddy-with-waf caddy list-modules | grep waf
```

The builder image sets `CADDY_VERSION` to the Caddy release of its tag, so `caddy:2.11-builder` builds the latest 2.11 patch; pin a full tag such as `2.11.9-builder` for a reproducible image. The result behaves like the official image: configuration in `/etc/caddy/Caddyfile`, data in `/data`. Add one `--with` line per extra plugin.

caddy-waf also publishes a ready-made image, `ghcr.io/fabriziosalmi/caddy-waf`, with the default rules and blacklists included. See [Docker](docker.md).

## caddy add-package

An existing Caddy binary (v2.7 or newer) can replace itself with one that includes extra modules, without Go:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

The command asks Caddy's shared build server for the new binary, so it depends on that service being up and does not give you a build you can reproduce. Use it by hand, not in CI. See [caddy add-package](add-package-guide.md) for pinning, removal and troubleshooting.

## Check what a binary contains

```bash
caddy version          # Caddy version
caddy list-modules     # every module compiled in
caddy build-info       # Go version and the exact version of every module
```

`caddy build-info` is the quickest way to see which version of a plugin a binary carries.
