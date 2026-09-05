# Caddy WAF

A Web Application Firewall middleware for the [Caddy](https://caddyserver.com/) web server, written in Go.

[![Tests](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/test.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/test.yml)
[![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql)
[![Build, Run and Validate](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build-run-validate.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build-run-validate.yml)

- **Module ID**: `http.handlers.waf` — [registered in Caddy's package registry](https://caddyserver.com/docs/modules/http.handlers.waf), so the module is selectable on the [download page](https://caddyserver.com/download?package=github.com%2Ffabriziosalmi%2Fcaddy-waf)
- **Go module path**: `github.com/fabriziosalmi/caddy-waf`
- **Current version**: `v0.4.14` (see [`caddywaf.go`](caddywaf.go) — `const wafVersion`)
- **License**: AGPL-3.0 — note this is a copyleft licence; check it suits your deployment before integrating

---

## Overview

`caddy-waf` is an HTTP handler middleware that inspects requests and responses across four well-defined phases, applies a regular-expression rule set with anomaly scoring, enforces IP/DNS/ASN/country blacklists and whitelists, performs token-bucket-style rate limiting, and exposes a JSON metrics endpoint.

The middleware is implemented as a single Caddy module registered under the ID `http.handlers.waf`. It can be configured through the Caddyfile or directly via JSON.

## Capabilities

| Capability | Implementation |
|---|---|
| Regex rule engine | Go [`regexp`](https://pkg.go.dev/regexp) package (RE2, linear-time guarantee). Compiled patterns are cached per rule ID. |
| Multi-phase inspection | Phase 1 (request headers and pre-request checks), Phase 2 (request body), Phase 3 (response headers), Phase 4 (response body). |
| Anomaly scoring | Each rule contributes its `score` to a per-request total; requests are blocked when the total reaches `anomaly_threshold`. |
| Explicit actions | Rule `mode` of `block` or `log`. `block` short-circuits the request; `log` records the match and continues. |
| IP blacklist | Plain IPs and CIDR ranges (IPv4 and IPv6) stored in a prefix trie ([`go-iptrie`](https://github.com/phemmer/go-iptrie)). |
| DNS blacklist | Exact-match (case-insensitive) host lookup. |
| GeoIP country block / whitelist | MaxMind GeoLite2 Country MMDB. |
| ASN block | MaxMind GeoLite2 ASN MMDB. |
| Tor exit-node block | Periodic fetch from `https://check.torproject.org/torbulkexitlist`. |
| Rate limiting | Per-IP, sliding-window, optional per-path matching with regex patterns. |
| Custom block responses | Per-status-code response with custom Content-Type, headers, and body (inline or from file). |
| Sensitive data redaction | Optional redaction of sensitive query parameters and log fields. |
| Hot reload | `fsnotify` watchers on rule files, IP blacklist, and DNS blacklist. |
| Metrics endpoint | JSON document exposed at the configured `metrics_endpoint` path. |
| Asynchronous logging | Buffered log channel with synchronous fallback when the buffer is full. |

## Engineering notes

- **Linear-time regex**: rules are compiled by Go's `regexp` (RE2). No catastrophic backtracking.
- **Wait-free counters**: per-rule hit counts use `atomic.Int64` stored in a `sync.Map`.
- **Bounded body reads**: request bodies are read through `io.LimitReader` (`max_request_body_size`, default 10 MiB) and restored with `io.MultiReader` so downstream handlers still see the full body.
- **Bounded response buffering**: the response body is only held in memory when a Phase 4 rule exists to inspect it, and never past `max_response_body_size` (default 10 MiB). Beyond that — or as soon as the upstream flushes — the WAF releases what it holds and streams the rest, so memory never scales with the response size.
- **Zero-copy body string**: the body is exposed to rule matching via `unsafe.String` to avoid an allocation per request.
- **Circuit breaker for GeoIP**: `geoip_fail_open` controls whether a GeoIP lookup failure blocks the request or allows it through.
- **Panic recovery**: `ServeHTTP` installs a deferred recovery that returns `500 Internal Server Error` on panic.

---

## Quick start

The fastest path to a working build:

```bash
curl -fsSL -H "Pragma: no-cache" \
  https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

The script ensures Go and `xcaddy` are installed, clones the repository, downloads the GeoLite2 database, builds Caddy with the `caddy-waf` module, and starts the server.

A representative provisioning log:

```
INFO  Provisioning WAF middleware     {"log_level":"info","log_path":"debug.json","log_json":true,"anomaly_threshold":20}
INFO  http.handlers.waf  Tor exit nodes updated  {"count":1093}
INFO  WAF middleware version  {"version":"v0.4.14"}
INFO  Rate limit configuration  {"requests":100,"window":10,"cleanup_interval":300,"paths":["/api/v1/.*"],"match_all_paths":false}
WARN  GeoIP database not found. Country blacklisting/whitelisting will be disabled  {"path":"GeoLite2-Country.mmdb"}
INFO  IP blacklist loaded     {"path":"ip_blacklist.txt","valid_entries":223770,"invalid_entries":0,"total_lines":223770}
INFO  DNS blacklist loaded    {"path":"dns_blacklist.txt","valid_entries":854479,"total_lines":854479}
INFO  WAF rules loaded successfully   {"total_rules":33,"rule_counts":"Phase 1: 17 rules, Phase 2: 16 rules, Phase 3: 0 rules, Phase 4: 0 rules, "}
INFO  WAF middleware provisioned successfully
```

---

## Installation

### Requirements

- Go **1.25.1** or newer ([`go.mod`](go.mod) declares `go 1.25.1`, propagated from `caddy/v2` which requires it)
- Caddy **v2.11.x** or newer (current build uses `github.com/caddyserver/caddy/v2 v2.11.4`)
- [`xcaddy`](https://github.com/caddyserver/xcaddy) for building Caddy with plugins

### Method 1 — Build with xcaddy (recommended)

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/fabriziosalmi/caddy-waf
./caddy list-modules | grep waf   # expect: http.handlers.waf
```

### Method 2 — Quick script

```bash
curl -fsSL -H "Pragma: no-cache" \
  https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

### Method 3 — Build from source

```bash
git clone https://github.com/fabriziosalmi/caddy-waf.git
cd caddy-waf
go mod tidy
wget https://git.io/GeoLite2-Country.mmdb           # optional, only for GeoIP
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./
./caddy fmt --overwrite
./caddy run
```

### Method 4 — `caddy add-package`

> [!IMPORTANT]
> **Prefer `xcaddy` or the container image.** Caddy's maintainers have proposed
> moving `add-package`, `remove-package` and `upgrade` out of Caddy's core to
> discourage their use ([caddyserver/caddy#7010](https://github.com/caddyserver/caddy/issues/7010)):
> the commands call Caddy's shared build server, and using them in CI/CD is an
> anti-pattern. Raised for this project in
> [#138](https://github.com/fabriziosalmi/caddy-waf/issues/138) by a Caddy
> maintainer.
>
> The command works today and the module remains registered, so this section
> stays accurate. Treat it as a convenience for one-off, hand-operated installs
> — not as the way to build or deploy caddy-waf.

The module is registered in Caddy's package registry, so an existing Caddy v2.7+ binary can pull it in without a Go toolchain:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
caddy list-modules | grep waf   # expect: http.handlers.waf
```

It is also selectable on [caddyserver.com/download](https://caddyserver.com/download). See [`docs/add-package-guide.md`](docs/add-package-guide.md) for version pinning, removal, and when to prefer `xcaddy` instead.

### Method 5 — Docker

Images are published to GitHub Container Registry on every release tag, for `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/fabriziosalmi/caddy-waf:0.4.14
docker run --rm -p 8080:8080 ghcr.io/fabriziosalmi/caddy-waf:0.4.14
```

Tags are `0.4.14`, `0.4` and `latest` — note there is **no `v` prefix**, unlike the Go module version. Pin an exact version in anything you deploy. See [`docs/docker.md`](docs/docker.md) for volumes, Compose, and hot reload.

---

## Minimal Caddyfile

```caddyfile
{
    auto_https off
    admin localhost:2019
}

:8080 {
    log {
        output stdout
        format console
        level INFO
    }

    route {
        waf {
            metrics_endpoint   /waf_metrics
            rule_file          rules.json
            ip_blacklist_file  ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
        }

        @wafmetrics path /waf_metrics
        handle @wafmetrics {
            # Falls through to the WAF handler, which serves metrics as JSON.
        }

        handle {
            respond "Hello world!" 200
        }
    }
}
```

A fully annotated example is provided in [`Caddyfile`](Caddyfile) and [`caddyfile.example`](caddyfile.example).

---

## Documentation

**[fabriziosalmi.github.io/caddy-waf](https://fabriziosalmi.github.io/caddy-waf/)** — the same pages as below, with full-text search and cross-linking. The Markdown under [`docs/`](docs/) remains the source and stays readable on GitHub.

| Document | Topic |
|---|---|
| [`docs/introduction.md`](docs/introduction.md) | What the middleware does and where it sits in the request pipeline. |
| [`docs/installation.md`](docs/installation.md) | All installation methods. |
| [`docs/configuration.md`](docs/configuration.md) | Caddyfile and JSON directives, request lifecycle, blocking precedence. |
| [`docs/rules.md`](docs/rules.md) | `rules.json` schema, target identifiers, regex semantics. |
| [`docs/blacklists.md`](docs/blacklists.md) | IP and DNS blacklist file formats. |
| [`docs/ratelimit.md`](docs/ratelimit.md) | Rate-limit block, path matching, behavior. |
| [`docs/geoblocking.md`](docs/geoblocking.md) | Country block / whitelist, ASN block, fallback behavior. |
| [`docs/attacks.md`](docs/attacks.md) | Attack categories addressed by the bundled rule sets. |
| [`docs/dynamicupdates.md`](docs/dynamicupdates.md) | File watchers, reload semantics, scope of each reload. |
| [`docs/metrics.md`](docs/metrics.md) | `/waf_metrics` JSON schema. |
| [`docs/prometheus.md`](docs/prometheus.md) | Bridging the JSON metrics to Prometheus and Grafana. |
| [`docs/caddy-waf-elk.md`](docs/caddy-waf-elk.md) | Shipping logs to an ELK stack with Filebeat. |
| [`docs/scripts.md`](docs/scripts.md) | Helper Python scripts for rule and blacklist generation. |
| [`docs/testing.md`](docs/testing.md) | Running the bundled `test.py` suite. |
| [`docs/docker.md`](docs/docker.md) | Building and running with Docker / Docker Compose. |
| [`docs/add-package-guide.md`](docs/add-package-guide.md) | Installing with `caddy add-package`. |
| [`docs/caddytest.md`](docs/caddytest.md) | The `caddytest.py` traffic-generation tool. |

---

## Project layout

```
.
├── caddywaf.go            Module registration, lifecycle, file watchers, metrics endpoint
├── handler.go             ServeHTTP, phase dispatch, blocking decisions
├── config.go              Caddyfile directive parsing
├── rules.go               Rule loading, validation, regex caching, hit accounting
├── request.go             Target extraction (URI, headers, body, JSON paths, ...)
├── response.go            Response recorder, block writer
├── blacklist.go           IP and DNS blacklist loaders and lookups
├── ratelimiter.go         Per-IP / per-path sliding-window rate limiter
├── geoip.go               MaxMind country and ASN lookups, with optional cache
├── tor.go                 Periodic Tor exit-node list fetcher
├── logging.go             Async log worker, sensitive-data redaction
├── helpers.go             IP parsing helpers
├── debug_waf.go           Debug helpers for rule evaluation
├── assets.go              Embedded dashboard assets (build tag)
├── assets_stub.go         No-op asset provider for builds without the dashboard
├── types.go               Public types (Middleware, Rule, RateLimit, ...)
├── doc.go                 Package documentation
├── rules.json             Default rule set (used by Caddyfile)
├── rules/                 Modular rule files by category
├── ui/                    Dashboard, with third-party assets vendored same-origin
├── ip_blacklist.txt       Default IP blacklist
├── dns_blacklist.txt      Default DNS blacklist
├── tor_blacklist.txt      Tor exit-node cache (auto-managed)
├── docs/                  Documentation
└── *_test.go              Unit and integration tests
```

---

## Testing

```bash
make test            # go test -v ./...
make it              # go test -v ./... -tags=it (integration)
make lint            # golangci-lint run
make test-integration # runs test.py inside a python:3.9-slim container
```

The repository also ships Python suites covering offensive payloads (`test.py`), traffic generation (`caddytest.py`), and benchmarking (`benchmark.py`). See [`docs/testing.md`](docs/testing.md) and [`docs/caddytest.md`](docs/caddytest.md).

---

## Commercial support & consulting

Running caddy-waf in production? I offer paid support, custom rule development,
and security consulting — WAF tuning, hardening, TLS automation, and cloud
detection & alerting. Reach out: **fabrizio.salmi@gmail.com**.

## Contributing

Pull requests are welcome. The project values:

1. Tests that exercise the change.
2. Rule contributions placed under [`rules/`](rules/) using the documented JSON schema.
3. Documentation kept in sync with code (every directive change must be reflected in [`docs/configuration.md`](docs/configuration.md) and the relevant topic page).

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security

Please do not open a public issue for a vulnerability. Use [private vulnerability reporting](https://github.com/fabriziosalmi/caddy-waf/security/advisories/new) — it is enabled on this repository, so it works for anyone without special permissions — or email `fabrizio.salmi@gmail.com`. Full policy in [`SECURITY.md`](SECURITY.md).

Only the latest release receives security fixes; there are no backport branches. Published advisories are listed under [Security → Advisories](https://github.com/fabriziosalmi/caddy-waf/security/advisories).

**Upgrade note:** v0.3.3 and earlier are affected by [GHSA-gfj3-cmff-q8wh](https://github.com/fabriziosalmi/caddy-waf/security/advisories/GHSA-gfj3-cmff-q8wh), a high-severity unauthenticated denial of service (unbounded response buffering, CVSS 7.5). Fixed in v0.3.4.

## License

AGPL-3.0. See [`LICENSE`](LICENSE).
