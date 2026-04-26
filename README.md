# Caddy WAF

A Web Application Firewall middleware for the [Caddy](https://caddyserver.com/) web server, written in Go.

[![Tests](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/test.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/test.yml)
[![CodeQL](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/github-code-scanning/codeql)
[![Build, Run and Validate](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build-run-validate.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-waf/actions/workflows/build-run-validate.yml)

- **Module ID**: `http.handlers.waf`
- **Go module path**: `github.com/fabriziosalmi/caddy-waf`
- **Current version**: `v0.3.0` (see [`caddywaf.go`](caddywaf.go) — `const wafVersion`)
- **License**: AGPL-3.0

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
INFO  WAF middleware version  {"version":"v0.3.0"}
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

- Go **1.25** or newer ([`go.mod`](go.mod) declares `go 1.25`)
- Caddy **v2.10.x** or newer (current build uses `github.com/caddyserver/caddy/v2 v2.10.2`)
- [`xcaddy`](https://github.com/caddyserver/xcaddy) for building Caddy with plugins

### Option 1 — Build with xcaddy (recommended)

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/fabriziosalmi/caddy-waf
./caddy list-modules | grep waf   # expect: http.handlers.waf
```

### Option 2 — Quick script

```bash
curl -fsSL -H "Pragma: no-cache" \
  https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

### Option 3 — Build from source

```bash
git clone https://github.com/fabriziosalmi/caddy-waf.git
cd caddy-waf
go mod tidy
wget https://git.io/GeoLite2-Country.mmdb           # optional, only for GeoIP
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./
./caddy fmt --overwrite
./caddy run
```

### `caddy add-package`

This module is **not registered** in Caddy's official package registry; `caddy add-package github.com/fabriziosalmi/caddy-waf` will fail with `HTTP 400: ... is not a registered Caddy module package path`. Use one of the build options above. See [`docs/add-package-guide.md`](docs/add-package-guide.md) for details.

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

| Document | Topic |
|---|---|
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
| [`docs/add-package-guide.md`](docs/add-package-guide.md) | Status of `caddy add-package` registration. |
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
├── types.go               Public types (Middleware, Rule, RateLimit, ...)
├── doc.go                 Package documentation
├── rules.json             Default rule set (used by Caddyfile)
├── rules/                 Modular rule files by category
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

## Contributing

Pull requests are welcome. The project values:

1. Tests that exercise the change.
2. Rule contributions placed under [`rules/`](rules/) using the documented JSON schema.
3. Documentation kept in sync with code (every directive change must be reflected in [`docs/configuration.md`](docs/configuration.md) and the relevant topic page).

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security

For vulnerability disclosure see [`SECURITY.md`](SECURITY.md). Reports may be sent to `fabrizio.salmi@gmail.com` or as a private GitHub Security Advisory; please do not open a public issue.

## License

AGPL-3.0. See [`LICENSE`](LICENSE).
