# Caddy WAF — Documentation

A Web Application Firewall middleware for the Caddy web server.

- **Module ID**: `http.handlers.waf`
- **Module type**: HTTP handler middleware
- **Go module path**: `github.com/fabriziosalmi/caddy-waf`
- **Latest version**: see [`caddywaf.go`](../caddywaf.go) — `const wafVersion`

## Reading order

A first-time reader is recommended to follow this sequence:

1. [Introduction](introduction.md) — what the middleware does and where it fits.
2. [Installation](installation.md) — supported build paths and prerequisites.
3. [Configuration](configuration.md) — the request lifecycle, every Caddyfile directive, every JSON-only field, blocking precedence.
4. [Rules](rules.md) — the JSON rule schema and target identifiers.
5. [Blacklists](blacklists.md) — file formats for IP and DNS blacklists.
6. [Rate limiting](ratelimit.md) — sliding-window limiter, path matching.
7. [Country and ASN blocking](geoblocking.md) — GeoIP / ASN behavior.

## Reference

| Document | Topic |
|---|---|
| [installation.md](installation.md) | Build with `xcaddy`, the install script, or from source. |
| [configuration.md](configuration.md) | Caddyfile directives, JSON fields, request phases, blocking precedence. |
| [rules.md](rules.md) | `rules.json` schema, target identifiers, regex semantics. |
| [blacklists.md](blacklists.md) | IP and DNS blacklist file formats. |
| [ratelimit.md](ratelimit.md) | The `rate_limit` block and behavior. |
| [geoblocking.md](geoblocking.md) | `block_countries`, `whitelist_countries`, `block_asns`, fallback. |
| [attacks.md](attacks.md) | Attack categories targeted by the bundled rule sets. |
| [dynamicupdates.md](dynamicupdates.md) | File watchers, what each reload covers and what it does not. |
| [metrics.md](metrics.md) | The `/waf_metrics` JSON document. |
| [prometheus.md](prometheus.md) | A small exporter that scrapes the JSON metrics for Prometheus. |
| [caddy-waf-elk.md](caddy-waf-elk.md) | Shipping the JSON log file to an ELK stack with Filebeat. |
| [scripts.md](scripts.md) | The Python helpers under the project root. |
| [testing.md](testing.md) | Running `test.py` against a live WAF. |
| [caddytest.md](caddytest.md) | Traffic generator for benchmarks and rule validation. |
| [docker.md](docker.md) | Building and running the supplied `Dockerfile` / `docker-compose.yml`. |
| [add-package-guide.md](add-package-guide.md) | Status of `caddy add-package` registration. |

## Bundled rule files

- [`rules.json`](../rules.json) — the default rule set wired into the supplied [`Caddyfile`](../Caddyfile).
- [`rules/`](../rules/) — modular rule files grouped by attack category. Each file is a JSON array of rules and can be referenced directly with one or more `rule_file` directives.
