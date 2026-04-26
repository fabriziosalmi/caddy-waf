# Caddy WAF — Module Information

| Property | Value |
|---|---|
| Module name | `caddy-waf` |
| Module ID | `http.handlers.waf` |
| Module type | HTTP handler middleware |
| Go module path | `github.com/fabriziosalmi/caddy-waf` |
| License | AGPL-3.0 |
| Latest version | see `const wafVersion` in [`caddywaf.go`](caddywaf.go) |
| Caddy version | v2.10.x or newer |
| Go version | 1.25 or newer |

## Description

A Web Application Firewall middleware for the Caddy web server. The middleware inspects HTTP requests and responses across four well-defined phases (request headers, request body, response headers, response body), applies a regular-expression rule set with anomaly scoring, and enforces IP / DNS / ASN / country blacklists and whitelists, Tor exit-node blocking, and per-IP rate limiting. It exposes a JSON metrics endpoint for monitoring.

## Implemented interfaces

| Interface | Method |
|---|---|
| `caddy.Module` | `CaddyModule()` |
| `caddy.Provisioner` | `Provision(ctx)` |
| `caddy.Validator` | `Validate()` |
| `caddyhttp.MiddlewareHandler` | `ServeHTTP(w, r, next)` |
| `caddyfile.Unmarshaler` | `UnmarshalCaddyfile(d)` |

Module registration:

```go
func init() {
    caddy.RegisterModule(&Middleware{})
    httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}
```

## Installation

```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
```

See [`docs/installation.md`](docs/installation.md) for alternatives.

## Caddyfile directives

The full table is in [`docs/configuration.md`](docs/configuration.md). A summary of every directive recognised by the parser:

| Directive | Form |
|---|---|
| `metrics_endpoint` | `metrics_endpoint <path>` |
| `log_path` | `log_path <file>` |
| `log_severity` | `log_severity (debug\|info\|warn\|error)` |
| `log_json` | `log_json` |
| `log_buffer` | `log_buffer <positive int>` |
| `rule_file` | `rule_file <file>` (repeatable) |
| `ip_blacklist_file` | `ip_blacklist_file <file>` |
| `dns_blacklist_file` | `dns_blacklist_file <file>` |
| `anomaly_threshold` | `anomaly_threshold <positive int>` |
| `block_countries` | `block_countries <mmdb> <ISO> [<ISO> …]` |
| `whitelist_countries` | `whitelist_countries <mmdb> <ISO> [<ISO> …]` |
| `block_asns` | `block_asns <mmdb> <ASN> [<ASN> …]` |
| `custom_response` | `custom_response <status> <content-type> (<inline-body…>\|<file-path>)` |
| `redact_sensitive_data` | `redact_sensitive_data` |
| `rate_limit { … }` | block — see configuration docs |
| `tor { … }` | block — see configuration docs |

## JSON-only fields

The following struct fields exist on `Middleware` but are not exposed as Caddyfile directives. To use them, configure Caddy with JSON.

| Field | JSON key | Default |
|---|---|---|
| `MaxRequestBodySize` | `max_request_body_size` | `10 MiB` |
| `GeoIPFailOpen` | `geoip_fail_open` | `false` |
| `Tor.CustomTORExitNodeURL` | `tor.custom_tor_exit_node_url` | `https://check.torproject.org/torbulkexitlist` |

## Basic usage

```caddyfile
example.com {
    waf {
        rule_file          rules.json
        ip_blacklist_file  ip_blacklist.txt
        dns_blacklist_file dns_blacklist.txt
        metrics_endpoint   /waf_metrics
    }

    respond "Protected by Caddy WAF" 200
}
```

## Documentation

Complete documentation lives in the [`docs/`](docs/) directory. Start at [`docs/README.md`](docs/README.md).

## Repository

`https://github.com/fabriziosalmi/caddy-waf`

## Support

- Issues: `https://github.com/fabriziosalmi/caddy-waf/issues`
- Security: see [`SECURITY.md`](SECURITY.md)
- Maintainer: `@fabriziosalmi`
