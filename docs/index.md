---
layout: home

hero:
  name: caddy-waf
  text: Web Application Firewall for Caddy
  tagline: Runs inside Caddy itself. No sidecar, no cloud service in the request path.
  image:
    src: /logo.svg
    alt: caddy-waf
  actions:
    - theme: brand
      text: Get started
      link: /introduction
    - theme: alt
      text: Configuration reference
      link: /configuration

features:
  - title: Rule engine
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6-6 6 6 6"/><path d="m15 6 6 6-6 6"/></svg>'
    details: Regular expressions compiled by Go's RE2, so matching is linear-time with no catastrophic backtracking. Rules carry a score; a request is blocked once the total reaches the anomaly threshold.
    link: /rules
    linkText: Rule schema
  - title: Four inspection phases
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 17 9 5 9-5"/></svg>'
    details: Request headers, request body, response headers and response body, each with its own rule set and target identifiers.
    link: /configuration
    linkText: Phases and directives
  - title: Blacklists and geo controls
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg>'
    details: IP and CIDR ranges in a prefix trie, exact-match DNS lookups, MaxMind country and ASN filtering, and a periodically refreshed Tor exit-node list.
    link: /blacklists
    linkText: File formats
  - title: Rate limiting
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20a8 8 0 1 1 8-8"/><path d="m12 12 5-3"/><path d="M12 4v2"/><path d="M4.9 7.5 6.3 8.6"/></svg>'
    details: Per-IP sliding window, optionally scoped to specific paths with regular expressions.
    link: /ratelimit
    linkText: Limiter behaviour
  - title: Observability
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M3 13h4l3 7 4-16 3 9h4"/></svg>'
    details: A JSON metrics endpoint, an async log worker with sensitive-data redaction, and worked examples for Prometheus, Grafana and ELK.
    link: /metrics
    linkText: Metrics schema
  - title: Hot reload
    icon: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v6h-6"/></svg>'
    details: File watchers on the rule files and both blacklists, with a documented matrix of what each reload covers and what still needs a caddy reload.
    link: /dynamicupdates
    linkText: Reload matrix
---

## Install

Build a Caddy binary with the module using [`xcaddy`](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
./caddy list-modules | grep waf    # http.handlers.waf
```

Or run the published container image, which needs no Go toolchain:

```bash
docker run --rm -p 8080:8080 ghcr.io/fabriziosalmi/caddy-waf:0.4.14
```

The module is also selectable on the [Caddy download page](https://caddyserver.com/download?package=github.com%2Ffabriziosalmi%2Fcaddy-waf), and `caddy add-package github.com/fabriziosalmi/caddy-waf` works for a one-off install — though Caddy's maintainers have proposed moving that command out of core, so do not build a deployment around it ([#138](https://github.com/fabriziosalmi/caddy-waf/issues/138)).

See [Installation](installation.md) for every supported path.

## Minimal configuration

```caddyfile
:8080 {
    route {
        waf {
            rule_file          rules.json
            ip_blacklist_file  ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            anomaly_threshold  20
            metrics_endpoint   /waf_metrics
        }
        reverse_proxy localhost:3000
    }
}
```

## Reading order

A first-time reader is recommended to follow this sequence:

1. [Introduction](introduction.md) — what the middleware does and where it fits.
2. [Installation](installation.md) — supported build paths and prerequisites.
3. [Configuration](configuration.md) — the request lifecycle, every Caddyfile directive, every JSON-only field, blocking precedence.
4. [Rules](rules.md) — the JSON rule schema and target identifiers.
5. [Blacklists](blacklists.md) — file formats for IP and DNS blacklists.
6. [Rate limiting](ratelimit.md) — sliding-window limiter, path matching.
7. [Country and ASN blocking](geoblocking.md) — GeoIP / ASN behaviour.

## Every page

| Document | Topic |
|---|---|
| [introduction.md](introduction.md) | What the middleware does and where it sits in the request pipeline. |
| [installation.md](installation.md) | Build with `xcaddy`, the install script, or from source. |
| [add-package-guide.md](add-package-guide.md) | Installing with `caddy add-package`. |
| [docker.md](docker.md) | Building and running the supplied `Dockerfile` / `docker-compose.yml`. |
| [configuration.md](configuration.md) | Caddyfile directives, JSON fields, request phases, blocking precedence. |
| [rules.md](rules.md) | `rules.json` schema, target identifiers, regex semantics. |
| [blacklists.md](blacklists.md) | IP and DNS blacklist file formats. |
| [ratelimit.md](ratelimit.md) | The `rate_limit` block and behaviour. |
| [geoblocking.md](geoblocking.md) | `block_countries`, `whitelist_countries`, `block_asns`, fallback. |
| [dynamicupdates.md](dynamicupdates.md) | File watchers, what each reload covers and what it does not. |
| [metrics.md](metrics.md) | The `/waf_metrics` JSON document. |
| [prometheus.md](prometheus.md) | A small exporter that scrapes the JSON metrics for Prometheus. |
| [caddy-waf-elk.md](caddy-waf-elk.md) | Shipping the JSON log file to an ELK stack with Filebeat. |
| [attacks.md](attacks.md) | Attack categories targeted by the bundled rule sets. |
| [testing.md](testing.md) | Running `test.py` against a live WAF. |
| [caddytest.md](caddytest.md) | Traffic generator for benchmarks and rule validation. |
| [scripts.md](scripts.md) | The Python helpers under the project root. |

## Bundled rule files

- [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json) — the default rule set wired into the supplied [`Caddyfile`](https://github.com/fabriziosalmi/caddy-waf/blob/main/Caddyfile).
- [`rules/`](https://github.com/fabriziosalmi/caddy-waf/tree/main/rules) — modular rule files grouped by attack category. Each file is a JSON array of rules and can be referenced directly with one or more `rule_file` directives.

## Security

Only the latest release receives security fixes. Published advisories are listed under [Security → Advisories](https://github.com/fabriziosalmi/caddy-waf/security/advisories).

**v0.3.3 and earlier** are affected by [GHSA-gfj3-cmff-q8wh](https://github.com/fabriziosalmi/caddy-waf/security/advisories/GHSA-gfj3-cmff-q8wh), a high-severity unauthenticated denial of service. Fixed in v0.3.4.

To report a vulnerability, use [private vulnerability reporting](https://github.com/fabriziosalmi/caddy-waf/security/advisories/new) rather than a public issue.
