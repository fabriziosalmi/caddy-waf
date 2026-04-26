# Introduction

`caddy-waf` is an HTTP handler middleware for the [Caddy](https://caddyserver.com/) web server. It is registered with the module ID `http.handlers.waf` and is configurable via the Caddyfile or directly via JSON.

## What it does

For every HTTP request that traverses the route in which the `waf` directive is placed, the middleware:

1. Initialises a per-request state (`WAFState`) holding the running anomaly score, blocking flag, status code, and a write marker.
2. Runs **Phase 1** — pre-request checks performed in this order: IP blacklist, DNS blacklist, rate limit, country whitelist, ASN block, country blacklist; then evaluates Phase 1 regex rules against request metadata and headers.
3. Runs **Phase 2** — Phase 2 regex rules against the request body and any other Phase 2 targets.
4. Calls the next handler in the route, capturing the response into a recorder.
5. Runs **Phase 3** — Phase 3 regex rules against the captured response headers.
6. Runs **Phase 4** — Phase 4 regex rules against the captured response body.
7. Either writes the captured response back to the client, or — if the request was blocked — emits a `403 Forbidden` (or the configured custom response).

If the configured `metrics_endpoint` matches the request path, the middleware serves a JSON metrics document instead of forwarding to the next handler.

## Capabilities at a glance

- Regex rules with phases, severity, score, and explicit `mode` (`block` or `log`).
- Anomaly scoring: rule scores accumulate; the request is blocked when `anomaly_threshold` is reached.
- IP blacklist (single addresses and CIDR ranges, IPv4 and IPv6) backed by a prefix trie.
- DNS blacklist with exact (case-insensitive) host matching.
- Country block / whitelist using a MaxMind GeoLite2 Country MMDB.
- ASN block using a MaxMind GeoLite2 ASN MMDB.
- Tor exit-node block, periodically refreshed from `check.torproject.org`.
- Sliding-window rate limiter, optionally restricted to regex-matched paths.
- Custom block responses per status code (Content-Type, headers, inline body or file).
- Optional sensitive-data redaction in logs and query parameters.
- Hot reload via `fsnotify` watchers on the rule and blacklist files.
- JSON metrics endpoint for Prometheus or ad-hoc tooling.
- Asynchronous logging worker with a synchronous fallback when the buffer fills.

## What it does not do

- It does not modify request bodies; it only inspects them. The body is read through `io.LimitReader` and re-attached with `io.MultiReader` so downstream handlers receive the full body.
- It does not perform TLS termination, HTTP routing, or response generation beyond the metrics endpoint and block responses; those remain the responsibility of Caddy and downstream handlers.
- It does not learn or self-tune; rules are static JSON files reloaded on change.
- It does not emit Prometheus directly; it exposes JSON that an external exporter can convert (see [prometheus.md](prometheus.md)).

## Next step

Continue with [installation.md](installation.md).
