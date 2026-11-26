---
title: "Rate limiting in Caddy: caddy-waf and caddy-ratelimit"
description: "Rate limit a login endpoint, an API or every path in Caddy with caddy-waf, and when to use the caddy-ratelimit module instead. Tested configs."
---

# Rate limiting in Caddy

Per-IP, fixed-window rate limiting: each client gets a counter that starts at its first request and resets when the window expires. Implemented in [`ratelimiter.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/ratelimiter.go) and configured through the `rate_limit` block inside the `waf` directive.

## Quick start: rate limit a login endpoint

```caddyfile
example.com {
    route {
        waf {
            rule_file /etc/caddy/rules.json

            # At most 5 requests per minute per client IP to /login; the 6th gets 429.
            rate_limit {
                requests 5
                window   1m
                paths    ^/login$
            }
        }

        reverse_proxy localhost:8080
    }
}
```

Each client IP gets 5 requests per minute on `/login`; the sixth gets `429 Too Many Requests` and other paths are not counted. Behind a CDN or reverse proxy set [`trusted_proxies`](/client-ip) first, or every client shares the proxy's address. Use `match_all_paths true` to limit every path.

## caddy-waf or caddy-ratelimit?

[`mholt/caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) is a dedicated rate limiting module for Caddy. Both answer `429 Too Many Requests`; they differ in what they are built for. The rows marked *measured* were run with Caddy v2.11.9, caddy-waf v0.4.19 and caddy-ratelimit v0.1.0 compiled into one binary, 5 requests per minute on `/login`: both let 5 through and answered the sixth with 429.

| | caddy-waf `rate_limit` | caddy-ratelimit |
|---|---|---|
| Algorithm | Fixed window per client, starting at its first request | Sliding window (ring buffer) |
| What a limit is keyed on | Client IP, or client IP plus the exact path when `paths` is set | Any placeholder: `{client_ip}`, a header, the host, ... |
| Scope | Paths matched by regular expressions | Any Caddy request matcher, several named zones |
| `Retry-After` on 429 (*measured*) | Not sent | Sent (`Retry-After: 60`), with optional jitter |
| Counters after `caddy reload` (*measured*) | Reset: the sixth request passed | Kept: the sixth request still got 429 |
| Several Caddy instances | Each instance counts on its own | Optional distributed mode through Caddy storage |
| Memory bound | `max_entries` caps the tracked clients | Expired limiters are swept periodically |
| Part of | The WAF (rules, blacklists, GeoIP, dashboard); one `rate_limit` block per `waf` | A module that only rate limits |

Use caddy-waf's limiter when you already run caddy-waf and need a simple per-client limit on a few paths, with the same client IP resolution as the rest of the WAF ([`trusted_proxies` or `client_ip_source caddy`](/client-ip)). Use caddy-ratelimit when you need a true sliding window, limits keyed on something other than the client, `Retry-After`, counters that survive reloads, or one limit shared by several instances.

The two can run in the same binary: `xcaddy build --with github.com/fabriziosalmi/caddy-waf --with github.com/mholt/caddy-ratelimit`. The same `/login` limit with caddy-ratelimit (its `rate_limit` directive is ordered by the module itself, so no `route` is needed):

```caddyfile
example.com {
    rate_limit {
        zone login {
            match {
                path /login
            }
            key    {client_ip}
            events 5
            window 1m
        }
    }
    reverse_proxy localhost:8080
}
```

## Caddyfile

```caddyfile
waf {
    rate_limit {
        requests         100
        window           10s
        cleanup_interval 5m
        paths            /api/v1/.*  /admin/.*
        match_all_paths  false
    }
}
```

| Sub-directive | Type | Default | Description |
|---|---|---|---|
| `requests` | positive integer | `100` | Maximum requests permitted per `window`, per bucket key. |
| `window` | Go duration (`10s`, `1m`, `1h`) | `10s` | Length of the window. It starts at the bucket's first request; when it has expired, the next request resets the count. |
| `cleanup_interval` | Go duration | `300s` (5 min) | How often the cleanup goroutine sweeps expired entries from the in-memory map. |
| `paths` | one or more regex patterns | empty | When non-empty (and `match_all_paths=false`), only requests whose path matches one of these regex patterns are subject to the limit. |
| `match_all_paths` | `true` / `false` | `false` | When `true`, the limiter applies to **every** request regardless of `paths`. |
| `max_entries` | positive integer | `1000000` | Upper bound on the number of distinct bucket keys tracked at once, so a flood of unique source IPs cannot grow the in-memory map without bound between cleanup sweeps. See [Behaviour](#behaviour). |

The block is required to set `requests > 0` and `window > 0`; otherwise the parser rejects the configuration.

## Bucket key

The bucket key — the value used to count requests against the limit — depends on configuration:

| `match_all_paths` | `paths` | Bucket key | Effect |
|---|---|---|---|
| `true` | (any) | `ip` | Every request is counted; one global counter per IP. |
| `false` | empty | _none_ | The limiter is a no-op. Requests bypass it without being counted. |
| `false` | non-empty | `ip + path` (when path matches a regex) | Each (IP, path) pair has its own counter; non-matching paths bypass the limiter. |

> Note: the bucket key uses the **exact** request path string concatenated with the IP, not the regex pattern. `/api/v1/users` and `/api/v1/orders` are tracked as separate buckets even when both match the same `paths` regex.

## Source IP

The bucket key's IP is the **resolved client IP** under the `trusted_proxies`
trust boundary — the connection peer by default, or the forwarded client when
the peer is a configured trusted proxy. Behind a CDN or reverse proxy, set
[`trusted_proxies`](/client-ip) (and optionally `client_ip_header`) so each
client is rate-limited on its own address; without it every request through the
proxy shares the proxy's IP and collapses into one bucket. See
[Client IP & trusted proxies](/client-ip).

## Behaviour

- Each request is checked under a write lock (`rl.Lock()`); the path-regex matching happens before the lock to keep the critical section short.
- When the bucket counter exceeds `requests` within the active window, the request is blocked with HTTP `429 Too Many Requests` and the per-rate-limiter `blockedRequests` counter is incremented.
- When the active window has expired, the bucket is reset (`count=1`, new `window=now`).
- `cleanup_interval` ticks a background goroutine that walks the map and deletes buckets whose window is older than `window`.
- The key table is bounded by `max_entries`. Once it is full, a request from a **new** key that is not yet tracked is allowed through without being counted (it is not rate-limited by this instance) rather than growing the map further; keys that are **already** tracked keep being counted normally, and a cleanup sweep frees capacity for new keys again. This is a deliberate memory bound: a flood of distinct source IPs cannot exhaust process memory, and — unlike an LRU — an attacker cannot evict and reset the counters of legitimate, already-tracked clients.

## Counters and metrics

| Metric (in `/waf_metrics`) | Source |
|---|---|
| `rate_limiter_requests` | Total requests that passed through the limiter (counted under lock; includes both blocked and allowed). |
| `rate_limiter_blocked_requests` | Requests blocked because the bucket counter exceeded `requests`. |

When the limiter is configured with `match_all_paths=false` and a non-empty `paths`, **only path-matching requests** are counted in `rate_limiter_requests`; non-matching paths are counted in the metric increment that runs immediately before the early return (see `isRateLimited` in [`ratelimiter.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/ratelimiter.go)).

## Reload semantics

The rate limiter is built during `Provision`. Subsequent file-watcher reloads of `rules.json` and the blacklists do **not** rebuild it; changing `requests`, `window`, `cleanup_interval`, `paths`, or `match_all_paths` requires a full `caddy reload`.

On shutdown, `signalStopCleanup` closes the cleanup channel, terminating the cleanup goroutine cleanly.

## Examples

### Limit a specific endpoint

```caddyfile
rate_limit {
    requests         5
    window           1m
    cleanup_interval 5m
    paths            ^/login$
}
```

### Global limit on every request

```caddyfile
rate_limit {
    requests         1000
    window           1m
    cleanup_interval 5m
    match_all_paths  true
}
```

### Limit two API surfaces independently

```caddyfile
rate_limit {
    requests         100
    window           10s
    cleanup_interval 5m
    paths            ^/api/v1/.*  ^/admin/.*
}
```

Note: only one `rate_limit` block is permitted per `waf` directive (a second block returns `rate_limit directive already specified`). For multiple independent limits, use multiple `waf` blocks on different routes.

## Pitfalls

- **No `paths`, no `match_all_paths`**: the limiter accepts every request without counting. This is rarely the intent.
- **Path regex misses the leading `/`**: regex patterns are matched against `r.URL.Path`, which always starts with `/`. Anchor with `^/`.
- **Tight `window` on noisy clients**: legitimate burstiness (page loads pulling many assets) can trip a low limit on the asset path. Either widen the window or scope `paths` to the resources that need protection.
