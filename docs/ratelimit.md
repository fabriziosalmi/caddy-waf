# Rate Limiting

Per-IP, sliding-window rate limiting. Implemented in [`ratelimiter.go`](../ratelimiter.go) and configured through the `rate_limit` block inside the `waf` directive.

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
| `window` | Go duration (`10s`, `1m`, `1h`) | `10s` | Width of the sliding window. |
| `cleanup_interval` | Go duration | `300s` (5 min) | How often the cleanup goroutine sweeps expired entries from the in-memory map. |
| `paths` | one or more regex patterns | empty | When non-empty (and `match_all_paths=false`), only requests whose path matches one of these regex patterns are subject to the limit. |
| `match_all_paths` | `true` / `false` | `false` | When `true`, the limiter applies to **every** request regardless of `paths`. |

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

The rate limiter uses the host portion of `r.RemoteAddr` (parsed by `net.SplitHostPort`). It does **not** consult `X-Forwarded-For`. If your deployment is behind a trusted reverse proxy that forwards the original client IP only via that header, place the WAF behind a Caddy upstream that rewrites `r.RemoteAddr`, or accept that all traffic shares the proxy's IP for rate-limit purposes.

## Behaviour

- Each request is checked under a write lock (`rl.Lock()`); the path-regex matching happens before the lock to keep the critical section short.
- When the bucket counter exceeds `requests` within the active window, the request is blocked with HTTP `429 Too Many Requests` and the per-rate-limiter `blockedRequests` counter is incremented.
- When the active window has expired, the bucket is reset (`count=1`, new `window=now`).
- `cleanup_interval` ticks a background goroutine that walks the map and deletes buckets whose window is older than `window`.

## Counters and metrics

| Metric (in `/waf_metrics`) | Source |
|---|---|
| `rate_limiter_requests` | Total requests that passed through the limiter (counted under lock; includes both blocked and allowed). |
| `rate_limiter_blocked_requests` | Requests blocked because the bucket counter exceeded `requests`. |

When the limiter is configured with `match_all_paths=false` and a non-empty `paths`, **only path-matching requests** are counted in `rate_limiter_requests`; non-matching paths are counted in the metric increment that runs immediately before the early return (see `isRateLimited` in [`ratelimiter.go`](../ratelimiter.go)).

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
