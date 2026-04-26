# Metrics

When `metrics_endpoint` is configured, the WAF serves a JSON metrics document at the given path. The document is emitted by `handleMetricsRequest` in [`caddywaf.go`](../caddywaf.go) and reflects the counters maintained by the runtime.

## Endpoint

```caddyfile
waf {
    metrics_endpoint /waf_metrics
    ...
}
```

The path must start with `/`. There is no authentication on the endpoint; if you expose it externally, place authentication in front of it (basic auth, IP allow-list, mTLS at the proxy, etc.).

## Response format

- HTTP status: `200 OK`
- `Content-Type: application/json`
- Body: a single JSON object with the fields below.

A representative response:

```json
{
  "total_requests":                27004,
  "blocked_requests":              25328,
  "allowed_requests":              1509,
  "rule_hits": {
    "block-scanners":               25,
    "sql-injection":                7,
    "xss-attacks":                  8,
    "log4j-jndi":                   2
  },
  "rule_hits_by_phase": {
    "1": 1461,
    "2": 705
  },
  "geoip_blocked":                 0,
  "ip_blacklist_hits":             0,
  "dns_blacklist_hits":            0,
  "rate_limiter_requests":         27004,
  "rate_limiter_blocked_requests": 23640,
  "version":                       "v0.3.0"
}
```

## Field reference

| Field | Type | Source | Meaning |
|---|---|---|---|
| `total_requests` | int | `Middleware.totalRequests` | Total number of requests that entered `ServeHTTP`. |
| `blocked_requests` | int | `Middleware.blockedRequests` | Total number of requests that resulted in a block (Phase 1 pre-checks, anomaly threshold, or `mode: block`). |
| `allowed_requests` | int | `Middleware.allowedRequests` | Total number of requests that were forwarded to the next handler and not subsequently blocked. |
| `rule_hits` | object<string,int> | `Middleware.ruleHits` (atomic counters per rule ID) | Number of times each rule's regex matched. The key is the rule's `id`. |
| `rule_hits_by_phase` | object<string,int> | `Middleware.ruleHitsByPhase` | Per-phase total of rule hits. Keys are phase numbers as strings (`"1"`, `"2"`, `"3"`, `"4"`). |
| `geoip_blocked` | int | `Middleware.geoIPBlocked` | Number of requests blocked by `block_countries`, `whitelist_countries`, or `block_asns`. |
| `ip_blacklist_hits` | int | `Middleware.IPBlacklistBlockCount` | Number of requests whose source IP matched the IP blacklist trie. |
| `dns_blacklist_hits` | int | `Middleware.DNSBlacklistBlockCount` | Number of requests whose `Host` matched the DNS blacklist map. |
| `rate_limiter_requests` | int | `RateLimiter.totalRequests` | Total requests counted by the rate limiter (under lock). |
| `rate_limiter_blocked_requests` | int | `RateLimiter.blockedRequests` | Requests blocked by the rate limiter for exceeding the bucket limit. |
| `version` | string | `wafVersion` constant in [`caddywaf.go`](../caddywaf.go) | Build version of the WAF. |

## Counter semantics

- All counters are **monotonic** and **process-local**. They reset when the process restarts and they are not aggregated across multiple Caddy instances.
- `rule_hits` keys appear only after the corresponding rule fires for the first time. A rule that has never matched is absent from the map (not present with value `0`).
- `rule_hits_by_phase` only contains keys for phases that have at least one hit.
- `total_requests` may exceed `blocked_requests + allowed_requests` briefly during a request that has not yet finished evaluating, because each counter is incremented at a distinct point in the pipeline.
- `rate_limiter_requests` includes both blocked and allowed requests, but only requests that actually pass through the limiter (see [ratelimit.md](ratelimit.md) for the path-matching subtleties).
- `ip_blacklist_hits`, `dns_blacklist_hits`, and `geoip_blocked` count **matches**, not blocking decisions. In practice the two are equivalent because a match in any of these layers immediately blocks the request.

## Sample queries

```bash
# Raw JSON
curl -s http://localhost:8080/waf_metrics | jq .

# Top 10 most-hit rules
curl -s http://localhost:8080/waf_metrics | jq '.rule_hits | to_entries | sort_by(-.value) | .[:10]'

# Block ratio
curl -s http://localhost:8080/waf_metrics | jq '.blocked_requests / .total_requests'

# Hits by phase as a CSV
curl -s http://localhost:8080/waf_metrics \
  | jq -r '.rule_hits_by_phase | to_entries | .[] | "\(.key),\(.value)"'
```

## Prometheus

The endpoint is plain JSON. To scrape it as Prometheus metrics, use the small exporter described in [prometheus.md](prometheus.md).

## Operational notes

- The metrics handler is wired through `ServeHTTP`; if a request matches `metrics_endpoint`, the WAF still runs Phase 1 and Phase 2 checks before the response is generated. A blocked request to the metrics path will return the block response, not the metrics document.
- The endpoint serializes the in-memory state under the metrics mutex; cost is O(rules-with-hits) per request.
- Because the response is small and uncached, exposing it on a debugging route or to an internal monitoring system is appropriate; do not put it on a high-RPS public path.
