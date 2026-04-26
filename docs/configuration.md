# Configuration

This document describes the request lifecycle, every Caddyfile directive recognised by the `waf` block, every JSON-only field on the middleware, and the order in which blocking decisions are taken.

The directive parser is implemented in [`config.go`](../config.go); the runtime fields are declared on the `Middleware` struct in [`types.go`](../types.go); the request pipeline lives in [`handler.go`](../handler.go).

---

## Request lifecycle

For each incoming request, [`Middleware.ServeHTTP`](../handler.go) performs the following steps:

1. **Generate a `log_id`** (UUID v4) and propagate it via `context.Context` so all log records for the request can be correlated.
2. **Install a panic recovery** that returns `500 Internal Server Error` on panic and logs the stack trace.
3. **Increment `total_requests`** in the metrics counters.
4. **Initialise `WAFState`** with `TotalScore=0`, `Blocked=false`, `StatusCode=200`, `ResponseWritten=false`.
5. **Phase 1** — pre-request checks, then Phase 1 regex rules. Returns immediately if blocked.
6. **Phase 2** — Phase 2 regex rules. Returns immediately if blocked.
7. **Call the next handler**, capturing its response into a `responseRecorder` (the recorder buffers the body, but delegates `Header()` and `WriteHeader()` directly to the underlying `ResponseWriter`).
8. **Phase 3** — Phase 3 regex rules against captured response headers. Returns immediately if blocked.
9. **Phase 4** — Phase 4 regex rules against the captured response body.
10. If the request matches the configured `metrics_endpoint`, serve the JSON metrics document (see [metrics.md](metrics.md)).
11. Otherwise, copy the recorded response body to the original `ResponseWriter` and increment `allowed_requests`.

### Phase 1 — pre-request checks (in order)

The order below reflects the actual code in [`handler.go`](../handler.go) (`handlePhase`, `phase==1`):

1. **IP blacklist** — uses `X-Forwarded-For` first IP if present, otherwise `r.RemoteAddr`. Match → `403`.
2. **DNS blacklist** — exact (case-insensitive) match against `r.Host`. Match → `403`.
3. **Rate limit** — when configured. Exceeded → `429 Too Many Requests`.
4. **Country whitelist** — when enabled, request is blocked unless the source country is in the list. On lookup failure: `geoip_fail_open` controls behaviour.
5. **ASN block** — when enabled. Match → `403`.
6. **Country blacklist** — when enabled. Match → `403`.
7. **Phase 1 regex rules**.

### Phase 1 / 2 / 3 / 4 regex rule evaluation

Within each phase the runtime iterates over the rules already sorted by descending `priority` (see [rules.md](rules.md)). For each rule:

1. The rule's `targets` are extracted in turn (URI, headers, body, JSON path, …).
2. Each extracted value is matched against the compiled regex.
3. On match:
   - The rule's per-ID hit counter (`atomic.Int64`) is incremented.
   - The per-phase hit counter is incremented.
   - The rule's `score` is added to `state.TotalScore`.
   - The request is **blocked** if either of the following is true:
     - `state.TotalScore >= anomaly_threshold`
     - the rule's `mode` field equals `"block"`
   - When blocked, `403 Forbidden` is written (or the configured custom response for that status code), and rule processing stops for that phase.
   - When the rule's `mode` is `"log"` and neither condition above is true, processing continues with the next target/rule.

### Blocking precedence summary

```
IP blacklist          (Phase 1, before rules)
DNS blacklist         (Phase 1, before rules)
Rate limit            (Phase 1, before rules)
Country whitelist     (Phase 1, before rules)   — geoip_fail_open governs lookup errors
ASN block             (Phase 1, before rules)
Country blacklist     (Phase 1, before rules)
Phase 1 rules         (priority-ordered)
Phase 2 rules         (priority-ordered)
Phase 3 rules         (response headers, after upstream)
Phase 4 rules         (response body, after upstream)
```

A `block` action from any rule, or any pre-request check above, short-circuits the rest of the pipeline.

### Custom block responses

If `custom_response` is configured for the resulting status code, the registered Content-Type, headers, and body replace the default `Request blocked by WAF. Reason: <reason>` plain-text response.

---

## Caddyfile directives

The full list is the `directiveHandlers` map in [`config.go`](../config.go). All directives below appear inside a `waf { ... }` block.

| Directive | Arguments | Default | Description |
|---|---|---|---|
| `metrics_endpoint` | `<path>` | unset | URL path for the JSON metrics document (must start with `/`). When unset, no metrics endpoint is exposed. |
| `log_path` | `<file>` | `debug.json` (Caddyfile) / `log.json` (Provision fallback) | File path for the JSON log sink. The middleware always writes to stdout in addition. |
| `log_severity` | `debug` \| `info` \| `warn` \| `error` | `info` | Minimum log level for the WAF logger. |
| `log_json` | _(no args)_ | off | Enable JSON-formatted logs. Sets the `LogJSON` boolean to `true`. |
| `log_buffer` | `<positive int>` | `1000` | Capacity of the asynchronous log channel. When full, logs fall back to synchronous emission. |
| `rule_file` | `<file>` | none | Path to a JSON rule file. Repeat the directive to load multiple files. At least one `rule_file` is required. |
| `ip_blacklist_file` | `<file>` | unset | Path to the IP blacklist (single IPs and CIDR ranges). The file is created empty if it does not exist. |
| `dns_blacklist_file` | `<file>` | unset | Path to the DNS blacklist (one host per line). The file is created empty if it does not exist. |
| `anomaly_threshold` | `<positive int>` | `5` (Caddyfile) / `20` (Provision fallback) | Score at which a request is blocked. Lower values are stricter. |
| `block_countries` | `<mmdb> <ISO> [<ISO> …]` | disabled | Block requests whose source country (per the GeoLite2 Country MMDB) is in the list. |
| `whitelist_countries` | `<mmdb> <ISO> [<ISO> …]` | disabled | Allow only requests whose source country is in the list. |
| `block_asns` | `<mmdb> <ASN> [<ASN> …]` | disabled | Block requests whose source IP belongs to one of the listed ASNs. ASN values are decimal integers without a leading `AS`. |
| `custom_response` | `<status> <content-type> <inline-body…>` _or_ `<status> <content-type> <file-path>` | unset | Custom block response. Repeat with different status codes. |
| `redact_sensitive_data` | _(no args)_ | off | Redact sensitive query parameters and log fields. The redaction key list is in [`logging.go`](../logging.go) (`sensitiveKeys`). |
| `tor` | block (see below) | disabled | Enable Tor exit-node blocking. |
| `rate_limit` | block (see below) | disabled | Enable per-IP rate limiting. |

### `rate_limit` block

Parsed in [`config.go`](../config.go) (`parseRateLimit`).

| Sub-directive | Arguments | Default | Description |
|---|---|---|---|
| `requests` | `<positive int>` | `100` | Maximum requests permitted per `window` per IP (or per `ip+path` when `paths` is set and `match_all_paths=false`). |
| `window` | `<duration>` | `10s` | Sliding-window duration. Accepts Go duration syntax (`10s`, `1m`, `1h`). |
| `cleanup_interval` | `<duration>` | `300s` | How often expired entries are swept from the in-memory map. |
| `paths` | `<regex…>` | empty | One or more Go regex patterns. When non-empty and `match_all_paths=false`, only matching paths are rate-limited; non-matching paths bypass the limiter. |
| `match_all_paths` | `true` \| `false` | `false` | When `true`, rate-limit every request regardless of `paths` (key is the IP only). When `false` and `paths` is empty, the limiter is effectively a no-op. |

Behavioural details (see [ratelimit.md](ratelimit.md) for the full discussion):

- The bucket key is `ip` when `match_all_paths=true`, and `ip+path` when matching by `paths`.
- A request is blocked with `429 Too Many Requests` once the bucket exceeds `requests` within `window`.
- Rate-limit metrics are exposed as `rate_limiter_requests` and `rate_limiter_blocked_requests` in `/waf_metrics`.

### `tor` block

Parsed in [`config.go`](../config.go) (`parseTorBlock`); fetcher in [`tor.go`](../tor.go).

| Sub-directive | Arguments | Default | Description |
|---|---|---|---|
| `enabled` | `true` \| `false` | `false` | Toggle Tor exit-node fetching. |
| `tor_ip_blacklist_file` | `<file>` | `tor_blacklist.txt` | File where fetched exit-node IPs are persisted. The contents are merged into the IP blacklist file used by `ip_blacklist_file` when configured to point at the same file. |
| `update_interval` | `<duration>` | `24h` | Interval between successful fetches from `https://check.torproject.org/torbulkexitlist`. |
| `retry_on_failure` | `true` \| `false` | `false` | When the fetch fails, retry after `retry_interval` instead of waiting for the next `update_interval` tick. |
| `retry_interval` | `<duration>` | `5m` | Delay between retries when `retry_on_failure=true`. |

The HTTP client used for the fetch has a 30 s timeout. A custom URL can be supplied via JSON only — see [the JSON-only fields](#json-only-fields) below.

### `custom_response` directive

Two forms are accepted:

```caddyfile
custom_response 403 application/json error.json     # body loaded from file
custom_response 429 text/plain Too many requests.   # inline body (joined with spaces)
```

- The status code must satisfy `100 <= code <= 599`.
- A second `custom_response` for the same status code is rejected.
- The Content-Type is the second token; everything that follows is either the file path or the inline body.

### Defaults set by the parser

When the `waf` block is parsed, [`UnmarshalCaddyfile`](../config.go) sets the following defaults before processing directives:

| Field | Default |
|---|---|
| `LogSeverity` | `info` |
| `LogJSON` | `false` |
| `AnomalyThreshold` | `5` |
| `CountryBlacklist.Enabled` | `false` |
| `CountryWhitelist.Enabled` | `false` |
| `BlockASNs.Enabled` | `false` |
| `LogFilePath` | `debug.json` |
| `RedactSensitiveData` | `false` |
| `LogBuffer` | `1000` |
| `Tor.Enabled` | `false` |
| `Tor.TORIPBlacklistFile` | `tor_blacklist.txt` |
| `Tor.UpdateInterval` | `24h` |
| `Tor.RetryOnFailure` | `false` |
| `Tor.RetryInterval` | `5m` |

Additional defaults applied during `Provision` (after Caddyfile parsing):

- If `LogSeverity` is empty → `info`.
- If `LogFilePath` is empty → `log.json` (Provision fallback differs from the parser default).
- If `AnomalyThreshold <= 0` → `20`.

---

## JSON-only fields

The following fields exist on the `Middleware` struct (in [`types.go`](../types.go)) and are honoured by the runtime, but are **not** wired up to the Caddyfile parser. To set them, configure Caddy via JSON instead of a Caddyfile.

| Field | JSON key | Type | Default | Description |
|---|---|---|---|---|
| `MaxRequestBodySize` | `max_request_body_size` | int64 (bytes) | `10 * 1024 * 1024` (10 MiB) | Upper bound for body reads via `io.LimitReader`. Validated as non-negative. |
| `GeoIPFailOpen` | `geoip_fail_open` | bool | `false` | When `true`, a GeoIP/ASN lookup error allows the request through; otherwise the request is blocked with `403`. |
| `CustomResponses` | `custom_responses` | map[int]CustomBlockResponse | unset | Same as the `custom_response` directive but as a JSON map of status codes. |
| `Tor.CustomTORExitNodeURL` | `tor.custom_tor_exit_node_url` | string | `https://check.torproject.org/torbulkexitlist` | Override URL for the exit-node feed. |

Additionally:

- `geoIPCacheTTL` and `geoIPLookupFallbackBehavior` are configured on the `GeoIPHandler` programmatically (see [`caddywaf.go`](../caddywaf.go), `Provision`); they do not currently have Caddyfile or JSON tags.

A JSON config snippet equivalent to the minimal Caddyfile:

```json
{
  "handler": "waf",
  "rule_files": ["rules.json"],
  "ip_blacklist_file": "ip_blacklist.txt",
  "dns_blacklist_file": "dns_blacklist.txt",
  "metrics_endpoint": "/waf_metrics",
  "anomaly_threshold": 20,
  "max_request_body_size": 20971520,
  "geoip_fail_open": true
}
```

---

## Validation

`Middleware.Validate` (called by Caddy after `Provision`) enforces:

- `anomaly_threshold` ≥ 0
- `max_request_body_size` ≥ 0
- `log_buffer` ≥ 0
- When `rate_limit.requests > 0`: `window > 0` and `cleanup_interval > 0`

Any of these failing aborts startup with a descriptive error.

---

## Reload semantics

The middleware installs `fsnotify` watchers on `rule_files` and the IP / DNS blacklist files. On a `WRITE` event:

- If the modified path contains the substring `rule`, [`ReloadRules`](../caddywaf.go) re-parses every configured rule file atomically and replaces the in-memory rule map.
- Otherwise, [`ReloadConfig`](../caddywaf.go) reloads the IP blacklist, DNS blacklist, **and** the rule files.

A reload does **not** rebuild the rate limiter, the GeoIP database handles, the Tor schedule, or any other Caddyfile-only setting. To apply such changes, run `caddy reload` so Caddy re-runs `Provision`.

See [dynamicupdates.md](dynamicupdates.md) for the full reload matrix.

---

## Worked example

The repository ships a complete Caddyfile in [`Caddyfile`](../Caddyfile). A condensed excerpt:

```caddyfile
:8080 {
    route {
        waf {
            metrics_endpoint  /waf_metrics
            anomaly_threshold 20

            rule_file rules.json

            ip_blacklist_file  ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt

            block_countries     GeoLite2-Country.mmdb RU CN KP
            whitelist_countries GeoLite2-Country.mmdb US

            custom_response 403 application/json error.json

            rate_limit {
                requests         100
                window           10s
                cleanup_interval 5m
                paths            /api/v1/.*
                match_all_paths  false
            }

            tor {
                enabled               true
                tor_ip_blacklist_file tor_blacklist.txt
                update_interval       24h
                retry_on_failure      true
                retry_interval        1h
            }

            log_severity info
            log_json
            log_path     debug.json
        }

        respond "Hello world!" 200
    }
}
```

> When both `block_countries` and `whitelist_countries` are configured with the same MMDB and the **same** ISO code, the whitelist wins because it is evaluated first in Phase 1.
