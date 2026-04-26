# Dynamic Updates

The WAF reloads selected configuration files in place, without restarting Caddy. This document describes exactly which paths trigger a reload, what each reload covers, and what it does not cover.

Implementation: `startFileWatcher`, `ReloadRules`, `ReloadConfig` in [`caddywaf.go`](../caddywaf.go).

## Watched files

At provision time, file watchers are registered for:

- Every path listed in `rule_file` directives.
- The `ip_blacklist_file` path (if configured).
- The `dns_blacklist_file` path (if configured).

For each path, a separate `fsnotify` watcher goroutine is started. Files that do not exist at startup are skipped with a WARN log; they are not retried.

## Trigger

Each watcher reacts only to `fsnotify.Write` events. Editors that create a backup and rename — for example `vim` with `backupcopy=no` — may not produce a `WRITE` on the original path; if you encounter this, configure your editor to write in place, or change the file via `cp newfile target`.

## Reload routing

`startFileWatcher` decides what to reload based on a substring check on the filename:

| Filename contains `rule` | Action invoked | Effect |
|---|---|---|
| Yes | `ReloadRules` | Re-parses every file listed in `RuleFiles`, re-validates each rule, re-uses cached compiled regex by ID, atomically replaces the in-memory rule map. |
| No | `ReloadConfig` | Re-loads the IP blacklist into a new prefix trie, re-loads the DNS blacklist into a new map, and re-runs `loadRules`. |

Both functions take the middleware mutex (`m.mu.Lock`) for the duration of the reload. Lookups during the reload are unaffected because the in-memory data structures are swapped only after a successful load.

## What a reload covers

| Setting | Reloads on file change? |
|---|---|
| `rule_file` contents | Yes (atomic). |
| `ip_blacklist_file` contents | Yes (atomic). |
| `dns_blacklist_file` contents | Yes (atomic). |
| `anomaly_threshold` | No. |
| `metrics_endpoint` | No. |
| `log_severity` / `log_path` / `log_json` / `log_buffer` | No. |
| `rate_limit { ... }` | No. The limiter is built once during `Provision`. |
| `block_countries` / `whitelist_countries` / `block_asns` (paths and ISO codes) | No. |
| `tor { ... }` settings | No. The fetcher schedule is set once during `Provision`. |
| `custom_response` definitions | No. |
| `redact_sensitive_data` | No. |
| `max_request_body_size` (JSON-only) | No. |
| `geoip_fail_open` (JSON-only) | No. |

For any "No" above, run `caddy reload` so Caddy re-parses the configuration and re-runs `Provision` on the WAF module.

## Tor exit-node updates

The Tor fetcher runs on its own schedule (`tor.update_interval`, default `24h`). On each tick it fetches the current exit-node list and writes it to `tor.tor_ip_blacklist_file`. To make those addresses effective in the IP blacklist, configure `ip_blacklist_file` to point at the same path (or merge the Tor file into your IP blacklist out-of-band). See [configuration.md](configuration.md) for details on the `tor` block.

## Reload via the Caddy admin API

Configuration changes that fall outside the file-watcher scope are applied through the Caddy admin API:

```bash
caddy reload --config Caddyfile
# or
curl -X POST http://localhost:2019/load \
     -H 'Content-Type: application/json' \
     -d @caddy.json
```

A `caddy reload` re-runs `Provision` on every module, including the WAF. The previous module instance is shut down (closing GeoIP databases, stopping the rate-limiter cleanup goroutine, and draining the log channel) before the new one is provisioned.

## Failure handling

- **Invalid JSON in a rule file**: the file is skipped with an ERROR log; rules from other files continue to load. If no valid rules remain across all files (and at least one path was provided), the reload returns an error.
- **Invalid individual rule**: dropped with a WARN log; the rest of the file continues.
- **Duplicate rule ID**: dropped with a WARN log; the first occurrence wins.
- **Invalid regex**: rule dropped with a WARN log.
- **Invalid IP/CIDR line in the IP blacklist**: line skipped, counted in `invalid_entries`.

The previous in-memory state is retained on failure: the WAF continues to enforce the last successfully-loaded configuration.

## Practical workflow

```bash
# Add a rule
$EDITOR rules.json

# Save the file (an in-place write triggers fsnotify on the watched path).
# The WAF logs:
#   "Detected configuration change. Reloading..."  {"file":"rules.json"}
#   "WAF rules loaded successfully" {"total_rules":34, ...}

# Add an IP to the blacklist
echo "203.0.113.99" >> ip_blacklist.txt

# Confirm the reload happened
tail -f debug.json
```

## Tips

- Write to a temp file and `mv` it over the target to make the update atomic from the file system's perspective.
- Keep large rule sets in modular files under `rules/` — a reload re-parses every file, so smaller files mean faster reloads.
- Watch the `total_rules` and `rule_counts` log fields after each reload to confirm the expected count was loaded.
