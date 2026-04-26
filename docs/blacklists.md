# Blacklists

The middleware loads two blacklists at startup and on demand: an IP blacklist and a DNS blacklist. Both are plain-text files. Their loaders live in [`blacklist.go`](../blacklist.go) (`LoadIPBlacklistFromFile`, `LoadDNSBlacklistFromFile`).

## Common file syntax

- One entry per line.
- Leading and trailing whitespace is trimmed.
- Empty lines are skipped.
- Lines starting with `#` are treated as comments and skipped.
- Files are read with UTF-8 expectations (no BOM handling).

## IP blacklist (`ip_blacklist_file`)

- **Configuration directive**: `ip_blacklist_file <path>`
- **Storage**: a [`go-iptrie`](https://github.com/phemmer/go-iptrie) prefix trie. Single addresses are stored as `/32` (IPv4) or `/128` (IPv6) prefixes; CIDR ranges are stored as-is.
- **Lookup path**: at request time the source IP is parsed with `netip.ParseAddr` and a `Contains` check against the trie is performed. If the file is missing, the lookup is a no-op (no requests are blocked by the IP layer).
- **Source IP selection**: when the `X-Forwarded-For` header is present, the **first** comma-separated value is used; otherwise `r.RemoteAddr` (host portion) is used.
- **Validation**: each entry is parsed first as a CIDR range (`net.ParseCIDR`) and, on failure, as a single IP (`net.ParseIP`). Invalid lines are logged at WARN level and counted as `invalid_entries`; valid lines are counted as `valid_entries`.

### Accepted entry forms

| Form | Example |
|---|---|
| IPv4 single address | `192.0.2.10` |
| IPv4 CIDR | `192.0.2.0/24` |
| IPv6 single address (full or shortened) | `2001:db8::1`, `2001:0db8:85a3:0000:0000:8a2e:0370:7334` |
| IPv6 CIDR | `2001:db8::/32` |
| Comment | `# scanner subnet` |

### Sample file

```text
# Block specific scanners
192.0.2.10
198.51.100.42

# Block ranges
203.0.113.0/24
2001:db8::/32

# Block private ranges (only meaningful behind a trusted proxy)
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

### Hot reload

When the IP blacklist file is rewritten, the file watcher (`fsnotify`) triggers `ReloadConfig`, which builds a new trie and atomically swaps it in. In-flight requests continue to see the previous trie; subsequent requests see the new one.

The Tor exit-node fetcher writes its own file (`tor_ip_blacklist_file`); to have those addresses become effective in the IP blacklist they must be appended to the file referenced by `ip_blacklist_file` (or that file must be the Tor file).

## DNS blacklist (`dns_blacklist_file`)

- **Configuration directive**: `dns_blacklist_file <path>`
- **Storage**: a `map[string]struct{}` for O(1) lookup.
- **Normalisation**: every entry is `strings.ToLower(strings.TrimSpace(line))` at load time. The runtime check normalises `r.Host` the same way.
- **Match semantics**: **exact** match. Subdomains are not implicitly blocked. To block `evil.example.com` and all of its subdomains, list each one individually.
- **Internationalised domains**: store as Punycode (e.g. `xn--80ak6aa92e.com`).
- **Lookup path**: the `Host` header on the request is normalised and looked up; on hit, the request is blocked with `403` and `dns_blacklist_hits` is incremented.

### Sample file

```text
# Phishing
phish.example
malware.example.org

# Punycode form for IDN
xn--80ak6aa92e.com

# Comments are skipped
```

### Hot reload

Identical to the IP blacklist: a file write triggers `ReloadConfig`, which rebuilds the map and swaps it in atomically.

## Counters

| Metric | Source |
|---|---|
| `ip_blacklist_hits` | Incremented every time the IP trie returns a match (see `isIPBlacklisted` in [`blacklist.go`](../blacklist.go)). |
| `dns_blacklist_hits` | Incremented every time the DNS map returns a match (see `isDNSBlacklisted`). |

Both are reported by the `/waf_metrics` endpoint — see [metrics.md](metrics.md).

## Rule of precedence

In Phase 1 the order is fixed: the IP blacklist is checked first, then the DNS blacklist, then the rate limiter, then GeoIP / ASN. A blacklist match short-circuits the rest of the request — the regex rule engine is not invoked.
