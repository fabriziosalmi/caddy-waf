# Country and ASN Blocking

The middleware can block or whitelist requests by country (using a MaxMind GeoLite2 Country MMDB) and block requests by Autonomous System Number (using a MaxMind GeoLite2 ASN MMDB). Implementation: [`geoip.go`](../geoip.go).

## Caddyfile directives

```caddyfile
waf {
    # Block requests from these ISO country codes
    block_countries     /path/to/GeoLite2-Country.mmdb  RU CN KP

    # Allow only requests from these ISO country codes
    whitelist_countries /path/to/GeoLite2-Country.mmdb  US

    # Block requests originating from these ASNs
    block_asns          /path/to/GeoLite2-ASN.mmdb      12345 67890
}
```

| Directive | First argument | Trailing arguments | Effect |
|---|---|---|---|
| `block_countries` | Path to a GeoLite2 Country MMDB | One or more ISO country codes (uppercased internally) | Block when the source country is in the list. |
| `whitelist_countries` | Path to a GeoLite2 Country MMDB | One or more ISO country codes | Allow only when the source country is in the list. |
| `block_asns` | Path to a GeoLite2 ASN MMDB | One or more decimal ASN numbers (no leading `AS`) | Block when the source IP belongs to one of the listed ASNs. |

If the configured MMDB file does not exist, the corresponding feature is **disabled with a WARN log** at startup; it does not prevent the WAF from starting.

## Source IP selection

GeoIP lookups use `getClientIP` ([`helpers.go`](../helpers.go)):

1. If `X-Forwarded-For` is present, the first comma-separated value is used **provided it parses as a valid IP**.
2. Otherwise `r.RemoteAddr` is used.

The host portion is then extracted (port stripped) and passed to the MMDB reader.

## Evaluation order in Phase 1

```
IP blacklist           ──┐
DNS blacklist            │
Rate limit               │  same Phase 1, in this order
Country whitelist        │
ASN block                │
Country blacklist      ──┘
```

A consequence: when both `block_countries` and `whitelist_countries` are configured **and the same ISO code appears on both**, the whitelist check (which runs first and **allows** the request) wins.

## Lookup-error handling (`geoip_fail_open`)

`Middleware.GeoIPFailOpen` (JSON-only field, see [configuration.md](configuration.md#json-only-fields)):

| `geoip_fail_open` | Behaviour on `geoIP.Lookup` error |
|---|---|
| `false` (default) | Block the request with `403`, log `Failed to check country …` at ERROR level. |
| `true` | Log a WARN message and allow the request to proceed. |

This applies to both the country whitelist/blacklist check and the ASN check. It is the circuit-breaker primitive that prevents a corrupted or unreachable MMDB from taking the entire site offline.

## Caching

`GeoIPHandler` exposes:

- `WithGeoIPCache(ttl)` — enables a per-IP cache of decoded MMDB records, with optional TTL-based eviction.
- `WithGeoIPLookupFallbackBehavior(behavior)` — controls what to do on lookup error inside `IsCountryInList` (independent of `geoip_fail_open`):

| `behavior` | Effect on lookup failure inside `IsCountryInList` |
|---|---|
| `""` (default) | Return the underlying error to the caller. |
| `"none"` | Return the underlying error to the caller. |
| `"default"` | Treat the IP as **not** in the list and return `(false, nil)`. |
| any ISO country code (e.g. `"US"`) | Pretend the lookup returned that country. If the country is in the configured list, the request is treated as a match. |

Both cache TTL and fallback behaviour are currently set programmatically only — no Caddyfile / JSON tag exposes them at the time of writing. They are wired in `Provision` (see [`caddywaf.go`](../caddywaf.go)).

## Counters

| Metric | Source |
|---|---|
| `geoip_blocked` | Incremented every time the country whitelist or country blacklist blocks a request (`incrementGeoIPRequestsMetric(true)`). |

ASN blocks reuse the same counter via the same helper.

## Examples

### Hard block for sanctioned regions

```caddyfile
waf {
    rule_file rules.json
    block_countries GeoLite2-Country.mmdb RU CN KP IR
}
```

### Whitelist single country (e.g. internal-only application)

```caddyfile
waf {
    rule_file rules.json
    whitelist_countries GeoLite2-Country.mmdb DE
}
```

### Block known abusive ASNs

```caddyfile
waf {
    rule_file rules.json
    block_asns GeoLite2-ASN.mmdb 14618 16509 13335
}
```

### Combined

```caddyfile
waf {
    rule_file rules.json

    # Allow EU traffic only…
    whitelist_countries GeoLite2-Country.mmdb DE FR IT ES NL

    # …but explicitly block these ASNs even from allowed countries
    block_asns GeoLite2-ASN.mmdb 13335 14061
}
```

## Obtaining the MMDB files

MaxMind requires a (free) account to download GeoLite2 databases. After registration:

```bash
# Country
curl -L \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_KEY&suffix=tar.gz" \
  -o GeoLite2-Country.tar.gz
tar -xzf GeoLite2-Country.tar.gz --strip-components=1 --wildcards '*.mmdb'

# ASN
curl -L \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz" \
  -o GeoLite2-ASN.tar.gz
tar -xzf GeoLite2-ASN.tar.gz --strip-components=1 --wildcards '*.mmdb'
```

The legacy `https://git.io/GeoLite2-Country.mmdb` redirect referenced by [`install.sh`](../install.sh) and the Dockerfile pulls a community-mirrored copy and may be out of date.
