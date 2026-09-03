# Client IP & trusted proxies

How the WAF decides *who* a request is from — and why that decision needs a trust boundary. Implementation: [`clientip.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/clientip.go).

## The problem

Every IP-based control needs the real client address. When the WAF is the edge, that is simply the connection's peer (`r.RemoteAddr`). Behind a reverse proxy or CDN it is not: the peer is the proxy, and the client is carried in a forwarding header such as `X-Forwarded-For`.

That header is set by whoever is upstream — including, if the WAF is reachable directly, the client itself. Trusting it blindly lets anyone send `X-Forwarded-For: 1.2.3.4` and impersonate any address, slipping past the GeoIP, ASN and `REMOTE_IP` checks. So a forwarding header is only trustworthy when it comes from a peer you actually trust.

## The model

By default `trusted_proxies` is empty: the WAF uses the **peer address** and **ignores every forwarding header**. A client reaching it directly cannot change its apparent IP.

Configure `trusted_proxies` with the addresses of your proxy or CDN edges. Then, and only when the immediate peer is one of them, the WAF resolves the real client:

1. If `client_ip_header` is set (e.g. `CF-Connecting-IP`), its value is used.
2. Otherwise `X-Forwarded-For` is walked **right-to-left**, and the first address that is not itself a trusted proxy is the client — so a chain `client, edge-lb, cdn` resolves to `client`.

If the peer is **not** trusted, forwarding headers are ignored entirely — header or no header.

## Directives

| Directive | Value | Default | Meaning |
|---|---|---|---|
| `trusted_proxies` | `<entry> [<entry> …]` | unset | Peers allowed to speak for their clients: bare IPs, CIDR ranges, or the token `private_ranges`. Repeatable. Empty = ignore forwarding headers, use the peer. |
| `client_ip_header` | `<name>` | unset | A single-IP header (`CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, …) read for the client IP once the peer is trusted, instead of `X-Forwarded-For`. |

## What uses the resolved client IP

| Subsystem | Address used |
|---|---|
| Rate limiter | Resolved client IP — so a CDN's edges don't collapse into one bucket |
| GeoIP country filter | Resolved client IP |
| ASN blocking | Resolved client IP |
| `REMOTE_IP` rule target | Resolved client IP (a bare IP, no port) |
| IP blacklist | Peer **plus every** `X-Forwarded-For` hop (unchanged) |
| IP whitelist | Peer **only**, never a forwarding header |

The last two are deliberate asymmetries. The **blacklist** checks every hop because for *blocking*, consulting more addresses can only ever block more, never less. The **whitelist** uses only the peer because for *allowing*, honouring a client-supplied header would let anyone exempt themselves — see [IP whitelist](/configuration#ip-whitelist).

## Cloudflare

Cloudflare terminates the connection, so the peer is always a Cloudflare edge IP and the real client is in `CF-Connecting-IP`:

```caddyfile
waf {
    rule_file rules.json
    trusted_proxies 173.245.48.0/20 103.21.244.0/22 108.162.192.0/18   # Cloudflare's published ranges
    client_ip_header CF-Connecting-IP
}
```

Keep the list in sync with Cloudflare's published ranges (<https://www.cloudflare.com/ips/>). Because [`whitelist_file`](/configuration#ip-whitelist) demonstrates the pattern, a scheduled job can even refresh a ranges file on disk and have it hot-reloaded.

## Generic reverse proxy

Behind an nginx / HAProxy / your-own edge that appends to `X-Forwarded-For`, trust that edge's address — no `client_ip_header` needed, the client is taken from the header:

```caddyfile
waf {
    rule_file rules.json
    trusted_proxies 10.0.0.0/8            # your internal proxy network
}
```

> [!IMPORTANT]
> ## Migration
>
> Earlier versions trusted `X-Forwarded-For` **unconditionally** for the GeoIP and ASN checks. That was spoofable whenever the WAF was reachable directly. The default is now secure: forwarding headers are ignored unless the peer is a configured trusted proxy.
>
> **If you run behind a CDN or reverse proxy and rely on filtering by the real client's country or ASN — or on per-client rate limiting, or `REMOTE_IP` rules — set `trusted_proxies`** (and, for header-based CDNs, `client_ip_header`). Without it those controls now judge the proxy's address instead of the client's.

> [!WARNING]
> `trusted_proxies` is a trust boundary: anything you list can set a request's apparent client IP. List only addresses you control or trust — your own edges, your CDN's published ranges. Never `0.0.0.0/0`, and never a range wider than your actual proxy fleet.
