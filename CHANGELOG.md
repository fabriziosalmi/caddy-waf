# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.4.7] - 2026-09-03

### Added
- **Built-in dashboard (opt-in).** A read-only web dashboard rendering the metrics payload — requests allowed/blocked with client-derived rates, blocked-by-reason and per-phase breakdowns, top rules, top offending IPs, blocks by country, and a live tail of recent blocked requests. Served by the WAF itself, same-origin with `metrics_endpoint`; a single self-contained page with **no vendored libraries and no third-party runtime requests**. Off unless enabled at two levels: the `with_ui` build tag **and** the `dashboard <path>` directive. Read-only — it cannot mutate WAF state — and carries no auth of its own, so protect it with Caddy (see [docs/dashboard.md](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/dashboard.md)). ([#168](https://github.com/fabriziosalmi/caddy-waf/pull/168), [#143](https://github.com/fabriziosalmi/caddy-waf/issues/143))

### Changed
- Bumped version constant `wafVersion` to `v0.4.7`.
- Removed the old, unwired `ui/` (a page hardcoding `localhost:8080` plus ~1 MB of vendored chart.js and font-awesome).

## [v0.4.6] - 2026-09-03

### Added
- **Dashboard metrics backend (M1).** `/waf_metrics` gains a `schema_version` (2) and a set of **back-compatible** fields for the planned built-in dashboard ([#143](https://github.com/fabriziosalmi/caddy-waf/issues/143)): `recent` — a bounded ring (256) of the most recent **blocked** decisions (timestamp, log id, client IP, method, path, reason, rule id, status, score, country); `top_ips` — the top offending client IPs by block count (bounded); `by_country` — blocks per ISO country (wiring up the previously unused per-country counter); `blocked_by_reason`; `top_rules`; and `server_time_ms` + `uptime_seconds` so a client can derive rates by diffing snapshots. Recorded once per block under a single mutex; all sections are bounded. Every pre-existing metrics field is unchanged. See [docs/metrics.md](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/metrics.md#dashboard-fields-schema-2).

### Changed
- Bumped version constant `wafVersion` to `v0.4.6`.

## [v0.4.5] - 2026-09-03

### Security
- **`trusted_proxies`: `X-Forwarded-For` is no longer trusted by default.** The GeoIP country/ASN checks previously honoured `X-Forwarded-For` unconditionally, so a client reaching the WAF directly could spoof it to move its apparent IP past those filters. Client-IP resolution now has a trust boundary: forwarding headers are honoured **only when the immediate peer is a configured trusted proxy**, otherwise the peer address is used and the header is ignored. ([#163](https://github.com/fabriziosalmi/caddy-waf/pull/163), closes [#94](https://github.com/fabriziosalmi/caddy-waf/issues/94))

### Added
- **`trusted_proxies`** (bare IPs, CIDR ranges, or `private_ranges`) — the peers allowed to speak for their clients. When the peer is trusted, the real client is taken from **`client_ip_header`** (e.g. `CF-Connecting-IP`) if set, else by walking `X-Forwarded-For` right-to-left to the first non-trusted address (resolving a trusted proxy chain). The resolved client IP now feeds the **rate limiter** (so a CDN's edges no longer share one bucket), the **GeoIP country/ASN** filters and the **`REMOTE_IP`** rule target. The IP blacklist is unchanged (peer + all hops). See [Client IP & trusted proxies](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/client-ip.md).

### Changed
- Bumped version constant `wafVersion` to `v0.4.5`.
- `REMOTE_IP` now yields a bare IP (no port), consistent with the resolved client IP.
- Removed the old `getClientIP` helper that trusted `X-Forwarded-For` unconditionally.

### Migration
This changes a default in the **secure** direction. **If you run behind a CDN or reverse proxy and rely on filtering by the real client's country/ASN — or on per-client rate limiting, or `REMOTE_IP` rules — set `trusted_proxies`** (and, for header-based CDNs like Cloudflare, `client_ip_header`). Without it, those controls now judge the proxy's address instead of the client's. Full guidance and a Cloudflare example: [docs/client-ip.md](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/client-ip.md).

## [v0.4.4] - 2026-09-03

### Fixed
- **SSRF rules no longer block benign query strings.** `ssrf-internal-ip` and `ssrf-reserved-ip` matched bare prefixes (`10\.`, `0\.`, `224\.`, …), so any digit-dot substring tripped them — a legitimate `/socket.io/?EIO=4&transport=polling&…` request whose Engine.IO cache-buster or sid contained something like `0.1` or `10.` accrued SSRF score until it hit a 403 at `anomaly_threshold` 20. The patterns now require full private/reserved dotted-quad IPs with word boundaries, so benign values no longer match while real SSRF still does — internal ranges (RFC1918, loopback), `0.0.0.0`, link-local `169.254.0.0/16` (the cloud metadata IP), and multicast/reserved. `ssrf-attacks`' bare cloud-keyword alternative was likewise narrowed to the actual metadata hostname. Applied across `rules.json`, `rules-browser-friendly.json` and `rules/ssrf.json`. ([#160](https://github.com/fabriziosalmi/caddy-waf/pull/160))

### Changed
- Bumped version constant `wafVersion` to `v0.4.4`.

## [v0.4.3] - 2026-09-02

### Added
- **`whitelist_file` — load whitelisted IPs from a file, hot-reloaded on change.** The counterpart to `ip_blacklist_file`: point it at a text file of IPs/CIDR ranges (one per line, `#` comments allowed) exempt from the IP-reputation checks, so a job that refreshes the list (a cloud provider's published ranges, a partner's egress IPs, country-blocking exceptions) takes effect without a restart. Inline `whitelist_ip` entries and the file feed the same trie; the file need not exist at startup and is picked up when it appears. ([#158](https://github.com/fabriziosalmi/caddy-waf/pull/158), closes [#151](https://github.com/fabriziosalmi/caddy-waf/issues/151))

### Changed
- Bumped version constant `wafVersion` to `v0.4.3`.
- The file watcher now follows the parent directory even when the watched file does not yet exist (so a later-created blocklist/whitelist file is picked up on creation), and selects ReloadRules vs ReloadConfig by rule-file identity rather than a path substring.

## [v0.4.2] - 2026-09-02

### Fixed
- **Every `POST` carrying a body no longer fails with a 502.** The WAF drained the request body during rule inspection and the upstream received an empty body while `Content-Length` kept its value, so `reverse_proxy` reported `ContentLength=N with Body length 0` and broke the connection. Rule extraction runs against per-rule request copies (`handlePhase` clones the request to tag the rule id), so restoring the body there never reached the request handed to the upstream. The body is now buffered once, up front, on the request that flows downstream and read from context during extraction; bodies within the inspection limit are re-readable with `GetBody` set, and larger bodies are forwarded whole (no upload truncation). ([#156](https://github.com/fabriziosalmi/caddy-waf/pull/156))
- **Hot-reload now follows atomic file updates.** The file watcher watched the file inode and reacted only to `Write`, so an atomic update (write temp + `os.Rename` over the target — the standard blocklist/rule refresh) replaced the inode and left the watch permanently deaf. It now watches the parent directory, filters by basename, and reloads on `Create`/`Rename`/`Write`. ([#155](https://github.com/fabriziosalmi/caddy-waf/pull/155))
- **Data race in the IP blacklist check.** `isIPBlacklisted` probed `m.ipBlacklist` outside the read lock, racing `ReloadConfig`'s locked swap (which hot reload performs). The redundant unsynchronised probe was removed; `go test -race ./...` is clean. ([#155](https://github.com/fabriziosalmi/caddy-waf/pull/155))

### Changed
- Bumped version constant `wafVersion` to `v0.4.2`.
- Dependency bumps already on `main`: `stretchr/testify` 1.12.1, `google.golang.org/grpc` 1.83.1, and the Docker builder image to Go 1.27-alpine.

## [v0.4.1] - 2026-08-21

### Fixed
- **A response-target rule in an early phase no longer panics the request.** A rule listing `RESPONSE_HEADERS` (or `RESPONSE_HEADERS:<name>`) in phase 1 or 2 — as several OWASP CRS rules do, e.g. `950010` — reached `w.Header()` on the nil `http.ResponseWriter` that `handlePhase` passes before the response exists. The panic was recovered into an HTTP 500, so **every** request behind the WAF failed. Response-header extraction is now nil-safe (mirroring the existing response-body guard): an out-of-phase response target degrades to a skipped target instead of crashing. Reported on OPNsense with OWASP rules ([#144](https://github.com/fabriziosalmi/caddy-waf/issues/144), [#146](https://github.com/fabriziosalmi/caddy-waf/pull/146)).

### Changed
- Bumped version constant `wafVersion` to `v0.4.1`.

### Internal
- `TestTorConfig_Provision` is now hermetic — it serves the Tor exit-node list from a local `httptest.Server` instead of a live external CDN, removing the last third-party network dependency from CI ([#147](https://github.com/fabriziosalmi/caddy-waf/pull/147)).

## [v0.4.0] - 2026-08-18

### Security
**Rule matching now inspects requests the way the application will decode them, closing encoding evasion.** Confirmed empirically before the fix: a percent-encoded attack in a raw request target slipped past literal rule patterns. `rules/sql-injection.json` blocked `id=1 UNION SELECT` but **not** `id=1 %55NION%20SELECT`, nor `%75nion`, nor the same payload in an `application/x-www-form-urlencoded` body. Because the application decodes the request before acting on it, the WAF must match the decoded form. This affected the raw targets `ARGS`, `URI`, `URL` and `BODY` — the targets used by the bulk of the bundled and modular rules (SQLi, XSS, RCE, SSTI, SSRF).

The fix is **additive dual-match**: each target is matched against the raw value first, then against a normalized copy, and the rule fires if either matches. Testing the raw value first is a mathematical guarantee that no rule which matches today can stop matching — the change only adds coverage, never removes it. Unencoded traffic runs no extra regex (the normalized pass is skipped when normalization does not change the value).

Design followed ModSecurity/OWASP-CRS/Coraza prior art, including its guardrails:

- **Single-pass decoding**, never recursive. `%2555` decodes to the literal `%55`, matching what a single-decoding backend sees; decoding twice would manufacture false positives and diverge from reality.
- **Context-aware `+`**: a space in query/body context, literal in the path portion of `URI`/`URL`, which are split on the first `?`.
- **Lenient decoder**: a malformed escape (`%`, `%zz`, a truncated `%a`) is left literal, never dropped — Go's `url.QueryUnescape` blanks the whole value on one bad byte, which would itself be a bypass.

### Added
- **Optional per-rule `transformations` field** (ModSecurity/CRS-style pipeline): `["urlDecodeUni","removeNulls","replaceComments","htmlEntityDecode",…]`. Absent means the per-target default chain (`urlDecode`, `removeNulls`, `compressWhitespace`); an explicit `[]` means match the raw value only. Names are case-insensitive, accept a `t:` prefix, and an unknown name **fails at load time** rather than silently doing nothing.
- **ModSecurity/CRS target aliases** so SecLang-derived rule files resolve: `REQUEST_HEADERS`→`HEADERS`, `REQUEST_COOKIES`→`COOKIES`, `QUERY_STRING`→`ARGS`, `REQUEST_URI`→`URI`, `REQUEST_BODY`→`BODY`, `REQUEST_FILENAME`→`PATH`. Previously these fell through to "unknown extraction target" and were skipped, so 135 bundled rules (88 using `REQUEST_COOKIES`, 47 `REQUEST_HEADERS`) silently lost cookie/header coverage and one rule was fully inert.
- `transform.go` with the transformation registry and lenient single-pass decoders; `normalization_test.go` and `transform_test.go` covering the closed evasions, the zero-regression property, per-rule transformations, the aliases, load-time validation, and — as an explicit test — the documented limit that double-encoding is not decoded twice.

### Honest limits
Single-pass decoding does not catch double-encoding (correct against a single-decoding backend), and `%uXXXX` / overlong-UTF-8 are not decoded by the default pipeline. Cookie and header targets are not normalized by default; a rule that needs it can set `transformations`. See [Input normalization](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/rules.md#input-normalization).

### Migration
This changes what every rule targeting `ARGS`/`URI`/`URL`/`BODY` sees. Because matching is additive (raw tested first), **no existing rule stops firing** and no config change is required. Rule authors who want the raw, un-normalized value only can set `"transformations": []` on a rule. Custom rule files using ModSecurity target names now gain coverage they were silently missing.

### Changed
- Bumped version constant `wafVersion` to `v0.4.0`.

## [v0.3.11] - 2026-08-18

### Added
- **`whitelist_ip` — exempt addresses from the IP-reputation checks without switching the WAF off for them.** Accepts bare IPs, CIDR ranges, or the token `private_ranges`, and is repeatable:

  ```caddyfile
  whitelist_ip private_ranges
  whitelist_ip 203.0.113.4 198.51.100.0/24
  ```

  Requested in [#137](https://github.com/fabriziosalmi/caddy-waf/issues/137) by [@nozonyan](https://github.com/nozonyan): `whitelist_countries` blocks anything it cannot geolocate, which includes every address on the local network, so enabling it locks you out of your own service from inside the LAN. The only workarounds were `geoip_fail_open` — which also admits every unresolvable *public* address — or maintaining two site blocks with separate rule sets, with the risk of leaving the public one unprotected after a test.

  The exemption covers the checks that judge a client by where it comes from: the **IP blacklist** (including Tor exit nodes fed into it), **`whitelist_countries` / `block_countries`**, and **`block_asns`**. It deliberately does **not** cover the DNS blacklist (which judges the requested host, not the client), the rate limiter, or the regex rules in any phase. Exempting an address from geolocation is the fix; stopping inspection of its requests is not.

  `private_ranges` expands to exactly the set Caddy uses for its own placeholder — `192.168.0.0/16`, `172.16.0.0/12`, `10.0.0.0/8`, `127.0.0.1/8`, `fd00::/8`, `::1`. Identical rather than "improved": a WAF and the server in front of it disagreeing about which addresses are private is how bypasses get built. An entry that does not parse fails startup rather than being skipped with a warning.

### Security notes on the design
- **The whitelist matches the peer address only, never `X-Forwarded-For`.** This is the deliberate opposite of the blacklist, which checks the peer address *and* every forwarded hop. When blocking, consulting extra addresses can only block more; when allowing, honouring a client-supplied header would let anyone send `X-Forwarded-For: 10.0.0.1` and exempt themselves from the blacklist, the country filter and the ASN filter in a single header. Covered by `TestWhitelistIgnoresForwardedHeaders`.
- **`private_ranges` is only safe when caddy-waf is the edge.** Because the check is on the peer address, running behind another proxy makes the peer that proxy — typically a private or loopback address — which would exempt every request passing through it. The WAF now logs a warning at startup when `private_ranges` is whitelisted, and `docs/configuration.md` documents the trap.

### Changed
- Bumped version constant `wafVersion` to `v0.3.11`.

## [v0.3.10] - 2026-07-28

### Fixed
- **`docker build .` ignored your source tree.** The Dockerfile ran `git clone https://github.com/fabriziosalmi/caddy-waf.git` and built that, so the build context was never used: the image contained whatever happened to be on `main` at build time, could not be pinned to a version, and a CI image build would have tested the wrong code. The build context is now the source.
- **The builder image was older than `go.mod` requires.** `golang:1.24-alpine` against a module declaring `go 1.25.1`; it only worked because `GOTOOLCHAIN=auto` silently downloaded a newer toolchain mid-build. Now `golang:1.26-alpine`.

### Added
- **Published container images at `ghcr.io/fabriziosalmi/caddy-waf`**, built on release tags for `linux/amd64` and `linux/arm64`. Tagged by version as well as `latest`, so a deployment can pin — `latest` alone would leave anyone who pulled before a security release with no way to name the image they wanted.
- **`.github/workflows/docker.yml`** builds the image on pull requests without pushing, and asserts `caddy list-modules` reports `http.handlers.waf` rather than trusting a green build. Nothing built this image before, which is how it came to clone the repository instead of using the context, and to pin a stale Go version.
- `.dockerignore` extended so the context excludes `node_modules`, `docs/`, tests and helper scripts. `ui/` is deliberately kept: `assets.go` embeds it behind the `with_ui` build tag.

### Changed
- Bumped version constant `wafVersion` to `v0.3.10`.

## [v0.3.9] - 2026-07-28

### Security
Two further defects in the same subsystem, one of them the sibling of a bug fixed in v0.3.7. Both were surfaced by an adversarial sweep that drives real requests through `ServeHTTP` and asks whether the client is actually refused, rather than whether a helper returns `true`.

- **`ReloadRules` had the identical self-deadlock fixed in `ReloadConfig`.** It took `m.mu` and then called `loadRules`, which takes `m.mu` again; the goroutine blocked forever while owning the write lock, so every later request stalled on the `RLock` in the request path. This is the *primary* hot-reload branch: `startFileWatcher` routes any changed path containing `"rule"` to `ReloadRules`, which means editing `rules.json` — the case `docs/dynamicupdates.md` documents — wedged the server. v0.3.7 fixed one branch of the watcher and missed the other. Found by the automated review on [#130](https://github.com/fabriziosalmi/caddy-waf/pull/130).

- **The DNS blacklist was bypassable, and inert on non-default ports.** `isDNSBlacklisted` only lowercased and trimmed the `Host` header, so `evil.example:8080` and `evil.example.` both missed an entry for `evil.example`. `r.Host` carries the port whenever the site is served on anything other than 80/443 — which every example in this repository does — so those deployments had no DNS filtering at all; and a client may send an explicit `:443` even on the default port, making it a one-header bypass. Hosts are now normalised (lowercase, port stripped, trailing dot removed, IPv6 brackets removed).

### Fixed
- **Data race on the IP blacklist during hot reload.** `ReloadConfig` swapped `m.ipBlacklist` under `m.mu`, but `isIPBlacklisted` read it without taking the lock, so the swap never synchronised with in-flight requests. The read is now under `RLock`, mirroring `isDNSBlacklisted`. Found by the automated review on [#130](https://github.com/fabriziosalmi/caddy-waf/pull/130).
- Documentation described the pre-v0.3.8 `X-Forwarded-For` behaviour ("first XFF value if present, otherwise `r.RemoteAddr`"), which stopped being true when that bypass was closed.

### Added
- `TestReloadRulesDoesNotDeadlock` — the branch v0.3.7 missed, asserted on a deadline and followed by a reader that must get through.
- The full suite now passes under `-race`.

### Changed
- Documented Go requirement corrected to **1.25.1**. `go.mod` declares it because `caddy/v2 v2.11.4` and `go.step.sm/crypto` require it and Go propagates the maximum; forcing `1.25.0` breaks the build.
- Bumped version constant `wafVersion` to `v0.3.9`.

## [v0.3.8] - 2026-07-28

### Security
**A single request header bypassed the IP blacklist entirely.** Phase 1 consulted `X-Forwarded-For` *instead of* `r.RemoteAddr` whenever the header was present:

```go
if xForwardedFor != "" {
    if m.isIPBlacklisted(firstIP) { block }
    // no else -- r.RemoteAddr was never checked
} else {
    if m.isIPBlacklisted(r.RemoteAddr) { block }
}
```

Any blacklisted client could send `X-Forwarded-For: 8.8.8.8` and skip the check. No tooling, no preconditions, no authentication — one arbitrary header. Demonstrated end to end: the same client is refused with `403` without the header and served `200` with it.

The peer address is now checked **first and unconditionally**, since it is the only value a client cannot forge, and the forwarded chain is checked **in addition** rather than instead. Checking more addresses can only block more, never less. A client can therefore blacklist itself by forging a listed address, which is harmless. Deciding which forwarded values to *trust* requires a `trusted_proxies` option and is tracked in [#94](https://github.com/fabriziosalmi/caddy-waf/issues/94).

This was masked until v0.3.7: before that the blacklist was never populated at all (see v0.3.7), so nothing was bypassable because nothing was enforced. Fixing enforcement made this the live bypass, which is why it ships one release later.

Covered by `GHSA-w6gv-76q4-prqg`, updated to reflect **v0.3.8** as the patched version.

### Added
- `TestBlacklistedIPIsBlockedEndToEnd/a_forged_X-Forwarded-For_cannot_skip_the_check` — a blacklisted peer sending a clean `X-Forwarded-For` must still be refused.

### Changed
- Bumped version constant `wafVersion` to `v0.3.8`.

## [v0.3.7] - 2026-07-28

### Security
Two defects in the blacklist subsystem, both silent. Reported in substance by [@doogienz](https://github.com/doogienz) in discussion [#96](https://github.com/fabriziosalmi/caddy-waf/discussions/96) on 2026-05-21, with the log evidence that pinned it down.

- **The IP blacklist never blocked anything.** `loadIPBlacklist` took the trie by value, and both callers — `Provision` and `ReloadConfig` — dereferenced their pointer to satisfy that signature. Every `Insert` therefore landed in a copy discarded on return: the trie the middleware consults stayed empty, while the loader still logged `IP blacklist loaded {"valid_entries": N}`. Any deployment relying on `ip_blacklist_file`, including the 223,770-entry list bundled with the project, had no IP filtering at all and no indication of it. Present since **v0.0.7** (commit `c905277`, "switch to go-trie", 2025-10-10) — 15 releases.

- **Hot-reloading a blacklist deadlocked the server.** `ReloadConfig` held `m.mu` and then called `loadRules`, which takes `m.mu` again; on Go's non-reentrant `RWMutex` the goroutine blocked forever *while still owning the write lock*. Since `isDNSBlacklisted` takes `m.mu.RLock()` on every request, all subsequent requests blocked forever — no crash, no log line. The file watcher calls `ReloadConfig` whenever `ip_blacklist_file` or `dns_blacklist_file` changes, and the documented Tor setup (`docs/dynamicupdates.md`) points `ip_blacklist_file` at the file the Tor fetcher rewrites every `update_interval` (default 24h), so the configuration the docs recommend wedges the server within a day of starting, unattended.

Both are fixed: the trie is passed by pointer, and `ReloadConfig` builds the new structures outside the lock, swaps them under it, and never holds `m.mu` across a call that takes it again.

### Added
- `blacklist_enforcement_test.go` — four regression tests: the trie is actually populated (IPv4, IPv6, CIDR, with and without a port), the reload path repopulates it, `ReloadConfig` completes and releases the lock under a deadline, and a full `ServeHTTP` pass confirms a blacklisted client is refused, never reaches the upstream, and that `X-Forwarded-For` is honoured.

### Changed
- Bumped version constant `wafVersion` to `v0.3.7`.

## [v0.3.6] - 2026-07-28

### Security
Cleared the Dependabot backlog on the default branch: **25 of 30 open alerts — 7 critical, 5 high, 13 moderate**. Every bump was verified by building and testing, not by trusting the suggestion.

| Module | From | To | Alerts closed |
|---|---|---|---|
| `golang.org/x/crypto` | v0.49.0 | **v0.52.0** | 7 critical, 2 high, 4 moderate |
| `github.com/caddyserver/caddy/v2` | v2.11.2 | **v2.11.4** | 2 high, 3 moderate |
| `google.golang.org/grpc` | v1.79.3 | **v1.82.1** | 1 high |
| `golang.org/x/net` | v0.52.0 | **v0.55.0** | 1 moderate |
| `github.com/quic-go/quic-go` | v0.59.0 | **v0.59.1** | 1 moderate |
| `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp` | v1.43.0 | **v1.44.0** | 1 moderate |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp` | v0.19.0 | **v0.20.0** | 1 moderate |

No source changes were required. `go build`, `go vet` and the full unit suite pass, and `xcaddy build` against the bumped tree produces a working Caddy **v2.11.4** binary that registers `http.handlers.waf`.

### Not fixed, and why

Five alerts remain open. Leaving them undocumented would be worse than leaving them open.

- **`github.com/google/cel-go` (moderate, GHSA-gcjh-h69q-9w9g)** — the suggested v0.29.0 **does not compile against Caddy v2.11.4**: `interpreter.NewCall` changed from `[]interpreter.Interpretable` to `[]interpreter.InterpretableV2`, and `caddyhttp/celmatcher.go` still passes the former. Caddy's own `go.mod` pins v0.28.1. Taking the bump would trade a moderate transitive advisory for a build that does not exist. Blocked until Caddy updates.
- **`vite` ×3 (1 high, 2 moderate) and `esbuild` ×1 (moderate)** — introduced in v0.3.5 by the `package-lock.json` for the VitePress docs site. All four are **development-server** issues (arbitrary origins reading dev-server responses; `server.fs.deny` bypass on Windows; NTLMv2 disclosure via UNC paths on Windows; path traversal in optimized-deps `.map` handling). CI only ever runs `vitepress build`, the published site is static HTML, and `npm audit --omit=dev` reports zero. The fix requires vite ≥ 6.4.3, which no stable VitePress pulls — `latest` is 1.6.4 and pins vite ^5.4.14; only the 2.0.0-alpha line moves to vite 6. Running an alpha documentation generator to silence dev-only advisories is the worse trade.

### Changed
- Documentation references to the pinned Caddy version updated from v2.11.2 to v2.11.4.
- Bumped version constant `wafVersion` to `v0.3.6`.

## [v0.3.5] - 2026-07-28

### Fixed
- **Caddy package registry could not scan this module.** `caddy.RegisterModule(&Middleware{})` parses as an `ast.UnaryExpr` wrapping the literal, and the static analyzer behind <https://caddyserver.com/account/register-package> accepts only a composite literal or `new()`. Every registration attempt therefore failed with the opaque portal error `unable to scan modules in package github.com/fabriziosalmi/caddy-waf`, which never names the offending line — leaving the module absent from <https://caddyserver.com/download> and `caddy add-package github.com/fabriziosalmi/caddy-waf` returning HTTP 400. Both `caddy.RegisterModule` and `ModuleInfo.New` now use `new(Middleware)`.

  The two forms are semantically identical (each allocates a zeroed `Middleware` and yields a pointer), so there is no behavioural change. The pointer is required regardless: `CaddyModule` has a pointer receiver and `Middleware` carries mutexes that must not be copied.

  Diagnosis courtesy of the Caddy community thread [Unable to register module in the portal](https://caddy.community/t/unable-to-register-module-in-the-portal/33572), where the underlying analyzer error is quoted as `unexpected argument to RegisterModule(): &ast.UnaryExpr{...} - expect either composite literal or new()`.

### Added
- `TestRegisterModuleArgumentIsScannable` — parses the package's own AST and asserts the `caddy.RegisterModule` argument stays a composite literal or `new()`, so the registry constraint cannot silently regress on a future edit. Verified to fail against the v0.3.4 pattern and pass against the fix.

### Changed
- Rewrote `CADDY_MODULE_REGISTRATION.md`, which was stale (referenced v0.0.6 and Caddy v2.9.1) and speculated that the failures were server-side and "may resolve automatically". It now records the verified root cause and the maintenance notes.
- Bumped version constant `wafVersion` to `v0.3.5`.

### Registered
With the scan fixed, `github.com/fabriziosalmi/caddy-waf` was claimed in Caddy's package registry on 2026-07-28 at 10:05:52 UTC, at `v0.3.5`. The build service now serves it (`GET /api/download?p=github.com%2Ffabriziosalmi%2Fcaddy-waf` returns a binary instead of HTTP 400), so `caddy add-package github.com/fabriziosalmi/caddy-waf` works and the module is selectable on <https://caddyserver.com/download>. `README.md`, `docs/installation.md` and `docs/add-package-guide.md` updated accordingly — they previously documented the install path as unavailable.

Note the module documentation shown on caddyserver.com is extracted from the doc comment on the `Middleware` struct in `types.go`.

## [v0.3.4] - 2026-07-28

### Security
- **Fixed unbounded response buffering (GHSA-gfj3-cmff-q8wh, CWE-400, CVSS 3.1 7.5 high, remote unauthenticated DoS).** Up to and including v0.3.3, `responseRecorder` accumulated the *entire* upstream response body in an in-memory `bytes.Buffer` before releasing a single byte to the client, with no configurable or hard-coded ceiling. A single unauthenticated request for a large or streaming resource made the Caddy process's heap grow in step with the response size, so an attacker could OOM-kill the process and take down every site served by that instance. Reported by [@EQSTLab](https://github.com/EQSTLab).

  The response body is now buffered only when it can actually be used, and only up to a bound:

  - **No Phase 4 rules ⇒ no buffering.** `ServeHTTP` now asks `hasResponseBodyRules()` before capturing anything; with no `RESPONSE_BODY` rule loaded the recorder is a pass-through that forwards writes as they arrive. The bundled `rules.json` has no Phase 4 rules, so the default configuration buffers nothing at all and no longer defeats HTTP streaming.
  - **Hard ceiling of `max_response_body_size`** (new setting, default 10 MiB). When a response outgrows the budget, the recorder writes out what it holds and streams the remainder straight to the client, so peak memory is bounded by the limit rather than by the response size.
  - **An upstream flush releases the buffer** instead of stalling, so server-sent events and chunked streaming work through a WAF-protected route rather than being held until the budget fills.
  - A released response cannot be blocked, since part of it is already on the wire. Phase 4 is skipped in that case and logged at `warn` (`"Response body exceeded the WAF inspection limit; Phase 4 rules were not applied"`) rather than scoring a truncated body and reporting the response as vetted.

  Measured on a 512 MiB response through a WAF-protected route: heap allocated during `ServeHTTP` drops from **1535 MiB to 0 MiB**, with all 512 MiB still delivered to the client.

### Added
- `max_response_body_size` (Caddyfile directive and JSON field, default `10485760`) — ceiling on how much of the response body is retained for Phase 4 inspection. Validated as non-negative by `Validate`; `0` selects the default.
- `max_request_body_size` is now settable from the Caddyfile as well, not only from JSON.
- `responseRecorder` implements `http.Flusher`.

### Fixed
- A Phase 4 block no longer swallows the configured `custom_response` body. `ServeHTTP` wrote the custom response into the recorder, whose buffer is discarded on the blocked path, so the client received an empty body; it now writes to the real `ResponseWriter`.

### Known limitation
- The status code of a Phase 3/4 block is still not applied: `responseRecorder.WriteHeader` forwards the status to the underlying `ResponseWriter` as soon as the upstream sets it, so by the time the response phases run the status line is already committed and a block surfaces as `200` with the custom body. This is pre-existing behaviour, unrelated to the advisory above, and is tracked separately.

### Changed
- Bumped version constant `wafVersion` to `v0.3.4`.

## [v0.3.2] - 2026-04-26

### Security
Patched 3 critical and 10 high severity Dependabot alerts by upgrading the affected dependencies to their fixed versions:

- `github.com/caddyserver/caddy/v2` v2.10.2 → v2.11.2 — fixes 4 high (FastCGI split_path Unicode case-folding bypass, MatchHost case-sensitivity bypass on >100 hosts, MatchPath %xx case normalization bypass, mTLS silent fail-open on missing CA file) and 2 medium (admin API CSRF on `/load`, file matcher glob sanitization).
- `google.golang.org/grpc` v1.78.0 → v1.79.3 — fixes 1 critical (authorization bypass via missing leading slash in `:path`).
- `github.com/jackc/pgx/v5` v5.8.0 → v5.9.2 — fixes 1 critical (memory-safety) and 1 low (SQL injection via dollar-quoted placeholder confusion).
- `github.com/smallstep/certificates` v0.29.0 → v0.30.2 — fixes 1 critical (unauthenticated certificate issuance via SCEP `UpdateReq` MessageType=18) and 1 low (TPM EKU validation index-out-of-bounds panic).
- `go.opentelemetry.io/otel` v1.39.0 → v1.43.0 — fixes 1 high (multi-value `baggage` header DoS amplification).
- `go.opentelemetry.io/otel/sdk` v1.39.0 → v1.43.0 — fixes 2 high (BSD `kenv` PATH hijacking; arbitrary code execution via PATH hijacking).
- `github.com/go-jose/go-jose/v4` v4.1.3 → v4.1.4 — fixes 1 high (JWE decryption panic).
- `github.com/go-jose/go-jose/v3` v3.0.4 → v3.0.5 — fixes 1 high (JWE decryption panic).
- `github.com/slackhq/nebula` v1.9.7 → v1.10.3 — fixes 1 high (blocklist bypass via ECDSA signature malleability).
- `github.com/cloudflare/circl` upgraded to v1.6.3 — fixes 1 low (incorrect `secp384r1` `CombinedMult` calculation).
- `filippo.io/edwards25519` upgraded to v1.2.0 — fixes 1 low (`MultiScalarMult` invalid results when receiver is not the identity).

No source-code changes required; the WAF compiles and the full unit test suite passes against the upgraded dependency tree.

### Changed
- Bumped version constant `wafVersion` to `v0.3.2`.

## [v0.3.1] - 2026-04-26

### Documentation
- Rewrote `README.md`, `MODULE.md`, `caddyfile.example`, and the entire `docs/` tree to be 1:1 accurate with the current source code.
- `docs/configuration.md` now lists every Caddyfile directive recognised by `config.go`, every JSON-only field on the `Middleware` struct, the precise Phase 1 evaluation order, and the parser- vs. `Provision`-time defaults.
- `docs/rules.md` documents the JSON tag mismatch on `Rule.Action` (struct tag is `mode`, while the bundled rule files commonly use `action`), so authors know which key is actually parsed.
- `docs/ratelimit.md` corrects the `match_all_paths` semantics to match `ratelimiter.go` (`true` ⇒ rate-limit every request; `false` + non-empty `paths` ⇒ rate-limit only matching paths).
- `docs/dynamicupdates.md` adds an explicit reload matrix showing which settings are reloaded by `fsnotify` and which require `caddy reload`.
- `docs/metrics.md` documents the actual response schema returned by `handleMetricsRequest` and clarifies that all counters are process-local and reset on restart.
- `docs/prometheus.md` switches the example exporter from `Counter.inc(absolute)` to `Gauge.set(absolute)` to match the WAF's monotonic process-local counter semantics.
- `caddyfile.example` no longer references non-existent directives (`country_block`, `custom_response { … }` block form).
- Removed emoji from all user-facing documentation.

### Changed
- Bumped version constant `wafVersion` to `v0.3.1`.

## [v0.3.0] - 2026-02-22

### Fixed
- Resolved duplicate response headers when a custom block response was emitted.
- IP blacklist loader now accepts CIDR notation in addition to single IPs (`net.ParseCIDR` is tried before `net.ParseIP`).

## [v0.2.0] - 2026-01-17

### Fixed
- Fixed potential panic in `isIPBlacklisted()` when parsing malformed IP addresses - now uses `netip.ParseAddr()` instead of `netip.MustParseAddr()`.
- Fixed type assertion panic in `processRuleMatch()` - now uses safe `getLogID()` helper function.
- Fixed potential panic in `extractIP()` and `getClientIP()` when handling empty or malformed input.

### Added
- Added 30-second HTTP client timeout in `tor.go` to prevent hanging requests during Tor exit node list fetches.
- Added comprehensive input validation in `Validate()` method for negative threshold/limit values.
- Added parameter validation in `NewRateLimiter()` to ensure positive values.

### Changed
- Updated installation documentation to clarify that `caddy add-package` is not available (module not registered in Caddy's package registry).
- Reordered installation methods in documentation to recommend Quick Script and xcaddy as primary options.
- Updated `CADDY_MODULE_REGISTRATION.md` with current registration status.

### Documentation
- Added warnings about `caddy add-package` limitations in README.md, installation.md, and add-package-guide.md.

## [v0.1.6] - 2025-12-10

### Fixed
- Minor bug fixes and stability improvements.

## [v0.1.5] - 2025-12-08
### Fixed
- Fixed critical bug where POST request bodies were lost or truncated by using `io.MultiReader` to restore the full body stream (fixes #76).

## [v0.1.4] - 2025-12-06

### Security
- Fixed Panic vulnerability in `quic-go` by upgrading to `v0.54.0` (requires Caddy v2.10.x and Go 1.25).
- Addressed Dependabot Alert #7.

### Changed
- Upgraded Caddy dependency to `v2.10.2`.
- Upgraded Go requirement to `1.25`.
- Improved CI workflows to use Go 1.25 for build and release.

## [v0.1.3] - 2025-12-06
### Fixed
- Downgraded `quic-go` to `v0.48.2` and Caddy to `v2.9.1` to temporarily resolve Go version conflicts (superseded by v0.1.4).
- Fixed import grouping for `gci` linter compliance.
- Fixed GitHub Actions release workflow.

## [v0.1.2] - 2025-12-06
### Added
- SOTA Engineering patterns (Zero-Copy headers, Wait-Free Ring Buffer, Circuit Breaker).
- ASN Blocking support.
- Configurable Request Body size limit.
- GeoIP Fail Open configuration.
