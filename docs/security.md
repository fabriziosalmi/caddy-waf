# Security posture

Notes on how the WAF itself resists being turned into a weapon — starting with
the regex engine, since a rule-driven WAF is an obvious target for a
regular-expression denial-of-service.

## ReDoS resistance

**caddy-waf is not vulnerable to catastrophic-backtracking ReDoS**, by
construction.

Every rule pattern is compiled with Go's [`regexp`](https://pkg.go.dev/regexp)
package, which uses the **RE2** engine. RE2 matches in time **linear in the
length of the input**, independent of the pattern — it does not backtrack. The
nested-quantifier constructs that make a pattern explode super-linearly under a
backtracking engine (PCRE, Oniguruma, JavaScript, Python's `re`) — `(a+)+`,
`(a|a)*`, `(.*a){n}` — simply run in linear time here. There is **no
backtracking engine anywhere in the match path**, and no PCRE fallback: both the
rule matcher and the rate-limiter path regexes go through `regexp`.

This is enforced two ways in the test suite:

- `TestRE2NeutralisesCatastrophicPatterns` compiles textbook "evil regex"
  patterns and matches them against a 60 KB adversarial input; each must return
  within a wall-clock budget a backtracking engine would blow past.
- `TestRuleCorpusIsReDoSResistant` throws a corpus of adversarial inputs (long
  homogeneous runs with a failing tail, repeated `../`, `%2e`, long query
  streams, …) at **every shipped rule** — the curated sets and every
  `rules/*.json` bundle — and asserts each match completes within budget.

Because RE2 is used, a rule author also **cannot** write a backtracking pattern:
RE2 rejects backreferences and lookaround outright (see
[the rule bundle notes](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/README.md)),
and `TestBundledRulePatternsCompile` fails CI if a shipped bundle contains one.

### Residual cost is linear, and bounded by request size

RE2 removes the *super-linear* risk; what remains is ordinary linear cost. Total
per-request matching work is roughly **O(input length × rule count)**: a large
body scanned by many phase-2/3 rules is proportionally more work. This is a
capacity/tuning concern, not a ReDoS one, and the lever is **request size**:

- **`max_request_body_size`** (default **10 MB**) caps the body handed to the
  matchers. Lower it if your endpoints never receive large bodies.
- **`max_response_body_size`** does the same for response-phase rules.
- Request line and header sizes are bounded by Caddy's HTTP server limits.

A per-match timeout was considered and deliberately **not** added: with RE2 the
worst case is already linear and the input is already size-bounded, so a timeout
would add goroutine and cancellation machinery (Go's `regexp` has no native
deadline) to guard against a blowup that cannot happen. Bounding request size is
the simpler, sufficient control.

## Fail-safe behaviour & secure defaults

What the WAF does when something goes wrong, per feature. "Fail-closed" = the
request is blocked or the server refuses to start; "fail-open" = the request is
allowed through.

### Startup (Provision)

Startup is **fail-closed** for anything that would leave the WAF misconfigured:

- **No rule file, or the only rule file is missing / unreadable / invalid JSON /
  has no valid rules** → Provision returns an error and **Caddy refuses to
  start**.
- **A malformed Caddyfile** (unknown directive, bad argument) → startup error.
- **An unreadable IP-blacklist or DNS-blacklist file**, or **invalid rate-limit
  config** → startup error.

Two things are tolerated at startup so a single typo doesn't take the server
down: a **single rule with an uncompilable regex** or an invalid field is
skipped (logged) and the rest of the file loads; a **malformed line in a
blacklist file** is skipped. Across *multiple* rule files, a file that fails
while another still yields rules lets startup proceed with the good ones (logged
at Error) — so review the logs after a deploy.

A **missing GeoIP database does not block startup**: the country/ASN filter is
left active but with no reader, which matters at request time — see below.

### Rule hot-reload

Hot-reload is **fail-safe**: if an edited rule file becomes invalid (bad JSON,
missing, or produces no rules), the reload **fails and the previously loaded
rules stay in effect** — the WAF is never left running with zero rules by a bad
edit. The failure is logged; fix the file and save again to reload. (Earlier
versions replaced the rule set before validating and could drop to zero rules on
a bad reload; fixed in the #113 audit.)

### Request time

| Feature | On failure | Direction |
|---|---|---|
| **Panic** anywhere in request handling | recovered → **500**, request not forwarded upstream | **fail-closed** |
| **GeoIP / ASN lookup error** (incl. missing DB with the filter enabled) | **403 by default**; allowed only if `geoip_fail_open` is set | **fail-closed by default** |
| **IP blacklist** — unparseable client IP or uninitialised trie | request allowed | fail-open |
| **DNS blacklist** — host not in the (static) set | request allowed | fail-open |
| **Rate limiter** — any non-match / edge | request allowed | fail-open |
| **Value-extraction error** for one target (non-panic) | that target is skipped, other rules still run | fail-open |

The fail-open cases are inherent to how those checks work — they block only on a
positive match, so an error or absence means "no match", i.e. allow. The
fail-closed cases are where an internal error could otherwise let traffic bypass
a control: a panic yields a 500 rather than a silent pass-through, and a GeoIP
error blocks by default.

> [!IMPORTANT]
> If you enable `block_countries` / `whitelist_countries` / `block_asns` but the
> GeoIP database is missing or unreadable, **every request is blocked with 403**
> by default (fail-closed). That is deliberate — a country filter that silently
> stopped filtering would be worse — but if you would rather allow traffic when
> GeoIP is unavailable, set **`geoip_fail_open`**. Make sure the database path is
> correct in the first place.

### Secure defaults

| Setting | Default | Notes |
|---|---|---|
| Blocking | **on** | The WAF blocks when a request's score reaches `anomaly_threshold` or a matched rule has `mode: block`. There is no global detection-only switch; use per-rule `mode: log` to observe without blocking. |
| `anomaly_threshold` | **5** (Caddyfile) | Lower = stricter. Raw-JSON configs with the value unset fall back to 20. |
| `max_request_body_size` | **10 MB** | Caps the body scanned by matchers (see [ReDoS residual cost](#residual-cost-is-linear-and-bounded-by-request-size)). |
| `max_response_body_size` | **10 MB** | Same, for response-phase rules. |
| `geoip_fail_open` | **false** (fail-closed) | A GeoIP lookup error blocks unless this is set. |
| `X-Forwarded-For` trust | **not trusted** | Header-derived client IP is honoured only from configured `trusted_proxies` — see [Client IP](/client-ip). |

## Related

- [Attack coverage](/attacks) — what the shipped rules detect.
- [Client IP & trusted proxies](/client-ip) — spoofing boundary for
  header-derived client IPs.
- [Security advisories](https://github.com/fabriziosalmi/caddy-waf/security/advisories)
  — report a vulnerability here.
