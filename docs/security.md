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

## Related

- [Attack coverage](/attacks) — what the shipped rules detect.
- [Client IP & trusted proxies](/client-ip) — spoofing boundary for
  header-derived client IPs.
- [Security advisories](https://github.com/fabriziosalmi/caddy-waf/security/advisories)
  — report a vulnerability here.
