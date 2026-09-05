# Rule bundles

Two kinds of rule files live in this project:

- **`../rules.json`** (repo root) — the **curated, shipped rule set**. This is what the
  Caddyfile examples and the Docker image point `rule_file` at. It is the set that
  is maintained, tested for false positives, and versioned with releases.
- **`rules/*.json`** (this directory) — an **opt-in menu of per-category bundles**
  (SQLi, XSS, LFI, RFI, SSRF, XXE, SSTI, …). They are **not** loaded by
  `rules.json`; you enable one by pointing `rule_file` at it explicitly, e.g.:

  ```
  waf {
      rule_file rules/sql-injection.json
      rule_file rules/ssrf.json
  }
  ```

  Load as many as you like — rules are merged and de-duplicated by `id`.
- **`rules/crs/`** — opt-in bundles **translated from the OWASP Core Rule Set**
  by `get_owasp_rules.py`, one file per paranoia level plus the response-phase
  rules. Every rule is `log` (advisory) until `log_scores_block` is set. See
  [`rules/crs/README.md`](crs/README.md) for what is and is not covered and the
  per-request cost.

## Constraints every bundle must satisfy

Patterns are compiled with Go's [`regexp`](https://pkg.go.dev/regexp) (the **RE2**
engine), not the ModSecurity operator set. That means:

- **No backreferences** (`\1`) and **no lookaround** (`(?=…)`, `(?<…)`). RE2 rejects
  them, so such a rule silently fails to load. Detections that need them (HPP
  parameter-combining, quoted-tautology balancing) belong in application logic, not
  a regex.
- **Repeat counts are capped at 1000.** Write `^.{1000}.{1000}…` rather than
  `^.{5000,}$`, and avoid nested repeats that multiply past the cap
  (`(?:.{1000}){5}`).
- **`pattern` is a bare regex**, not a ModSecurity operator expression. Strings like
  `@rx …`, `@eq 0`, `@pmFromFile …` are not understood — they compile as literal
  text and never match real traffic.

`TestBundledRulePatternsCompile` compiles every file here (and the curated top-level
sets) under RE2 and rejects duplicate IDs, so a broken bundle fails CI rather than
shipping inert.

## OWASP CRS

A raw ModSecurity CRS export is **not** RE2-loadable as-is (operators, chained
rules, `t:` names and per-parameter anchors all differ). Generate a loadable,
RE2-validated subset with [`get_owasp_rules.py`](../get_owasp_rules.py), which
ports the `@rx`/`@pm`/`@pmFromFile` rules and writes a coverage report of what
it had to skip:

```bash
python3 get_owasp_rules.py --ref v4.9.0 --output-dir rules/crs
```

See [docs/scripts.md](../docs/scripts.md#get_owasp_rulespy) for the options.
[`get_spiderlabs_rules.py`](../get_spiderlabs_rules.py) is the older, cruder
converter for the SpiderLabs rule set (keeps `@rx` rules only, validates with
Python's `re`, not RE2).
