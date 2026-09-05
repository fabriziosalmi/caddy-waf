# OWASP CRS bundles

Opt-in rule bundles translated from the [OWASP Core Rule Set](https://coreruleset.org/)
(CRS) v4.9.0 by [`get_owasp_rules.py`](../../get_owasp_rules.py). They are **not**
loaded by default and they **complement** the curated `rules.json`; they do not
replace it (see [What is not covered](#what-is-not-covered)).

| File | Rules | What it holds |
|---|---:|---|
| `crs-pl1.json` | 101 | Paranoia level 1 request rules (phases 1–2): scanner detection, protocol attacks, LFI/RFI, RCE, PHP/Java/Node injection, XSS, SQLi, session fixation. |
| `crs-pl1-response.json` | 50 | Paranoia level 1 response rules (phase 4): SQL/PHP/Java/IIS error leakage, directory listings, web-shell fingerprints. Runs against every response body, so it is the more expensive half. |
| `tuning.txt` | | Per-rule adjustments applied at generation time (the caddy-waf equivalent of CRS `SecRuleUpdateTargetById`). Each line carries its reason. |
| `COVERAGE.md` | | Generated report: what was ported, what was skipped and why, and which ported rules lost a transformation, an exclusion or an anchor on the way. |

## Enabling

```caddyfile
waf {
    rule_file rules.json
    rule_file rules/crs/crs-pl1.json
    rule_file rules/crs/crs-pl1-response.json   # optional, response-body checks
    anomaly_threshold 5
    log_scores_block
}
```

Every CRS rule is emitted with `"action": "log"` and its CRS severity as the
score (CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2). Since v0.4.14 a `log` rule's
score is **advisory**: it is logged and reported but never blocks. That is the
default so the bundle can be enabled in observation mode first.

`log_scores_block` restores CRS-style anomaly scoring: the scores add up and a
request is blocked once they reach `anomaly_threshold` (CRS uses 5, so one
CRITICAL match blocks). Without it, the bundle only produces an `advisory_score`
on the request log.

Higher paranoia levels are cumulative: load `crs-pl2.json` on top of
`crs-pl1.json`, and so on.

## What is not covered

The CRS is written for ModSecurity's engine; caddy-waf matches one RE2 regex
per target. The translator ports the `@rx` and `@pm`/`@pmFromFile` rules and
skips everything else, and `COVERAGE.md` lists every skipped rule with its
reason. The important gaps:

- **libinjection.** CRS detects most SQL injection and XSS at PL1 with
  `@detectSQLi`/`@detectXSS`, which have no regex form. The classic quote
  tautology (`' OR 1=1--`) is therefore **not** caught by the PL1 bundle alone;
  `rules.json` catches it, which is why the two are meant to be loaded together
  (`TestCRSPL1KnownGaps` pins this).
- **Chained rules** (57) and the other non-regex operators
  (`@validateByteRange`, `@eq`, `@ipMatch`, …) are skipped.
- **Parsed parameters.** ModSecurity matches each decoded parameter value on
  its own; caddy-waf matches the raw query string and the raw body. `ARGS`
  rules are emitted against `ARGS` + `BODY`, `^`/`$` anchors are rewritten to
  member boundaries, and three rules have `BODY` removed by `tuning.txt`
  because they match JSON, YAML or multipart framing.
- **Transformations** the engine lacks (`cmdLine`, `normalizePath`,
  `jsDecode`, `cssDecode`, `utf8toUnicode`) are dropped, which loses only the
  corresponding evasion coverage; rules that need `base64Decode` or `length`
  are skipped.
- **Paranoia level** is a file choice, not a runtime setting, and there is no
  exclusion-rule language: edit `tuning.txt` and regenerate.

## Cost

The `@pmFromFile` keyword lists (`lfi-os-files.data`, `unix-shell.data`,
`windows-powershell-commands.data`, `php-function-names-*.data`, …) become
multi-kilobyte alternations that Go's regexp engine has to run against every
request part they target. On this machine a small benign JSON POST costs about
0.6 ms with the PL1 request bundle alone (`BenchmarkCRSPL1BenignPOST`) against
about 0.2 ms with `rules.json` alone, and the cost grows linearly with the
body size.
Set `max_request_body_size` to bound it, and load the response bundle only if
you want the data-leakage checks: `crs-953100` (PHP error strings, a 77 KB
alternation) alone costs about 0.7 ms per 1 KB of response body.

## Regenerating

```bash
python3 get_owasp_rules.py --ref v4.9.0 --output rules/crs/crs-pl1.json \
    --paranoia-level 1 --tuning rules/crs/tuning.txt
go test -run TestCRS .
```

The Go toolchain is required so every pattern is compiled by the same `regexp`
package caddy-waf uses. `TestCRSPL1NoBrowserFalsePositives` names the rule that
blocked a benign request; add a `remove-target` or `remove` line for it to
`tuning.txt` with the reason, regenerate, and the reason shows up in
`COVERAGE.md`.

## License

The rules in this directory are derived from the OWASP Core Rule Set,
Copyright (c) 2006-2020 Trustwave and contributors, Copyright (c) 2021-2024
CRS project, and are licensed under the
[Apache License 2.0](https://github.com/coreruleset/coreruleset/blob/main/LICENSE).
