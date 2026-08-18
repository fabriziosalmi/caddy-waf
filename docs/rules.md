# Rules

The WAF evaluates a set of rules defined in one or more JSON files. Each file is a JSON array of rule objects. Files are loaded by the `rule_file` directive (which may be repeated to load several files).

The schema below mirrors the `Rule` struct in [`types.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/types.go) and the validation in [`rules.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.go) (`validateRule`).

---

## Schema

```json
{
  "id":          "unique-rule-id",
  "phase":       1,
  "pattern":     "(?i)example",
  "targets":     ["URI", "ARGS"],
  "severity":    "HIGH",
  "score":       8,
  "mode":        "block",
  "description": "Human-readable description",
  "priority":    10
}
```

| Field | JSON key | Type | Required | Notes |
|---|---|---|---|---|
| ID | `id` | string | yes | Must be unique across all loaded files. Duplicate IDs are dropped with a warning. |
| Phase | `phase` | int | yes | One of `1`, `2`, `3`, `4`. See [Phases](#phases). |
| Pattern | `pattern` | string | yes | A Go [`regexp`](https://pkg.go.dev/regexp) pattern (RE2 syntax). Compiled at load time and cached per rule ID. Invalid patterns drop the rule with a warning. |
| Targets | `targets` | array of string | yes | One or more target identifiers. See [Targets](#targets). |
| Transformations | `transformations` | array of string | no | Optional per-rule input transformation pipeline (ModSecurity/CRS names, e.g. `["urlDecodeUni","removeNulls"]`). See [Input normalization](#input-normalization). Absent = the per-target default chain; explicit `[]` = no transformation. |
| Severity | `severity` | string | no | Free-form label used only for logging (e.g. `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). It does **not** affect blocking decisions. |
| Score | `score` | int | yes (validated ≥ 0) | Added to the request's anomaly score on match. |
| Mode | `mode` | string | no | `"block"` (block immediately on match) or `"log"` (log and continue). Empty / missing means: rely on the anomaly threshold only. The Go field is `Action` but the JSON tag is `mode` — see [Field name caveat](#field-name-caveat). |
| Description | `description` | string | no | Human-readable description, written to log records. |
| Priority | `priority` | int | no | Higher priority is evaluated first within a phase. Defaults to `0`. |

### Validation rules (from `validateRule` in [`rules.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.go))

A rule is rejected (and dropped from the runtime ruleset, with a warning logged) if any of the following holds:

- `id` is empty
- `pattern` is empty
- `targets` is empty
- `phase` is outside `[1, 4]`
- `score` is negative
- `mode` is non-empty and not equal to `"block"` or `"log"`

Loading a file is aborted only when the file cannot be read or its contents cannot be parsed as a JSON array of rules. Individual invalid rules do not abort the load; they are reported in the `Validation errors in rules` log entry.

### Field name caveat

The Go struct declares the action as `Action string \`json:"mode"\`` ([`types.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/types.go) line 79). This means the JSON property name read by the loader is **`mode`**, not `action`. Files that use `"action"` will be parsed (the field is simply absent from the rule), and the rule will not have an explicit block — it will rely entirely on the cumulative anomaly score reaching `anomaly_threshold`.

The bundled [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json) currently uses `"action"`; the bundled [`sample_rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/sample_rules.json) uses `"mode"`. Files under [`rules/`](https://github.com/fabriziosalmi/caddy-waf/tree/main/rules) use `"action"` and therefore behave as if no explicit block were set.

When authoring new rules, prefer `"mode"`.

---

## Phases

| Phase | Inspected at | Available targets |
|---|---|---|
| **1** | After pre-request checks (IP / DNS blacklist, rate limit, GeoIP, ASN), before the upstream handler. | Request method, URL, headers, cookies, query parameters, JSON body paths. |
| **2** | After Phase 1, before the upstream handler. Same time window as Phase 1; useful for separating header-only checks from body-aware checks. | Request body (`BODY`, `JSON_PATH:`), plus all Phase 1 targets. |
| **3** | After the upstream handler returns, before the response leaves the proxy. | `RESPONSE_HEADERS`, `RESPONSE_HEADERS:<name>`. |
| **4** | After Phase 3. | `RESPONSE_BODY`. |

Within a phase, rules are sorted by descending `priority`, then evaluated in order. The first rule that triggers a block stops the phase.

---

## Targets

Defined in [`request.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/request.go). Names are matched case-insensitively unless noted otherwise.

ModSecurity/CRS target names are accepted as aliases: `REQUEST_HEADERS`→`HEADERS`, `REQUEST_COOKIES`→`COOKIES`, `QUERY_STRING`→`ARGS`, `REQUEST_URI`→`URI`, `REQUEST_BODY`→`BODY`, `REQUEST_FILENAME`→`PATH`.

### Static targets

| Target | Source |
|---|---|
| `METHOD` | `r.Method` |
| `REMOTE_IP` | `r.RemoteAddr` (host:port form) |
| `PROTOCOL` | `r.Proto` |
| `HOST` | `r.Host` |
| `URI` | `r.URL.RequestURI()` |
| `URL` | `r.URL.String()` |
| `PATH` | `r.URL.Path` |
| `ARGS` | `r.URL.RawQuery` |
| `USER_AGENT` | `r.UserAgent()` |
| `CONTENT_TYPE` | `r.Header.Get("Content-Type")` |
| `BODY` | Request body, read through `io.LimitReader(MaxRequestBodySize)` and re-attached so downstream handlers still see the full body. |
| `HEADERS` | All request headers serialised as `Name: v1,v2; Name: v…`. |
| `COOKIES` | All request cookies serialised as `name=value; name=value`. |
| `FILE_NAME` | First file name from `r.MultipartForm`. |
| `FILE_MIME_TYPE` | First file Content-Type from `r.MultipartForm`. |
| `RESPONSE_HEADERS` | All response headers (Phase 3 only). |
| `RESPONSE_BODY` | Response body captured by the response recorder (Phase 4 only). |

### Dynamic targets

These accept an argument after the colon. Parameter and header names are case-sensitive in the value passed to lookup, but the prefix is matched case-insensitively.

| Target | Source |
|---|---|
| `HEADERS:<name>` | `r.Header.Get("<name>")` |
| `COOKIES:<name>` | `r.Cookie("<name>")` |
| `URL_PARAM:<name>` | `r.URL.Query().Get("<name>")` |
| `JSON_PATH:<dotted.path>` | Reads the body, parses as JSON, and walks the dotted path (numeric segments are array indices). |
| `RESPONSE_HEADERS:<name>` | `w.Header().Get("<name>")` (Phase 3 only). |

### Multiple targets in one rule

A single `targets` entry may itself be a comma-separated list. The extractor will try each value in turn, joining successful extractions with commas. Failures on individual sub-targets are tolerated — only the successful extractions are passed to the regex engine.

```json
"targets": ["URI,HEADERS:User-Agent,COOKIES:sessionid"]
```

---

## Input normalization

Rule patterns are matched against the request the way the **application behind
the WAF will consume it**, not only the raw bytes on the wire. This closes
encoding evasion: a payload like `%75nion%20select` (or a fully percent-encoded
query, or a percent-encoded form body) reaches a SQL engine as `union select`,
so the WAF must see it that way too.

### How matching works

Each target value is matched **twice**: once as the raw extracted value, and
once as a transformed copy. The rule fires if **either** matches. Because the
raw value is always tested first, a rule that matches today can never stop
matching — transformations only add coverage. Unencoded traffic pays no extra
regex (the second pass runs only when normalization actually changed the value).

### Default chain

When a rule does not set `transformations`, the raw request targets `ARGS`,
`URI`, `URL` and `BODY` get a conservative default chain:

1. `urlDecode` — single-pass percent-decode. `+` becomes a space in query/body
   context; in the path portion of `URI`/`URL` it stays literal.
2. `removeNulls` — strip NUL bytes used to split keywords (`un%00ion`).
3. `compressWhitespace` — fold runs of whitespace to one space (defeats
   tab/newline substitution).

`PATH` and `URL_PARAM:<name>` are already decoded by Go and are left untouched by the
default. All other targets get no default transformation.

### Per-rule transformations

A rule may override the default with its own pipeline, applied in order:

```json
{
  "id": "941-xss-entity",
  "phase": 2,
  "pattern": "(?i)<script",
  "targets": ["ARGS", "BODY"],
  "transformations": ["urlDecode", "htmlEntityDecode"]
}
```

| Name | Effect |
|---|---|
| `urlDecode` / `urlDecodeUni` | Single-pass percent-decode (context-aware `+`). |
| `removeNulls` | Remove NUL bytes. |
| `compressWhitespace` | Collapse whitespace runs to one space. |
| `replaceComments` | Replace `/* … */` with a space (defeats `union/**/select`). |
| `htmlEntityDecode` | Decode common HTML entities (`&lt;`, `&#39;`, …). |
| `lowercase` | Lowercase (patterns already use `(?i)`, so rarely needed). |
| `none` | No-op. |

Names are case-insensitive and an optional `t:` prefix is accepted, so both
`t:urlDecodeUni` and `urldecodeuni` resolve. An unknown name **fails at load
time** rather than silently doing nothing. An explicit empty array means "match
the raw value only".

### What this does NOT close

Decoding is **single-pass by design**: `%2555` decodes to the literal `%55`,
not to `U`. This is correct — an application that decodes once also sees `%55` —
so double-encoding is not "caught" because it is not an attack against a
single-decoding backend. `%uXXXX` (IIS/.NET Unicode) and overlong UTF-8 are not
decoded by the current pipeline. Cookie and header targets are not normalized by
default; add `transformations` to a rule that needs it.

## How a match becomes a block

For each rule that matches:

1. The hit counter for the rule (a `*atomic.Int64` in `Middleware.ruleHits`) is incremented.
2. The phase counter (`Middleware.ruleHitsByPhase[phase]`) is incremented.
3. `state.TotalScore += rule.score`.
4. The request is blocked with `403 Forbidden` if either:
   - `state.TotalScore >= anomaly_threshold`, or
   - `rule.mode == "block"`.
5. When blocked, the configured custom response for `403` (if any) is written; otherwise the default plain-text body is sent.

Rules with `mode == "log"` log the match at INFO level and let evaluation continue.

---

## Examples

```json
[
  {
    "id": "block-scanners",
    "phase": 1,
    "pattern": "(?i)(nikto|sqlmap|nmap|acunetix|nessus|wpscan|burpsuite|metasploit|nuclei)",
    "targets": ["HEADERS:User-Agent"],
    "severity": "CRITICAL",
    "score": 10,
    "mode": "block",
    "priority": 100,
    "description": "Block well-known vulnerability scanners by User-Agent."
  },
  {
    "id": "log4j-jndi",
    "phase": 2,
    "pattern": "(?i)\\$\\{jndi:(ldap|rmi|dns):\\/\\/[^}]*\\}",
    "targets": ["BODY", "ARGS", "URI", "HEADERS"],
    "severity": "CRITICAL",
    "score": 10,
    "mode": "block",
    "description": "Detect Log4Shell (CVE-2021-44228) JNDI injection attempts."
  },
  {
    "id": "low-score-log",
    "phase": 2,
    "pattern": "(?i)suspicious-keyword",
    "targets": ["BODY"],
    "severity": "LOW",
    "score": 1,
    "mode": "log",
    "description": "Record suspicious keyword without blocking."
  },
  {
    "id": "json-admin-flag",
    "phase": 2,
    "pattern": "^true$",
    "targets": ["JSON_PATH:user.is_admin"],
    "severity": "HIGH",
    "score": 8,
    "mode": "block",
    "description": "Block requests attempting to set is_admin via mass assignment."
  },
  {
    "id": "leaky-server-header",
    "phase": 3,
    "pattern": "(?i)apache|nginx/\\d|iis",
    "targets": ["RESPONSE_HEADERS:Server"],
    "severity": "MEDIUM",
    "score": 2,
    "mode": "log",
    "description": "Log responses leaking the server software identity."
  }
]
```

---

## Notes on regex performance

- Patterns are compiled by Go's [`regexp`](https://pkg.go.dev/regexp) (RE2). RE2 guarantees linear-time execution; ReDoS attacks against the matcher are not possible.
- Compiled patterns are cached by rule ID in the per-middleware `RuleCache`. Reloading rules reuses cached compilations when the rule ID has not changed; new IDs trigger compilation.
- Use `(?i)` at the start of the pattern for case-insensitive matching. RE2 also supports `(?s)` (`.` matches newlines) and other flags as documented in the Go regexp syntax reference.
- Avoid expensive constructs (large `[abc]{1,1000}` ranges, deep alternations of long literals) — RE2 is linear in input size, but constants matter.

## Authoring tips

- Prefer modular files under [`rules/`](https://github.com/fabriziosalmi/caddy-waf/tree/main/rules) over a single monolithic `rules.json`. Multiple `rule_file` directives load them all.
- Always test new rules against the bundled offensive payloads in [`test.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/test.py) before deploying.
- Set `priority` on rules that should evaluate before others within the same phase.
- Use `mode: "log"` while tuning thresholds; switch to `mode: "block"` once false-positive rates are acceptable.
