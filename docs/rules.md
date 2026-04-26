# Rules

The WAF evaluates a set of rules defined in one or more JSON files. Each file is a JSON array of rule objects. Files are loaded by the `rule_file` directive (which may be repeated to load several files).

The schema below mirrors the `Rule` struct in [`types.go`](../types.go) and the validation in [`rules.go`](../rules.go) (`validateRule`).

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
| Severity | `severity` | string | no | Free-form label used only for logging (e.g. `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). It does **not** affect blocking decisions. |
| Score | `score` | int | yes (validated ≥ 0) | Added to the request's anomaly score on match. |
| Mode | `mode` | string | no | `"block"` (block immediately on match) or `"log"` (log and continue). Empty / missing means: rely on the anomaly threshold only. The Go field is `Action` but the JSON tag is `mode` — see [Field name caveat](#field-name-caveat). |
| Description | `description` | string | no | Human-readable description, written to log records. |
| Priority | `priority` | int | no | Higher priority is evaluated first within a phase. Defaults to `0`. |

### Validation rules (from `validateRule` in [`rules.go`](../rules.go))

A rule is rejected (and dropped from the runtime ruleset, with a warning logged) if any of the following holds:

- `id` is empty
- `pattern` is empty
- `targets` is empty
- `phase` is outside `[1, 4]`
- `score` is negative
- `mode` is non-empty and not equal to `"block"` or `"log"`

Loading a file is aborted only when the file cannot be read or its contents cannot be parsed as a JSON array of rules. Individual invalid rules do not abort the load; they are reported in the `Validation errors in rules` log entry.

### Field name caveat

The Go struct declares the action as `Action string \`json:"mode"\`` ([`types.go`](../types.go) line 79). This means the JSON property name read by the loader is **`mode`**, not `action`. Files that use `"action"` will be parsed (the field is simply absent from the rule), and the rule will not have an explicit block — it will rely entirely on the cumulative anomaly score reaching `anomaly_threshold`.

The bundled [`rules.json`](../rules.json) currently uses `"action"`; the bundled [`sample_rules.json`](../sample_rules.json) uses `"mode"`. Files under [`rules/`](../rules/) use `"action"` and therefore behave as if no explicit block were set.

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

Defined in [`request.go`](../request.go). Names are matched case-insensitively unless noted otherwise.

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

- Prefer modular files under [`rules/`](../rules/) over a single monolithic `rules.json`. Multiple `rule_file` directives load them all.
- Always test new rules against the bundled offensive payloads in [`test.py`](../test.py) before deploying.
- Set `priority` on rules that should evaluate before others within the same phase.
- Use `mode: "log"` while tuning thresholds; switch to `mode: "block"` once false-positive rates are acceptable.
