# Testing

The repository ships several testing layers:

| Layer | Tool | Scope |
|---|---|---|
| Go unit tests | `go test ./...` (or `make test`) | Per-package logic in [`*_test.go`](../). |
| Go integration tests | `go test ./... -tags=it` (or `make it`) | Tests guarded by the `it` build tag. |
| Lint | `golangci-lint run` (or `make lint`) | Style and static analysis configured in [`.golangci.yml`](../.golangci.yml). |
| Live attack suite | [`test.py`](../test.py) (or `make test-integration`) | Sends a curated payload set to a live WAF and checks the returned status codes. |
| Traffic generator | [`caddytest.py`](../caddytest.py) | High-volume, configurable traffic generation; see [caddytest.md](caddytest.md). |
| Benchmark | [`benchmark.py`](../benchmark.py) | Throughput/latency measurement against a running WAF. |

This page focuses on the live attack suite; the others are documented inline in their files.

---

## `test.py` — live attack suite

`test.py` exercises the WAF against a long list of attack payloads using `curl`. Each test case is a tuple of `(description, url, expected_code, headers, body)`; the script issues the request and compares the HTTP status returned by the WAF against the expected one.

### Configuration constants

Defined at the top of [`test.py`](../test.py):

| Constant | Default | Meaning |
|---|---|---|
| `TARGET_URL` | `http://localhost:8080` | Base URL of the running WAF. |
| `TIMEOUT` | `8` | `curl` connect/total timeout in seconds. |
| `OUTPUT_FILE` | `waf_test_results.log` | Per-case log file (appended to). |
| `DEFAULT_USER_AGENT` | `WAF-Test-Script/1.0` | UA sent when a test case does not specify one. |

To run against a different target, edit `TARGET_URL` directly (the script does not currently expose it as a CLI flag).

### Running

```bash
python3 test.py
```

CLI flags:

| Flag | Description |
|---|---|
| `--user-agent`, `-ua` | Override `DEFAULT_USER_AGENT` for this run. |

### Output

The script:

- Prints a colour-coded line per test (green `[+]` for pass, red `[!]` for fail or `curl` error).
- Appends every test result (pass and fail) to `waf_test_results.log`, including the URL, headers, body, expected code, and observed code.
- Prints a summary at the end with the total number of cases, the number passed, the number failed, and a final verdict.

### Test categories

`test.py` covers (non-exhaustive):

- SQL injection (boolean, UNION, time-based, header- and cookie-borne)
- XSS (script tags, attribute injections, encoded payloads)
- Path traversal and LFI (encoded variants, header- and cookie-borne)
- RCE / command injection
- Header injection, host-header tampering
- Insecure deserialization (Java, PHP, Python)
- SSRF (cloud-metadata, internal IPs)
- XXE (inline and parameter entities)
- HTTP request smuggling and response splitting
- IDOR, mass assignment, NoSQL injection, XPath, LDAP, XML
- File upload payloads, JWT manipulation, GraphQL abuse
- Clickjacking and CSRF probes
- A set of valid baseline requests that should pass

### Workflow

```bash
# 1. Start the WAF
./caddy run --config Caddyfile &

# 2. Run the suite
python3 test.py

# 3. Inspect failures
grep '\[FAIL\]\|\[ERROR\]' waf_test_results.log

# 4. Iterate on rules, repeat
```

### Inside Docker

The Makefile target `test-integration` runs `test.py` inside a `python:3.9-slim` container against the host's WAF:

```bash
make test-integration
```

This requires Docker and a WAF reachable at `http://localhost:8080` from inside the container — typically meaning the WAF runs on the host.

---

## Tuning workflow

A pragmatic tuning loop:

1. Start with the bundled `rules.json` (or a curated subset under [`rules/`](../rules/)).
2. Run `test.py` to confirm the baseline behaviour.
3. Use [`caddytest.py`](../caddytest.py) with `--behavior burst_calm` and `--composite` to mix legitimate and malicious traffic and watch the false-positive rate.
4. Watch the WAF metrics endpoint (`/waf_metrics`) for the rule IDs with the highest hit counts. False positives usually concentrate on a small number of rules.
5. Adjust the offending rules: tighten the regex, scope the `targets`, lower the `score`, or move them to `mode: log` for observation.
6. Reload — the file watcher applies the new rule set without restarting Caddy (see [dynamicupdates.md](dynamicupdates.md)).

---

## Go test suite

```bash
make test            # go test -v ./...
make it              # go test -v ./... -tags=it (integration)
make lint            # golangci-lint run
make lintfix         # golangci-lint run --fix
```

Test files cover: blacklist loading, configuration parsing, GeoIP, rate limiter, request value extraction, response handling, rule loading, Tor fetcher, the middleware lifecycle, and integration scenarios.

---

## CI

The repository ships three GitHub Actions workflows in [`.github/workflows/`](../.github/workflows/):

- `test.yml` — runs `go test ./...` and the lint suite on push and pull request.
- `build-run-validate.yml` — builds Caddy with the WAF, starts it, and runs validation requests.
- `release.yml` — builds binaries and creates a GitHub release on a tag.

A green badge from these workflows on a commit is a reasonable signal that the change at minimum compiles, passes unit tests, and survives a smoke test of the bundled Caddyfile.
