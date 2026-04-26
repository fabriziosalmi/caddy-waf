# `caddytest.py` — Traffic Generator

`caddytest.py` is a configurable HTTP traffic generator. It mixes legitimate and malicious payloads against a target URL to exercise WAF rules and to stress-test request handling. The script is intended for local benchmarking and rule validation, not as part of an automated CI suite — for the latter use [`test.py`](../test.py) (see [testing.md](testing.md)).

## Capabilities

- A library of attack payloads covering SQLi, XSS, command injection, LFI, RCE, CRLF injection, SSRF, XXE, XPath, NoSQL, HTTP smuggling, Shellshock, LDAP, and RFI.
- "Composite" requests that mix legitimate and malicious parameters in the same call.
- Configurable behaviour profiles (constant, burst-then-calm, stealth) that change the request mix and pacing over the run.
- Random HTTP method, random path segment, and random cookie generation.
- Concurrency via a configurable thread count, retries, and timeouts.
- Latency metrics (mean, stdev, min/max, median, p95, p99), response-size metrics, status-code distribution, and throughput.
- Optional JSON summary file for machine consumption.

## Installation

```bash
pip install requests tqdm
```

## Invocation

```bash
python3 caddytest.py [OPTIONS]
```

### Options

| Option | Default | Description |
|---|---|---|
| `--url` | `http://localhost:8080` | Target base URL. |
| `--method` | `GET` | Default HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`). |
| `--num-requests` | `100` | Total number of requests to send. |
| `--delay` | `1.0` | Base delay between requests (seconds). |
| `--delay-jitter` | `0.0` | Maximum jitter added to / subtracted from `--delay`. |
| `--attack-type` | `all` | Attack key to use (or `all` for the full set). |
| `--legit-percent` | `0.0` | Percentage of requests that should be legitimate. |
| `--composite` | _off_ | Mix legitimate and malicious parameters per request. |
| `--max-errors` | `3` | Maximum errors before aborting. |
| `--timeout` | `5.0` | HTTP timeout per request (seconds). |
| `--max-retries` | `0` | Retries on failure. |
| `--retry-delay` | `0.1` | Delay between retries (seconds). |
| `--seed` | _none_ | Random seed for reproducibility. |
| `--proxy` | _none_ | Outbound proxy URL. |
| `--threads` | `1` | Concurrent worker threads. |
| `--random-method` | _off_ | Randomise the HTTP method per request. |
| `--random-cookies` | _off_ | Add random cookie headers. |
| `--random-path` | _off_ | Append a random path segment to `--url`. |
| `--json` | _off_ | Send payloads as JSON instead of form-encoded. |
| `--log-file` | _none_ | File for log output. |
| `--progress` | _off_ | Display a `tqdm` progress bar. |
| `--score` | _off_ | Compute a pass / fail score against the expected status codes below. |
| `--expected-status-legit` | `200` | Expected status code for legitimate requests. |
| `--expected-status-malicious` | `403` | Expected status code for malicious requests. |
| `--expected-status-composite` | `200` | Expected status code for composite requests. |
| `--behavior` | `default` | One of `default`, `burst_calm`, `stealth`. |
| `--insecure` | _off_ | Disable TLS verification. |
| `--json-summary-file` | _none_ | Path to write a JSON summary at the end. |

## Behaviour profiles

| Profile | What it does |
|---|---|
| `default` | Uses the supplied options unchanged. |
| `burst_calm` | First 30% of the run: rapid all-malicious burst with minimal delay. Next 30%: slower pace with the user-configured legitimate percentage and increased delay. Last 40%: forced GET requests against scanning-style endpoints (`/admin`, `/config`, `/login`, …). |
| `stealth` | Bumps the legitimate percentage, slows pacing, restricts methods to GET / POST. |

## Examples

```bash
# 1000 default requests
python3 caddytest.py --num-requests 1000

# 1000 mostly-legitimate requests, four threads, no delay, stealth profile
python3 caddytest.py --num-requests 1000 --threads 4 --delay 0 \
    --legit-percent 100 --behavior stealth --progress

# 500 composite requests with the burst-then-calm profile
python3 caddytest.py --num-requests 500 --composite --behavior burst_calm --progress

# 200 random-method, random-cookie requests; write JSON summary
python3 caddytest.py --num-requests 200 --random-method --random-cookies \
    --json-summary-file summary.json --progress
```

## Output

A representative end-of-run summary:

```
--- Test Summary ---
Total Requests        : 1000
Passed                : 574 (57.40% success)
Errors                : 0   (0.00% error)
Avg Latency           : 0.002 s
Std Latency           : 0.001 s
Min / Max Latency     : 0.001 s / 0.008 s
Median / P95 / P99    : 0.002 s / 0.003 s / 0.004 s
Throughput            : 2070.09 requests/s

Avg / Min / Max Body  : 5 / 0 / 12 bytes
Median / P95 / P99    : 0 / 12 / 12 bytes

Status Code Distribution: {403: 614, 200: 386}
Total Duration        : 0.48 s
```

When `--json-summary-file` is provided, the same data is also written as JSON.

## Notes

- The script uses Python's `requests` library; for HTTP/2 traffic generation use a different tool (e.g. `h2load`).
- Concurrency is thread-based and, on CPython, bound by the GIL for parsing work. The script is I/O-bound in practice and scales reasonably to a few dozen threads.
- Always run the generator from a host you control against a target you control. The payloads are intentionally malicious.
