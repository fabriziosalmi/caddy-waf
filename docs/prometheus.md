# Prometheus and Grafana

The WAF speaks Prometheus **natively**. Set `prometheus_endpoint` and Prometheus can scrape it directly — the counters plus a request-duration histogram, in the text exposition format, no exporter needed.

```caddyfile
waf {
    rule_file rules.json
    prometheus_endpoint /metrics
}
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: caddy-waf
    static_configs:
      - targets: ["your-host:port"]
    metrics_path: /metrics
```

The series are prefixed `caddywaf_` — `caddywaf_total_requests`, `caddywaf_blocked_requests`, `caddywaf_rule_hits{rule_id=…}`, `caddywaf_blocked_by_reason{reason=…}`, `caddywaf_blocks_by_country{country=…}`, and the `caddywaf_request_duration_seconds` histogram. The counters are **process-local** and reset on restart (use `rate()`/`increase()`, which handle a reset as a counter drop).

> [!TIP]
> Protect `prometheus_endpoint` the same way as the dashboard and metrics endpoint — it exposes operational detail. Put Caddy `basic_auth`/`forward_auth` in front, or keep it on an internal listener.

## Alternative: a JSON exporter

If you prefer to scrape the [JSON `/waf_metrics`](metrics.md) document instead (for a pull-based setup that already polls JSON), the exporter below polls it and re-publishes the values.

## A note on counter semantics

The values in `/waf_metrics` are **monotonic process-local counters**. They reset to zero when Caddy restarts. The exporter below mirrors this by exposing them as Prometheus **Gauges** that are set on each scrape (rather than `Counter.inc(delta)`, which would compound the absolute values into a runaway total). When using `rate()` in PromQL the underlying values must be a counter; either:

- expose them as Gauges and use `irate()` of the gauge (acceptable but lossy), or
- track deltas in the exporter and call `Counter.inc(delta)` with the delta (handles restarts gracefully because the delta becomes negative and is dropped).

The example below uses Gauges for clarity.

## Exporter

Save as `exporter.py`:

```python
#!/usr/bin/env python3
"""Prometheus exporter for caddy-waf JSON metrics."""

import argparse
import time

import requests
from prometheus_client import Gauge, start_http_server

TOTAL_REQUESTS                = Gauge("caddywaf_total_requests",                "Total requests processed (process-local)")
BLOCKED_REQUESTS              = Gauge("caddywaf_blocked_requests",              "Total requests blocked (process-local)")
ALLOWED_REQUESTS              = Gauge("caddywaf_allowed_requests",              "Total requests allowed (process-local)")
DNS_BLACKLIST_HITS            = Gauge("caddywaf_dns_blacklist_hits",            "DNS blacklist hits (process-local)")
IP_BLACKLIST_HITS             = Gauge("caddywaf_ip_blacklist_hits",             "IP blacklist hits (process-local)")
GEOIP_BLOCKED                 = Gauge("caddywaf_geoip_blocked",                 "GeoIP / ASN blocks (process-local)")
RATE_LIMITER_REQUESTS         = Gauge("caddywaf_rate_limiter_requests",         "Rate-limited requests counted (process-local)")
RATE_LIMITER_BLOCKED          = Gauge("caddywaf_rate_limiter_blocked_requests", "Rate-limited requests blocked (process-local)")
RULE_HITS                     = Gauge("caddywaf_rule_hits",                     "Per-rule hit count",  ["rule_id"])
RULE_HITS_BY_PHASE            = Gauge("caddywaf_rule_hits_by_phase",            "Per-phase hit count", ["phase"])
INFO                          = Gauge("caddywaf_build_info",                    "Build information",   ["version"])


def scrape(url: str, timeout: float) -> None:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    TOTAL_REQUESTS.set(data["total_requests"])
    BLOCKED_REQUESTS.set(data["blocked_requests"])
    ALLOWED_REQUESTS.set(data["allowed_requests"])
    DNS_BLACKLIST_HITS.set(data["dns_blacklist_hits"])
    IP_BLACKLIST_HITS.set(data["ip_blacklist_hits"])
    GEOIP_BLOCKED.set(data["geoip_blocked"])
    RATE_LIMITER_REQUESTS.set(data["rate_limiter_requests"])
    RATE_LIMITER_BLOCKED.set(data["rate_limiter_blocked_requests"])

    INFO.labels(version=data.get("version", "unknown")).set(1)

    for rule_id, hits in data.get("rule_hits", {}).items():
        RULE_HITS.labels(rule_id=rule_id).set(hits)

    for phase, hits in data.get("rule_hits_by_phase", {}).items():
        RULE_HITS_BY_PHASE.labels(phase=str(phase)).set(hits)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target",   default="http://127.0.0.1:8080/waf_metrics",
                        help="WAF metrics endpoint URL")
    parser.add_argument("--interval", type=float, default=10.0,
                        help="Scrape interval in seconds")
    parser.add_argument("--timeout",  type=float, default=5.0,
                        help="HTTP timeout per scrape")
    parser.add_argument("--port",     type=int, default=8000,
                        help="Port for the exporter to listen on")
    args = parser.parse_args()

    start_http_server(args.port)
    print(f"Exporter listening on :{args.port}/metrics, scraping {args.target} every {args.interval}s")

    while True:
        try:
            scrape(args.target, args.timeout)
        except Exception as exc:  # pragma: no cover
            print(f"scrape error: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
```

### Run it

```bash
pip install requests prometheus-client
python3 exporter.py --target http://localhost:8080/waf_metrics
```

Verify:

```bash
curl -s http://localhost:8000/metrics | grep caddywaf_
```

## Prometheus configuration

Add a scrape job pointing at the exporter:

```yaml
scrape_configs:
  - job_name: caddywaf
    metrics_path: /metrics
    scrape_interval: 15s
    static_configs:
      - targets: ['exporter-host:8000']
```

Reload Prometheus (`SIGHUP`, or `curl -X POST http://prometheus:9090/-/reload`) and check **Status > Targets** — the `caddywaf` job should report `UP`.

## Grafana queries

Add Prometheus as a data source in Grafana, then use queries such as:

```promql
# Block rate (per second) over the last minute
deriv(caddywaf_blocked_requests[1m])

# Top 10 most-hit rules
topk(10, caddywaf_rule_hits)

# Rule hits by phase
sum by (phase) (caddywaf_rule_hits_by_phase)

# Allow vs. block over time
caddywaf_allowed_requests
caddywaf_blocked_requests

# Build info (table panel)
caddywaf_build_info
```

## Optional: run as a systemd service

```ini
# /etc/systemd/system/caddywaf-exporter.service
[Unit]
Description=Caddy WAF Prometheus exporter
After=network.target

[Service]
User=caddywaf
ExecStart=/usr/bin/python3 /opt/caddywaf/exporter.py --target http://127.0.0.1:8080/waf_metrics
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now caddywaf-exporter
```

## Caveats

- The values are **process-local** — when Caddy restarts they reset to zero. Use `irate(...[5m])` or `delta(...[5m])` to handle resets gracefully.
- The metrics endpoint is served by the WAF itself; if the request matches a blocking rule (e.g. an IP blacklist match), the metrics request itself is blocked. Whitelist the exporter's source IP (or use a separate site / route without the WAF directive for it).
- Do not expose `metrics_endpoint` to the public internet without authentication — there is no auth in the WAF; rely on a Caddy `basic_auth` block, an IP filter, or mTLS at the front door.
