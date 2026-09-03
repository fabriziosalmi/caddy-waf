---
title: Live demo
---

# Live demo

This is the **real** built-in dashboard (the page shipped in the WAF) running on **generated sample data** — no backend, nothing is collected. Watch the counters climb, the sparklines move, and the recent-blocks tail scroll. Change the refresh interval or pause it; it follows your system light/dark theme.

<iframe
  src="/dashboard-demo.html"
  title="caddy-waf dashboard demo"
  loading="lazy"
  style="width:100%;height:860px;border:1px solid var(--vp-c-divider);border-radius:10px;margin-top:8px"></iframe>

<p style="margin-top:10px"><a href="/dashboard-demo.html" target="_blank" rel="noopener">Open the demo full-screen ↗</a></p>

## In production

The same page reads live figures from your WAF's [`/waf_metrics`](/metrics), served same-origin. It is **read-only** and **opt-in** — compiled in with the `with_ui` build tag and enabled with the `dashboard` directive. See [Dashboard](/dashboard) to run it, and protect it behind Caddy auth.

```caddyfile
waf {
    rule_file rules.json
    metrics_endpoint /waf_metrics
    dashboard /waf
}
```
