# Built-in dashboard

A read-only web dashboard for a live view of what the WAF is doing — requests allowed vs blocked, block rate, top rules, top offending IPs, per-country and per-phase breakdowns, and a tail of the most recent blocked requests. It is **served by the WAF itself**, same-origin with the metrics endpoint: no external stack, no CDN, no third-party runtime requests. The page is modular — structure (`ui/index.html`), style (`ui/dashboard.css`) and behaviour (`ui/dashboard.js`, split into decoupled config/store/view/api modules) are separate embedded files, served beneath the dashboard path.

Implementation: [`dashboard.go`](https://github.com/fabriziosalmi/caddy-waf/blob/main/dashboard.go) and [`ui/`](https://github.com/fabriziosalmi/caddy-waf/tree/main/ui).

## Opt-in at two levels

A dashboard is welcome in a homelab and unwanted surface on a hardened production edge, so it is **off unless you enable it explicitly, twice**:

1. **Build time** — it is compiled in only with the `with_ui` build tag, so a production binary need not carry the page at all.
2. **Run time** — even in a `with_ui` build, the `dashboard` directive turns it on. Upgrading never grows a new web surface on its own.

```sh
# Build a binary that includes the dashboard:
xcaddy build --with github.com/fabriziosalmi/caddy-waf
# (pass the with_ui tag to the Go build, e.g. GOFLAGS or an xcaddy --with build that sets -tags with_ui)
```

If the `dashboard` directive is set in a binary built **without** `with_ui`, the path returns a short notice explaining how to get the UI — never a blank page.

## Configuration

```caddyfile
waf {
    rule_file rules.json
    metrics_endpoint /waf_metrics   # required: the dashboard reads this
    dashboard        /waf           # serve the UI here
}
```

| Directive | Value | Meaning |
|---|---|---|
| `dashboard` | `<path>` | Path at which the dashboard is served (e.g. `/waf`). Must start with `/`. |

The dashboard reads [`metrics_endpoint`](/metrics) with a relative fetch (the path is injected into the page), so there is no CORS and no hardcoded host — it works wherever you run it. `metrics_endpoint` must be configured; without it the page shows a hint.

## Read-only

The dashboard only **reads** `/waf_metrics`. It cannot toggle rules, edit blocklists, or change any WAF state. Enabling it does not add any mutating surface.

> [!WARNING]
> ## Protect it — it is not authenticated on its own
>
> The dashboard and the metrics endpoint expose operational detail (your rules, traffic volumes, attacker IPs). The WAF does **not** add authentication of its own — put Caddy in front of it:
>
> ```caddyfile
> example.com {
>     @waf path /waf /waf_metrics*
>     basic_auth @waf {
>         admin $2a$14$...          # a bcrypt hash
>     }
>     route {
>         waf {
>             rule_file rules.json
>             metrics_endpoint /waf_metrics
>             dashboard /waf
>         }
>         reverse_proxy localhost:8080
>     }
> }
> ```
>
> Or gate it with `forward_auth`/mTLS, or keep it on an internal listener. Do not expose `/waf` and `/waf_metrics` publicly unauthenticated.

## What it shows

Everything comes from the metrics payload ([schema 2](/metrics#dashboard-fields-schema-2)):

- **Requests / Blocked / Allowed / block ratio**, each with a client-derived per-minute rate and sparkline (rates are computed in the browser by diffing snapshots; the server keeps no time series).
- **Blocked by reason** and **hits by phase**.
- **Top rules**, **top offending source IPs**, **blocks by country**.
- **Recent blocks** — a live tail of the most recent blocked requests: time, source IP + country, method, path, reason, rule id, score, status.

The theme follows the viewer's system light/dark preference automatically (and honours an explicit override). The page auto-refreshes (2–30s, selectable) and can be paused; it degrades gracefully to the last data if the endpoint becomes unreachable.
