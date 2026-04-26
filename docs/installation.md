# Installation

## Requirements

| Component | Minimum version | Source of truth |
|---|---|---|
| Go | **1.25** | [`go.mod`](../go.mod) — `go 1.25` |
| Caddy | **v2.10.x** | [`go.mod`](../go.mod) — `github.com/caddyserver/caddy/v2 v2.10.2` |
| `xcaddy` | latest | [github.com/caddyserver/xcaddy](https://github.com/caddyserver/xcaddy) |
| MaxMind GeoLite2 Country MMDB | optional, only when using country block / whitelist | [maxmind.com](https://www.maxmind.com/) |
| MaxMind GeoLite2 ASN MMDB | optional, only when using `block_asns` | [maxmind.com](https://www.maxmind.com/) |

## Method 1 — Build with `xcaddy` (recommended)

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/fabriziosalmi/caddy-waf
./caddy list-modules | grep waf      # expect: http.handlers.waf
```

This produces a `./caddy` binary in the current directory with the WAF compiled in.

## Method 2 — Quick script

The repository ships [`install.sh`](../install.sh), which performs an end-to-end setup: it ensures Go and `xcaddy` are present, clones (or pulls) the repository, downloads the GeoLite2 Country database, builds Caddy with the WAF, formats the bundled Caddyfile, and starts the server.

```bash
curl -fsSL -H "Pragma: no-cache" \
  https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

The script targets Go `1.23.4` for new installs and refuses to proceed if a present Go installation is older than `1.22.3`. Review the [source](../install.sh) before piping it into a shell.

A representative provisioning log:

```
INFO  Provisioning WAF middleware     {"log_level":"info","log_path":"debug.json","log_json":true,"anomaly_threshold":20}
INFO  http.handlers.waf  Tor exit nodes updated  {"count":1093}
INFO  WAF middleware version          {"version":"v0.3.0"}
INFO  Rate limit configuration        {"requests":100,"window":10,"cleanup_interval":300,"paths":["/api/v1/.*"],"match_all_paths":false}
WARN  GeoIP database not found. Country blacklisting/whitelisting will be disabled  {"path":"GeoLite2-Country.mmdb"}
INFO  IP blacklist loaded             {"path":"ip_blacklist.txt","valid_entries":223770,"invalid_entries":0,"total_lines":223770}
INFO  DNS blacklist loaded            {"path":"dns_blacklist.txt","valid_entries":854479,"total_lines":854479}
INFO  WAF rules loaded successfully   {"total_rules":33,"rule_counts":"Phase 1: 17 rules, Phase 2: 16 rules, Phase 3: 0 rules, Phase 4: 0 rules, "}
INFO  WAF middleware provisioned successfully
```

## Method 3 — Build from source

```bash
git clone https://github.com/fabriziosalmi/caddy-waf.git
cd caddy-waf

go mod tidy
wget https://git.io/GeoLite2-Country.mmdb        # only if you intend to use GeoIP

xcaddy build --with github.com/fabriziosalmi/caddy-waf=./
./caddy fmt --overwrite
./caddy run
```

The `=./` form of `--with` instructs `xcaddy` to use the local checkout rather than pulling from the module proxy; this is the right choice when developing or applying local patches.

## Method 4 — `caddy add-package`

This module is **not registered** in Caddy's official package registry. Attempting `caddy add-package github.com/fabriziosalmi/caddy-waf` returns:

```
Error: download failed: HTTP 400: github.com/fabriziosalmi/caddy-waf is not a registered Caddy module package path
```

Use Method 1, 2, or 3 above. Background and the registration checklist are in [add-package-guide.md](add-package-guide.md) and [`CADDY_MODULE_REGISTRATION.md`](../CADDY_MODULE_REGISTRATION.md).

## Verifying the build

```bash
./caddy list-modules | grep waf
# http.handlers.waf

./caddy version
# v2.10.x ...
```

## Where to go next

Continue with [configuration.md](configuration.md) for every directive, or jump to [the bundled `Caddyfile`](../Caddyfile) for a working example.
