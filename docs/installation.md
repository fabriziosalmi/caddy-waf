# Installation

## Requirements

| Component | Minimum version | Source of truth |
|---|---|---|
| Go | **1.25.1** | [`go.mod`](https://github.com/fabriziosalmi/caddy-waf/blob/main/go.mod) — `go 1.25.1`, propagated from `caddy/v2` |
| Caddy | **v2.11.x** | [`go.mod`](https://github.com/fabriziosalmi/caddy-waf/blob/main/go.mod) — `github.com/caddyserver/caddy/v2 v2.11.4` |
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

The repository ships [`install.sh`](https://github.com/fabriziosalmi/caddy-waf/blob/main/install.sh), which performs an end-to-end setup: it ensures Go and `xcaddy` are present, clones (or pulls) the repository, downloads the GeoLite2 Country database, builds Caddy with the WAF, formats the bundled Caddyfile, and starts the server.

```bash
curl -fsSL -H "Pragma: no-cache" \
  https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

The script targets Go `1.25.11` for new installs and refuses to proceed if a present Go installation is older than `1.25.0`. Review the [source](https://github.com/fabriziosalmi/caddy-waf/blob/main/install.sh) before piping it into a shell.

A representative provisioning log:

```
INFO  Provisioning WAF middleware     {"log_level":"info","log_path":"debug.json","log_json":true,"anomaly_threshold":20}
INFO  http.handlers.waf  Tor exit nodes updated  {"count":1093}
INFO  WAF middleware version          {"version":"v0.4.14"}
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

> [!IMPORTANT]
> **Prefer `xcaddy` or the container image.** Caddy's maintainers have proposed
> moving `add-package`, `remove-package` and `upgrade` out of Caddy's core to
> discourage their use ([caddyserver/caddy#7010](https://github.com/caddyserver/caddy/issues/7010)):
> the commands call Caddy's shared build server, and using them in CI/CD is an
> anti-pattern. Raised for this project in
> [#138](https://github.com/fabriziosalmi/caddy-waf/issues/138) by a Caddy
> maintainer.
>
> The command works today and the module remains registered, so this section
> stays accurate. Treat it as a convenience for one-off, hand-operated installs
> — not as the way to build or deploy caddy-waf.

The module is registered in Caddy's package registry, so an existing Caddy v2.7+ binary can pull it in without a Go toolchain:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

This asks the Caddy build service for a binary containing your current module set plus `caddy-waf`, then replaces the binary in place (backing up the old one unless `--keep-backup` is passed). Pin a version with `@v0.4.14` if needed.

The module is also selectable on <https://caddyserver.com/download>.

See [add-package-guide.md](add-package-guide.md) for the full flow, removal, and troubleshooting.

## Method 5 — Docker

Images are published to GitHub Container Registry on every release tag, for `linux/amd64` and `linux/arm64`. No Go toolchain, no build step:

```bash
docker run --rm -p 8080:8080 ghcr.io/fabriziosalmi/caddy-waf:0.4.14
```

| Tag | Meaning |
|---|---|
| `0.4.14` | An exact release. **Prefer this in deployments.** |
| `0.4` | Latest patch of the 0.4 line. |
| `latest` | Latest release, whatever it currently is. |

The image tag carries **no `v` prefix**, unlike the Go module version: `@v0.4.14` for `add-package`, `:0.4.14` for `docker pull`.

See [docker.md](docker.md) for mounting rule files and blacklists, Docker Compose, and hot reload inside a container.

## Verifying the build

```bash
./caddy list-modules | grep waf
# http.handlers.waf

./caddy version
# v2.11.x ...
```

## Where to go next

Continue with [configuration.md](configuration.md) for every directive, or jump to [the bundled `Caddyfile`](https://github.com/fabriziosalmi/caddy-waf/blob/main/Caddyfile) for a working example.
