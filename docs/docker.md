# Docker

The repository ships a [`Dockerfile`](../Dockerfile) and a [`docker-compose.yml`](../docker-compose.yml). This document describes both, and a few common operational patterns.

## Image build

```bash
docker build -t caddy-waf .
```

The build is a two-stage build:

### Stage 1 — `builder` (`golang:1.24-alpine`)

1. Installs `git` and `wget`, plus `xcaddy`.
2. Clones `https://github.com/fabriziosalmi/caddy-waf.git`.
3. Runs `go mod tidy`.
4. Downloads the GeoLite2 Country database from `https://git.io/GeoLite2-Country.mmdb`.
5. Compiles a Caddy binary with the WAF module via `xcaddy build --with github.com/fabriziosalmi/caddy-waf=./`.

> The Dockerfile clones from GitHub regardless of the build context. To use a local checkout (e.g. with uncommitted changes) modify the Dockerfile to `COPY . /app/caddy-waf` instead of `git clone`, or build with `xcaddy` outside Docker and `COPY` the binary in.

### Stage 2 — runtime (`alpine:latest`)

1. Copies `/app/caddy-waf/caddy` to `/usr/bin/caddy`.
2. Copies `GeoLite2-Country.mmdb`, `rules.json`, `ip_blacklist.txt`, `dns_blacklist.txt` into `/app/`.
3. Copies the local `Caddyfile` into `/app/`.
4. Creates a `caddy:caddy` non-root user, `chown`s `/app`, and `USER caddy`.
5. Exposes port `8080`.
6. Runs `caddy run --config /app/Caddyfile`.

## Running

```bash
docker run --rm -p 8080:8080 caddy-waf
```

| Flag | Effect |
|---|---|
| `-p 8080:8080` | Map host port `8080` to the container's HTTP port. Adjust the host side as needed. |
| `-d` | Detach. |
| `--name caddy-waf` | Name the container for easier management (`docker logs caddy-waf`). |
| `-v $(pwd)/Caddyfile:/app/Caddyfile:ro` | Mount a custom Caddyfile read-only. |
| `-v $(pwd)/rules.json:/app/rules.json` | Mount a custom rule set (read-write so `fsnotify` can detect updates). |
| `-v $(pwd)/ip_blacklist.txt:/app/ip_blacklist.txt` | Mount a custom IP blacklist. |
| `-v $(pwd)/dns_blacklist.txt:/app/dns_blacklist.txt` | Mount a custom DNS blacklist. |
| `-v $(pwd)/logs:/app/logs` | Persist the JSON log file (point `log_path` to `/app/logs/debug.json` in the Caddyfile). |

A typical production run, with all configuration mounted from the host:

```bash
docker run -d --name caddy-waf \
  -p 80:8080 \
  -v $(pwd)/Caddyfile:/app/Caddyfile:ro \
  -v $(pwd)/rules.json:/app/rules.json \
  -v $(pwd)/ip_blacklist.txt:/app/ip_blacklist.txt \
  -v $(pwd)/dns_blacklist.txt:/app/dns_blacklist.txt \
  -v $(pwd)/GeoLite2-Country.mmdb:/app/GeoLite2-Country.mmdb:ro \
  -v $(pwd)/logs:/app/logs \
  caddy-waf
```

## Docker Compose

The shipped [`docker-compose.yml`](../docker-compose.yml) is a minimal example. A more complete file:

```yaml
services:
  caddy-waf:
    build: .
    image: caddy-waf:latest
    container_name: caddy-waf
    restart: unless-stopped
    ports:
      - "80:8080"
    volumes:
      - ./Caddyfile:/app/Caddyfile:ro
      - ./rules.json:/app/rules.json
      - ./ip_blacklist.txt:/app/ip_blacklist.txt
      - ./dns_blacklist.txt:/app/dns_blacklist.txt
      - ./GeoLite2-Country.mmdb:/app/GeoLite2-Country.mmdb:ro
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "wget", "-q", "-O-", "http://localhost:8080/"]
      interval: 30s
      timeout: 5s
      retries: 3
```

```bash
docker compose up -d
docker compose logs -f caddy-waf
```

## Hot reload inside a container

`fsnotify` works inside containers as long as the watched files are on a normal mount (bind mount, named volume, or `tmpfs`). Edit the mounted `rules.json` from the host and the watcher inside the container will see the `WRITE` event and reload — see [dynamicupdates.md](dynamicupdates.md) for the reload matrix.

For settings that require a full `Provision` cycle (rate limiter, GeoIP, Tor, custom responses, log paths) you must reload Caddy itself:

```bash
docker exec caddy-waf caddy reload --config /app/Caddyfile
```

## Operational checklist

- **Pin the base image**. The shipped Dockerfile uses `golang:1.24-alpine` and `alpine:latest`. For reproducible builds pin `alpine:<version>`.
- **Run as non-root**. Already done by the Dockerfile (`USER caddy`). Do not switch to `root` for convenience.
- **Mount configuration read-only when possible**. Only the rule files and blacklists need to be writable for `fsnotify` to fire.
- **Expose `metrics_endpoint` only on a private network**. Use a separate Caddy site / route or a sidecar to apply authentication.
- **Persist the log file**. The JSON log written to `log_path` is otherwise lost when the container is replaced.
- **Set resource limits**. `--memory`, `--cpus` (or the equivalent Compose / Kubernetes settings).
- **Keep the GeoLite2 database fresh**. Re-build periodically or mount a managed copy from the host.
