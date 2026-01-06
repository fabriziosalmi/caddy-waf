# Installation

## Method 1: Using `caddy add-package` (Recommended)

If you already have Caddy installed, you can add the WAF plugin directly:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

This command will download and install a new Caddy binary with the WAF module included. It uses Caddy's remote build service to compile a custom binary with the module.

**Advantages:**
- No need to install Go or build tools
- Keeps your existing Caddy modules intact
- Automatic backup of your current binary
- Quick and simple installation

**Options:**
- `--keep-backup` - Keep the backup of your previous Caddy binary

**Note:** This is an experimental Caddy feature introduced in Caddy v2.7.

After installation, verify the module is loaded:
```bash
caddy list-modules | grep waf
```

You should see `http.handlers.waf` in the output.

## Method 2: Quick Script Installation

```bash
curl -fsSL -H "Pragma: no-cache" https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/install.sh | bash
```

**Example Output:**

```
INFO    Provisioning WAF middleware     {"log_level": "info", "log_path": "debug.json", "log_json": true, "anomaly_threshold": 10}
INFO    http.handlers.waf       Updated Tor exit nodes in IP blacklist  {"count": 1077}
INFO    WAF middleware version  {"version": "v0.0.0-20250115164938-7f35253f2ffc"}
INFO    Rate limit configuration        {"requests": 100, "window": 10, "cleanup_interval": 300, "paths": ["/api/v1/.*", "/admin/.*"], "match_all_paths": false}
WARN    GeoIP database not found. Country blocking/whitelisting will be disabled        {"path": "GeoLite2-Country.mmdb"}
INFO    IP blacklist loaded successfully        {"file": "ip_blacklist.txt", "valid_entries": 3, "total_lines": 3}
INFO    DNS blacklist loaded successfully       {"file": "dns_blacklist.txt", "valid_entries": 2, "total_lines": 2}
INFO    Rules loaded    {"file": "rules.json", "total_rules": 70, "invalid_rules": 0}
INFO    WAF middleware provisioned successfully
```

## Method 3: Build from Source (Advanced)

For development or if you need full control over the build process:

```bash
# Step 1: Clone the caddy-waf repository from GitHub
git clone https://github.com/fabriziosalmi/caddy-waf.git

# Step 2: Navigate into the caddy-waf directory
cd caddy-waf

# Step 3: Clean up and update the go.mod file
go mod tidy

# Step 4: Fetch and install the required Go modules
go get github.com/caddyserver/caddy/v2
go get github.com/caddyserver/caddy/v2/caddyconfig/caddyfile
go get github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile
go get github.com/caddyserver/caddy/v2/modules/caddyhttp
go get github.com/oschwald/maxminddb-golang
go get github.com/fsnotify/fsnotify
go get -v github.com/fabriziosalmi/caddy-waf
go mod tidy

# Step 5: Download the GeoLite2 Country database (required for country blocking/whitelisting)
wget https://git.io/GeoLite2-Country.mmdb

# Step 6: Build Caddy with the caddy-waf module
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./

# Step 7: Fix Caddyfile format
caddy fmt --overwrite

# Step 8: Run the compiled Caddy server
./caddy run
```

Go to the [configuration](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/configuration.md) documentation section.

