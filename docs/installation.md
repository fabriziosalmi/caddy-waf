# Installation

## Method 1: Quick Script Installation (Recommended)

The fastest and most reliable way to install caddy-waf:

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

## Method 2: Build with xcaddy

For users who prefer to build Caddy with xcaddy:

```bash
# Install xcaddy if you don't have it
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with the WAF module
xcaddy build --with github.com/fabriziosalmi/caddy-waf

# Verify the module is loaded
./caddy list-modules | grep waf
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

## Method 4: Using `caddy add-package` (Experimental)

> **⚠️ Important Note:** The `caddy add-package` command requires the module to be registered in Caddy's official module registry. This module is **not yet registered** in the registry, so this method will return an error: `github.com/fabriziosalmi/caddy-waf is not a registered Caddy module package path`. Please use Method 1 (Quick Script), Method 2 (xcaddy), or Method 3 (Build from Source) instead.

If the module gets registered in the future, you would be able to use:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

For more details, see the [add-package guide](add-package-guide.md).

Go to the [configuration](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/configuration.md) documentation section.

