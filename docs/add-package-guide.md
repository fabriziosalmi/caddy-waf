# Using `caddy add-package` to Install Caddy WAF

This guide demonstrates how to install the Caddy WAF module using Caddy's built-in `caddy add-package` command.

## Prerequisites

- Caddy v2.7 or higher already installed on your system
- Internet connection (to download the custom binary)
- Appropriate permissions to replace the Caddy binary

## Quick Installation

To add the Caddy WAF module to your existing Caddy installation:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

That's it! The command will:
1. Detect your current Caddy installation and modules
2. Send a build request to Caddy's remote build service
3. Download a new binary with the WAF module included
4. Backup your current Caddy binary
5. Replace the binary with the new one

## Verification

After installation, verify the module is loaded:

```bash
caddy list-modules | grep waf
```

Expected output:
```
http.handlers.waf
```

You can also check the full list of modules:
```bash
caddy list-modules --packages
```

## Usage Example

Once installed, you can use the WAF module in your Caddyfile:

```caddyfile
{
    auto_https off
    admin localhost:2019
}

:8080 {
    log {
        output stdout
        format console
        level INFO
    }

    route {
        waf {
            metrics_endpoint /waf_metrics
            rule_file rules.json
            ip_blacklist_file ip_blacklist.txt
            dns_blacklist_file dns_blacklist.txt
            anomaly_threshold 10
            
            rate_limit {
                requests 100
                window 60s
                cleanup_interval 300s
            }
        }

        respond "Hello, World!" 200
    }
}
```

## Advanced Options

### Keep Backup

By default, the command deletes the backup after successful replacement. To keep the backup:

```bash
caddy add-package --keep-backup github.com/fabriziosalmi/caddy-waf
```

The backup will be saved as `caddy.backup` in the same directory.

### Version Pinning

To install a specific version of the module:

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf@vX.Y.Z
```

Replace `vX.Y.Z` with the desired version tag (e.g., `v0.1.3`). You can find available versions on the [GitHub releases page](https://github.com/fabriziosalmi/caddy-waf/releases).

## Troubleshooting

### Command Not Found

If the `caddy add-package` command is not available, you may be using an older version of Caddy:

```bash
caddy version
```

You need Caddy v2.7 or higher. To update Caddy, visit [caddyserver.com/download](https://caddyserver.com/download) and follow the instructions for your operating system and architecture.

### Permission Denied

If you get a permission denied error, run the command with sudo:

```bash
sudo caddy add-package github.com/fabriziosalmi/caddy-waf
```

### Build Service Unavailable

If Caddy's remote build service is unavailable, you can build from source instead:

```bash
# Install xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build with the module
xcaddy build --with github.com/fabriziosalmi/caddy-waf
```

### Module Already Exists

If you get an error that the package already exists, the module is already installed. To update:

```bash
# Remove the package first
caddy remove-package github.com/fabriziosalmi/caddy-waf

# Then add it again
caddy add-package github.com/fabriziosalmi/caddy-waf
```

## Removing the Module

To remove the Caddy WAF module:

```bash
caddy remove-package github.com/fabriziosalmi/caddy-waf
```

## Comparison with Other Installation Methods

| Method | Pros | Cons |
|--------|------|------|
| `caddy add-package` | Simple, no build tools needed, keeps existing modules | Requires internet, depends on remote build service |
| `xcaddy build` | Full control, works offline (after dependencies cached), good for development | Requires Go and build tools, more complex |
| Quick script | Automated setup with sample configs | Downloads and builds from source, requires build tools |

## Next Steps

- Read the [Configuration Guide](configuration.md) to customize your WAF rules
- Learn about [Rate Limiting](ratelimit.md) configuration
- Explore [GeoIP Blocking](geoblocking.md) features
- Check out the [Metrics](metrics.md) endpoint for monitoring

## References

- [Caddy Command Line Documentation](https://caddyserver.com/docs/command-line)
- [Caddy Module System](https://caddyserver.com/docs/extending-caddy)
- [xcaddy Build Tool](https://github.com/caddyserver/xcaddy)
