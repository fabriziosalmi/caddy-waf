# `caddy add-package` — Status and Reference

> **Important.** This module is **not** registered in Caddy's official package registry at `caddyserver.com`. Attempting to install it with `caddy add-package` returns:
>
> ```
> Error: download failed: HTTP 400: github.com/fabriziosalmi/caddy-waf is not a registered Caddy module package path
> ```
>
> Use one of the supported installation methods documented in [installation.md](installation.md) instead:
>
> - [Build with `xcaddy`](installation.md#method-1--build-with-xcaddy-recommended) (recommended)
> - [Quick script](installation.md#method-2--quick-script)
> - [Build from source](installation.md#method-3--build-from-source)

This page is retained as a reference in case the module is registered in the future. Until then, every command shown below will fail.

## Prerequisites (if registration ever completes)

- Caddy v2.7 or newer (the `add-package` command was introduced in 2.7).
- Network access from the Caddy host to `caddyserver.com`.
- Permission to replace the running Caddy binary.

## Hypothetical install

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

If the registration succeeds, the command would:

1. Detect the currently running Caddy and its module set.
2. Send a build request to the Caddy build service.
3. Download a new binary that includes the existing modules **plus** `caddy-waf`.
4. Back up the current Caddy binary (deleted unless `--keep-backup` is passed).
5. Replace the Caddy binary in place.

Verify:

```bash
caddy list-modules | grep waf
# Expected: http.handlers.waf
```

## Hypothetical version pinning

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf@vX.Y.Z
```

`vX.Y.Z` is any tag from the [GitHub Releases](https://github.com/fabriziosalmi/caddy-waf/releases) page.

## Hypothetical removal

```bash
caddy remove-package github.com/fabriziosalmi/caddy-waf
```

## Why `add-package` does not work today

The Caddy build service maintains an allow-list of registered package paths. Until the maintainer of `caddy-waf` registers `github.com/fabriziosalmi/caddy-waf` through `https://caddyserver.com/account/register-package`, the build service refuses requests for it. The registration history and prior error references are tracked in [`CADDY_MODULE_REGISTRATION.md`](../CADDY_MODULE_REGISTRATION.md).

## Use this instead

The recommended flow on a host that already has `xcaddy` (and hence Go) installed:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/fabriziosalmi/caddy-waf
./caddy version
./caddy list-modules | grep waf
```

If Go is not available, run the bundled `install.sh` (see [installation.md](installation.md#method-2--quick-script)) which installs Go and `xcaddy` on first use.

## Troubleshooting

### `command not found: caddy add-package`

You are running Caddy older than 2.7. Update Caddy and retry — but note the registration warning above still applies.

### `permission denied`

The new binary cannot replace the existing one. Re-run with `sudo`, or run `add-package` from a directory where the user has write access and copy the resulting binary into place manually.

### `Error: download failed: HTTP 400: ... is not a registered Caddy module package path`

Expected. Use one of the build paths from [installation.md](installation.md).

## References

- Caddy command line documentation: <https://caddyserver.com/docs/command-line>
- Extending Caddy: <https://caddyserver.com/docs/extending-caddy>
- `xcaddy`: <https://github.com/caddyserver/xcaddy>
- Module registration tracker: [`CADDY_MODULE_REGISTRATION.md`](../CADDY_MODULE_REGISTRATION.md)
