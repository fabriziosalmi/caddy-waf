# `caddy add-package`

> [!IMPORTANT]
> **This is not the recommended way to install caddy-waf.** Caddy's maintainers
> have proposed moving `add-package`, `remove-package` and `upgrade` out of
> Caddy's core to discourage their use
> ([caddyserver/caddy#7010](https://github.com/caddyserver/caddy/issues/7010)):
> the commands call Caddy's shared build server, and periodic use from CI/CD is
> an anti-pattern. Raised for this project in
> [#138](https://github.com/fabriziosalmi/caddy-waf/issues/138) by a Caddy
> maintainer.
>
> Build with [`xcaddy`](installation.md#method-1--build-with-xcaddy-recommended)
> or run the [container image](installation.md#method-5--docker) instead. Both
> are reproducible, pinnable, and do not depend on someone else's build service.
>
> The command still works and the module remains registered, so this page is
> accurate — treat it as a convenience for a one-off, hand-operated install.

`github.com/fabriziosalmi/caddy-waf` is registered in Caddy's package registry
(since 2026-07-28), so it can be added to an existing Caddy binary without a Go
toolchain. It is also selectable on <https://caddyserver.com/download>.

For registration status and history see
[`CADDY_MODULE_REGISTRATION.md`](https://github.com/fabriziosalmi/caddy-waf/blob/main/CADDY_MODULE_REGISTRATION.md).

## Requirements

- Caddy v2.7 or newer (`add-package` was introduced in 2.7).
- Network access from the Caddy host to `caddyserver.com`.
- Permission to replace the running Caddy binary.

## Install

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf
```

This will:

1. Detect the currently running Caddy and its module set.
2. Send a build request to the Caddy build service.
3. Download a new binary containing the existing modules **plus** `caddy-waf`.
4. Back up the current binary (deleted unless `--keep-backup` is passed).
5. Replace the Caddy binary in place.

Verify:

```bash
caddy list-modules | grep waf
# expect: http.handlers.waf
```

## Pin a version

```bash
caddy add-package github.com/fabriziosalmi/caddy-waf@v0.4.14
```

Any tag from the [Releases](https://github.com/fabriziosalmi/caddy-waf/releases)
page works. Without a version the build service uses the latest tag.

Note that v0.3.3 and earlier carry a high-severity denial-of-service
([GHSA-gfj3-cmff-q8wh](https://github.com/fabriziosalmi/caddy-waf/security/advisories/GHSA-gfj3-cmff-q8wh)),
fixed in v0.3.4; do not pin below v0.3.4.

## Remove

```bash
caddy remove-package github.com/fabriziosalmi/caddy-waf
```

## When to build with xcaddy instead

`add-package` replaces a binary in place using a remote build service. Prefer
[`xcaddy`](installation.md#method-1--build-with-xcaddy-recommended) when you
need to build from a fork or an untagged commit, pin the Caddy version itself,
build in an air-gapped environment, or produce reproducible artifacts in CI:

```bash
xcaddy build --with github.com/fabriziosalmi/caddy-waf
```

## Troubleshooting

### `command not found: caddy add-package`

You are running Caddy older than 2.7. Update Caddy.

### `permission denied`

The new binary cannot replace the existing one. Re-run with `sudo`, or run
`add-package` from a directory the user can write to and move the resulting
binary into place manually.

### `Error: download failed: HTTP 400: ... is not a registered Caddy module package path`

Check the import path for typos. Go module paths are not URLs, so no `https://`
prefix and no trailing slash. If the path is correct and the error persists, the
registration may have been removed — see
[`CADDY_MODULE_REGISTRATION.md`](https://github.com/fabriziosalmi/caddy-waf/blob/main/CADDY_MODULE_REGISTRATION.md).

## References

- Caddy command line: <https://caddyserver.com/docs/command-line>
- Extending Caddy: <https://caddyserver.com/docs/extending-caddy>
- `xcaddy`: <https://github.com/caddyserver/xcaddy>
