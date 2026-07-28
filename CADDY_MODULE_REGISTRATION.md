# Caddy Module Registration — Status

Tracks the registration of `github.com/fabriziosalmi/caddy-waf` in Caddy's
package registry, which is what makes the module appear on
<https://caddyserver.com/download> and installable with `caddy add-package`.

## Current status: REGISTERED

Claimed 2026-07-28 at 10:05:52 UTC, at version `v0.3.5`. Verified against the
build service endpoint that `add-package` calls:

```console
$ curl -s -o caddy -w "HTTP %{http_code} bytes=%{size_download}\n" \
    "https://caddyserver.com/api/download?p=github.com%2Ffabriziosalmi%2Fcaddy-waf&os=linux&arch=amd64"
HTTP 200 bytes=48586914
```

and in the registry index:

```console
$ curl -s "https://caddyserver.com/api/packages?q=caddy-waf"
{
  "path": "github.com/fabriziosalmi/caddy-waf",
  "published": "2026-07-28T10:05:52.532759Z",
  "listed": true,
  "available": true,
  "modules": [{"name": "http.handlers.waf", ...}]
}
```

The module documentation rendered on caddyserver.com is extracted from the
doc comment on the `Middleware` struct in [types.go](types.go). Editing that
comment changes what users read on Caddy's site.

## Do not reintroduce `&Middleware{}`

Registering a package makes the registry run a **static analyzer** over the
source to discover which Caddy modules it registers. That analyzer is
deliberately simple and accepts only two forms as the argument to
`caddy.RegisterModule`:

- a composite literal — `caddy.RegisterModule(Foo{})`
- `new()` — `caddy.RegisterModule(new(Foo))`

Until v0.3.4 this module used:

```go
caddy.RegisterModule(&Middleware{}) // parses as ast.UnaryExpr -> rejected
```

`&Middleware{}` is a `*ast.UnaryExpr` wrapping the literal, not a literal, so
the scan aborted and the portal reported only:

```
Sorry, something went wrong:
unable to scan modules in package github.com/fabriziosalmi/caddy-waf
Please include this error ID if reporting: <uuid>
```

That message never names the offending line, which is why earlier attempts
(error ids `d9ae3bd6-bc8f-4f8a-a0de-dcff0399e7a9` and
`2b782e50-057d-4dac-bbd5-4cd1c1188669`, logged at v0.0.6) went undiagnosed for
so long and were wrongly assumed to be transient server-side faults. The same
failure and its resolution are documented in the Caddy community thread
[Unable to register module in the
portal](https://caddy.community/t/unable-to-register-module-in-the-portal/33572),
where Matt Holt quotes the underlying analyzer error:

> `unexpected argument to RegisterModule(): &ast.UnaryExpr{...} - expect either composite literal or new()`

v0.3.5 switched both `caddy.RegisterModule` and `ModuleInfo.New` to
`new(Middleware)`. The forms are semantically identical — each allocates a
zeroed `Middleware` and yields a pointer — so there is no behavioural change.
The pointer is required either way: `CaddyModule` has a pointer receiver and
`Middleware` carries mutexes that must not be copied.

`TestRegisterModuleArgumentIsScannable` in
[module_registration_test.go](module_registration_test.go) parses the package's
own AST and fails the build if this regresses. Do not delete it.

## Maintenance

- **New releases are picked up automatically**; the registry resolves the latest
  tag. Use **Rescan** on <https://caddyserver.com/account> to force a refresh —
  for example after changing the `Middleware` doc comment, since that is what
  the module documentation page shows.
- **Verifying a release is installable**, before announcing it:

  ```console
  $ xcaddy build --with github.com/fabriziosalmi/caddy-waf@vX.Y.Z
  $ ./caddy list-modules | grep waf
  http.handlers.waf
  ```

  Use `@vX.Y.Z`, not `=./`. CI builds with `--with github.com/fabriziosalmi/caddy-waf=./`,
  a local `replace`, which verifies the working tree but **not** that the
  published module resolves and builds from the Go proxy — which is the path the
  registry actually exercises.
- **If a future registration or rescan fails**, capture the error `id` verbatim
  and quote it when asking the Caddy maintainers; it is what lets them find the
  server-side log. The portal message alone is not diagnostic.
