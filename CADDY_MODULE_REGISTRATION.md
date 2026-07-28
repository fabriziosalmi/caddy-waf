# Caddy Module Registration — Status

Tracks whether `github.com/fabriziosalmi/caddy-waf` is registered in Caddy's
package registry, which is what makes the module appear on
<https://caddyserver.com/download> and installable with `caddy add-package`.

## Current status: NOT REGISTERED

Verified 2026-07-28 against the build service endpoint that `add-package` calls:

```console
$ curl -s "https://caddyserver.com/api/download?p=github.com%2Ffabriziosalmi%2Fcaddy-waf&os=linux&arch=amd64"
{"status_code":400,"error":{"message":"github.com/fabriziosalmi/caddy-waf is not a registered Caddy module package path","id":"aed165cf-9d85-4b97-9b65-c5404988d648"}}
```

Until this returns a build, `caddy add-package github.com/fabriziosalmi/caddy-waf`
fails and users must build with `xcaddy`. See [docs/installation.md](docs/installation.md).

## Module readiness: verified ready

The registry validates a package by resolving it from the Go module proxy and
building it. That exact path was reproduced end to end on 2026-07-28 against the
**published** module — not a local `replace` — and it succeeds:

```console
$ xcaddy build --with github.com/fabriziosalmi/caddy-waf@v0.3.4
go: downloading github.com/fabriziosalmi/caddy-waf v0.3.4
[INFO] Build complete: ./caddy

$ ./caddy version
v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0=

$ ./caddy list-modules | grep waf
http.handlers.waf
```

Checked alongside it:

| Requirement | Status |
|---|---|
| Module path matches `go.mod` (`github.com/fabriziosalmi/caddy-waf`) | OK |
| Semantic import versioning (`/vN` suffix required only at v2+; this module is v0.x) | Not applicable |
| Resolvable on `proxy.golang.org` at the latest tag | OK — `v0.3.4` |
| Builds against current Caddy from the proxy | OK — Caddy v2.11.4 |
| Registers module ID `http.handlers.waf` at runtime | OK |
| Cross-compiles for linux/amd64, linux/arm64, windows/amd64 | OK |

Note that CI builds with `xcaddy build --with github.com/fabriziosalmi/caddy-waf=./`,
a local `replace`. That verifies the working tree but **not** that the published
module resolves and builds from the proxy, which is what the registry does. When
diagnosing a registration failure, always reproduce with `@<tag>` rather than `=./`.

## What is left

Registration is a web form behind a GitHub login; there is no API for it.

1. Sign in at <https://caddyserver.com/account>.
2. Click **Register package**.
3. Package import path: `github.com/fabriziosalmi/caddy-waf`
4. Version: `v0.3.4` (the field is optional; the registry resolves the latest tag otherwise).
5. Re-run the `curl` above. A `200` with a binary means it is live; a `400` with a
   fresh error `id` means it still failed — quote that id when asking the Caddy
   maintainers, since it is what lets them find the server-side log.

## Root cause of the earlier failures — fixed in v0.3.5

Registering a package does more than resolve and build the module: the registry
runs a **static analyzer** over the source to discover which Caddy modules the
package registers. That analyzer is deliberately simple, and it only accepts two
forms as the argument to `caddy.RegisterModule`:

- a composite literal — `caddy.RegisterModule(Foo{})`
- `new()` — `caddy.RegisterModule(new(Foo))`

Anything else fails. Until v0.3.4 this module used:

```go
caddy.RegisterModule(&Middleware{}) // parses as ast.UnaryExpr -> rejected
```

`&Middleware{}` is a `*ast.UnaryExpr` wrapping the literal, not a literal, so the
scan aborts and the portal reports the generic:

```
Sorry, something went wrong:
unable to scan modules in package github.com/fabriziosalmi/caddy-waf
Please include this error ID if reporting: <uuid>
```

That message never names the offending line, which is why the earlier attempts
(error ids `d9ae3bd6-bc8f-4f8a-a0de-dcff0399e7a9` and
`2b782e50-057d-4dac-bbd5-4cd1c1188669`, logged while the module was at v0.0.6)
were never diagnosed. The same failure and its resolution are documented in the
Caddy community thread [Unable to register module in the
portal](https://caddy.community/t/unable-to-register-module-in-the-portal/33572),
where Matt Holt identifies the underlying analyzer error:

> `unexpected argument to RegisterModule(): &ast.UnaryExpr{...} - expect either composite literal or new()`

**v0.3.5 switches both `caddy.RegisterModule` and `ModuleInfo.New` to `new(Middleware)`.**
The forms are semantically identical — each allocates a zeroed `Middleware` and
yields a pointer — so there is no behavioural change; it only makes the source
legible to the scanner. `Middleware` must stay a pointer here: `CaddyModule` has a
pointer receiver, and the struct carries mutexes that must not be copied.

Do not reintroduce `&Middleware{}` in either place, or registration will break
again on the next version bump.
