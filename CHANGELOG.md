# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.3.2] - 2026-04-26

### Security
Patched 3 critical and 10 high severity Dependabot alerts by upgrading the affected dependencies to their fixed versions:

- `github.com/caddyserver/caddy/v2` v2.10.2 → v2.11.2 — fixes 4 high (FastCGI split_path Unicode case-folding bypass, MatchHost case-sensitivity bypass on >100 hosts, MatchPath %xx case normalization bypass, mTLS silent fail-open on missing CA file) and 2 medium (admin API CSRF on `/load`, file matcher glob sanitization).
- `google.golang.org/grpc` v1.78.0 → v1.79.3 — fixes 1 critical (authorization bypass via missing leading slash in `:path`).
- `github.com/jackc/pgx/v5` v5.8.0 → v5.9.2 — fixes 1 critical (memory-safety) and 1 low (SQL injection via dollar-quoted placeholder confusion).
- `github.com/smallstep/certificates` v0.29.0 → v0.30.2 — fixes 1 critical (unauthenticated certificate issuance via SCEP `UpdateReq` MessageType=18) and 1 low (TPM EKU validation index-out-of-bounds panic).
- `go.opentelemetry.io/otel` v1.39.0 → v1.43.0 — fixes 1 high (multi-value `baggage` header DoS amplification).
- `go.opentelemetry.io/otel/sdk` v1.39.0 → v1.43.0 — fixes 2 high (BSD `kenv` PATH hijacking; arbitrary code execution via PATH hijacking).
- `github.com/go-jose/go-jose/v4` v4.1.3 → v4.1.4 — fixes 1 high (JWE decryption panic).
- `github.com/go-jose/go-jose/v3` v3.0.4 → v3.0.5 — fixes 1 high (JWE decryption panic).
- `github.com/slackhq/nebula` v1.9.7 → v1.10.3 — fixes 1 high (blocklist bypass via ECDSA signature malleability).
- `github.com/cloudflare/circl` upgraded to v1.6.3 — fixes 1 low (incorrect `secp384r1` `CombinedMult` calculation).
- `filippo.io/edwards25519` upgraded to v1.2.0 — fixes 1 low (`MultiScalarMult` invalid results when receiver is not the identity).

No source-code changes required; the WAF compiles and the full unit test suite passes against the upgraded dependency tree.

### Changed
- Bumped version constant `wafVersion` to `v0.3.2`.

## [v0.3.1] - 2026-04-26

### Documentation
- Rewrote `README.md`, `MODULE.md`, `caddyfile.example`, and the entire `docs/` tree to be 1:1 accurate with the current source code.
- `docs/configuration.md` now lists every Caddyfile directive recognised by `config.go`, every JSON-only field on the `Middleware` struct, the precise Phase 1 evaluation order, and the parser- vs. `Provision`-time defaults.
- `docs/rules.md` documents the JSON tag mismatch on `Rule.Action` (struct tag is `mode`, while the bundled rule files commonly use `action`), so authors know which key is actually parsed.
- `docs/ratelimit.md` corrects the `match_all_paths` semantics to match `ratelimiter.go` (`true` ⇒ rate-limit every request; `false` + non-empty `paths` ⇒ rate-limit only matching paths).
- `docs/dynamicupdates.md` adds an explicit reload matrix showing which settings are reloaded by `fsnotify` and which require `caddy reload`.
- `docs/metrics.md` documents the actual response schema returned by `handleMetricsRequest` and clarifies that all counters are process-local and reset on restart.
- `docs/prometheus.md` switches the example exporter from `Counter.inc(absolute)` to `Gauge.set(absolute)` to match the WAF's monotonic process-local counter semantics.
- `caddyfile.example` no longer references non-existent directives (`country_block`, `custom_response { … }` block form).
- Removed emoji from all user-facing documentation.

### Changed
- Bumped version constant `wafVersion` to `v0.3.1`.

## [v0.3.0] - 2026-02-22

### Fixed
- Resolved duplicate response headers when a custom block response was emitted.
- IP blacklist loader now accepts CIDR notation in addition to single IPs (`net.ParseCIDR` is tried before `net.ParseIP`).

## [v0.2.0] - 2026-01-17

### Fixed
- Fixed potential panic in `isIPBlacklisted()` when parsing malformed IP addresses - now uses `netip.ParseAddr()` instead of `netip.MustParseAddr()`.
- Fixed type assertion panic in `processRuleMatch()` - now uses safe `getLogID()` helper function.
- Fixed potential panic in `extractIP()` and `getClientIP()` when handling empty or malformed input.

### Added
- Added 30-second HTTP client timeout in `tor.go` to prevent hanging requests during Tor exit node list fetches.
- Added comprehensive input validation in `Validate()` method for negative threshold/limit values.
- Added parameter validation in `NewRateLimiter()` to ensure positive values.

### Changed
- Updated installation documentation to clarify that `caddy add-package` is not available (module not registered in Caddy's package registry).
- Reordered installation methods in documentation to recommend Quick Script and xcaddy as primary options.
- Updated `CADDY_MODULE_REGISTRATION.md` with current registration status.

### Documentation
- Added warnings about `caddy add-package` limitations in README.md, installation.md, and add-package-guide.md.

## [v0.1.6] - 2025-12-10

### Fixed
- Minor bug fixes and stability improvements.

## [v0.1.5] - 2025-12-08
### Fixed
- Fixed critical bug where POST request bodies were lost or truncated by using `io.MultiReader` to restore the full body stream (fixes #76).

## [v0.1.4] - 2025-12-06

### Security
- Fixed Panic vulnerability in `quic-go` by upgrading to `v0.54.0` (requires Caddy v2.10.x and Go 1.25).
- Addressed Dependabot Alert #7.

### Changed
- Upgraded Caddy dependency to `v2.10.2`.
- Upgraded Go requirement to `1.25`.
- Improved CI workflows to use Go 1.25 for build and release.

## [v0.1.3] - 2025-12-06
### Fixed
- Downgraded `quic-go` to `v0.48.2` and Caddy to `v2.9.1` to temporarily resolve Go version conflicts (superseded by v0.1.4).
- Fixed import grouping for `gci` linter compliance.
- Fixed GitHub Actions release workflow.

## [v0.1.2] - 2025-12-06
### Added
- SOTA Engineering patterns (Zero-Copy headers, Wait-Free Ring Buffer, Circuit Breaker).
- ASN Blocking support.
- Configurable Request Body size limit.
- GeoIP Fail Open configuration.
