# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
