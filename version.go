package caddywaf

import "runtime/debug"

// modulePath is this module's import path as it appears in a Caddy binary's
// build info.
const modulePath = "github.com/fabriziosalmi/caddy-waf"

// readBuildInfo is a variable so tests can substitute the build info.
var readBuildInfo = debug.ReadBuildInfo

// resolveVersion decides the version the WAF reports, in this order:
//
//  1. ModuleVersion, when a build injects it with -ldflags -X (the release
//     workflow and the Docker image do, from the git tag);
//  2. the version Go recorded for this module in the binary's build info.
//     This is what `xcaddy build --with github.com/fabriziosalmi/caddy-waf@vX`,
//     `caddy add-package` and caddyserver.com/download produce, so those
//     binaries report the version they were really built at;
//  3. wafVersionDefault.
//
// A dependency that is replaced by a local directory (`--with ...=./`) carries
// no usable version: Go records a placeholder for the requirement and an empty
// version for the replacement, so such builds fall through to step 3.
func resolveVersion(injected string, read func() (*debug.BuildInfo, bool)) string {
	if injected != "" {
		return injected
	}
	if bi, ok := read(); ok && bi != nil {
		if v := moduleVersion(bi); v != "" {
			return v
		}
	}
	return wafVersionDefault
}

// moduleVersion returns this module's version from the build info, or "" when
// the binary does not carry a real one.
func moduleVersion(bi *debug.BuildInfo) string {
	if bi.Main.Path == modulePath {
		// Built as the main module (go test, go build in this repo): Go
		// reports "(devel)" unless it could stamp a VCS tag.
		return usable(bi.Main.Version)
	}
	for _, dep := range bi.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil {
			return usable(dep.Replace.Version)
		}
		return usable(dep.Version)
	}
	return ""
}

// usable rejects the values Go uses when it has no real version: an empty
// string, "(devel)", and the zero pseudo-version a `replace` requirement gets.
func usable(v string) string {
	switch v {
	case "", "(devel)", "v0.0.0-00010101000000-000000000000":
		return ""
	}
	return v
}
