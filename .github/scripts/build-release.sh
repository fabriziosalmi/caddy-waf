#!/usr/bin/env bash
# Build one release archive: a Caddy binary with caddy-waf compiled in.
#
#   GOOS=linux GOARCH=amd64 TAG=v0.4.18 .github/scripts/build-release.sh
#
# Run from the repository root. Writes dist/caddy-waf_<tag>_<goos>_<goarch>.tar.gz
# holding the binary (caddy, or caddy.exe on Windows), LICENSE, README.md and
# the default rules.json.
#
# The module is a library (package caddywaf), so `go build` on it produces a Go
# archive, not a program. Release assets used to be exactly that. xcaddy builds
# the actual Caddy binary.
set -euo pipefail

: "${GOOS:?set GOOS}"
: "${GOARCH:?set GOARCH}"
TAG="${TAG:-}"
XCADDY="${XCADDY:-xcaddy}"
MODULE=github.com/fabriziosalmi/caddy-waf

# Build against the Caddy version go.mod requires, not the newest release
# xcaddy would otherwise pick (same rule as build-run-validate.yml).
CADDY_VERSION=$(go list -m -f '{{.Version}}' github.com/caddyserver/caddy/v2)

# Setting XCADDY_GO_BUILD_FLAGS replaces xcaddy's default flags, so they are
# restated here (-w -s, -trimpath, the build tags) next to the version stamp.
export XCADDY_GO_BUILD_FLAGS="-ldflags '-w -s -X ${MODULE}.ModuleVersion=${TAG}' -trimpath -tags nobadger,nomysql,nopgx"
export CGO_ENABLED=0

name="caddy-waf_${TAG:-dev}_${GOOS}_${GOARCH}"
bin=caddy
[ "$GOOS" = windows ] && bin=caddy.exe

stage="dist/${name}"
rm -rf "$stage"
mkdir -p "$stage"

"$XCADDY" build "$CADDY_VERSION" --with "${MODULE}=./" --output "${stage}/${bin}"
cp LICENSE README.md rules.json "$stage/"

# The binary must be a program for the target, not a Go package archive.
case "$GOOS" in
  linux)   want='ELF' ;;
  darwin)  want='Mach-O' ;;
  windows) want='PE32' ;;
  *)       want='' ;;
esac
if [ -n "$want" ] && ! file "${stage}/${bin}" | grep -q "$want"; then
  echo "error: ${stage}/${bin} is not a ${want} executable:" >&2
  file "${stage}/${bin}" >&2
  exit 1
fi

tar -C dist -czf "dist/${name}.tar.gz" "$name"
rm -rf "$stage"
echo "dist/${name}.tar.gz"
