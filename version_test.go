package caddywaf

import (
	"runtime/debug"
	"testing"
)

func buildInfo(main debug.Module, deps ...*debug.Module) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: main, Deps: deps}, true
	}
}

func TestResolveVersion(t *testing.T) {
	caddyMain := debug.Module{Path: "caddy", Version: "(devel)"}
	noInfo := func() (*debug.BuildInfo, bool) { return nil, false }

	cases := []struct {
		name     string
		injected string
		read     func() (*debug.BuildInfo, bool)
		want     string
	}{
		{
			name:     "ldflags value wins over build info",
			injected: "v9.9.9",
			read:     buildInfo(caddyMain, &debug.Module{Path: modulePath, Version: "v0.9.1"}),
			want:     "v9.9.9",
		},
		{
			// xcaddy build --with github.com/fabriziosalmi/caddy-waf@vX.Y.Z,
			// caddy add-package, caddyserver.com/download.
			name: "dependency version from build info",
			read: buildInfo(caddyMain,
				&debug.Module{Path: "github.com/caddyserver/caddy/v2", Version: "v2.11.9"},
				&debug.Module{Path: modulePath, Version: "v0.9.1"}),
			want: "v0.9.1",
		},
		{
			name: "replaced by a tagged module version",
			read: buildInfo(caddyMain, &debug.Module{
				Path: modulePath, Version: "v0.4.10",
				Replace: &debug.Module{Path: "example.com/fork/caddy-waf", Version: "v0.9.1-fork.1"},
			}),
			want: "v0.9.1-fork.1",
		},
		{
			// xcaddy build --with github.com/fabriziosalmi/caddy-waf=./
			name: "replaced by a local directory falls back",
			read: buildInfo(caddyMain, &debug.Module{
				Path: modulePath, Version: "v0.0.0-00010101000000-000000000000",
				Replace: &debug.Module{Path: "/src"},
			}),
			want: wafVersionDefault,
		},
		{
			name: "main module (devel) falls back",
			read: buildInfo(debug.Module{Path: modulePath, Version: "(devel)"}),
			want: wafVersionDefault,
		},
		{
			name: "main module stamped with a VCS tag",
			read: buildInfo(debug.Module{Path: modulePath, Version: "v0.9.1"}),
			want: "v0.9.1",
		},
		{
			name: "module absent from build info falls back",
			read: buildInfo(caddyMain),
			want: wafVersionDefault,
		},
		{
			name: "no build info falls back",
			read: noInfo,
			want: wafVersionDefault,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.injected, tc.read); got != tc.want {
				t.Fatalf("resolveVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}
