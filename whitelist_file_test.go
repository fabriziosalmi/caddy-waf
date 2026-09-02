package caddywaf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

// TestWhitelistFileLoadsAndCombinesWithInline pins that whitelist_file entries
// are loaded and exempt addresses, alongside inline whitelist_ip entries, and
// that a malformed line is skipped rather than failing the whole load.
func TestWhitelistFileLoadsAndCombinesWithInline(t *testing.T) {
	logger := zap.NewNop()
	dir := t.TempDir()
	path := writeFile(t, dir, "allow.txt",
		"# provider ranges\n203.0.113.7\n198.51.100.0/24\nnot-an-ip\n")

	m := &Middleware{
		logger:          logger,
		IPWhitelist:     []string{"192.0.2.5"}, // inline
		IPWhitelistFile: path,
	}
	require.NoError(t, m.rebuildIPWhitelist())

	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"203.0.113.7:12345", true}, // exact, from file
		{"198.51.100.42:80", true},  // inside the file CIDR
		{"192.0.2.5:443", true},     // inline entry
		{"8.8.8.8:53", false},       // not whitelisted
	} {
		assert.Equalf(t, tc.want, m.isIPWhitelisted(tc.addr), "isIPWhitelisted(%q)", tc.addr)
	}
}

// TestWhitelistFileHotReloadViaReloadConfig pins that a change to the whitelist
// file is picked up by ReloadConfig, the hot-reload path the watcher drives.
func TestWhitelistFileHotReloadViaReloadConfig(t *testing.T) {
	logger := zap.NewNop()
	dir := t.TempDir()
	path := writeFile(t, dir, "allow.txt", "203.0.113.7\n")

	m := &Middleware{
		logger:          logger,
		blacklistLoader: NewBlacklistLoader(logger),
		IPWhitelistFile: path,
	}
	require.NoError(t, m.rebuildIPWhitelist())
	require.True(t, m.isIPWhitelisted("203.0.113.7:1"))
	require.False(t, m.isIPWhitelisted("198.51.100.9:1"))

	require.NoError(t, os.WriteFile(path, []byte("203.0.113.7\n198.51.100.9\n"), 0o644))
	require.NoError(t, m.ReloadConfig())

	assert.True(t, m.isIPWhitelisted("198.51.100.9:1"), "a new whitelist entry must be enforced after reload")
	assert.True(t, m.isIPWhitelisted("203.0.113.7:1"))
}

// TestWhitelistFileWatcherReloadsOnAtomicRename ties whitelist_file to the
// directory watcher: an atomic update (write temp + rename) is hot-reloaded
// end to end, exercising the same path a maintained feed would use.
func TestWhitelistFileWatcherReloadsOnAtomicRename(t *testing.T) {
	logger := zap.NewNop()
	dir := t.TempDir()
	path := filepath.Join(dir, "ip_whitelist.txt")
	require.NoError(t, os.WriteFile(path, []byte("203.0.113.7\n"), 0o644))

	m := &Middleware{
		logger:          logger,
		blacklistLoader: NewBlacklistLoader(logger),
		IPWhitelistFile: path,
	}
	require.NoError(t, m.rebuildIPWhitelist())
	require.True(t, m.isIPWhitelisted("203.0.113.7:1"))
	require.False(t, m.isIPWhitelisted("198.51.100.9:1"))

	m.startFileWatcher([]string{path})
	time.Sleep(150 * time.Millisecond) // let the goroutine arm its directory watch

	writeAtomic(t, dir, path, "203.0.113.7\n198.51.100.9\n")

	require.Eventually(t, func() bool { return m.isIPWhitelisted("198.51.100.9:1") },
		3*time.Second, 25*time.Millisecond,
		"an atomic rename of the whitelist file must hot-reload the exemptions")
}

// TestParseWhitelistFileDirective pins the Caddyfile directive wiring.
func TestParseWhitelistFileDirective(t *testing.T) {
	cl := NewConfigLoader(zap.NewNop())
	m := &Middleware{logger: zap.NewNop()}
	d := caddyfile.NewTestDispenser(`whitelist_file /etc/caddy/allow.txt`)
	d.Next() // consume the directive name
	require.NoError(t, cl.parseWhitelistFile(d, m))
	assert.Equal(t, "/etc/caddy/allow.txt", m.IPWhitelistFile)
}
