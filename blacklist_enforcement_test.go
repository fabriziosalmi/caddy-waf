package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// writeBlacklist writes entries to a temp file and returns its path.
func writeBlacklist(t *testing.T, entries string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ip_blacklist*.txt")
	require.NoError(t, err)
	_, err = f.WriteString(entries)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// TestIPBlacklistIsActuallyPopulated guards against the trie being filled in a
// copy rather than in the trie the middleware consults.
//
// loadIPBlacklist used to take the trie by value, and both callers dereferenced
// their pointer to satisfy that signature. Every Insert therefore landed in a
// copy discarded on return: the middleware's trie stayed empty, while the
// loader still logged "IP blacklist loaded" with a non-zero entry count. The
// blacklist enforced nothing, silently, and the logs said otherwise.
func TestIPBlacklistIsActuallyPopulated(t *testing.T) {
	logger := zap.NewNop()
	path := writeBlacklist(t, "127.0.0.1\n203.0.113.7\n10.0.0.0/8\n2001:db8::1\n")

	m := &Middleware{logger: logger, blacklistLoader: NewBlacklistLoader(logger)}
	m.ipBlacklist = iptrie.NewTrie()
	require.NoError(t, m.loadIPBlacklist(path, m.ipBlacklist))

	for _, tc := range []struct {
		addr    string
		blocked bool
	}{
		{"127.0.0.1:53569", true},   // exact IPv4, with port as http.Request carries it
		{"127.0.0.1", true},         // exact IPv4, bare
		{"203.0.113.7:443", true},   // second exact entry
		{"10.1.2.3:80", true},       // inside the /8
		{"[2001:db8::1]:443", true}, // exact IPv6
		{"8.8.8.8:443", false},      // not listed
		{"11.0.0.1:80", false},      // just outside the /8
	} {
		assert.Equalf(t, tc.blocked, m.isIPBlacklisted(tc.addr),
			"isIPBlacklisted(%q)", tc.addr)
	}
}

// TestReloadConfigRepopulatesIPBlacklist covers the same defect on the hot-reload
// path, which had its own dereferencing call site.
func TestReloadConfigRepopulatesIPBlacklist(t *testing.T) {
	logger := zap.NewNop()
	path := writeBlacklist(t, "198.51.100.4\n")

	m := &Middleware{
		logger:          logger,
		blacklistLoader: NewBlacklistLoader(logger),
		IPBlacklistFile: path,
		ipBlacklist:     iptrie.NewTrie(),
	}
	require.NoError(t, m.ReloadConfig())

	assert.True(t, m.isIPBlacklisted("198.51.100.4:1234"),
		"a reloaded blacklist must be consulted, not discarded")
	assert.False(t, m.isIPBlacklisted("198.51.100.5:1234"))
}

// TestReloadConfigDoesNotDeadlock pins the hot-reload path against a
// self-deadlock on Go's non-reentrant RWMutex.
//
// ReloadConfig used to take m.mu and then call loadRules, which takes m.mu
// again. The goroutine blocked forever while still owning the write lock, so
// every later request stalled on the RLock in isDNSBlacklisted. Since the file
// watcher calls ReloadConfig whenever a blacklist file changes, editing one was
// enough to wedge the server. The failure mode is a hang, so this asserts on a
// deadline rather than on a return value.
func TestReloadConfigDoesNotDeadlock(t *testing.T) {
	logger := zap.NewNop()
	m := &Middleware{
		logger:          logger,
		blacklistLoader: NewBlacklistLoader(logger),
		IPBlacklistFile: writeBlacklist(t, "198.51.100.4\n"),
		ipBlacklist:     iptrie.NewTrie(),
		dnsBlacklist:    map[string]struct{}{},
		ruleCache:       NewRuleCache(),
		Rules:           map[int][]Rule{},
	}

	done := make(chan error, 1)
	go func() { done <- m.ReloadConfig() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("ReloadConfig deadlocked: it must not hold m.mu across loadRules")
	}

	// The write lock must have been released: a reader has to get through.
	readerDone := make(chan bool, 1)
	go func() { readerDone <- m.isDNSBlacklisted("example.com") }()
	select {
	case <-readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("a request-path reader blocked after ReloadConfig; the write lock was never released")
	}
}

// TestBlacklistedIPIsBlockedEndToEnd drives a full request through ServeHTTP,
// so the guarantee is "the client is refused", not merely "a lookup returns
// true". Without this, a future refactor could keep the trie correct and still
// fail to act on it.
func TestBlacklistedIPIsBlockedEndToEnd(t *testing.T) {
	logger := zap.NewNop()
	path := writeBlacklist(t, "192.0.2.10\n")

	m := &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		IPBlacklistFile:       path,
		Rules:                 map[int][]Rule{},
		AnomalyThreshold:      20,
		ruleCache:             NewRuleCache(),
		dnsBlacklist:          map[string]struct{}{},
		ipBlacklist:           iptrie.NewTrie(),
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
	require.NoError(t, m.loadIPBlacklist(path, m.ipBlacklist))

	reached := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		reached = true
		_, err := w.Write([]byte("UPSTREAM"))
		return err
	})

	t.Run("blacklisted IP never reaches the upstream", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodGet, testURL, nil)
		req.RemoteAddr = "192.0.2.10:41234"
		w := httptest.NewRecorder()
		require.NoError(t, m.ServeHTTP(w, req, next))

		assert.False(t, reached, "the upstream handler must not run")
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.NotContains(t, w.Body.String(), "UPSTREAM")
	})

	t.Run("an IP not on the list passes through", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodGet, testURL, nil)
		req.RemoteAddr = "192.0.2.11:41234"
		w := httptest.NewRecorder()
		require.NoError(t, m.ServeHTTP(w, req, next))

		assert.True(t, reached)
		assert.Equal(t, "UPSTREAM", w.Body.String())
	})

	t.Run("a forged X-Forwarded-For cannot skip the check", func(t *testing.T) {
		// The peer address is blacklisted; the client forges a clean XFF.
		// Consulting XFF *instead of* the peer address used to let this
		// through, making the whole blacklist bypassable with one header.
		reached = false
		req := httptest.NewRequest(http.MethodGet, testURL, nil)
		req.RemoteAddr = "192.0.2.10:41234"
		req.Header.Set("X-Forwarded-For", "8.8.8.8")
		w := httptest.NewRecorder()
		require.NoError(t, m.ServeHTTP(w, req, next))

		assert.False(t, reached, "a forged X-Forwarded-For must not bypass the blacklist")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("X-Forwarded-For is honoured for the blacklist", func(t *testing.T) {
		reached = false
		req := httptest.NewRequest(http.MethodGet, testURL, nil)
		req.RemoteAddr = "203.0.113.99:41234"
		req.Header.Set("X-Forwarded-For", "192.0.2.10, 70.41.3.18")
		w := httptest.NewRecorder()
		require.NoError(t, m.ServeHTTP(w, req, next))

		assert.False(t, reached, "the upstream handler must not run")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
