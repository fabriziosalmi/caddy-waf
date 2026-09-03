package caddywaf

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Fail-safe behaviour audit (#113).

const validRuleFileJSON = `[
  {"id":"fs-block-uri","phase":1,"pattern":"/blockme","targets":["URI"],"severity":"HIGH","mode":"block","score":10,"description":"test"}
]`

func newRuleMiddleware(t *testing.T) *Middleware {
	t.Helper()
	return &Middleware{
		logger:    zap.NewNop(),
		mu:        sync.RWMutex{},
		ruleCache: NewRuleCache(),
	}
}

func countRules(m *Middleware) int {
	n := 0
	for _, rs := range m.Rules {
		n += len(rs)
	}
	return n
}

// TestReloadKeepsRulesWhenNewFileBecomesInvalid pins the fail-safe fix: a live
// rule file that is edited into invalid JSON must NOT wipe the in-memory rule
// set. loadRules previously assigned m.Rules before validating, so a bad reload
// left the WAF running with zero rules (fail-open). The reload must now fail and
// keep the previously loaded good rules.
func TestReloadKeepsRulesWhenNewFileBecomesInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	require.NoError(t, os.WriteFile(path, []byte(validRuleFileJSON), 0o644))

	m := newRuleMiddleware(t)
	require.NoError(t, m.loadRules([]string{path}))
	require.Equal(t, 1, countRules(m), "good rules must load initially")

	// Corrupt the file and reload.
	require.NoError(t, os.WriteFile(path, []byte("{ this is not valid json"), 0o644))
	err := m.loadRules([]string{path})

	require.Error(t, err, "a reload from an invalid file must return an error")
	assert.Equal(t, 1, countRules(m), "the previously loaded rules must be preserved on a failed reload")
}

// TestReloadKeepsRulesWhenFileDisappears covers the missing-file reload case.
func TestReloadKeepsRulesWhenFileDisappears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	require.NoError(t, os.WriteFile(path, []byte(validRuleFileJSON), 0o644))

	m := newRuleMiddleware(t)
	require.NoError(t, m.loadRules([]string{path}))
	require.Equal(t, 1, countRules(m))

	require.NoError(t, os.Remove(path))
	err := m.loadRules([]string{path})

	require.Error(t, err)
	assert.Equal(t, 1, countRules(m), "rules must survive a reload of a now-missing file")
}

// TestInitialLoadStillFailsClosed confirms the fix did not weaken startup: a
// fresh middleware (no prior rules) pointed at an invalid file still errors, so
// Provision refuses to start rather than running with zero rules.
func TestInitialLoadStillFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))

	m := newRuleMiddleware(t)
	err := m.loadRules([]string{path})

	require.Error(t, err, "initial load of an invalid file must fail (fail-closed startup)")
	assert.Equal(t, 0, countRules(m))
}

// TestGeoIPFailOpenDirective pins the new Caddyfile directive that exposes the
// GeoIP fail-open safety knob (previously JSON-only). Default remains
// fail-closed (false) when the directive is absent.
func TestGeoIPFailOpenDirective(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     string
		want    bool
		wantErr bool
	}{
		{"absent defaults to fail-closed", "waf {\n rule_file rules.json\n}", false, false},
		{"bare enables fail-open", "waf {\n rule_file rules.json\n geoip_fail_open\n}", true, false},
		{"explicit true", "waf {\n rule_file rules.json\n geoip_fail_open true\n}", true, false},
		{"explicit off", "waf {\n rule_file rules.json\n geoip_fail_open off\n}", false, false},
		{"invalid value errors", "waf {\n rule_file rules.json\n geoip_fail_open maybe\n}", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Middleware{}
			err := NewConfigLoader(zap.NewNop()).UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.cfg), m)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, m.GeoIPFailOpen)
		})
	}
}
