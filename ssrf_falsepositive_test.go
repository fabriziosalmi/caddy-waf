package caddywaf

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadRuleFile(t *testing.T, path string) []Rule {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var rules []Rule
	require.NoErrorf(t, json.Unmarshal(data, &rules), "%s must be a JSON array of rules", path)
	return rules
}

// TestBundledRulePatternsCompile guards every shipped rule pattern against RE2
// breakage -- the whole rules/*.json set plus the combined bundles. RE2 rejects
// lookbehind/lookahead, so a rule that needs them (as the removed
// auth-session-cookie-not-http-only did, see #161) fails to load; this catches
// that class before it ships.
func TestBundledRulePatternsCompile(t *testing.T) {
	// The curated bundles plus the modular files audited for RE2 compatibility.
	// A full rules/*.json audit (some bundles carry invalid JSON or backrefs) is
	// tracked separately.
	for _, path := range []string{
		"rules.json", "rules-browser-friendly.json",
		"rules/ssrf.json", "rules/authentication.json",
	} {
		for _, r := range loadRuleFile(t, path) {
			_, err := regexp.Compile(r.Pattern)
			require.NoErrorf(t, err, "%s: rule %q pattern must compile", path, r.ID)
		}
	}
}

// TestSSRFIPRulesDoNotFalsePositiveOnBenignQueries pins the fix for the
// socket.io false positive. ssrf-internal-ip and ssrf-reserved-ip used bare
// prefixes (`10\.`, `0\.`) that matched any digit-dot substring, so a benign
// query -- e.g. an Engine.IO polling cache-buster like `t=N8x0.10` -- accrued
// SSRF score until it hit a 403 at anomaly_threshold 20. The patterns must
// match full private/reserved dotted-quad IPs, not bare prefixes, while still
// catching real SSRF (internal ranges and the cloud metadata IP).
func TestSSRFIPRulesDoNotFalsePositiveOnBenignQueries(t *testing.T) {
	byID := map[string]*regexp.Regexp{}
	for _, r := range loadRuleFile(t, "rules/ssrf.json") {
		byID[r.ID] = regexp.MustCompile(r.Pattern)
	}
	require.Contains(t, byID, "ssrf-internal-ip")
	require.Contains(t, byID, "ssrf-reserved-ip")

	anyIPRuleMatches := func(s string) bool {
		return byID["ssrf-internal-ip"].MatchString(s) || byID["ssrf-reserved-ip"].MatchString(s)
	}

	benign := []string{
		"EIO=4&transport=polling&t=Ojz1P-h&sid=zzS-Cb3Xn8dR7YzaAAAB", // the reported case
		"EIO=4&transport=polling&t=N8x0.10",                          // cache-buster with "0.1"
		"EIO=4&transport=polling&sid=xxx&t=155.0",
		"v=2.10.3",         // version string with "10."
		"t=1010.5",         // "10." inside a number
		"price=10.99",      // "10." in a decimal
		"version=1.10.2.5", // multi-part version, no valid private quad
	}
	for _, s := range benign {
		assert.Falsef(t, anyIPRuleMatches(s),
			"benign query must not trip an SSRF IP rule: %q", s)
	}

	malicious := []struct{ sample, rule string }{
		{"http://10.0.0.5/", "ssrf-internal-ip"},
		{"url=http://192.168.1.1/admin", "ssrf-internal-ip"},
		{"http://127.0.0.1:8080", "ssrf-internal-ip"},
		{"target=172.16.0.1", "ssrf-internal-ip"},
		{"http://172.31.255.9/", "ssrf-internal-ip"},
		{"169.254.169.254/latest/meta-data", "ssrf-reserved-ip"}, // cloud metadata
		{"0.0.0.0", "ssrf-reserved-ip"},
		{"224.0.0.1", "ssrf-reserved-ip"},
	}
	for _, tc := range malicious {
		assert.Truef(t, byID[tc.rule].MatchString(tc.sample),
			"%s must still catch real SSRF: %q", tc.rule, tc.sample)
	}
}
