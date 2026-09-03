package caddywaf

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ReDoS resistance audit (#111).
//
// caddy-waf compiles every rule pattern with Go's regexp package, which uses
// the RE2 engine. RE2 matches in time linear in the length of the input,
// independent of the pattern: it has no backtracking, so the catastrophic
// super-linear blowup that powers a classic ReDoS attack cannot occur here.
// There is no PCRE/backtracking fallback anywhere in the match path
// (handler.go and ratelimiter.go both call regexp.MatchString).
//
// These tests turn that guarantee into an executable, regression-proof check:
// canonical "evil regex" inputs and long adversarial strings are thrown at both
// a deliberately pathological pattern and every shipped rule, and each match
// must complete within a wall-clock budget that a backtracking engine would
// blow past by orders of magnitude while RE2 stays sub-millisecond.
//
// The residual cost is linear: total per-request work is O(input length x rule
// count), bounded by MaxRequestBodySize (default 10MB) and the server's header
// limits. That is a capacity concern, not a ReDoS one, and the knob to bound it
// is request size -- see docs/security.md.

// perMatchBudget is deliberately generous so the test is not flaky on a loaded
// CI runner, yet still separates RE2 (sub-millisecond here) from a backtracking
// engine, which on these inputs would take seconds to minutes or never finish.
const perMatchBudget = 2 * time.Second

// mustMatchWithin runs one regex match and fails if it does not return within
// perMatchBudget. The match runs in a goroutine so a pathological hang is
// reported as a test failure instead of wedging the whole run.
func mustMatchWithin(t *testing.T, re *regexp.Regexp, input, label string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = re.MatchString(input)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(perMatchBudget):
		t.Fatalf("%s: match did not complete within %s on a %d-byte input -- possible super-linear pattern", label, perMatchBudget, len(input))
	}
}

// redosInputs returns adversarial strings shaped to trigger catastrophic
// backtracking in an engine that backtracks: long homogeneous runs with a
// single failing tail, repeated separators, encodings, and long token streams
// resembling real request values (paths, query strings, cookies).
func redosInputs() []string {
	const n = 50000
	return []string{
		strings.Repeat("a", n) + "!",
		strings.Repeat("a", n),
		strings.Repeat("1", n) + "x",
		strings.Repeat("/", n),
		strings.Repeat("../", n/3),
		strings.Repeat("..\\", n/3),
		strings.Repeat("%2e", n/3),
		strings.Repeat("A1", n/2) + "@",
		strings.Repeat("x=1&", n/4),
		strings.Repeat(" ", n) + ";",
		strings.Repeat("<", n),
		strings.Repeat("'", n),
		strings.Repeat("http://", n/7),
		strings.Repeat("\t", n) + "\n",
	}
}

// TestRuleCorpusIsReDoSResistant runs the adversarial corpus against every
// shipped rule's compiled pattern (the curated sets plus every rules/*.json
// bundle) and asserts each match completes within budget. This proves RE2's
// linear-time guarantee holds in practice for the real ruleset -- and would
// catch a future change that somehow introduced a super-linear matcher.
func TestRuleCorpusIsReDoSResistant(t *testing.T) {
	bundles, err := filepath.Glob("rules/*.json")
	require.NoError(t, err)
	paths := append([]string{"rules.json", "rules-browser-friendly.json"}, bundles...)

	inputs := redosInputs()
	for _, path := range paths {
		for _, r := range loadRuleFile(t, path) {
			re, err := regexp.Compile(r.Pattern)
			require.NoErrorf(t, err, "%s: rule %q must compile", path, r.ID)
			for _, in := range inputs {
				mustMatchWithin(t, re, in, path+" rule "+r.ID)
			}
		}
	}
}

// TestRE2NeutralisesCatastrophicPatterns documents the guarantee at the engine
// level: patterns that are textbook ReDoS killers under a backtracking engine
// -- nested quantifiers over an overlapping class -- run in linear time under
// RE2. Each is matched against a long failing input and must return promptly.
func TestRE2NeutralisesCatastrophicPatterns(t *testing.T) {
	evil := []string{
		`(a+)+$`,
		`(a*)*$`,
		`(a|a)*$`,
		`(a|aa)+$`,
		`(.*a){20}$`,
		`([a-zA-Z]+)*$`,
	}
	input := strings.Repeat("a", 60000) + "!" // matches the prefix, fails the anchor
	for _, pat := range evil {
		re := regexp.MustCompile(pat)
		mustMatchWithin(t, re, input, "catastrophic pattern "+pat)
	}
}
