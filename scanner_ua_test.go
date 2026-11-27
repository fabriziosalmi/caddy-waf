package caddywaf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// FFUF's default User-Agent is "Fuzz Faster U Fool v<version>", which carries no
// "ffuf" token, so block-scanners let it through until the phrase was added.
func TestBlockScannersDetectsFFUF(t *testing.T) {
	cases := []struct {
		ua      string
		blocked bool
	}{
		{"Fuzz Faster U Fool v2.3.0", true},
		{"Fuzz Faster U Fool", true},
		{"fuzz faster u fool", true},
		{"ffuf", true},
		{"FFUF/2.3.0", true},
		{"Mozilla/5.0", false},
		{"curl/8.12.1", false},
	}
	for _, file := range []string{"rules.json", "rules-browser-friendly.json"} {
		m := fpMiddleware(t)
		m.AnomalyThreshold = 10
		m.ruleCache = NewRuleCache() // compiled regexes are cached by rule ID, shared by both files
		if err := m.loadRules([]string{file}); err != nil {
			t.Fatalf("loadRules(%s): %v", file, err)
		}
		for _, c := range cases {
			t.Run(file+" "+c.ua, func(t *testing.T) {
				assert.Equalf(t, c.blocked, fpBlockedUA(m, c.ua), "User-Agent %q", c.ua)
			})
		}
	}
}
