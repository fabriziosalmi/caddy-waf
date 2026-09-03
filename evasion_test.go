package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// Evasion & bypass corpus (#112). A systematic, repeatable set of malicious
// payloads wrapped in evasion techniques -- encoding (percent/double/unicode),
// case folding, comment/whitespace insertion, null bytes, and delivery via
// query vs body -- fired through the real WAF loaded with the shipped
// rules.json, asserting the attacks are still blocked. It is both a coverage
// record and a regression guard: if a rule change lets one of these through,
// this test fails.

func corpusMiddleware(t *testing.T) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	m := &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      5,
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		ruleHitsByPhase:       map[int]int64{},
		RuleFiles:             []string{"rules.json"},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(),
		topIPsBlocked:         map[string]int64{},
		blockedByReason:       map[string]int64{},
		geoIPStats:            map[string]int64{},
	}
	if err := m.loadRules(m.RuleFiles); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	return m
}

var corpusNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

// sendQuery sets the exact on-wire query bytes (bypassing url.Parse so raw
// evasion bytes reach the WAF as an attacker's socket would send them).
func corpusBlockedQuery(m *Middleware, onWireValue string) bool {
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.URL.RawQuery = "q=" + onWireValue
	req.RequestURI = "/search?q=" + onWireValue
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, corpusNext)
	return rec.Code == http.StatusForbidden
}

func corpusBlockedBody(m *Middleware, body string) bool {
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, corpusNext)
	return rec.Code == http.StatusForbidden
}

// TestEvasionCorpusQuery asserts the shipped rules block a malicious payload in
// the query string regardless of the evasion wrapping. Double-percent-encoding
// is caught by an encoding meta-rule (a %XX survives one decode). The
// %uXXXX case here is caught because a plaintext token (alert() leaks through --
// %uXXXX itself is not decoded (see docs/security.md); a fully %uXXXX-encoded
// payload is a known gap. Pinned so a future edit cannot regress this coverage.
func TestEvasionCorpusQuery(t *testing.T) {
	m := corpusMiddleware(t)
	enc := url.QueryEscape
	dbl := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "%", "%25") }

	cases := []struct{ name, onWire string }{
		// Path traversal / LFI
		{"traversal single-encoded", enc("../../../../etc/passwd")},
		{"traversal double-encoded", dbl("../../../../etc/passwd")},
		{"traversal mixed %2f", "..%2f..%2f..%2fetc%2fpasswd"},
		{"traversal %252e", "%252e%252e%252fetc%252fpasswd"},
		{"traversal null byte", enc("../../etc/passwd") + "%00.png"},
		// SQLi
		{"sqli tautology", enc("1' OR '1'='1")},
		{"sqli union", enc("1 UNION SELECT username,password FROM users")},
		{"sqli union mixed-case", enc("1 uNiOn SeLeCt username,password FROM users")},
		{"sqli inline-comment", enc("1 UNION/**/SELECT/**/1")},
		{"sqli double-encoded", dbl("1' OR '1'='1")},
		{"sqli padded-whitespace", enc("1'    OR    '1'='1")},
		// XSS
		{"xss script", enc("<script>alert(1)</script>")},
		{"xss mixed-case", enc("<ScRiPt>alert(1)</ScRiPt>")},
		{"xss double-encoded", dbl("<script>alert(1)</script>")},
		{"xss img onerror", enc("<img src=x onerror=alert(1)>")},
		{"xss svg onload", enc("<svg/onload=alert(1)>")},
		{"xss unicode-escape (alert() leaks)", "%u003cscript%u003ealert(1)%u003c/script%u003e"},
		// RCE / command injection
		{"rce semicolon", enc(";cat /etc/passwd")},
		{"rce pipe", enc("|cat /etc/passwd")},
		{"rce backticks", enc("`id`")},
		{"rce subshell", enc("$(id)")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Truef(t, corpusBlockedQuery(m, c.onWire), "evasion %q (on-wire q=%s) must be blocked", c.name, c.onWire)
		})
	}
}

// TestEvasionCorpusBody asserts the request body is inspected for SQLi, XSS and
// path traversal (command-injection rules target the query/args and headers, not
// the body, so they are exercised in TestEvasionCorpusQuery). It also pins the
// #112 fix that added a conservative
// body-targeted path-traversal rule: LFI delivered through a POST form field is
// now caught, while a single benign "../" in a body is NOT blocked (the rule
// requires repeated "../" or a sensitive-file path, to avoid false positives).
func TestEvasionCorpusBody(t *testing.T) {
	m := corpusMiddleware(t)

	blocked := []struct{ name, body string }{
		{"body sqli", "user=admin&q=1' OR '1'='1"},
		{"body xss", "c=<script>alert(1)</script>"},
		{"body traversal", "f=../../../../etc/passwd"},
		{"body traversal encoded", "f=..%2F..%2F..%2Fetc%2Fpasswd"},
		{"body sensitive file", "f=/proc/self/environ"},
	}
	for _, c := range blocked {
		t.Run(c.name, func(t *testing.T) {
			assert.Truef(t, corpusBlockedBody(m, c.body), "%s must be blocked in the body", c.name)
		})
	}

	// The conservative body-traversal rule must NOT fire on a single benign
	// relative path (proves the fix does not introduce a false positive).
	t.Run("benign single relative path is allowed", func(t *testing.T) {
		assert.Falsef(t, corpusBlockedBody(m, "path=../shared/config.js"),
			"a single '../' in a body must not be blocked by the traversal rule")
	})
}
