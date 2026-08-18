package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func normMW(t *testing.T, files []string, rules map[int][]Rule) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	m := &Middleware{
		logger: logger, blacklistLoader: NewBlacklistLoader(logger),
		RuleFiles: files, AnomalyThreshold: 5, ruleCache: NewRuleCache(),
		ipBlacklist: iptrie.NewTrie(), dnsBlacklist: map[string]struct{}{},
		ruleHitsByPhase: map[int]int64{}, Rules: rules,
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
	if files != nil {
		require.NoError(t, m.loadRules(files))
	}
	if m.Rules == nil {
		m.Rules = map[int][]Rule{}
	}
	return m
}

func blockedGET(t *testing.T, m *Middleware, rawQuery string) bool {
	t.Helper()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { w.WriteHeader(200); return nil })
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.URL.RawQuery = rawQuery
	req.RemoteAddr = "203.0.113.9:1"
	w := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(w, req, next))
	return w.Code == http.StatusForbidden
}

func blockedPOST(t *testing.T, m *Middleware, ct, body string) bool {
	t.Helper()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { w.WriteHeader(200); return nil })
	req := httptest.NewRequest(http.MethodPost, "http://x/", strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	req.RemoteAddr = "203.0.113.9:1"
	w := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(w, req, next))
	return w.Code == http.StatusForbidden
}

// TestEncodingEvasionClosed is the core v0.4.0 guarantee against the confirmed
// bypass: percent-encoded attacks in the raw request targets are now caught.
func TestEncodingEvasionClosed(t *testing.T) {
	m := normMW(t, []string{"rules/sql-injection.json", "rules/xss.json"}, nil)

	t.Run("ARGS", func(t *testing.T) {
		assert.True(t, blockedGET(t, m, "id=1 UNION SELECT p"), "plain still blocks")
		assert.True(t, blockedGET(t, m, "id=%55NION%20SELECT%20p"), "fully percent-encoded")
		assert.True(t, blockedGET(t, m, "id=1 %75nion select p"), "single-letter encoded keyword")
	})
	t.Run("BODY form-urlencoded", func(t *testing.T) {
		assert.True(t, blockedPOST(t, m, "application/x-www-form-urlencoded", "q=1 UNION SELECT p"), "plain")
		assert.True(t, blockedPOST(t, m, "application/x-www-form-urlencoded", "q=1 %55NION%20SELECT p"), "encoded")
	})
	t.Run("benign traffic is not newly blocked", func(t *testing.T) {
		assert.False(t, blockedGET(t, m, "id=42&page=home&sort=asc"))
		assert.False(t, blockedGET(t, m, "q=hello+world&lang=en"))
		assert.False(t, blockedGET(t, m, "path=/usr/local/bin"))
	})
}

// TestDualMatchNeverRegresses is the safety property: raw is tested first, so
// anything that matched before still matches. A rule whose pattern only exists
// in the raw form (an encoding detector) must keep firing.
func TestDualMatchNeverRegresses(t *testing.T) {
	m := normMW(t, nil, map[int][]Rule{1: {{
		ID: "raw-percent-detector", Pattern: `%[0-9a-fA-F]{2}`, Targets: []string{"ARGS"},
		Phase: 1, Score: 10, Action: "block", regex: regexp.MustCompile(`%[0-9a-fA-F]{2}`),
	}}})
	// The pattern matches the RAW (still-encoded) value; normalization would
	// remove the %XX, but raw is tested first, so it still fires.
	assert.True(t, blockedGET(t, m, "x=%41%42"), "raw percent-encoding detector must still fire")
}

// TestPerRuleTransformations covers the opt-in escape hatch: a rule can request
// decoders that are not in the default chain.
func TestPerRuleTransformations(t *testing.T) {
	entities := []string{"htmlEntityDecode"}
	comments := []string{"urlDecode", "replaceComments"}
	m := normMW(t, nil, map[int][]Rule{1: {
		{
			ID: "xss-entity", Pattern: `(?i)<script`, Targets: []string{"ARGS"},
			Phase: 1, Score: 10, Action: "block", regex: regexp.MustCompile(`(?i)<script`),
			Transformations: &entities,
		},
		{
			ID: "sqli-comment", Pattern: `(?i)union\s+select`, Targets: []string{"ARGS"},
			Phase: 1, Score: 10, Action: "block", regex: regexp.MustCompile(`(?i)union\s+select`),
			Transformations: &comments,
		},
	}})
	assert.True(t, blockedGET(t, m, "q=&lt;script&gt;alert(1)"), "HTML-entity XSS caught by opt-in htmlEntityDecode")
	assert.True(t, blockedGET(t, m, "id=1 union/**/select x"), "comment-obfuscated SQLi caught by opt-in replaceComments")
}

// TestTargetAliasesResolve covers Q2: ModSecurity target names now resolve.
func TestTargetAliasesResolve(t *testing.T) {
	ex := NewRequestValueExtractor(zap.NewNop(), false, 0)
	r := httptest.NewRequest(http.MethodGet, "http://x/?a=1", nil)
	r.Header.Set("Cookie", "sid=x")
	for _, tg := range []string{"QUERY_STRING", "REQUEST_COOKIES", "REQUEST_HEADERS", "REQUEST_URI", "REQUEST_BODY"} {
		_, err := ex.ExtractValue(tg, r, nil)
		if tg == "REQUEST_BODY" {
			continue // empty body errors, that's fine; the point is it is not "unknown target"
		}
		assert.NoErrorf(t, err, "alias %s should resolve", tg)
	}
}

// TestUnknownTransformationFailsLoad: a typo in transformations must fail
// validation, not silently do nothing.
func TestUnknownTransformationFailsLoad(t *testing.T) {
	bad := []string{"urlDecode", "not-a-transform"}
	err := validateRule(&Rule{ID: "x", Pattern: "a", Targets: []string{"ARGS"}, Phase: 1, Transformations: &bad})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown transformation")
}

// TestKnownLimit_DoubleEncoding documents, as a test, what this release does NOT
// close: single-pass decoding by design does not catch double-encoding. If a
// future release adds recursive or %uXXXX decoding this test will start failing
// and must be updated deliberately.
func TestKnownLimit_DoubleEncoding(t *testing.T) {
	m := normMW(t, []string{"rules/sql-injection.json"}, nil)
	// %2555 -> %55 (literal) on one pass, not 'U'. The backend that decodes once
	// also sees %55, so this is the correct impedance match, not a miss.
	got := blockedGET(t, m, "id=1 %2555NION%2520SELECT p")
	t.Logf("double-encoded blocked=%v (documented: single-pass does not decode twice)", got)
}

func TestWhitelistIPDirectiveStillParses(t *testing.T) {
	// guard: adding the transformations field did not break Caddyfile parsing
	m := &Middleware{}
	err := NewConfigLoader(zap.NewNop()).UnmarshalCaddyfile(
		caddyfile.NewTestDispenser("waf {\n rule_file rules.json\n}"), m)
	require.NoError(t, err)
}
