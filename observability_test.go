package caddywaf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func obsMiddleware(t *testing.T) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	return &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      5,
		MetricsEndpoint:       "/waf_metrics",
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		ruleHitsByPhase:       map[int]int64{},
		provisionTime:         time.Now(),
		topIPsBlocked:         map[string]int64{},
		blockedByReason:       map[string]int64{},
		geoIPStats:            map[string]int64{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		Rules: map[int][]Rule{1: {{
			ID: "block-uri", Pattern: "/blockme", Targets: []string{"URI"},
			Phase: 1, Score: 10, Action: "block", regex: regexp.MustCompile("/blockme"),
		}}},
	}
}

// TestMetricsM1Payload pins the dashboard backend slice (#143 M1): blocked
// requests populate the recent-blocks tail and the aggregates, the payload stays
// back-compatible, and the new sections are shaped as the frozen schema expects.
func TestMetricsM1Payload(t *testing.T) {
	m := obsMiddleware(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	block := func(remote string) {
		req := httptest.NewRequest(http.MethodPost, testURL+"/blockme?x=1", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		require.NoError(t, m.ServeHTTP(rec, req, next))
		require.Equal(t, http.StatusForbidden, rec.Code, "the rule must block")
	}
	// IP A blocked 3x, IP B 2x.
	block("203.0.113.7:1111")
	block("203.0.113.7:2222")
	block("203.0.113.7:3333")
	block("198.51.100.9:4444")
	block("198.51.100.9:5555")

	// Scrape the metrics endpoint.
	req := httptest.NewRequest(http.MethodGet, testURL+"/waf_metrics", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rec := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(rec, req, next))
	require.Equal(t, http.StatusOK, rec.Code)

	var p map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))

	// Back-compat: the v0.4.x keys are still there.
	for _, k := range []string{"total_requests", "blocked_requests", "rule_hits", "rule_hits_by_phase", "version"} {
		assert.Contains(t, p, k, "back-compat key %q must remain", k)
	}

	// New envelope.
	assert.EqualValues(t, 2, p["schema_version"])
	assert.Contains(t, p, "server_time_ms")
	assert.Contains(t, p, "uptime_seconds")

	// blocked_by_reason: all five were rule blocks.
	reasons := p["blocked_by_reason"].(map[string]any)
	assert.EqualValues(t, 5, reasons["rule"])

	// recent: five entries, newest first, with the expected shape.
	recent := p["recent"].(map[string]any)
	assert.EqualValues(t, recentBlocksCap, recent["cap"])
	items := recent["items"].([]any)
	require.Len(t, items, 5)
	first := items[0].(map[string]any)
	assert.Equal(t, "198.51.100.9", first["ip"], "newest block first")
	assert.Equal(t, "rule", first["reason"])
	assert.Equal(t, "block-uri", first["rule_id"])
	assert.EqualValues(t, http.StatusForbidden, first["status"])
	assert.Equal(t, "POST", first["method"])

	// top_ips: A(3) before B(2); two distinct.
	topIPs := p["top_ips"].(map[string]any)
	assert.EqualValues(t, 2, topIPs["distinct_seen"])
	ips := topIPs["items"].([]any)
	require.GreaterOrEqual(t, len(ips), 2)
	top := ips[0].(map[string]any)
	assert.Equal(t, "203.0.113.7", top["ip"])
	assert.EqualValues(t, 3, top["blocked"])

	// top_rules: the rule fired five times.
	rules := p["top_rules"].([]any)
	require.NotEmpty(t, rules)
	r0 := rules[0].(map[string]any)
	assert.Equal(t, "block-uri", r0["id"])
	assert.EqualValues(t, 5, r0["hits"])
}
