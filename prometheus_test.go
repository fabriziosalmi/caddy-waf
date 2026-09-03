package caddywaf

import (
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

func promMiddleware(t *testing.T) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	return &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      5,
		PrometheusEndpoint:    "/metrics",
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

// TestPrometheusEndpoint pins the native Prometheus exposition (#118): after
// some traffic, /metrics returns the WAF counters and a request-duration
// histogram in the text format Prometheus scrapes.
func TestPrometheusEndpoint(t *testing.T) {
	m := promMiddleware(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	send := func(path string) {
		req := httptest.NewRequest(http.MethodGet, testURL+path, nil)
		req.RemoteAddr = "203.0.113.5:1234"
		require.NoError(t, m.ServeHTTP(httptest.NewRecorder(), req, next))
	}
	send("/ok")      // allowed
	send("/ok2")     // allowed
	send("/blockme") // blocked by the rule

	req := httptest.NewRequest(http.MethodGet, testURL+"/metrics", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(rec, req, next))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain; version=0.0.4")
	body := rec.Body.String()

	for _, want := range []string{
		"# TYPE caddywaf_total_requests counter",
		"caddywaf_blocked_requests ",
		"caddywaf_rule_hits{rule_id=\"block-uri\"} 1",
		"caddywaf_blocked_by_reason{reason=\"rule\"} 1",
		"# TYPE caddywaf_request_duration_seconds histogram",
		"caddywaf_request_duration_seconds_bucket{le=\"+Inf\"}",
		"caddywaf_request_duration_seconds_count ",
		"caddywaf_build_info{version=\"" + wafVersion + "\"} 1",
	} {
		assert.Containsf(t, body, want, "prometheus output must contain %q", want)
	}

	// The histogram count must equal the number of requests observed so far
	// (3 sends + this /metrics scrape counts once the deferred observe runs on a
	// later request; here at least the 3 sends + the in-flight scrape's own
	// observe happens after write, so count >= 3).
	countRe := regexp.MustCompile(`caddywaf_request_duration_seconds_count (\d+)`)
	m2 := countRe.FindStringSubmatch(body)
	require.Len(t, m2, 2)
	assert.GreaterOrEqual(t, m2[1], "3")
}
