package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func dashMiddleware(t *testing.T) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	return &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      1000,
		DashboardEndpoint:     "/waf",
		MetricsEndpoint:       "/waf_metrics",
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		ruleHitsByPhase:       map[int]int64{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
}

func TestDashboardRouting(t *testing.T) {
	m := dashMiddleware(t)
	assert.True(t, m.isDashboardRequest(httptest.NewRequest("GET", "http://x/waf", nil)))
	assert.False(t, m.isDashboardRequest(httptest.NewRequest("GET", "http://x/other", nil)))

	m.DashboardEndpoint = ""
	assert.False(t, m.isDashboardRequest(httptest.NewRequest("GET", "http://x/waf", nil)),
		"unset directive must not route")
}

// TestDashboardServedThroughServeHTTP checks the path is handled by the WAF
// (same-origin) and short-circuits to next. In a binary built WITHOUT the
// with_ui tag the embedded Assets are empty, so the page is unavailable and the
// handler returns a plain notice with 404 -- never the upstream. With the tag,
// TestDashboardServesPageWithUI (dashboard_with_ui_test.go) asserts the page.
func TestDashboardServedThroughServeHTTP(t *testing.T) {
	m := dashMiddleware(t)
	upstreamHit := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, testURL+"/waf", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(rec, req, next))
	assert.False(t, upstreamHit, "the dashboard path must be served by the WAF, not proxied upstream")
	if !hasEmbeddedUI() {
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Body.String(), "with_ui")
	}
}

// hasEmbeddedUI reports whether the UI page is compiled in.
func hasEmbeddedUI() bool {
	_, err := Assets.ReadFile("ui/index.html")
	return err == nil
}
