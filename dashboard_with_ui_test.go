//go:build with_ui

package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveDash(t *testing.T, m *Middleware, path string) *httptest.ResponseRecorder {
	t.Helper()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatalf("upstream must not be reached for dashboard path %q", path)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, testURL+path, nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(rec, req, next))
	return rec
}

// TestDashboardServesPageWithUI runs only under `-tags with_ui`, where the page
// is embedded. It asserts the WAF serves the modular assets same-origin with the
// metrics path and base path injected, so the browser fetches CSS/JS/metrics
// with relative URLs.
func TestDashboardServesPageWithUI(t *testing.T) {
	m := dashMiddleware(t) // DashboardEndpoint "/waf", MetricsEndpoint "/waf_metrics"

	// index.html
	rec := serveDash(t, m, "/waf")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	body := rec.Body.String()
	assert.Contains(t, body, "<title>caddy-waf</title>")
	assert.Contains(t, body, `content="/waf_metrics"`, "metrics path injected into the meta tag")
	assert.Contains(t, body, `href="/waf/dashboard.css"`, "base path injected into the stylesheet link")
	assert.Contains(t, body, `src="/waf/dashboard.js"`, "base path injected into the script src")
	assert.NotContains(t, body, "__WAF_METRICS_PATH__")
	assert.NotContains(t, body, "__BASE__")
	assert.NotContains(t, body, "http://", "no external resources")
	assert.NotContains(t, body, "cdn", "no CDN references")

	// modular assets served beneath the endpoint
	css := serveDash(t, m, "/waf/dashboard.css")
	assert.Equal(t, http.StatusOK, css.Code)
	assert.Contains(t, css.Header().Get("Content-Type"), "text/css")
	assert.Contains(t, css.Body.String(), ":root")

	js := serveDash(t, m, "/waf/dashboard.js")
	assert.Equal(t, http.StatusOK, js.Code)
	assert.Contains(t, js.Header().Get("Content-Type"), "javascript")
	assert.Contains(t, js.Body.String(), "wafDashboard")

	// unknown asset under the endpoint is a 404, not the page
	assert.Equal(t, http.StatusNotFound, serveDash(t, m, "/waf/nope.png").Code)
	assert.False(t, strings.Contains(js.Body.String(), "__BASE__"))
}
