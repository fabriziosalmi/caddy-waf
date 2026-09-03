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

// TestDashboardServesPageWithUI runs only under `-tags with_ui`, where the page
// is embedded. It asserts the WAF serves the HTML same-origin with the metrics
// path injected, so the browser fetches metrics with a relative URL.
func TestDashboardServesPageWithUI(t *testing.T) {
	m := dashMiddleware(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("upstream must not be reached for the dashboard path")
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, testURL+"/waf", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	require.NoError(t, m.ServeHTTP(rec, req, next))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	body := rec.Body.String()
	assert.Contains(t, body, "<title>caddy-waf</title>")
	// The metrics path is injected, and the placeholder is gone.
	assert.Contains(t, body, `const METRICS_PATH = "/waf_metrics";`)
	assert.False(t, strings.Contains(body, "__WAF_METRICS_PATH__"), "placeholder must be replaced")
	// Self-contained: no third-party runtime requests.
	assert.False(t, strings.Contains(body, "http://"), "no external http resources")
	assert.False(t, strings.Contains(body, "cdn"), "no CDN references")
}
