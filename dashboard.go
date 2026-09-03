package caddywaf

import (
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// isDashboardRequest reports whether r targets the configured dashboard path.
func (m *Middleware) isDashboardRequest(r *http.Request) bool {
	return m.DashboardEndpoint != "" && r.URL.Path == m.DashboardEndpoint
}

// serveDashboard serves the built-in read-only dashboard page.
//
// The page ships embedded under the `with_ui` build tag; without it, Assets is
// empty and the path returns a short notice rather than a blank 404, so the
// operator knows the directive is set but the binary was built without the UI.
// The page is served same-origin with the metrics endpoint, which is injected
// so the browser fetches it with a relative path (no CORS, no hardcoded host).
func (m *Middleware) serveDashboard(w http.ResponseWriter, r *http.Request) error {
	page, err := Assets.ReadFile("ui/index.html")
	if err != nil {
		m.logger.Debug("Dashboard requested but UI not compiled", zap.Error(err))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("caddy-waf dashboard is not available: this binary was built without the `with_ui` tag.\nRebuild with: xcaddy build --with github.com/fabriziosalmi/caddy-waf (and -tags with_ui).\n"))
		return nil
	}

	html := strings.ReplaceAll(string(page), "__WAF_METRICS_PATH__", m.MetricsEndpoint)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The dashboard is read-only and self-contained; forbid embedding and
	// third-party resources defensively.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
	return nil
}
