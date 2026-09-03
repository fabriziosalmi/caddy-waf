package caddywaf

import (
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// dashboardAssets maps a request path suffix (relative to DashboardEndpoint) to
// an embedded file and its content type. index.html is templated at serve time;
// the CSS and JS are served verbatim. Keeping the page modular (structure /
// style / behaviour in separate files) rather than one inlined blob is the
// point of serving more than index.html.
var dashboardAssets = map[string]struct {
	file, mime string
	template   bool
}{
	"":               {"ui/index.html", "text/html; charset=utf-8", true},
	"/":              {"ui/index.html", "text/html; charset=utf-8", true},
	"/dashboard.css": {"ui/dashboard.css", "text/css; charset=utf-8", false},
	"/dashboard.js":  {"ui/dashboard.js", "application/javascript; charset=utf-8", false},
}

// isDashboardRequest reports whether r targets the dashboard path or one of its
// assets served beneath it.
func (m *Middleware) isDashboardRequest(r *http.Request) bool {
	if m.DashboardEndpoint == "" {
		return false
	}
	p := r.URL.Path
	return p == m.DashboardEndpoint || strings.HasPrefix(p, m.DashboardEndpoint+"/")
}

// serveDashboard serves the built-in read-only dashboard and its assets.
//
// The page ships embedded under the `with_ui` build tag; without it, Assets is
// empty and the path returns a short notice rather than a blank 404. index.html
// is served same-origin with the metrics endpoint, which -- together with the
// dashboard's own base path -- is injected so the browser fetches everything
// with relative URLs (no CORS, no hardcoded host).
func (m *Middleware) serveDashboard(w http.ResponseWriter, r *http.Request) error {
	suffix := strings.TrimPrefix(r.URL.Path, m.DashboardEndpoint)
	asset, ok := dashboardAssets[suffix]
	if !ok {
		http.NotFound(w, r)
		return nil
	}

	body, err := Assets.ReadFile(asset.file)
	if err != nil {
		m.logger.Debug("Dashboard requested but UI not compiled", zap.Error(err))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("caddy-waf dashboard is not available: this binary was built without the `with_ui` tag.\nRebuild with the with_ui build tag to include the UI.\n"))
		return nil
	}

	out := string(body)
	if asset.template {
		out = strings.ReplaceAll(out, "__BASE__", strings.TrimRight(m.DashboardEndpoint, "/"))
		out = strings.ReplaceAll(out, "__WAF_METRICS_PATH__", m.MetricsEndpoint)
	}

	w.Header().Set("Content-Type", asset.mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if asset.template {
		w.Header().Set("X-Frame-Options", "DENY")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(out))
	return nil
}
