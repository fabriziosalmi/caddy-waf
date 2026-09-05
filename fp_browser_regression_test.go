package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Browser-traffic false-positive regression guard for the shipped rules.json
// (rules-purge audit). The earlier fp_regression_test.go corpus only exercised
// bare query strings; every case below carries the request shape real clients
// send — Referer, cookies, Sec-Fetch headers, multipart bodies, percent-encoded
// values — because that is where the purged rules false-positived. Each case
// was a 403 before the purge at the default anomaly_threshold of 5.

func fpServe(t *testing.T, m *Middleware, req *http.Request) int {
	t.Helper()
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, fpNext)
	return rec.Code
}

func TestNoFalsePositiveOnBrowserTraffic(t *testing.T) {
	m := fpMiddleware(t)

	cases := []struct {
		name  string
		build func() *http.Request
	}{
		{"percent-encoded query value", func() *http.Request {
			r := httptest.NewRequest("GET", "/search", nil)
			r.URL.RawQuery = "q=hello%20world"
			r.RequestURI = "/search?q=hello%20world"
			return r
		}},
		{"navigation with Referer", func() *http.Request {
			r := httptest.NewRequest("GET", "/page", nil)
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Referer", "https://www.google.com/search")
			return r
		}},
		{"cross-site POST with Origin", func() *http.Request {
			r := httptest.NewRequest("POST", "/api/submit", strings.NewReader("a=1"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://partner.example.com")
			r.Header.Set("Referer", "https://partner.example.com/checkout")
			return r
		}},
		{"plain-English form body", func() *http.Request {
			r := httptest.NewRequest("POST", "/comment", strings.NewReader("comment=don't forget to set a date"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}},
		{"login page", func() *http.Request {
			return httptest.NewRequest("GET", "/login", nil)
		}},
		{"multipart upload (boundary dashes)", func() *http.Request {
			body := "------WebKitFormBoundaryABC\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhi\r\n------WebKitFormBoundaryABC--\r\n"
			r := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
			r.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryABC")
			return r
		}},
		{"explicit Content-Length 0", func() *http.Request {
			r := httptest.NewRequest("POST", "/ping", nil)
			r.Header.Set("Content-Length", "0")
			return r
		}},
		{"cookie named id", func() *http.Request {
			r := httptest.NewRequest("GET", "/home", nil)
			r.Header.Set("Cookie", "session=abc123; id=42")
			return r
		}},
		{"cross-site image fetch (Sec-Fetch)", func() *http.Request {
			r := httptest.NewRequest("GET", "/img/logo.png", nil)
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Dest", "image")
			return r
		}},
		{"OAuth redirect_uri param", func() *http.Request {
			r := httptest.NewRequest("GET", "/authorize", nil)
			r.URL.RawQuery = "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
			r.RequestURI = "/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
			return r
		}},
		{"SPA config fetch", func() *http.Request {
			return httptest.NewRequest("GET", "/assets/config.json", nil)
		}},
		{"JSON body with common field names", func() *http.Request {
			r := httptest.NewRequest("POST", "/api/items", strings.NewReader(`{"count": 3, "name": "widget", "data": {"list": [1, 2]}}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}},
		{"bearer JWT", func() *http.Request {
			r := httptest.NewRequest("GET", "/api/me", nil)
			r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.dGVzdHNpZ25hdHVyZQ")
			return r
		}},
		{"CI YAML body with template syntax", func() *http.Request {
			r := httptest.NewRequest("POST", "/api/pipelines", strings.NewReader("data: 42\nrun: echo \"${{ inputs.name }}\"\n"))
			r.Header.Set("Content-Type", "application/yaml")
			return r
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code := fpServe(t, m, c.build())
			assert.NotEqualf(t, http.StatusForbidden, code, "benign request must not be blocked (got %d)", code)
		})
	}
}

// TestAttacksStillBlockedAfterPurge pins that removing the false-positive rules
// did not lose the detections the remaining rules are responsible for.
func TestAttacksStillBlockedAfterPurge(t *testing.T) {
	m := fpMiddleware(t)

	cases := []struct {
		name  string
		build func() *http.Request
	}{
		{"script-tag XSS in query", func() *http.Request {
			r := httptest.NewRequest("GET", "/s", nil)
			q := "q=<script>alert(1)</script>"
			r.URL.RawQuery = q
			r.RequestURI = "/s?" + q
			return r
		}},
		{"UNION SELECT SQLi in query", func() *http.Request {
			r := httptest.NewRequest("GET", "/s", nil)
			q := "id=1' UNION SELECT NULL,password FROM users"
			r.URL.RawQuery = q
			r.RequestURI = "/s?" + q
			return r
		}},
		{"path traversal in query", func() *http.Request {
			r := httptest.NewRequest("GET", "/download", nil)
			q := "file=../../etc/passwd"
			r.URL.RawQuery = q
			r.RequestURI = "/download?" + q
			return r
		}},
		{"cloud metadata SSRF in body", func() *http.Request {
			r := httptest.NewRequest("POST", "/fetch", strings.NewReader(`{"url": "http://169.254.169.254/latest/meta-data/"}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}},
		{"Java deserialization payload in body", func() *http.Request {
			r := httptest.NewRequest("POST", "/api", strings.NewReader("payload=rO0ABXNyABZqYXZhLnV0aWwuSGFzaE1hcA"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}},
		{"SQLi in header", func() *http.Request {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("X-Forwarded-For", "1' UNION SELECT NULL--")
			return r
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code := fpServe(t, m, c.build())
			assert.Equalf(t, http.StatusForbidden, code, "attack must still be blocked (got %d)", code)
		})
	}
}
