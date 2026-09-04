package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestAllBundlesLoadedNoBrowserFP loads rules.json AND every rules/*.json
// bundle together — the maximal-coverage deployment — and asserts ordinary
// traffic is not blocked. This is the configuration where the additive anomaly
// score bites: several independent "log" rules can each contribute a few
// points and cross the default threshold together even though none blocks on
// its own. The rules-audit part 3 fixes are pinned here.
func allBundlesMiddleware(t *testing.T) *Middleware {
	t.Helper()
	bundles, err := filepath.Glob("rules/*.json")
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no rule bundles found: %v", err)
	}
	logger := zap.NewNop()
	m := &Middleware{
		logger: logger, blacklistLoader: NewBlacklistLoader(logger),
		AnomalyThreshold: 5, ruleCache: NewRuleCache(), ipBlacklist: iptrie.NewTrie(),
		dnsBlacklist: map[string]struct{}{}, ruleHitsByPhase: map[int]int64{},
		RuleFiles:             append([]string{"rules.json"}, bundles...),
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(), topIPsBlocked: map[string]int64{},
		blockedByReason: map[string]int64{}, geoIPStats: map[string]int64{},
	}
	if err := m.loadRules(m.RuleFiles); err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	return m
}

var allBundlesNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func TestAllBundlesLoadedNoBrowserFP(t *testing.T) {
	m := allBundlesMiddleware(t)
	serve := func(r *http.Request) int {
		r.RemoteAddr = "203.0.113.9:1234"
		rec := httptest.NewRecorder()
		_ = m.ServeHTTP(rec, r, allBundlesNext)
		return rec.Code
	}

	cases := []struct {
		name string
		r    func() *http.Request
	}{
		{"encoded query value", func() *http.Request {
			r := httptest.NewRequest("GET", "/s", nil)
			r.URL.RawQuery = "q=hello%20world"
			r.RequestURI = "/s?q=hello%20world"
			return r
		}},
		{"navigation with Referer", func() *http.Request {
			r := httptest.NewRequest("GET", "/p", nil)
			r.Header.Set("Referer", "https://www.google.com/search?q=caddy")
			r.Header.Set("User-Agent", "Mozilla/5.0")
			return r
		}},
		{"JSON body with common fields", func() *http.Request {
			r := httptest.NewRequest("POST", "/api", strings.NewReader(`{"count":3,"user":"alice","data":{"list":[1,2]}}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}},
		{"English prose body", func() *http.Request {
			r := httptest.NewRequest("POST", "/c", strings.NewReader("comment=please select an item from the list, don't forget to set a date and update where needed"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}},
		{"legit GraphQL query", func() *http.Request {
			r := httptest.NewRequest("POST", "/graphql", strings.NewReader(`{"query":"query { user(id: 1) { name email version } }"}`))
			r.Header.Set("Content-Type", "application/json")
			return r
		}},
		{"login page", func() *http.Request { return httptest.NewRequest("GET", "/login", nil) }},
		{"multipart upload", func() *http.Request {
			b := "------WebKitFormBoundaryX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhi\r\n------WebKitFormBoundaryX--\r\n"
			r := httptest.NewRequest("POST", "/u", strings.NewReader(b))
			r.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryX")
			return r
		}},
		{"CSS custom properties in body", func() *http.Request {
			r := httptest.NewRequest("POST", "/s", strings.NewReader("css=--main-color: #fff; padding: 10px"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}},
		{"pagination limit param", func() *http.Request {
			r := httptest.NewRequest("GET", "/items", nil)
			r.URL.RawQuery = "limit=20&offset=40"
			r.RequestURI = "/items?limit=20&offset=40"
			return r
		}},
		{"framework array params", func() *http.Request {
			r := httptest.NewRequest("GET", "/search", nil)
			r.URL.RawQuery = "filter[status]=open&filter[tag]=urgent&sort[]=date"
			r.RequestURI = "/search?filter[status]=open&filter[tag]=urgent&sort[]=date"
			return r
		}},
		{"YAML config body", func() *http.Request {
			r := httptest.NewRequest("POST", "/config", strings.NewReader("data: 42\nname: my-service\nversion: 1.2.3\n"))
			r.Header.Set("Content-Type", "application/yaml")
			return r
		}},
		{"cookie named id + user", func() *http.Request {
			r := httptest.NewRequest("GET", "/home", nil)
			r.Header.Set("Cookie", "session=abc; id=42; user=alice")
			return r
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.NotEqualf(t, http.StatusForbidden, serve(c.r()), "%s must not be blocked with all bundles loaded", c.name)
		})
	}
}
