package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"go.uber.org/zap"
)

// benchMiddleware builds a middleware with the shipped rules.json loaded, so the
// hot-path benchmarks run against a representative rule set rather than a toy.
func benchMiddleware(b *testing.B) *Middleware {
	b.Helper()
	logger := zap.NewNop()
	m := &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      5,
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		ruleHitsByPhase:       map[int]int64{},
		RuleFiles:             []string{"rules.json"},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		provisionTime:         time.Now(),
		topIPsBlocked:         map[string]int64{},
		blockedByReason:       map[string]int64{},
		geoIPStats:            map[string]int64{},
	}
	if err := m.loadRules(m.RuleFiles); err != nil {
		b.Fatalf("loadRules: %v", err)
	}
	return m
}

var benchNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

// runServeHTTP drives one request per iteration through the full middleware,
// reporting ns/op and allocs/op. newReq is called each iteration so per-request
// state (body, context) is fresh, as in production.
func runServeHTTP(b *testing.B, m *Middleware, newReq func() *http.Request) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ServeHTTP(httptest.NewRecorder(), newReq(), benchNext) //nolint:errcheck
	}
}

// BenchmarkServeHTTP_Benign is the common case: a request that matches nothing
// and passes through. This is the latency every legitimate request pays.
func BenchmarkServeHTTP_Benign(b *testing.B) {
	m := benchMiddleware(b)
	runServeHTTP(b, m, func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, testURL+"/products?category=books&page=2", nil)
		r.RemoteAddr = "203.0.113.5:1234"
		r.Header.Set("User-Agent", "Mozilla/5.0")
		return r
	})
}

// BenchmarkServeHTTP_BenignParallel runs the benign path from many goroutines at
// once. It is the throughput-under-concurrency measure for #116: it surfaces
// contention on shared state (the per-request metric counters) that the
// single-goroutine benchmarks cannot show.
func BenchmarkServeHTTP_BenignParallel(b *testing.B) {
	m := benchMiddleware(b)
	b.ReportAllocs()
	b.ResetTimer() // exclude benchMiddleware() setup, matching the other benchmarks
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest(http.MethodGet, testURL+"/products?category=books&page=2", nil)
			r.RemoteAddr = "203.0.113.5:1234"
			r.Header.Set("User-Agent", "Mozilla/5.0")
			m.ServeHTTP(httptest.NewRecorder(), r, benchNext) //nolint:errcheck
		}
	})
}

// BenchmarkServeHTTP_Blocked exercises the block path: a request whose query
// trips the SQLi rules and is refused.
func BenchmarkServeHTTP_Blocked(b *testing.B) {
	m := benchMiddleware(b)
	runServeHTTP(b, m, func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, testURL+"/items?id=1%20UNION%20SELECT%20password%20FROM%20users", nil)
		r.RemoteAddr = "203.0.113.9:1234"
		return r
	})
}

// BenchmarkServeHTTP_POSTBody exercises the request-body path (buffering +
// body-target rules) with a form body.
func BenchmarkServeHTTP_POSTBody(b *testing.B) {
	m := benchMiddleware(b)
	body := strings.Repeat("field=value&", 40)
	runServeHTTP(b, m, func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, testURL+"/submit", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "203.0.113.5:1234"
		return r
	})
}

// BenchmarkMetricsScrape measures the /waf_metrics handler (snapshot + marshal),
// the read path the dashboard polls.
func BenchmarkMetricsScrape(b *testing.B) {
	m := benchMiddleware(b)
	m.MetricsEndpoint = "/waf_metrics"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest(http.MethodGet, testURL+"/waf_metrics", nil)
		r.RemoteAddr = "203.0.113.5:1234"
		m.ServeHTTP(httptest.NewRecorder(), r, benchNext) //nolint:errcheck
	}
}
