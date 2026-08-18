package caddywaf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestMetricsEndpointUnderConcurrentTraffic guards the metrics handler against
// reading the shared counters without synchronisation.
//
// The counters were read straight off the struct while every request wrote to
// them. rule_hits_by_phase made that more than a benign race: it is a map, and
// it was passed to json.Marshal by reference, so the marshal iterated it while
// requests mutated it. Go answers that with "concurrent map read and map write",
// a runtime throw, which ServeHTTP's panic recovery converts into a 500 -- so
// scraping metrics under load could take out requests.
//
// Run with -race for this to be meaningful; the map case can also fail outright.
func TestMetricsEndpointUnderConcurrentTraffic(t *testing.T) {
	logger := zap.NewNop()
	m := &Middleware{
		logger:           logger,
		blacklistLoader:  NewBlacklistLoader(logger),
		MetricsEndpoint:  "/waf_metrics",
		AnomalyThreshold: 1000, // score, never block: we want counters moving
		ruleCache:        NewRuleCache(),
		ipBlacklist:      iptrie.NewTrie(),
		dnsBlacklist:     map[string]struct{}{},
		ruleHitsByPhase:  map[int]int64{},
		// A matching rule on every request keeps ruleHitsByPhase being written.
		Rules: map[int][]Rule{1: {{
			ID: "probe", Pattern: "probe", Targets: []string{"URI"},
			Phase: 1, Score: 1, Action: "log", regex: regexp.MustCompile("probe"),
		}}},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, err := w.Write([]byte("ok"))
		return err
	})

	const (
		writers   = 8
		readers   = 4
		perWriter = 60
		perReader = 40
	)

	var wg sync.WaitGroup
	scrapes := make(chan []byte, readers*perReader)

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				req := httptest.NewRequest(http.MethodGet, testURL+"/?q=probe", nil)
				req.RemoteAddr = "203.0.113.7:1234"
				_ = m.ServeHTTP(httptest.NewRecorder(), req, next)
			}
		}()
	}

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perReader; j++ {
				req := httptest.NewRequest(http.MethodGet, testURL+"/waf_metrics", nil)
				req.RemoteAddr = "203.0.113.8:1234"
				w := httptest.NewRecorder()
				_ = m.ServeHTTP(w, req, next)
				scrapes <- w.Body.Bytes()
			}
		}()
	}

	wg.Wait()
	close(scrapes)

	// Every scrape must be a 200 with parseable JSON. A panic recovered by
	// ServeHTTP would surface as a 500 with a plain-text body.
	checked := 0
	for body := range scrapes {
		var payload map[string]any
		require.NoErrorf(t, json.Unmarshal(body, &payload),
			"metrics response was not JSON: %q", string(body))
		assert.Contains(t, payload, "rule_hits_by_phase")
		assert.Contains(t, payload, "total_requests")
		checked++
	}
	require.Equal(t, readers*perReader, checked)
}
