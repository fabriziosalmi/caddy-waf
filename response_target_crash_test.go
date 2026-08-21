package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newCrashProbeMiddleware builds a minimal, provisioned-enough Middleware that
// carries a single rule, so a test can drive a target through the full
// ServeHTTP path.
func newCrashProbeMiddleware(t *testing.T, rule Rule) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	return &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      1000, // score only, never block: we want the request to reach next
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		ruleHitsByPhase:       map[int]int64{},
		Rules:                 map[int][]Rule{rule.Phase: {rule}},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
}

// TestResponseHeaderTargetInEarlyPhaseDoesNotPanic pins issue #144.
//
// handlePhase passes a nil http.ResponseWriter to value extraction in Phases 1
// and 2, because the response does not exist yet. A rule that targets
// RESPONSE_HEADERS in one of those phases (several OWASP CRS rules do, e.g.
// 950010, which lists RESPONSE_HEADERS in phase 2) therefore reached
// w.Header() on a nil writer and panicked. ServeHTTP's recovery turned that
// into a 500 on *every* request, taking the whole site offline behind the WAF.
//
// The extractor must degrade to a skipped target, not a nil dereference, so the
// request passes through untouched.
func TestResponseHeaderTargetInEarlyPhaseDoesNotPanic(t *testing.T) {
	for _, target := range []string{"RESPONSE_HEADERS", "RESPONSE_HEADERS:Content-Encoding"} {
		t.Run(target, func(t *testing.T) {
			m := newCrashProbeMiddleware(t, Rule{
				ID: "950010", Phase: 2, Pattern: "gzip",
				Targets: []string{target},
				Score:   1, Action: "log", regex: regexp.MustCompile("gzip"),
			})

			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Encoding", "gzip")
				_, err := w.Write([]byte("ok"))
				return err
			})

			req := httptest.NewRequest(http.MethodGet, testURL+"/", nil)
			req.RemoteAddr = "203.0.113.7:1234"
			rec := httptest.NewRecorder()

			err := m.ServeHTTP(rec, req, next)
			require.NoError(t, err)

			// A recovered panic surfaces as a 500 with a plain-text body; the
			// healthy path returns the upstream's 200 "ok".
			assert.Equal(t, http.StatusOK, rec.Code,
				"a response-target rule in an early phase must not 500 the request")
			assert.Equal(t, "ok", rec.Body.String())
		})
	}
}
