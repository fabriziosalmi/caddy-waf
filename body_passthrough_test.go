package caddywaf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// bodyProbeMiddleware builds a middleware whose only rules target BODY, so the
// request-body extractor runs on every request and must put the body back.
func bodyProbeMiddleware(t *testing.T, ruleCount int) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	rules := make([]Rule, ruleCount)
	for i := range rules {
		rules[i] = Rule{
			ID:      "body-probe",
			Pattern: "zzz-never-matches-zzz",
			Targets: []string{"BODY"},
			Phase:   2, Score: 1, Action: "log",
			regex: regexp.MustCompile("zzz-never-matches-zzz"),
		}
	}
	return &Middleware{
		logger:                logger,
		blacklistLoader:       NewBlacklistLoader(logger),
		AnomalyThreshold:      1000, // score only, never block
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		ruleHitsByPhase:       map[int]int64{},
		Rules:                 map[int][]Rule{2: rules},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
}

// TestPOSTBodyReachesUpstreamIntact pins the request-body passthrough.
//
// extractBody read the body with io.ReadAll(io.LimitReader(r.Body, max)) and
// then "restored" it by splicing the already-consumed r.Body into an
// io.MultiReader. With more than one BODY extraction (any config with multiple
// BODY-targeting rules -- the common case), the reconstructed stream stopped
// yielding the bytes while r.ContentLength kept its original value. The upstream
// transport then saw "ContentLength=N with Body length 0", broke the connection,
// and every POST carrying a body failed with a 502.
//
// The downstream handler must read the full, intact body, and Content-Length
// must still match it. Runs with several BODY rules so the extractor fires more
// than once, which is what actually triggered the corruption.
func TestPOSTBodyReachesUpstreamIntact(t *testing.T) {
	const payload = "hello=world&n=42&msg=a%20test"

	for _, rc := range []int{1, 3} {
		t.Run("body_rules="+strings.Repeat("x", rc), func(t *testing.T) {
			m := bodyProbeMiddleware(t, rc)

			var gotBody string
			var gotLen int64
			var readErr error
			var upstreamReq *http.Request
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				upstreamReq = r
				b, err := io.ReadAll(r.Body)
				readErr = err
				gotBody = string(b)
				gotLen = r.ContentLength
				w.WriteHeader(http.StatusOK)
				return nil
			})

			req := httptest.NewRequest(http.MethodPost, testURL+"/socket.io/?EIO=4&transport=polling", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "203.0.113.5:1234"
			rec := httptest.NewRecorder()

			require.NoError(t, m.ServeHTTP(rec, req, next))
			require.NoError(t, readErr)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, payload, gotBody, "upstream must read the full, intact request body")
			assert.Equal(t, int64(len(payload)), gotLen, "Content-Length must still match the body the upstream can read")

			// GetBody must be usable on the request the upstream receives, so the
			// transport can rebuild the body for retries/redirects.
			require.NotNil(t, upstreamReq.GetBody, "GetBody must be set for transport retries")
			rc2, err := upstreamReq.GetBody()
			require.NoError(t, err)
			replay, err := io.ReadAll(rc2)
			require.NoError(t, err)
			assert.Equal(t, payload, string(replay), "GetBody must reproduce the full body")
		})
	}
}

// TestPOSTBodyLargerThanLimitForwardedIntact guards uploads: a request body
// larger than the inspection limit must still reach the upstream whole. The
// WAF inspects only the first max_request_body_size bytes but must forward the
// complete body, or a large POST/upload would be silently truncated.
func TestPOSTBodyLargerThanLimitForwardedIntact(t *testing.T) {
	m := bodyProbeMiddleware(t, 1)
	m.MaxRequestBodySize = 8 // tiny inspection window; body below is larger

	payload := strings.Repeat("A", 8) + strings.Repeat("B", 40) // 48 bytes, 8 inspected

	var gotBody string
	var gotLen int64
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = string(b)
		gotLen = r.ContentLength
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, testURL+"/upload", strings.NewReader(payload))
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()

	require.NoError(t, m.ServeHTTP(rec, req, next))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, payload, gotBody, "the full body must reach the upstream even when larger than the inspection window")
	assert.Equal(t, int64(len(payload)), gotLen, "Content-Length must match the forwarded body")
}
