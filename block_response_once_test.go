package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// blockingHeaderMiddleware blocks in Phase 1 every request whose X-Attack
// header says "yes", and answers blocks with the given custom responses.
func blockingHeaderMiddleware(custom map[int]CustomBlockResponse) *Middleware {
	logger := zap.NewNop()
	return &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {{
				ID:      "attack-header",
				Pattern: "^yes$",
				Targets: []string{"HEADERS:X-Attack"},
				Phase:   1,
				Score:   5,
				Action:  "block",
				regex:   regexp.MustCompile("^yes$"),
			}},
		},
		CustomResponses:       custom,
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
}

func upstreamOK() caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		return err
	})
}

// A custom_response is written once, with the content type it declares (#247).
// It used to be written twice, by blockRequest and again by the caller, and
// under text/plain because blockRequest sent the status before the custom
// headers were set.
func TestCustomResponseIsWrittenOnceWithItsContentType(t *testing.T) {
	m := blockingHeaderMiddleware(map[int]CustomBlockResponse{
		http.StatusForbidden: {
			StatusCode: http.StatusForbidden,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"error":"blocked"}`,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/blocked", nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Attack", "yes")
	w := httptest.NewRecorder()

	assert.NoError(t, m.ServeHTTP(w, req, upstreamOK()))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, `{"error":"blocked"}`, w.Body.String(), "the custom body must be written exactly once")
	assert.Equal(t, "application/json", w.Result().Header.Get("Content-Type"), "the content type the client received")
}

// Without a custom_response for the block status, the default text is written once.
func TestDefaultBlockResponseIsWrittenOnce(t *testing.T) {
	m := blockingHeaderMiddleware(nil)

	req := httptest.NewRequest(http.MethodGet, "/blocked", nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Attack", "yes")
	w := httptest.NewRecorder()

	assert.NoError(t, m.ServeHTTP(w, req, upstreamOK()))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "Request blocked by WAF. Reason: Rule action is 'block'", w.Body.String())
	assert.Equal(t, "text/plain", w.Result().Header.Get("Content-Type"), "the content type the client received")
}

// Every request is counted once, as blocked or as allowed, so blocked and
// allowed add up to the total and the dashboard's block ratio cannot pass 100%
// (#248). A block used to be counted twice, by blockRequest and by the phase
// that reported it, and an allowed request once per phase it passed.
func TestBlockedAndAllowedAddUpToTotal(t *testing.T) {
	m := blockingHeaderMiddleware(nil)

	for i, attack := range []bool{true, true, true, false, false} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = localIP
		if attack {
			req.Header.Set("X-Attack", "yes")
		}
		w := httptest.NewRecorder()
		assert.NoError(t, m.ServeHTTP(w, req, upstreamOK()), "request %d", i)
	}

	assert.Equal(t, int64(5), m.totalRequests.Load(), "total")
	assert.Equal(t, int64(3), m.blockedRequests.Load(), "blocked")
	assert.Equal(t, int64(2), m.allowedRequests.Load(), "allowed")
}
