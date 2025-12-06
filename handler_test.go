package caddywaf

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestBlockedRequestPhase1_DNSBlacklist(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		dnsBlacklist: map[string]struct{}{
			"malicious.domain": {},
		},
		ipBlacklist:           iptrie.NewTrie(),
		CustomResponses:       customResponse,
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	w := httptest.NewRecorder()
	state := &WAFState{}

	t.Run("Allow unblocked domain", func(t *testing.T) {
		// Simulate a request to a blacklisted domain
		req := httptest.NewRequest("GET", testURL, nil)
		req.RemoteAddr = localIP

		// Process the request in Phase 1
		middleware.handlePhase(w, req, 1, state)
		assert.False(t, state.Blocked, "Request should be allowed")
		assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	})

	t.Run("Block blacklisted domain", func(t *testing.T) {
		// Simulate a request to a blacklisted domain
		req := httptest.NewRequest("GET", "http://malicious.domain", nil)
		req.RemoteAddr = localIP

		// Process the request in Phase 1
		middleware.handlePhase(w, req, 1, state)

		// Verify that the request was blocked
		assert.True(t, state.Blocked, "Request should be blocked")
		assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
		assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
	})
}

func TestBlockedRequestPhase1_GeoIPBlocking(t *testing.T) {
	if _, err := os.Stat(geoIPdata); os.IsNotExist(err) {
		t.Skip("GeoIP database not found, skipping test")
	}
	logger, err := zap.NewDevelopment()
	assert.NoError(t, err)

	geoIPHandler := NewGeoIPHandler(logger)
	geoIPBlock, err := geoIPHandler.LoadGeoIPDatabase(geoIPdata)
	assert.NoError(t, err)

	blMiddleware := &Middleware{
		logger:       logger,
		ipBlacklist:  iptrie.NewTrie(),
		geoIPHandler: geoIPHandler,
		CountryBlacklist: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"US", "RU"},
			GeoIPDBPath: geoIPdata, // Path to a test GeoIP database
			geoIP:       geoIPBlock,
		},
		CustomResponses:       customResponse,
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	wlMiddleware := &Middleware{
		logger:       logger,
		ipBlacklist:  iptrie.NewTrie(),
		geoIPHandler: geoIPHandler,
		CountryWhitelist: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"BR"},
			GeoIPDBPath: geoIPdata, // Path to a test GeoIP database
			geoIP:       geoIPBlock,
		},
		CustomResponses:       customResponse,
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	blackWhiteMw := &Middleware{
		logger:       logger,
		ipBlacklist:  iptrie.NewTrie(),
		geoIPHandler: geoIPHandler,
		CountryWhitelist: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"BR"},
			GeoIPDBPath: geoIPdata, // Path to a test GeoIP database
			geoIP:       geoIPBlock,
		},
		CountryBlacklist: CountryAccessFilter{
			Enabled:     true,
			CountryList: []string{"US", "RU"},
			GeoIPDBPath: geoIPdata, // Path to a test GeoIP database
			geoIP:       geoIPBlock,
		},
		CustomResponses:       customResponse,
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)

	state := &WAFState{}

	t.Run("GeoIP Blacklist: Allow CN IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		req.RemoteAddr = aliCNIP

		// Process the request in Phase 1
		blMiddleware.handlePhase(w, req, 1, state)
		assert.False(t, state.Blocked, "Request should be allowed")
		assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	})

	t.Run("GeoIP Blacklist: Block US IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		req.RemoteAddr = googleUSIP

		// Process the request in Phase 1
		blMiddleware.handlePhase(w, req, 1, state)

		// Verify that the request was blocked
		assert.True(t, state.Blocked, "Request should be blocked")
		assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
		assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
	})

	t.Run("GeoIP Whitelist: Allow BR IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		req.RemoteAddr = googleBRIP

		// Process the request in Phase 1
		wlMiddleware.handlePhase(w, req, 1, state)
		assert.False(t, state.Blocked, "Request should be allowed")
		assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	})

	t.Run("GeoIP Whitelist: Block RU IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		req.RemoteAddr = googleRUIP

		// Process the request in Phase 1
		wlMiddleware.handlePhase(w, req, 1, state)

		// Verify that the request was blocked
		assert.True(t, state.Blocked, "Request should be blocked")
		assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
		assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
	})

	t.Run("GeoIP whitelist and blacklist: whitelist has the priority", func(t *testing.T) {

		w := httptest.NewRecorder()

		// BR should be allowed
		req0 := httptest.NewRequest("GET", testURL, nil)
		req0.RemoteAddr = googleBRIP

		blackWhiteMw.handlePhase(w, req0, 1, state)
		assert.False(t, state.Blocked, "Request should be allowed")
		assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")

		// US must be blocked
		req1 := httptest.NewRequest("GET", testURL, nil)
		req1.RemoteAddr = googleUSIP

		blackWhiteMw.handlePhase(w, req1, 1, state)
		// Verify that the request was blocked
		assert.True(t, state.Blocked, "Request should be blocked")
		assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
		assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
	})
}

func TestBlockedRequestPhase1_IPBlocking(t *testing.T) {
	logger, err := zap.NewDevelopment()
	assert.NoError(t, err)

	blackList := iptrie.NewTrie()
	loader := iptrie.NewTrieLoader(blackList)

	for _, net := range []string{
		"192.168.0.0/24",
		"192.168.1.1/32",
	} {
		loader.Insert(netip.MustParsePrefix(net), "net="+net)
	}

	state := &WAFState{}
	w := httptest.NewRecorder()

	t.Run("Allow unblocked CIDR", func(t *testing.T) {
		middleware := &Middleware{
			logger:                logger,
			ipBlacklist:           blackList,
			CustomResponses:       customResponse,
			requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		}

		req := httptest.NewRequest("GET", testURL, nil)
		req.RemoteAddr = localIP

		// Process the request in Phase 1
		middleware.handlePhase(w, req, 1, state)

		assert.False(t, state.Blocked, "Request should be allowed")
		assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	})

	t.Run("Blocks blacklisted CIDR", func(t *testing.T) {
		middleware := &Middleware{
			logger:                logger,
			ipBlacklist:           blackList,
			CustomResponses:       customResponse,
			requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		}

		req := httptest.NewRequest("GET", testURL, nil)
		req.RemoteAddr = "192.168.1.1"

		// Process the request in Phase 1
		middleware.handlePhase(w, req, 1, state)

		// Verify that the request was blocked
		assert.True(t, state.Blocked, "Request should be blocked")
		assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
		assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
	})
}

func TestHandlePhase_Phase2_NiktoUserAgent(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2",
					Pattern: "nikto",
					Targets: []string{"USER_AGENT"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nikto"),
				},
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
		CustomResponses:       customResponse,
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.Header.Set("User-Agent", "nikto")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-nikto" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx) // Create new request with context

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Access Denied", "Response body should contain 'Access Denied'")
}

func TestBlockedRequestPhase1_HeaderRegex(t *testing.T) {
	logger, err := zap.NewDevelopment()
	assert.NoError(t, err)

	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule1",
					Pattern: "bad-header",
					Targets: []string{"HEADERS:X-Custom-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-header"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Custom-Header", "this-is-a-bad-header") // Simulate a request with bad header

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-headerregex" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx) // Create new request with context

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Header Regex", "Response body should contain 'Blocked by Header Regex'")
}

func TestBlockedRequestPhase1_HeaderRegex_SpecificValue(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_specific",
					Pattern: "^specific-value$",
					Targets: []string{"HEADERS:X-Specific-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("^specific-value$"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Specific Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Specific-Header", "specific-value") // Simulate a request with the specific header

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-headerspecificvalue" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx) // Create new request with context

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Specific Header Regex", "Response body should contain 'Blocked by Specific Header Regex'")
}

func TestBlockedRequestPhase1_HeaderRegex_CommaSeparatedTargets(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_comma",
					Pattern: "bad-value",
					Targets: []string{"HEADERS:X-Custom-Header1,HEADERS:X-Custom-Header2"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-value"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Comma-Separated Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Custom-Header1", "good-value")
	req.Header.Set("X-Custom-Header2", "bad-value") // Simulate a request with bad value in one of the headers

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-headercomma" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx) // Create new request with context

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Comma-Separated Header Regex", "Response body should contain 'Blocked by Comma-Separated Header Regex'")
}

func TestBlockedRequestPhase1_CombinedConditions(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_combined",
					Pattern: "bad-user|bad-host",
					Targets: []string{"USER_AGENT", "HOST"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-user|bad-host"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Combined Condition Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", "http://bad-host.com", nil)
	req.RemoteAddr = localIP
	req.Header.Set("User-Agent", "good-user")

	// Create a context and add logID to it
	ctx := context.Background()
	logID := "test-log-id-combined"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Combined Condition Regex", "Response body should contain 'Blocked by Combined Condition Regex'")
}

func TestBlockedRequestPhase1_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_no_match",
					Pattern: "nomatch",
					Targets: []string{"USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("User-Agent", "good-user")

	// Create a context and add logID to it
	ctx := context.Background()
	logID := "test-log-id-nomatch"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_HeaderRegex_EmptyHeader(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_empty",
					Pattern: ".+", // Match anything (including empty)
					Targets: []string{"HEADERS:X-Empty-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(".+"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Empty Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP

	// Create a context and add logID to it
	ctx := context.Background()
	logID := "test-log-id-headerempty"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked because header is empty")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_HeaderRegex_MissingHeader(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_missing",
					Pattern: "test-value",
					Targets: []string{"HEADERS:X-Missing-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("test-value"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Missing Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil) // Header not set
	req.RemoteAddr = localIP

	// Create a context and add logID to it
	ctx := context.Background()
	logID := "test-log-id-headermissing"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked because header is missing")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_HeaderRegex_ComplexPattern(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_complex",
					Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, // Email regex
					Targets: []string{"HEADERS:X-Email-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Complex Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Email-Header", "test@example.com") // Simulate a request with a valid email

	// Create a context and add logID to it
	ctx := context.Background()
	logID := "test-log-id-headercomplex"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Complex Header Regex", "Response body should contain 'Blocked by Complex Header Regex'")
}

func TestBlockedRequestPhase1_MultiTargetMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_multi_target",
					Pattern: "bad",
					Targets: []string{"HEADERS:X-Custom-Header", "USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multi-Target Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Custom-Header", "good-header")
	req.Header.Set("User-Agent", "bad-user-agent")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-multimatch" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)
	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Multi-Target Regex", "Response body should contain 'Blocked by Multi-Target Regex'")
}

func TestBlockedRequestPhase1_MultiTargetNoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_multi_target_no_match",
					Pattern: "bad",
					Targets: []string{"HEADERS:X-Custom-Header", "USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multi-Target Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Custom-Header", "good-header")
	req.Header.Set("User-Agent", "good-user-agent")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-multinomatch" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx) // Create new request with context

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_URLParameterRegex_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_url_param_no_match",
					Pattern: "nomatch",
					Targets: []string{"URL_PARAM:param1"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by URL Parameter Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", "http://example.com?param1=good-param-value¶m2=good-value", nil)
	req.RemoteAddr = localIP

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-urlparamnomatch" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)
	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase1_MultipleRules(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_multi1",
					Pattern: "bad-user",
					Targets: []string{"USER_AGENT"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-user"),
				},
				{
					ID:      "rule_multi2",
					Pattern: "bad-host",
					Targets: []string{"HOST"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-host"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multiple Rules",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", "http://bad-host.com", nil)
	req.RemoteAddr = localIP
	req.Header.Set("User-Agent", "bad-user") // Simulate a request with a bad user agent

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-multiplerules" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Multiple Rules", "Response body should contain 'Blocked by Multiple Rules'")

	req2 := httptest.NewRequest("GET", "http://good-host.com", nil)
	req2.RemoteAddr = localIP
	req2.Header.Set("User-Agent", "bad-user") // Simulate a request with a bad user agent

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE for req2 as well!
	ctx2 := context.Background() // New context for the second request!
	logID2 := "test-log-id-multiplerules2"
	ctx2 = context.WithValue(ctx2, ContextKeyLogId("logID"), logID2)
	req2 = req2.WithContext(ctx2)

	w2 := httptest.NewRecorder()
	state2 := &WAFState{}

	middleware.handlePhase(w2, req2, 1, state2)

	t.Logf("State Blocked: %v", state2.Blocked)
	t.Logf("Response Code: %d", w2.Code)
	t.Logf("Response Body: %s", w2.Body.String())

	assert.True(t, state2.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w2.Code, "Expected status code 403")
	assert.Contains(t, w2.Body.String(), "Blocked by Multiple Rules", "Response body should contain 'Blocked by Multiple Rules'")
}

func TestBlockedRequestPhase2_BodyRegex(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2",
					Pattern: "bad-body",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad-body"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("POST", testURL,
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString("this-is-a-bad-body")
			return b
		}(), // Simulate a request with bad body
	)
	req.RemoteAddr = localIP
	req.Header.Set("Content-Type", "text/plain")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-bodyregex" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Body Regex", "Response body should contain 'Blocked by Body Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_JSON(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_json",
					Pattern: `"malicious":true`,
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`"malicious":true`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by JSON Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("POST", testURL,
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString(`{"data":{"malicious":true,"name":"test"}}`)
			return b
		}(), // Simulate a request with JSON body
	)
	req.RemoteAddr = localIP
	req.Header.Set("Content-Type", "application/json")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-bodyregexjson" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by JSON Body Regex", "Response body should contain 'Blocked by JSON Body Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_FormURLEncoded(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_form",
					Pattern: "secret=badvalue",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("secret=badvalue"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Form URL Encoded Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("POST", testURL,
		strings.NewReader("param1=value1&secret=badvalue¶m2=value2"),
	)
	req.RemoteAddr = localIP
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-bodyregexform"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Form URL Encoded Regex", "Response body should contain 'Blocked by Form URL Encoded Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_SpecificPattern(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_specific",
					Pattern: `\d{3}-\d{2}-\d{4}`,
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Specific Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("POST", testURL,
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString("User ID: 123-45-6789")
			return b
		}(),
	)
	req.RemoteAddr = localIP
	req.Header.Set("Content-Type", "text/plain") // Setting content type

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-bodyregexspecific"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Specific Body Regex", "Response body should contain 'Blocked by Specific Body Regex'")
}

func TestBlockedRequestPhase2_BodyRegex_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule2_no_match",
					Pattern: "nomatch",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("POST", testURL,
		func() *bytes.Buffer {
			b := new(bytes.Buffer)
			b.WriteString("this-is-a-good-body")
			return b
		}(),
	)
	req.RemoteAddr = localIP
	req.Header.Set("Content-Type", "text/plain")

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-bodyregexnomatch"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase2_BodyRegex_NoMatch_MultipartForm(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule_multipart_no_match",
					Pattern: "maliciousfile.txt",
					Targets: []string{"FILE_NAME"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("maliciousfile.txt"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multipart File Name Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "goodfile.txt")
	if err != nil {
		t.Fatalf("Failed to create multipart form file: %v", err)
	}
	_, err = part.Write([]byte("file content"))
	if err != nil {
		t.Fatalf("Failed to write multipart form file: %v", err)
	}
	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close multipart writer: %v", err)
	}

	req := httptest.NewRequest("POST", testURL, body)
	req.RemoteAddr = localIP
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-bodyregexmultipartnomatch"
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase2_BodyRegex_NoBody(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			2: {
				{
					ID:      "rule_body_no_match",
					Pattern: "some-pattern",
					Targets: []string{"BODY"},
					Phase:   2,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("some-pattern"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("POST", testURL, nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 2, state)
	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

/////

func TestBlockedRequestPhase3_ResponseHeaderRegex_NoMatch(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			3: {
				{
					ID:      "rule3_no_match",
					Pattern: "nomatch",
					Targets: []string{"RESPONSE_HEADERS:X-Response-Header"},
					Phase:   3,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("nomatch"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Response Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Response-Header", "good-header")
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	state := &WAFState{}

	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase4_ResponseBodyRegex_EmptyBody(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			4: {
				{
					ID:      "rule4_empty",
					Pattern: "test",
					Targets: []string{"RESPONSE_BODY"},
					Phase:   4,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("test"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Response Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	state := &WAFState{}
	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

////

func TestBlockedRequestPhase4_ResponseBodyRegex_NoBody(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			4: {
				{
					ID:      "rule4_no_body",
					Pattern: "test",
					Targets: []string{"RESPONSE_BODY"},
					Phase:   4,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("test"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Response Body Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	state := &WAFState{}
	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

func TestBlockedRequestPhase3_ResponseHeaderRegex_NoSetCookie(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			3: {
				{
					ID:      "rule_no_setcookie",
					Pattern: "(?i)Set-Cookie:.*?(%0d|\\r)%0a",
					Targets: []string{"RESPONSE_HEADERS"},
					Phase:   3,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile(`(?i)Set-Cookie:.*?(%0d|\r)%0a`),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Set-Cookie Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
	mockHandler := func() caddyhttp.Handler {
		return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Custom-Header", "some-header-value") // Simulating a normal non-matching response
			w.WriteHeader(http.StatusOK)
			return nil
		})
	}()

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	state := &WAFState{}
	err := middleware.ServeHTTP(w, req, mockHandler)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.False(t, state.Blocked, "Request should not be blocked")
	assert.Equal(t, http.StatusOK, w.Code, "Expected status code 200")
	assert.Empty(t, w.Body.String(), "Response body should be empty")
}

//

func TestBlockedRequestPhase1_HeaderRegex_CaseInsensitive(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_case_insensitive",
					Pattern: "(?i)bad-value",
					Targets: []string{"HEADERS:X-Custom-Header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("(?i)bad-value"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Case-Insensitive Header Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Custom-Header", "bAd-VaLuE") // Test with mixed-case header value

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-headercaseinsensitive" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked by case-insensitive regex")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Case-Insensitive Header Regex", "Response body should contain 'Blocked by Case-Insensitive Header Regex'")
}

func TestBlockedRequestPhase1_HeaderRegex_MultipleMatchingHeaders(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule_header_multi",
					Pattern: "bad",
					Targets: []string{"HEADERS:X-Custom-Header1,HEADERS:X-Custom-Header2"},
					Phase:   1,
					Score:   5,
					Action:  "block",
					regex:   regexp.MustCompile("bad"),
				},
			},
		},
		CustomResponses: map[int]CustomBlockResponse{
			403: {
				StatusCode: http.StatusForbidden,
				Body:       "Blocked by Multiple Matching Headers Regex",
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}

	req := httptest.NewRequest("GET", testURL, nil)
	req.RemoteAddr = localIP
	req.Header.Set("X-Custom-Header1", "bad-value")
	req.Header.Set("X-Custom-Header2", "bad-value") // Both headers have a "bad" value

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE for req
	ctx := context.Background()
	logID := "test-log-id-headermultimatch" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	state := &WAFState{}

	middleware.handlePhase(w, req, 1, state)

	t.Logf("State Blocked: %v", state.Blocked)
	t.Logf("Response Code: %d", w.Code)
	t.Logf("Response Body: %s", w.Body.String())

	assert.True(t, state.Blocked, "Request should be blocked when both headers match")
	assert.Equal(t, http.StatusForbidden, w.Code, "Expected status code 403")
	assert.Contains(t, w.Body.String(), "Blocked by Multiple Matching Headers Regex", "Response body should contain 'Blocked by Multiple Matching Headers Regex'")

	req2 := httptest.NewRequest("GET", testURL, nil)
	req2.RemoteAddr = localIP
	req2.Header.Set("X-Custom-Header1", "good-value")
	req2.Header.Set("X-Custom-Header2", "bad-value") // One header has a "bad" value

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE for req2
	ctx2 := context.Background()
	logID2 := "test-log-id-headermultimatch2" // Unique log ID for this test
	ctx2 = context.WithValue(ctx2, ContextKeyLogId("logID"), logID2)
	req2 = req2.WithContext(ctx2)

	w2 := httptest.NewRecorder()
	state2 := &WAFState{}

	middleware.handlePhase(w2, req2, 1, state2)

	t.Logf("State Blocked: %v", state2.Blocked)
	t.Logf("Response Code: %d", w2.Code)
	t.Logf("Response Body: %s", w2.Body.String())

	assert.True(t, state2.Blocked, "Request should be blocked when one header match")
	assert.Equal(t, http.StatusForbidden, w2.Code, "Expected status code 403")
	assert.Contains(t, w2.Body.String(), "Blocked by Multiple Matching Headers Regex", "Response body should contain 'Blocked by Multiple Matching Headers Regex'")

	req3 := httptest.NewRequest("GET", testURL, nil)
	req3.RemoteAddr = localIP
	req3.Header.Set("X-Custom-Header1", "good-value")
	req3.Header.Set("X-Custom-Header2", "good-value") // None headers have a "bad" value

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE for req3
	ctx3 := context.Background()
	logID3 := "test-log-id-headermultimatch3" // Unique log ID for this test
	ctx3 = context.WithValue(ctx3, ContextKeyLogId("logID"), logID3)
	req3 = req3.WithContext(ctx3)

	w3 := httptest.NewRecorder()
	state3 := &WAFState{}

	middleware.handlePhase(w3, req3, 1, state3)

	t.Logf("State Blocked: %v", state3.Blocked)
	t.Logf("Response Code: %d", w3.Code)
	t.Logf("Response Body: %s", w3.Body.String())

	assert.False(t, state3.Blocked, "Request should not be blocked when none headers match")
	assert.Equal(t, http.StatusOK, w3.Code, "Expected status code 200")
}

// RequestLimit represents the rate limit state for a specific request
type RequestLimit struct {
	Count     int
	LastReset time.Time
}

func TestBlockedRequestPhase1_RateLimiting_MultiplePaths(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: func() *RateLimiter {
			config := RateLimit{
				Requests:        1,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
				Paths:           []string{"/api/v1/.*", "/admin/.*"},
				MatchAllPaths:   false,
			}
			rl, err := NewRateLimiter(config)
			if err != nil {
				t.Fatalf("Failed to create rate limiter: %v", err)
			}
			rl.startCleanup()
			return rl
		}(),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  iptrie.NewTrie(),
		dnsBlacklist: make(map[string]struct{}),
	}

	// Test path 1
	req1 := httptest.NewRequest("GET", "/api/v1/users", nil)
	req1.RemoteAddr = localIP
	w1 := httptest.NewRecorder()
	state1 := &WAFState{}

	middleware.handlePhase(w1, req1, 1, state1)
	assert.False(t, state1.Blocked, "First request to /api/v1 should be allowed")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	req2 := httptest.NewRequest("GET", "/api/v1/users", nil)
	req2.RemoteAddr = localIP
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}
	middleware.handlePhase(w2, req2, 1, state2)
	assert.True(t, state2.Blocked, "Second request to /api/v1 should be rate-limited")
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Expected status code 429")

	// Test path 2
	req3 := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req3.RemoteAddr = localIP
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}
	middleware.handlePhase(w3, req3, 1, state3)
	assert.False(t, state3.Blocked, "First request to /admin should be allowed")
	assert.Equal(t, http.StatusOK, w3.Code, "Expected status code 200")

	req4 := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req4.RemoteAddr = localIP
	w4 := httptest.NewRecorder()
	state4 := &WAFState{}
	middleware.handlePhase(w4, req4, 1, state4)
	assert.True(t, state4.Blocked, "Second request to /admin should be rate-limited")
	assert.Equal(t, http.StatusTooManyRequests, w4.Code, "Expected status code 429")

	req5 := httptest.NewRequest("GET", "/not-rate-limited", nil)
	req5.RemoteAddr = localIP
	w5 := httptest.NewRecorder()
	state5 := &WAFState{}
	middleware.handlePhase(w5, req5, 1, state5)
	assert.False(t, state5.Blocked, "Request not rate limited path should be allowed")
	assert.Equal(t, http.StatusOK, w5.Code, "Expected status code 200")
}

func TestBlockedRequestPhase1_RateLimiting_DifferentIPs(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: func() *RateLimiter {
			rl, err := NewRateLimiter(RateLimit{
				Requests:        1,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
				MatchAllPaths:   true,
			})
			if err != nil {
				t.Fatalf("Failed to create rate limiter: %v", err)
			}
			return rl
		}(),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  iptrie.NewTrie(),
		dnsBlacklist: make(map[string]struct{}),
	}

	// Test different IPs
	req1 := httptest.NewRequest("GET", "/api/users", nil)
	req1.RemoteAddr = localIP
	w1 := httptest.NewRecorder()
	state1 := &WAFState{}

	middleware.handlePhase(w1, req1, 1, state1)
	assert.False(t, state1.Blocked, "First request from 192.168.1.1 should be allowed")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	req2 := httptest.NewRequest("GET", "/api/users", nil)
	req2.RemoteAddr = "192.168.1.2"
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}
	middleware.handlePhase(w2, req2, 1, state2)
	assert.False(t, state2.Blocked, "First request from 192.168.1.2 should be allowed")
	assert.Equal(t, http.StatusOK, w2.Code, "Expected status code 200")

	req3 := httptest.NewRequest("GET", "/api/users", nil)
	req3.RemoteAddr = localIP
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}
	middleware.handlePhase(w3, req3, 1, state3)
	assert.True(t, state3.Blocked, "Second request from 192.168.1.1 should be blocked")
	assert.Equal(t, http.StatusTooManyRequests, w3.Code, "Expected status code 429")
}

func TestBlockedRequestPhase1_RateLimiting_MatchAllPaths(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		rateLimiter: func() *RateLimiter {
			rl, err := NewRateLimiter(RateLimit{
				Requests:        1,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
				MatchAllPaths:   true,
			})
			if err != nil {
				t.Fatalf("Failed to create rate limiter: %v", err)
			}
			return rl
		}(),
		CustomResponses: map[int]CustomBlockResponse{
			429: {
				StatusCode: http.StatusTooManyRequests,
				Body:       "Rate limit exceeded",
			},
		},
		ipBlacklist:  iptrie.NewTrie(),
		dnsBlacklist: make(map[string]struct{}),
	}

	// Test with match all paths
	req1 := httptest.NewRequest("GET", "/api/users", nil)
	req1.RemoteAddr = localIP
	w1 := httptest.NewRecorder()
	state1 := &WAFState{}
	middleware.handlePhase(w1, req1, 1, state1)
	assert.False(t, state1.Blocked, "First request to /api/users should be allowed")
	assert.Equal(t, http.StatusOK, w1.Code, "Expected status code 200")

	req2 := httptest.NewRequest("GET", "/api/users", nil)
	req2.RemoteAddr = localIP
	w2 := httptest.NewRecorder()
	state2 := &WAFState{}

	middleware.handlePhase(w2, req2, 1, state2)
	assert.True(t, state2.Blocked, "Second request to /api/users should be rate-limited")
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Expected status code 429")

	req3 := httptest.NewRequest("GET", "/some-other-path", nil)
	req3.RemoteAddr = localIP
	w3 := httptest.NewRecorder()
	state3 := &WAFState{}
	middleware.handlePhase(w3, req3, 1, state3)
	assert.True(t, state3.Blocked, "Second request to /some-other-path should be rate-limited because MatchAllPaths=true")
	assert.Equal(t, http.StatusTooManyRequests, w3.Code, "Expected status code 429")
}
