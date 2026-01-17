package caddywaf

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestPOSTBodyPreservation tests that POST request bodies are preserved
// after WAF inspection and forwarded correctly to upstream.
// This test addresses GitHub issue #76.
func TestPOSTBodyPreservation(t *testing.T) {
	logger := zap.NewNop()

	t.Run("JSON POST with BODY rule inspection", func(t *testing.T) {
		// Simulate a JSON POST request
		postData := map[string]interface{}{
			"username": "testuser",
			"password": "testpass123",
			"email":    "test@example.com",
		}
		jsonData, err := json.Marshal(postData)
		assert.NoError(t, err)

		// Create middleware with a Phase 2 rule that inspects BODY
		middleware := &Middleware{
			logger:                zap.NewNop(),
			requestValueExtractor: NewRequestValueExtractor(logger, false, 10*1024*1024),
			Rules: map[int][]Rule{
				2: {
					{
						ID:      "test-sql-injection",
						Targets: []string{"BODY"},
						Pattern: `(?i)(union.*select|drop.*table)`, // Pattern that won't match our test data
						Score:   5,
						Action:  "log",
					},
				},
			},
			AnomalyThreshold: 10,
		}

		// Create a test request
		req := httptest.NewRequest("POST", "/api/login", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(jsonData))

		// Create a response recorder
		recorder := httptest.NewRecorder()

		// Track what the upstream handler receives
		var upstreamReceivedBody []byte
		upstreamHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// Read the body that the upstream receives
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Upstream failed to read body: %v", err)
			}
			upstreamReceivedBody = body
			w.WriteHeader(http.StatusOK)
			return nil
		})

		// Execute the request through the WAF
		err = middleware.ServeHTTP(recorder, req, upstreamHandler)
		assert.NoError(t, err)

		// Verify upstream received the complete body
		assert.Equal(t, jsonData, upstreamReceivedBody, "Upstream should receive complete POST body")

		// Verify the body content is valid JSON
		var receivedData map[string]interface{}
		err = json.Unmarshal(upstreamReceivedBody, &receivedData)
		assert.NoError(t, err, "Upstream should receive valid JSON")
		assert.Equal(t, postData["username"], receivedData["username"])
		assert.Equal(t, postData["password"], receivedData["password"])
		assert.Equal(t, postData["email"], receivedData["email"])
	})

	t.Run("Form POST with BODY rule inspection", func(t *testing.T) {
		// Simulate a form POST request
		formData := "username=testuser&password=testpass123&email=test@example.com"

		// Create middleware with a Phase 2 rule that inspects BODY
		middleware := &Middleware{
			logger:                zap.NewNop(),
			requestValueExtractor: NewRequestValueExtractor(logger, false, 10*1024*1024),
			Rules: map[int][]Rule{
				2: {
					{
						ID:      "test-xss",
						Targets: []string{"BODY"},
						Pattern: `(?i)(<script|javascript:|onerror=)`, // Pattern that won't match our test data
						Score:   5,
						Action:  "log",
					},
				},
			},
			AnomalyThreshold: 10,
		}

		// Create a test request
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = int64(len(formData))

		// Create a response recorder
		recorder := httptest.NewRecorder()

		// Track what the upstream handler receives
		var upstreamReceivedBody string
		upstreamHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// Read the body that the upstream receives
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Upstream failed to read body: %v", err)
			}
			upstreamReceivedBody = string(body)
			w.WriteHeader(http.StatusOK)
			return nil
		})

		// Execute the request through the WAF
		err := middleware.ServeHTTP(recorder, req, upstreamHandler)
		assert.NoError(t, err)

		// Verify upstream received the complete body
		assert.Equal(t, formData, upstreamReceivedBody, "Upstream should receive complete form POST body")
	})

	t.Run("Large POST body within maxSize", func(t *testing.T) {
		// Create a reasonably large POST body (500KB)
		largeData := strings.Repeat("x", 500*1024)

		// Create middleware with a Phase 2 rule that inspects BODY
		middleware := &Middleware{
			logger:                zap.NewNop(),
			requestValueExtractor: NewRequestValueExtractor(logger, false, 10*1024*1024), // 10MB limit
			Rules: map[int][]Rule{
				2: {
					{
						ID:      "test-pattern",
						Targets: []string{"BODY"},
						Pattern: `impossible-pattern-to-match-12345`,
						Score:   5,
						Action:  "log",
					},
				},
			},
			AnomalyThreshold: 10,
		}

		// Create a test request
		req := httptest.NewRequest("POST", "/api/upload", strings.NewReader(largeData))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = int64(len(largeData))

		// Create a response recorder
		recorder := httptest.NewRecorder()

		// Track what the upstream handler receives
		var upstreamReceivedSize int
		upstreamHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// Read the body that the upstream receives
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Upstream failed to read body: %v", err)
			}
			upstreamReceivedSize = len(body)
			w.WriteHeader(http.StatusOK)
			return nil
		})

		// Execute the request through the WAF
		err := middleware.ServeHTTP(recorder, req, upstreamHandler)
		assert.NoError(t, err)

		// Verify upstream received the complete body
		assert.Equal(t, len(largeData), upstreamReceivedSize, "Upstream should receive complete large POST body")
	})

	t.Run("Multiple BODY inspections", func(t *testing.T) {
		// Simulate a POST request that will be inspected by multiple rules
		postData := `{"query": "SELECT * FROM users WHERE active=1"}`

		// Create middleware with multiple Phase 2 rules that inspect BODY
		middleware := &Middleware{
			logger:                zap.NewNop(),
			requestValueExtractor: NewRequestValueExtractor(logger, false, 10*1024*1024),
			Rules: map[int][]Rule{
				2: {
					{
						ID:      "sql-injection-check",
						Targets: []string{"BODY"},
						Pattern: `(?i)(union.*select|drop.*table)`,
						Score:   5,
						Action:  "log",
					},
					{
						ID:      "xss-check",
						Targets: []string{"BODY"},
						Pattern: `(?i)(<script|javascript:)`,
						Score:   5,
						Action:  "log",
					},
					{
						ID:      "command-injection-check",
						Targets: []string{"BODY"},
						Pattern: `(?i)(;.*rm\s+-rf|&&.*cat\s+)`,
						Score:   5,
						Action:  "log",
					},
				},
			},
			AnomalyThreshold: 20,
		}

		// Create a test request
		req := httptest.NewRequest("POST", "/api/query", strings.NewReader(postData))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(postData))

		// Create a response recorder
		recorder := httptest.NewRecorder()

		// Track what the upstream handler receives
		var upstreamReceivedBody string
		upstreamHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// Read the body that the upstream receives
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("Upstream failed to read body: %v", err)
			}
			upstreamReceivedBody = string(body)
			w.WriteHeader(http.StatusOK)
			return nil
		})

		// Execute the request through the WAF
		err := middleware.ServeHTTP(recorder, req, upstreamHandler)
		assert.NoError(t, err)

		// Verify upstream received the complete body after multiple inspections
		assert.Equal(t, postData, upstreamReceivedBody, "Upstream should receive complete body even after multiple BODY inspections")
	})
}

// TestSimpleBodyFlowNoRules tests that body is preserved even when no rules are present
func TestSimpleBodyFlowNoRules(t *testing.T) {
logger := zap.NewNop()

middleware := &Middleware{
logger:                logger,
requestValueExtractor: NewRequestValueExtractor(logger, false, 10*1024*1024),
Rules:                 map[int][]Rule{}, // No rules
AnomalyThreshold:      10,
}

testData := []byte("simple test body")
req := httptest.NewRequest("POST", "/", bytes.NewReader(testData))
req.ContentLength = int64(len(testData))

recorder := httptest.NewRecorder()

var upstreamBody []byte
upstreamHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
var err error
upstreamBody, err = io.ReadAll(r.Body)
if err != nil {
t.Logf("Upstream read error: %v", err)
} else {
t.Logf("Upstream received: %d bytes", len(upstreamBody))
}
return err
})

err := middleware.ServeHTTP(recorder, req, upstreamHandler)
assert.NoError(t, err)
assert.Equal(t, testData, upstreamBody, "Upstream should receive body even with no rules")
}
