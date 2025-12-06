package caddywaf

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestExtractValue(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, true)

	tests := []struct {
		name          string
		target        string
		setupRequest  func() (*http.Request, http.ResponseWriter)
		expectedValue string
		expectedError bool
	}{
		{
			name:   "Extract METHOD",
			target: "METHOD",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("POST", testURL, nil)
				return req, httptest.NewRecorder()
			},
			expectedValue: "POST",
			expectedError: false,
		},
		{
			name:   "Extract PATH",
			target: "PATH",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com/test/path", nil)
				return req, httptest.NewRecorder()
			},
			expectedValue: "/test/path",
			expectedError: false,
		},
		{
			name:   "Extract USER_AGENT",
			target: "USER_AGENT",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", testURL, nil)
				req.Header.Set("User-Agent", "test-agent")
				return req, httptest.NewRecorder()
			},
			expectedValue: "test-agent",
			expectedError: false,
		},
		{
			name:   "Extract HEADERS prefix",
			target: "HEADERS:Content-Type",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", testURL, nil)
				req.Header.Set("Content-Type", "application/json")
				return req, httptest.NewRecorder()
			},
			expectedValue: "application/json",
			expectedError: false,
		},
		{
			name:   "Extract multiple targets",
			target: "METHOD,PATH",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				return req, httptest.NewRecorder()
			},
			expectedValue: "GET,/test",
			expectedError: false,
		},
		{
			name:   "Empty target",
			target: "",
			setupRequest: func() (*http.Request, http.ResponseWriter) {
				return httptest.NewRequest("GET", testURL, nil), httptest.NewRecorder()
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, w := tt.setupRequest()
			value, err := rve.ExtractValue(tt.target, req, w)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectedError && value != tt.expectedValue {
				t.Errorf("Expected value %q but got %q", tt.expectedValue, value)
			}
		})
	}
}

func TestRedactValueIfSensitive(t *testing.T) {
	logger := zap.NewNop()
	tests := []struct {
		name             string
		redactSensitive  bool
		target           string
		value            string
		expectedRedacted bool
	}{
		{
			name:             "Sensitive target with redaction enabled",
			redactSensitive:  true,
			target:           "password",
			value:            "secret123",
			expectedRedacted: true,
		},
		{
			name:             "Sensitive target with redaction disabled",
			redactSensitive:  false,
			target:           "password",
			value:            "secret123",
			expectedRedacted: false,
		},
		{
			name:             "Non-sensitive target",
			redactSensitive:  true,
			target:           "username",
			value:            "user123",
			expectedRedacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rve := NewRequestValueExtractor(logger, tt.redactSensitive)
			result := rve.RedactValueIfSensitive(tt.target, tt.value)

			if tt.expectedRedacted && result != "REDACTED" {
				t.Errorf("Expected REDACTED but got %q", result)
			}
			if !tt.expectedRedacted && result != tt.value {
				t.Errorf("Expected %q but got %q", tt.value, result)
			}
		})
	}
}

func TestExtractValue_HeaderCaseInsensitive(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("x-test-header", "test-value")
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("HEADERS:X-Test-Header", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "test-value", value) // Check if case-insensitive extraction works
}

func TestExtractValue_EmptyTarget(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	_, err := rve.ExtractValue("", req, w)
	assert.Error(t, err)
	assert.Equal(t, "empty extraction target", err.Error())
}

func TestExtractValue_Method(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("METHOD", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "GET", value)
}

func TestExtractValue_RemoteIP(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("REMOTE_IP", req, w)
	assert.NoError(t, err)
	assert.Equal(t, localIP, value)
}

func TestExtractValue_Protocol(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/1.1"
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("PROTOCOL", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "HTTP/1.1", value)
}

func TestExtractValue_Host(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("HOST", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", value)
}

func TestExtractValue_Args(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/?foo=bar&baz=qux", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("ARGS", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "foo=bar&baz=qux", value)
}

func TestExtractValue_UserAgent(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("USER_AGENT", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "test-agent", value)
}

func TestExtractValue_Path(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/test-path", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("PATH", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "/test-path", value)
}

func TestExtractValue_URI(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/test-path?foo=bar", nil)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("URI", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "/test-path?foo=bar", value)
}

func TestExtractValue_Body(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	body := bytes.NewBufferString("test body")
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("BODY", req, w)
	assert.NoError(t, err)
	assert.Equal(t, "test body", value)
}

func TestExtractValue_Headers(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Test-Header", "test-value")
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("HEADERS", req, w)
	assert.NoError(t, err)
	assert.Contains(t, value, "X-Test-Header: test-value")
}

func TestExtractValue_Cookies(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "test-cookie", Value: "test-value"})
	w := httptest.NewRecorder()

	value, err := rve.ExtractValue("COOKIES", req, w)
	assert.NoError(t, err)
	assert.Contains(t, value, "test-cookie=test-value")
}

func TestExtractValue_UnknownTarget(t *testing.T) {
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	_, err := rve.ExtractValue("UNKNOWN_TARGET", req, w)
	assert.Error(t, err)
	assert.Equal(t, "unknown extraction target: UNKNOWN_TARGET", err.Error())
}

// MockLogger is a mock logger for testing purposes.
type MockLogger struct {
	*zap.Logger
	lastLog zapcore.Entry
	mu      sync.Mutex
}

func (m *MockLogger) Log(level zapcore.Level, msg string, fields ...zap.Field) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLog = zapcore.Entry{
		Level:   level,
		Message: msg,
	}
	m.Logger.Log(level, msg, fields...)
}

func (m *MockLogger) LastLog() zapcore.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastLog
}

func newMockLogger() *MockLogger {
	logger, _ := zap.NewDevelopment()
	return &MockLogger{Logger: logger}
}

func TestProcessRuleMatch_HighScore(t *testing.T) {
	logger := newMockLogger()
	middleware := &Middleware{
		logger:                logger.Logger,
		AnomalyThreshold:      100, // High threshold
		ruleHits:              sync.Map{},
		muMetrics:             sync.RWMutex{},
		requestValueExtractor: NewRequestValueExtractor(logger.Logger, false), // Initialize
	}

	rule := &Rule{
		ID:          "rule1",
		Targets:     []string{"header"},
		Description: "Test rule with high score",
		Score:       200, // Very high score
		Action:      "block",
	}

	state := &WAFState{
		TotalScore:      0,
		ResponseWritten: false,
	}

	req := httptest.NewRequest("GET", testURL, nil)

	// Create a context and add logID to it - FIX: ADD CONTEXT HERE
	ctx := context.Background()
	logID := "test-log-id-highscore" // Unique log ID for this test
	ctx = context.WithValue(ctx, ContextKeyLogId("logID"), logID)
	req = req.WithContext(ctx) // Create new request with context

	w := httptest.NewRecorder()

	// Test blocking rule with high score
	shouldContinue := middleware.processRuleMatch(w, req, rule, "header", "value", state)
	assert.False(t, shouldContinue)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, state.Blocked)
	assert.Equal(t, 200, state.TotalScore)
}

func TestValidateRule_EmptyTargets(t *testing.T) {
	rule := &Rule{
		ID:      "rule1",
		Pattern: ".*",
		Targets: []string{}, // Empty targets
		Phase:   1,
		Score:   5,
		Action:  "block",
	}

	err := validateRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has no targets")
}

func TestNewRequestValueExtractor(t *testing.T) {
	logger := zap.NewNop()
	redactSensitiveData := true
	rve := NewRequestValueExtractor(logger, redactSensitiveData)

	assert.NotNil(t, rve)
	assert.Equal(t, logger, rve.logger)
	assert.Equal(t, redactSensitiveData, rve.redactSensitiveData)
}

// testing tests :)

func TestConcurrentRuleEvaluation(t *testing.T) {
	logger := zap.NewNop()
	middleware := &Middleware{
		logger: logger,
		Rules: map[int][]Rule{
			1: {
				{
					ID:      "rule1",
					Pattern: ".*",
					Targets: []string{"header"},
					Phase:   1,
					Score:   5,
					Action:  "block",
				},
			},
		},
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false),
		rateLimiter: func() *RateLimiter {
			rl, err := NewRateLimiter(RateLimit{
				Requests:        10,
				Window:          time.Minute,
				CleanupInterval: time.Minute,
			})
			if err != nil {
				t.Fatalf("Failed to create rate limiter: %v", err)
			}
			return rl
		}(),
		CustomResponses: customResponse,
	}

	// Add some IPs to the blacklist
	middleware.ipBlacklist.Insert(netip.MustParsePrefix("192.168.1.0/24"), nil)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", testURL, nil)
			req.RemoteAddr = fmt.Sprintf("192.168.1.%d", i%256) // Simulate different IPs
			req.Header.Set("User-Agent", "test-agent")          // Add a header for rule evaluation
			w := httptest.NewRecorder()
			state := &WAFState{}
			middleware.handlePhase(w, req, 1, state)
		}(i)
	}
	wg.Wait()
}

// TestParseRateLimit_InvalidRequests tests invalid requests value
func TestParseRateLimit_InvalidRequests(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        rate_limit {
            requests invalid
            window 10s
        }
    `)

	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}
	err := cl.parseRateLimit(d, m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid syntax")
}

// TestParseRateLimit_InvalidWindow tests invalid window value
func TestParseRateLimit_InvalidWindow(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        rate_limit {
            requests 100
            window invalid
        }
    `)

	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}
	err := cl.parseRateLimit(d, m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid duration")
}

// TestParseAnomalyThreshold_Invalid tests invalid anomaly threshold
func TestParseAnomalyThreshold_Invalid(t *testing.T) {
	logger := zap.NewNop()
	cl := NewConfigLoader(logger)
	m := &Middleware{}
	d := caddyfile.NewTestDispenser(`
        anomaly_threshold invalid
    `)
	// Advance to the "anomaly_threshold" directive
	if !d.Next() {
		t.Fatal("Failed to advance to the first directive")
	}

	err := cl.parseAnomalyThreshold(d, m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid syntax")
}
