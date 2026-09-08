package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

func TestLogRequest(t *testing.T) {
	// Create a test logger using zaptest
	logger := zaptest.NewLogger(t)

	// Create a Middleware instance with the test logger
	middleware := &Middleware{
		logger:   logger,
		logLevel: zapcore.DebugLevel,
		logChan:  make(chan LogEntry, 100),
	}

	// Create a test request
	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	req.RemoteAddr = localIP
	req.Header.Set("User-Agent", "test-agent")

	// Log a test message
	middleware.logRequest(zapcore.InfoLevel, "Test message", req,
		zap.String("custom_field", "custom_value"),
	)

	// Wait for the log entry to be processed
	time.Sleep(100 * time.Millisecond)
}

func TestRedactSensitiveFields(t *testing.T) {
	m := &Middleware{}
	fields := []zap.Field{
		zap.String("password", "secret123"),
		zap.String("token", "abc123"),
		zap.String("normal", "value"),
	}

	redacted := m.redactSensitiveFields(fields)

	for _, field := range redacted {
		if field.Key == "password" || field.Key == "token" {
			if field.String != "[REDACTED]" {
				t.Errorf("Expected sensitive field %s to be redacted, got %s", field.Key, field.String)
			}
		}
		if field.Key == "normal" && field.String != "value" {
			t.Errorf("Expected normal field to remain unchanged")
		}
	}
}

func TestRedactQueryParams(t *testing.T) {
	m := &Middleware{}
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty query",
			input:    "",
			expected: "",
		},
		{
			name:     "Query with sensitive param",
			input:    "password=secret&name=john",
			expected: "password=REDACTED&name=john",
		},
		{
			name:     "Multiple sensitive params",
			input:    "token=abc&apikey=xyz&normal=value",
			expected: "token=REDACTED&apikey=REDACTED&normal=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.redactQueryParams(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestPrepareLogFields(t *testing.T) {
	redact := true
	m := &Middleware{
		RedactSensitiveData: &redact,
		logger:              zaptest.NewLogger(t),
	}

	url, _ := url.Parse("http://example.com/path?password=secret&name=john")
	req := &http.Request{
		Method:     "GET",
		URL:        url,
		RemoteAddr: "127.0.0.1",
		Header: http.Header{
			"User-Agent": []string{"test-agent"},
		},
	}

	fields := []zap.Field{
		zap.String("custom", "value"),
		zap.String("password", "secret"),
	}

	result := m.prepareLogFields(req, fields)

	// Verify basic fields exist
	fieldMap := make(map[string]string)
	for _, f := range result {
		if f.Type == zapcore.StringType {
			fieldMap[f.Key] = f.String
		}
	}

	expectedFields := []string{"source_ip", "user_agent", "request_method", "request_path", "query_params", "log_id"}
	for _, expected := range expectedFields {
		if _, exists := fieldMap[expected]; !exists {
			t.Errorf("Expected field %s not found in log fields", expected)
		}
	}

	// Verify sensitive data is redacted
	if fieldMap["query_params"] != "password=REDACTED&name=john" {
		t.Error("Sensitive query parameters were not properly redacted")
	}
}

func TestLogWorker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	m := &Middleware{
		logger:    logger,
		LogBuffer: 10,
	}

	m.StartLogWorker()
	defer m.StopLogWorker()

	// Test logging through channel
	testMessage := "test message"
	m.logRequest(zapcore.InfoLevel, testMessage, nil)

	// Allow some time for async processing
	time.Sleep(100 * time.Millisecond)
}
