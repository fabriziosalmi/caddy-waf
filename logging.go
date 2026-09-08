package caddywaf

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var sensitiveKeys = []string{
	"password",
	"token",
	"apikey",
	"authorization",
	"secret",
	"secretkey",
	"accesskey",
	"privatekey",
	"credentials",
	"pwd",
	"pin",
	"ssn",        // Social Security Number
	"creditcard", // Credit card number
	"cvv",        // Card verification value
	"cvc",        // Card verification code
	"email",      // Email address
	"phone",      // Phone number
	"address",    // Physical address
	"account",    // Bank account number
	"iban",       // International Bank Account Number
	"swift",      // Swift code
	"routing",    // Routing number
	"mfa",        // Multi-factor authentication code
	"otp",        // One-time password
	//"code",       // Generic code <------ REMOVED THIS
}

var sensitiveKeysMutex sync.RWMutex // Add mutex for thread safety when modifying

func RedactSensitiveData(data map[string]interface{}) map[string]interface{} {
	redactedData := make(map[string]interface{})
	sensitiveKeysMutex.RLock() // Lock for reading
	localSensitiveKeys := make([]string, len(sensitiveKeys))
	for i, key := range sensitiveKeys {
		localSensitiveKeys[i] = strings.ToLower(key)
	}
	sensitiveKeysMutex.RUnlock() // Unlock after reading

	for k, v := range data {
		lowerK := strings.ToLower(k)
		isSensitive := false
		for _, sk := range localSensitiveKeys {
			if strings.Contains(lowerK, sk) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			redactedData[k] = "[REDACTED]"
		} else {
			redactedData[k] = v
		}
	}
	return redactedData
}

// Function to modify sensitiveKeys in thread-safe way
func AddSensitiveKey(key string) {
	sensitiveKeysMutex.Lock()
	defer sensitiveKeysMutex.Unlock()
	sensitiveKeys = append(sensitiveKeys, key)
}

func RemoveSensitiveKey(key string) {
	sensitiveKeysMutex.Lock()
	defer sensitiveKeysMutex.Unlock()
	for i, v := range sensitiveKeys {
		if v == key {
			sensitiveKeys = append(sensitiveKeys[:i], sensitiveKeys[i+1:]...)
			return
		}
	}
}

func (m *Middleware) logRequest(level zapcore.Level, msg string, r *http.Request, fields ...zap.Field) {
	if m.logger == nil || level < m.logLevel {
		return // Early return if logger is nil or level is below threshold
	}

	allFields := m.prepareLogFields(r, fields) // Prepare all fields in one function

	// Send the log entry to the buffered channel
	select {
	case m.logChan <- LogEntry{Level: level, Message: msg, Fields: allFields}:
		// Log entry successfully queued
	default:
		// If the channel is full, fall back to synchronous logging
		m.logger.Warn("Log buffer full, falling back to synchronous logging",
			zap.String("message", msg),
			zap.Any("fields", allFields),
		)
		m.logger.Log(level, msg, allFields...)
	}
}

// redactSensitiveFields redacts sensitive information in the log fields.
func (m *Middleware) redactSensitiveFields(fields []zap.Field) []zap.Field {
	redactedFields := make([]zap.Field, len(fields))
	for i, field := range fields {
		redacted := false
		for _, key := range sensitiveKeys {
			if strings.Contains(strings.ToLower(field.Key), key) {
				redactedFields[i] = zap.String(field.Key, "[REDACTED]")
				redacted = true
				break
			}
		}
		if !redacted {
			redactedFields[i] = field
		}
	}
	return redactedFields
}

// prepareLogFields consolidates the logic for preparing log fields, including common fields and log_id.
func (m *Middleware) prepareLogFields(r *http.Request, fields []zap.Field) []zap.Field {
	var logID string
	allFields := make([]zap.Field, 0)

	// Initialize with common fields
	var sourceIP, userAgent, requestMethod, requestPath, queryParams string
	var statusCode int
	if r != nil {
		sourceIP = r.RemoteAddr
		userAgent = r.UserAgent()
		requestMethod = r.Method
		requestPath = r.URL.Path
		queryParams = r.URL.RawQuery
	}
	if m.redactEnabled() {
		queryParams = m.redactQueryParams(queryParams)
	}

	commonFields := []zap.Field{
		zap.String("source_ip", sourceIP),
		zap.String("user_agent", userAgent),
		zap.String("request_method", requestMethod),
		zap.String("request_path", requestPath),
		zap.String("query_params", queryParams),
		zap.Int("status_code", statusCode),
		zap.Time("timestamp", time.Now()),
	}

	// Extract log_id from given fields and prepare all fields
	mergedFields := make(map[string]zap.Field)
	for _, field := range fields {
		if field.Key == "log_id" {
			logID = field.String
		}
		mergedFields[field.Key] = field
	}

	if logID == "" {
		logID = uuid.New().String()
	}

	for _, common := range commonFields {
		if _, present := mergedFields[common.Key]; !present {
			mergedFields[common.Key] = common
		}
	}

	mergedFields["log_id"] = zap.String("log_id", logID)

	for _, field := range mergedFields {
		allFields = append(allFields, field)
	}

	// Redact sensitive information in the log fields
	allFields = m.redactSensitiveFields(allFields)

	return allFields
}

func (m *Middleware) redactQueryParams(queryParams string) string {
	if queryParams == "" {
		return ""
	}

	parts := strings.Split(queryParams, "&")
	for i, part := range parts {
		if strings.Contains(part, "=") {
			keyValue := strings.SplitN(part, "=", 2)
			if len(keyValue) == 2 {
				key := strings.ToLower(keyValue[0])
				if m.isSensitiveQueryParamKey(key) { // Use helper function for sensitive key check
					parts[i] = keyValue[0] + "=REDACTED"
				}
			}
		}
	}
	return strings.Join(parts, "&")
}

func (m *Middleware) isSensitiveQueryParamKey(key string) bool {
	sensitiveKeysMutex.RLock()
	defer sensitiveKeysMutex.RUnlock()
	for _, sensitiveKey := range sensitiveKeys { // Use package level sensitiveKeys variable
		if strings.Contains(key, sensitiveKey) {
			return true
		}
	}
	return false
}

func caddyTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006/01/02 15:04:05.000"))
}

// LogEntry represents a single log entry to be processed asynchronously.
type LogEntry struct {
	Level   zapcore.Level
	Message string
	Fields  []zap.Field
}

// StartLogWorker initializes the background logging worker.
func (m *Middleware) StartLogWorker() {
	if m.LogBuffer == 0 {
		m.LogBuffer = 1000 // Setting default log buffer
	}
	m.logChan = make(chan LogEntry, m.LogBuffer) // Buffer size can be adjusted
	m.logDone = make(chan struct{})

	go func() {
		for entry := range m.logChan {
			m.logger.Log(entry.Level, entry.Message, entry.Fields...)
		}
		close(m.logDone) // Signal that the worker has finished
	}()
}

// StopLogWorker stops the background logging worker.
func (m *Middleware) StopLogWorker() {
	close(m.logChan) // Close the channel to stop the worker
	<-m.logDone      // Wait for the worker to finish processing
}
