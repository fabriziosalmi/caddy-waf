package caddywaf

import (
	"bytes"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

// allowRequest - handles request allowing
func (m *Middleware) allowRequest(state *WAFState) {
	state.Blocked = false
	state.StatusCode = http.StatusOK
	state.ResponseWritten = false

	m.incrementAllowedRequestsMetric()
}

// blockRequest handles blocking a request and logging the details.
func (m *Middleware) blockRequest(recorder http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, reason, ruleID string, fields ...zap.Field) {
	// CRITICAL FIX: Set these flags before any other operations
	state.Blocked = true
	state.StatusCode = statusCode
	state.ResponseWritten = true

	// Record the decision for the dashboard's recent-blocks tail and aggregates.
	m.recordBlock(r, state, statusCode, reason, ruleID)

	// CRITICAL FIX: Log at WARN level for visibility
	m.logger.Warn("REQUEST BLOCKED BY WAF", append(fields,
		zap.String("rule_id", ruleID),
		zap.String("reason", reason),
		zap.Int("status_code", statusCode),
		zap.String("remote_addr", r.RemoteAddr),
		zap.Int("total_score", state.TotalScore))...)

	// CRITICAL FIX: Increment blocked metrics immediately
	m.incrementBlockedRequestsMetric()

	// Write a simple text response for blocked requests
	recorder.Header().Set("Content-Type", "text/plain")
	recorder.WriteHeader(statusCode)

	if m.CustomResponses != nil {
		m.writeCustomResponse(recorder, state.StatusCode)
	} else {
		message := fmt.Sprintf("Request blocked by WAF. Reason: %s", reason)
		if _, err := recorder.Write([]byte(message)); err != nil {
			m.logger.Error("Failed to write blocked response", zap.Error(err))
		}
	}
}

// DefaultMaxResponseBodySize is the number of response bytes the WAF will hold
// in memory for Phase 4 (response body) inspection when no explicit limit is
// configured.
const DefaultMaxResponseBodySize int64 = 10 * 1024 * 1024 // 10 MiB

// responseRecorder captures the response status code, headers, and body.
//
// The body is only buffered while Phase 4 rules still have something to
// inspect, and never beyond limit bytes: once the upstream response outgrows
// the budget (or the upstream flushes, meaning it wants bytes on the wire now)
// the recorder releases what it holds and turns into a pass-through for the
// remainder of the stream. Memory therefore stays bounded by limit regardless
// of how large the upstream response is (GHSA-gfj3-cmff-q8wh).
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool // To track if a write to the original writer has been done.

	limit       int64 // Maximum number of bytes retained in body for inspection.
	passthrough bool  // True once writes go straight to the underlying writer.
	partial     bool  // True if bytes reached the client before inspection completed.
}

// NewResponseRecorder creates a new responseRecorder that buffers up to
// DefaultMaxResponseBodySize bytes for inspection.
func NewResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return NewResponseRecorderWithLimit(w, DefaultMaxResponseBodySize, true)
}

// NewResponseRecorderWithLimit creates a responseRecorder that retains at most
// limit bytes of the response body. A limit of zero or less falls back to
// DefaultMaxResponseBodySize. When inspect is false the recorder never buffers
// at all and simply forwards writes as they arrive, which is the right thing to
// do when no Phase 4 rule is configured.
func NewResponseRecorderWithLimit(w http.ResponseWriter, limit int64, inspect bool) *responseRecorder {
	if limit <= 0 {
		limit = DefaultMaxResponseBodySize
	}
	return &responseRecorder{
		ResponseWriter: w,
		body:           new(bytes.Buffer),
		statusCode:     0, // Zero means not explicitly set
		written:        false,
		limit:          limit,
		passthrough:    !inspect,
	}
}

// WriteHeader captures the response status code.
func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Header returns the response headers.
func (r *responseRecorder) Header() http.Header {
	return r.ResponseWriter.Header()
}

// BodyString returns the captured response body as a string.
func (r *responseRecorder) BodyString() string {
	return r.body.String()
}

// StatusCode returns the captured status code.
func (r *responseRecorder) StatusCode() int {
	if r.statusCode == 0 {
		return http.StatusOK
	}
	return r.statusCode
}

// Partial reports whether part of the response reached the client before the
// WAF could inspect the whole body, which happens when the body exceeds the
// configured limit or when the upstream flushed mid-stream. Phase 4 cannot
// block such a response, so it must not pretend to have vetted it.
func (r *responseRecorder) Partial() bool {
	return r.partial
}

// Write captures the response body into the inspection buffer, or forwards it
// straight to the client once the recorder has switched to pass-through.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 && !r.written {
		r.WriteHeader(http.StatusOK) // Default to 200 if not set
	}
	r.written = true

	if r.passthrough {
		return r.ResponseWriter.Write(b)
	}

	if int64(r.body.Len())+int64(len(b)) <= r.limit {
		return r.body.Write(b)
	}

	// The response outgrew the inspection budget. Release what we already hold
	// and stream the rest, so a large or endless upstream response can no
	// longer grow the heap in step with its size.
	if err := r.release(); err != nil {
		return 0, err
	}
	return r.ResponseWriter.Write(b)
}

// Flush implements http.Flusher. An upstream flush means the handler wants
// bytes on the wire now (SSE, chunked streaming), so honour it by releasing the
// buffer and streaming from here on instead of stalling the response.
func (r *responseRecorder) Flush() {
	if !r.passthrough {
		if err := r.release(); err != nil {
			return
		}
	}
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// release hands the buffered bytes to the client and puts the recorder into
// pass-through mode. The buffer contents are kept so the captured prefix stays
// available to callers, but they are never sent twice: copyResponse skips a
// recorder that has already released.
func (r *responseRecorder) release() error {
	r.partial = true
	r.passthrough = true
	if r.body.Len() == 0 {
		return nil
	}
	_, err := r.ResponseWriter.Write(r.body.Bytes())
	return err
}
