package caddywaf

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

// allowRequest - handles request allowing
func (m *Middleware) allowRequest(state *WAFState) {
	state.Blocked = false
	state.StatusCode = http.StatusOK
	state.ResponseWritten = false
	// Not counted here: this runs at the end of every phase a request passes,
	// so counting here counted one allowed request up to four times. ServeHTTP
	// counts it once, where the request leaves the WAF.
}

// blockRequest handles blocking a request and logging the details.
func (m *Middleware) blockRequest(w http.ResponseWriter, r *http.Request, state *WAFState, statusCode int, reason, ruleID string, fields ...zap.Field) {
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

	// The one place a block is counted, so blocked and allowed add up to the
	// total (#248).
	m.incrementBlockedRequestsMetric()

	// A response-phase (Phase 3/4) block is only recorded here. The upstream's
	// headers sit in the shared header map and the upstream may still be
	// writing, so the block response is written once, by ServeHTTP, after the
	// upstream returned and its headers are gone (writeResponseBlock). Writing
	// it into the recorder appended it to the upstream body in pass-through
	// mode and lost it in inspect mode.
	if rec, ok := w.(*responseRecorder); ok {
		rec.block(statusCode, reason)
		return
	}

	m.writeBlockResponse(w, statusCode, reason)
}

// writeBlockResponse writes the block response: the custom_response configured
// for statusCode, or a plain-text default. It is the one place a block body is
// produced (#247). Headers go before WriteHeader, or the client never sees the
// custom Content-Type.
func (m *Middleware) writeBlockResponse(w http.ResponseWriter, statusCode int, reason string) {
	if custom, ok := m.CustomResponses[statusCode]; ok {
		for k, v := range custom.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(custom.StatusCode)
		if _, err := w.Write([]byte(custom.Body)); err != nil {
			m.logger.Error("Failed to write custom response body", zap.Error(err))
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	message := fmt.Sprintf("Request blocked by WAF. Reason: %s", reason)
	if _, err := w.Write([]byte(message)); err != nil {
		m.logger.Error("Failed to write blocked response", zap.Error(err))
	}
}

// writeResponseBlock sends the block response for a response-phase (Phase 3/4)
// block. Every header the upstream set is dropped first: the header map is put
// back to what it held before the upstream ran, so the upstream's
// Content-Length, Content-Encoding, Content-Type and the rest cannot describe
// (or leak alongside) the block body. If the upstream's status line already
// reached the client, a block body can only be appended to a response the
// client is already reading, so the connection is aborted instead
// (http.ErrAbortHandler, Caddy's convention); the block stays counted once.
func (m *Middleware) writeResponseBlock(w http.ResponseWriter, recorder *responseRecorder, logID string) {
	if recorder.headerSent {
		m.logger.Error("Response blocked after it started reaching the client; aborting the response",
			zap.String("log_id", logID),
			zap.Int("status_code", recorder.blockStatus),
			zap.String("reason", recorder.blockReason),
		)
		panic(http.ErrAbortHandler)
	}
	h := w.Header()
	clear(h)
	for k, v := range recorder.preHeader {
		h[k] = v
	}
	// Nothing of the upstream's may follow the block response.
	recorder.headerSent = true
	m.writeBlockResponse(w, recorder.blockStatus, recorder.blockReason)
}

// DefaultMaxResponseBodySize is the number of response bytes the WAF will hold
// in memory for Phase 4 (response body) inspection when no explicit limit is
// configured.
const DefaultMaxResponseBodySize int64 = 10 * 1024 * 1024 // 10 MiB

// errResponseBlocked is what the recorder returns to an upstream that keeps
// writing after a response-phase rule blocked its response, so the upstream
// stops producing bytes nobody will receive.
var errResponseBlocked = errors.New("caddy-waf: response blocked by a response-phase rule")

// responseRecorder captures the response status code, headers, and body.
//
// The body is only buffered while Phase 4 rules still have something to
// inspect, and never beyond limit bytes: once the upstream response outgrows
// the budget (or the upstream flushes, meaning it wants bytes on the wire now)
// the recorder releases what it holds and turns into a pass-through for the
// remainder of the stream. Memory therefore stays bounded by limit regardless
// of how large the upstream response is (GHSA-gfj3-cmff-q8wh).
//
// The status line and headers never reach the client before Phase 3 has seen
// them: when Phase 3 rules exist, ServeHTTP installs headerCheck and the
// recorder runs it at the moment the upstream's status line would be
// forwarded (commitHeader). In pass-through mode that is the upstream's
// WriteHeader (or the implicit one of a first Write or Flush), so the body
// still streams; in inspect mode it is when the held response is released or
// copied out. Once a response-phase rule blocks, the recorder forwards nothing
// more of the upstream's, and ServeHTTP writes the block response.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool // To track if a write to the original writer has been done.

	limit       int64 // Maximum number of bytes retained in body for inspection.
	passthrough bool  // True once writes go straight to the underlying writer.
	partial     bool  // True if bytes reached the client before inspection completed.
	headerSent  bool  // True once the status line has actually been forwarded to the client.

	headerCheck   func()      // Runs Phase 3; a block lands in block(). Nil when no Phase 3 rule exists.
	headerChecked bool        // True once headerCheck has run (it runs at most once).
	preHeader     http.Header // The header map as it was before the upstream ran; restored for a block response.
	blocked       bool        // True once a response-phase rule blocked this response.
	blockStatus   int         // Status the block response is written with.
	blockReason   string      // Reason the default block response reports.
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

// WriteHeader captures the response status code. In pass-through mode (no
// response-body inspection) it forwards the status to the client immediately,
// after Phase 3 (if any) has seen the headers. In inspect mode it only records
// the status: the status line is held until the WAF finishes Phase 3/4
// evaluation, so a response-phase block can still replace the response.
// release() / copyResponse forwards it once inspection is done.
func (r *responseRecorder) WriteHeader(statusCode int) {
	if r.blocked {
		return
	}
	// A 1xx informational status (103 Early Hints, for one) is not the final
	// status. While the recorder holds headers for inspection it is dropped:
	// it would put upstream headers on the wire before Phase 3 saw them, and
	// treating it as final would run Phase 3 on headers the upstream has not
	// finished setting.
	if statusCode >= 100 && statusCode < 200 && statusCode != http.StatusSwitchingProtocols &&
		(r.headerCheck != nil || !r.passthrough) && !r.headerSent {
		return
	}
	r.statusCode = statusCode
	if r.passthrough {
		r.commitHeader(statusCode)
	}
}

// block records a response-phase block. From here on nothing more of the
// upstream's response is forwarded; ServeHTTP writes the block response.
func (r *responseRecorder) block(statusCode int, reason string) {
	r.blocked = true
	r.blockStatus = statusCode
	r.blockReason = reason
}

// checkHeaders runs Phase 3 once and reports whether the response is blocked.
func (r *responseRecorder) checkHeaders() bool {
	if !r.headerChecked {
		r.headerChecked = true
		if r.headerCheck != nil {
			r.headerCheck()
		}
	}
	return r.blocked
}

// commitHeader is how the upstream's status line reaches the client: Phase 3
// sees the headers first, and a blocked response is never forwarded. It
// reports whether the status line is (now) on the wire.
func (r *responseRecorder) commitHeader(code int) bool {
	if r.headerSent {
		return true
	}
	if r.checkHeaders() {
		return false
	}
	r.forwardHeader(code)
	return true
}

// forwardHeader writes the status line to the underlying writer exactly once.
// It is idempotent, so both the inspect path (copyResponse) and the
// pass-through path can call it without risking a superfluous WriteHeader.
func (r *responseRecorder) forwardHeader(code int) {
	if r.headerSent {
		return
	}
	r.headerSent = true
	r.ResponseWriter.WriteHeader(code)
}

// Header returns the response headers.
func (r *responseRecorder) Header() http.Header {
	return r.ResponseWriter.Header()
}

// BodyString returns the captured response body as a string.
func (r *responseRecorder) BodyString() string {
	return r.body.String()
}

// StatusCode returns the status the client gets: the block status once a
// response-phase rule blocked, otherwise the captured upstream status.
func (r *responseRecorder) StatusCode() int {
	if r.blocked {
		return r.blockStatus
	}
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
// straight to the client once the recorder has switched to pass-through. A
// blocked response takes nothing more: the upstream gets errResponseBlocked.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.blocked {
		return 0, errResponseBlocked
	}
	if r.statusCode == 0 && !r.written {
		r.WriteHeader(http.StatusOK) // Default to 200 if not set
		if r.blocked {
			// The implicit status commit ran Phase 3, and it blocked.
			return 0, errResponseBlocked
		}
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
// buffer and streaming from here on instead of stalling the response. A flush
// commits the status line, so Phase 3 sees the headers first; a blocked
// response is never flushed.
func (r *responseRecorder) Flush() {
	if r.blocked {
		return
	}
	if !r.passthrough {
		if err := r.release(); err != nil {
			return
		}
	} else if r.headerCheck != nil && !r.commitHeader(r.StatusCode()) {
		return
	}
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// release hands the buffered bytes to the client and puts the recorder into
// pass-through mode. The buffer contents are kept so the captured prefix stays
// available to callers, but they are never sent twice: copyResponse skips a
// recorder that has already released. Phase 3 sees the headers before the
// status line goes out; if it blocks, nothing is released.
func (r *responseRecorder) release() error {
	// Send the held status before streaming: once bytes are on the wire the
	// status can no longer change (Partial() reflects this).
	if !r.commitHeader(r.StatusCode()) {
		return errResponseBlocked
	}
	r.partial = true
	r.passthrough = true
	if r.body.Len() == 0 {
		return nil
	}
	_, err := r.ResponseWriter.Write(r.body.Bytes())
	return err
}
