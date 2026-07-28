package caddywaf

import (
	"bytes"
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

// countingWriter records how many bytes have reached the client so far, so a
// test can tell buffered delivery apart from streamed delivery.
type countingWriter struct {
	header  http.Header
	code    int
	written int64
	flushes int
}

func newCountingWriter() *countingWriter {
	return &countingWriter{header: make(http.Header)}
}

func (c *countingWriter) Header() http.Header { return c.header }

func (c *countingWriter) WriteHeader(statusCode int) { c.code = statusCode }

func (c *countingWriter) Write(b []byte) (int, error) {
	c.written += int64(len(b))
	return len(b), nil
}

func (c *countingWriter) Flush() { c.flushes++ }

// TestResponseRecorderBoundedBuffering covers GHSA-gfj3-cmff-q8wh: the recorder
// must never retain an unbounded amount of the upstream response.
func TestResponseRecorderBoundedBuffering(t *testing.T) {
	t.Run("buffers below the limit without touching the client", func(t *testing.T) {
		w := httptest.NewRecorder()
		rec := NewResponseRecorderWithLimit(w, 1024, true)

		n, err := rec.Write([]byte(strings.Repeat("a", 100)))
		require.NoError(t, err)
		assert.Equal(t, 100, n)

		assert.Equal(t, strings.Repeat("a", 100), rec.BodyString())
		assert.Empty(t, w.Body.String(), "nothing may reach the client before inspection")
		assert.False(t, rec.Partial())
	})

	t.Run("releases and streams once the limit is exceeded", func(t *testing.T) {
		w := httptest.NewRecorder()
		rec := NewResponseRecorderWithLimit(w, 16, true)

		_, err := rec.Write([]byte(strings.Repeat("a", 10)))
		require.NoError(t, err)
		assert.Empty(t, w.Body.String(), "still within the budget")

		_, err = rec.Write([]byte(strings.Repeat("b", 20)))
		require.NoError(t, err)

		assert.True(t, rec.Partial(), "recorder must report the body as un-inspected")
		assert.True(t, rec.passthrough)
		assert.Equal(t, strings.Repeat("a", 10)+strings.Repeat("b", 20), w.Body.String(),
			"every byte must reach the client exactly once, in order")
	})

	t.Run("a single oversized write is never buffered", func(t *testing.T) {
		w := httptest.NewRecorder()
		rec := NewResponseRecorderWithLimit(w, 16, true)

		payload := bytes.Repeat([]byte("x"), 1<<20)
		n, err := rec.Write(payload)
		require.NoError(t, err)
		assert.Equal(t, len(payload), n)

		assert.LessOrEqual(t, int64(rec.body.Len()), rec.limit, "retained bytes must stay within the limit")
		assert.Equal(t, len(payload), w.Body.Len())
	})

	t.Run("memory stays bounded across many writes", func(t *testing.T) {
		w := newCountingWriter()
		rec := NewResponseRecorderWithLimit(w, 4096, true)

		chunk := bytes.Repeat([]byte("z"), 64*1024)
		const chunks = 256 // 16 MiB total
		for i := 0; i < chunks; i++ {
			_, err := rec.Write(chunk)
			require.NoError(t, err)
			require.LessOrEqual(t, int64(rec.body.Len()), rec.limit,
				"recorder grew past its limit on chunk %d", i)
		}

		assert.Equal(t, int64(chunks*len(chunk)), w.written, "client must receive the whole response")
	})

	t.Run("no inspection means no buffering at all", func(t *testing.T) {
		w := newCountingWriter()
		rec := NewResponseRecorderWithLimit(w, 4096, false)

		payload := bytes.Repeat([]byte("q"), 1<<20)
		_, err := rec.Write(payload)
		require.NoError(t, err)

		assert.Zero(t, rec.body.Len(), "a pass-through recorder must not allocate a copy")
		assert.Equal(t, int64(len(payload)), w.written)
	})

	t.Run("an upstream flush releases the buffer instead of stalling", func(t *testing.T) {
		w := newCountingWriter()
		rec := NewResponseRecorderWithLimit(w, 1<<20, true)

		_, err := rec.Write([]byte("event: ping\n\n"))
		require.NoError(t, err)
		assert.Zero(t, w.written, "buffered until the upstream asks for a flush")

		rec.Flush()

		assert.Equal(t, int64(len("event: ping\n\n")), w.written)
		assert.Equal(t, 1, w.flushes)
		assert.True(t, rec.Partial())
	})

	t.Run("a non-positive limit falls back to the default", func(t *testing.T) {
		rec := NewResponseRecorderWithLimit(httptest.NewRecorder(), 0, true)
		assert.Equal(t, DefaultMaxResponseBodySize, rec.limit)

		rec = NewResponseRecorderWithLimit(httptest.NewRecorder(), -1, true)
		assert.Equal(t, DefaultMaxResponseBodySize, rec.limit)

		assert.Equal(t, DefaultMaxResponseBodySize, NewResponseRecorder(httptest.NewRecorder()).limit)
	})
}

// newResponseLimitMiddleware builds a middleware with the given Phase 4 rules
// and response body budget.
func newResponseLimitMiddleware(t *testing.T, maxResponseBody int64, phase4 []Rule) *Middleware {
	t.Helper()
	logger := zap.NewNop()
	rules := map[int][]Rule{}
	if len(phase4) > 0 {
		rules[4] = phase4
	}
	return &Middleware{
		logger:                logger,
		Rules:                 rules,
		MaxResponseBodySize:   maxResponseBody,
		AnomalyThreshold:      5,
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
}

func serveBody(t *testing.T, m *Middleware, w http.ResponseWriter, body []byte) {
	t.Helper()
	handler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		return err
	})
	req := httptest.NewRequest(http.MethodGet, testURL, nil)
	req.RemoteAddr = localIP
	require.NoError(t, m.ServeHTTP(w, req, handler))
}

func TestServeHTTPDoesNotBufferLargeResponses(t *testing.T) {
	t.Run("without Phase 4 rules the body is streamed, not held", func(t *testing.T) {
		m := newResponseLimitMiddleware(t, 4096, nil)
		w := newCountingWriter()

		payload := bytes.Repeat([]byte("a"), 8<<20)
		serveBody(t, m, w, payload)

		assert.Equal(t, int64(len(payload)), w.written, "the client must get the body exactly once")
	})

	t.Run("with Phase 4 rules the body is capped and still delivered intact", func(t *testing.T) {
		m := newResponseLimitMiddleware(t, 4096, []Rule{{
			ID:      "resp_leak",
			Pattern: "SECRET",
			Targets: []string{"RESPONSE_BODY"},
			Phase:   4,
			Score:   10,
			Action:  "block",
			regex:   regexp.MustCompile("SECRET"),
		}})
		w := httptest.NewRecorder()

		payload := append(bytes.Repeat([]byte("a"), 1<<20), []byte("SECRET")...)
		serveBody(t, m, w, payload)

		// The response outgrew the inspection budget, so it could not be
		// blocked -- but it must be delivered whole and exactly once.
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, len(payload), w.Body.Len())
	})

	// NOTE: the status code of a Phase 4 block cannot be asserted here.
	// responseRecorder.WriteHeader forwards the status to the real
	// ResponseWriter as soon as the upstream sets it, so by the time Phase 4
	// runs the status line is already committed. That is a separate,
	// pre-existing limitation of the response phases; what this test pins down
	// is that the offending body is withheld.
	t.Run("a body within the budget is still inspected and blocked", func(t *testing.T) {
		m := newResponseLimitMiddleware(t, 1<<20, []Rule{{
			ID:      "resp_leak",
			Pattern: "SECRET",
			Targets: []string{"RESPONSE_BODY"},
			Phase:   4,
			Score:   10,
			Action:  "block",
			regex:   regexp.MustCompile("SECRET"),
		}})
		m.CustomResponses = map[int]CustomBlockResponse{
			http.StatusForbidden: {StatusCode: http.StatusForbidden, Body: "Blocked"},
		}
		w := httptest.NewRecorder()

		serveBody(t, m, w, []byte("leaking a SECRET value"))

		assert.NotContains(t, w.Body.String(), "SECRET", "the offending body must never reach the client")
		assert.Equal(t, "Blocked", w.Body.String(), "the custom block response must reach the client")
	})
}
