package caddywaf

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestMiddleware_RequestBodyRestoration(t *testing.T) {
	// Setup middleware
	// Create extractor
	logger := zap.NewNop()
	rve := NewRequestValueExtractor(logger, false, 1024*1024) // 1MB limit

	t.Run("Body < MaxSize", func(t *testing.T) {
		bodyContent := "small body"
		req := httptest.NewRequest("POST", "/", strings.NewReader(bodyContent))

		// Extract body (simulates WAF inspecting it)
		extracted, err := rve.ExtractValue(TargetBody, req, nil)
		assert.NoError(t, err)
		assert.Equal(t, bodyContent, extracted)

		// Verify body is restored and readable again
		restoredBody, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		assert.Equal(t, bodyContent, string(restoredBody))
	})

	t.Run("Body > MaxSize", func(t *testing.T) {
		// Max size is 1MB. Let's send 2MB.
		size := 2 * 1024 * 1024
		bodyContent := make([]byte, size)
		// Fill with some data
		for i := 0; i < size; i++ {
			bodyContent[i] = 'a'
		}

		req := httptest.NewRequest("POST", "/", bytes.NewReader(bodyContent))

		// Extract body
		extracted, err := rve.ExtractValue(TargetBody, req, nil)
		assert.NoError(t, err)

		// Extracted should be truncated to 1MB
		assert.Equal(t, 1024*1024, len(extracted))

		// Verify body restoration
		// If the implementation is naive, it might only restore the 1MB we read,
		// and the rest is lost because LimitReader consumed the prefix.
		// OR, if it restores using LimitReader's underlying reader, maybe it's fine?
		// Wait, LimitReader wraps the original request body.
		// We read from LimitReader.
		// If we replace req.Body with a new reader containing key read bytes...
		// The original req.Body (the socket/buffer) has been advanced by 1MB.
		// If we set req.Body = NewReader(readBytes), subsequent consumers will read 1MB and then EOF.
		// The remaining 1MB in the original req.Body is skipped/lost!

		restored, err := io.ReadAll(req.Body)
		assert.NoError(t, err)

		// This assertion is expected to FAIL if the bug exists for large bodies.
		// Use NotEqual or expect failure if we want to demonstrate the bug?
		// User says "POST request's body gone". They didn't specify size.
		// But let's see what happens.
		if len(restored) != size {
			t.Logf("Bug confirmed: Expected %d bytes, got %d", size, len(restored))
		}
		assert.Equal(t, size, len(restored))
	})
}
