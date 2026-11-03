package caddywaf

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// A response-phase (Phase 3 or Phase 4) block used to leak the upstream
// response. With no Phase 4 rule the recorder streams, so a Phase 3 block
// arrived after the upstream's 200 and body had already gone out, and the block
// text was appended to them. With a Phase 4 rule loaded the Phase 3 block was
// written into the recorder and never forwarded: the client got an empty 200.
// A Phase 4 block went out with the upstream's headers still set, so the
// client read a 403 that declared the upstream's Content-Length and
// Content-Encoding, plus every other upstream header, and hit an unexpected
// EOF. These tests pin the fixed behaviour: exactly one block response, with
// the block status and none of the upstream's headers or body bytes.

const (
	upstreamSecretBody = "SECRET-UPSTREAM-BODY-THAT-IS-LONGER-THAN-THE-BLOCK-MESSAGE-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	customBlockBody    = `{"error":"blocked"}`
)

var customBlock = map[int]CustomBlockResponse{
	http.StatusForbidden: {
		StatusCode: http.StatusForbidden,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       customBlockBody,
	},
}

// responsePhaseMiddleware loads a Phase 3 rule that blocks when the response
// carries "X-Response-Header: evil" (phase3), a Phase 4 rule (phase4), and
// sets whether the Phase 4 rule can match the upstream body (p4Matches).
func responsePhaseMiddleware(phase3, phase4, p4Matches bool, custom map[int]CustomBlockResponse) *Middleware {
	logger := zap.NewNop()
	rules := map[int][]Rule{}
	if phase3 {
		rules[3] = []Rule{{
			ID: "resp-header", Pattern: "evil", Targets: []string{"RESPONSE_HEADERS:X-Response-Header"},
			Phase: 3, Score: 5, Action: "block", regex: regexp.MustCompile("evil"),
		}}
	}
	if phase4 {
		pattern := "never-in-the-body"
		if p4Matches {
			pattern = "SECRET"
		}
		rules[4] = []Rule{{
			ID: "resp-body", Pattern: pattern, Targets: []string{"RESPONSE_BODY"},
			Phase: 4, Score: 5, Action: "block", regex: regexp.MustCompile(pattern),
		}}
	}
	return &Middleware{
		logger:                logger,
		Rules:                 rules,
		CustomResponses:       custom,
		ruleCache:             NewRuleCache(),
		ipBlacklist:           iptrie.NewTrie(),
		dnsBlacklist:          map[string]struct{}{},
		requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
	}
}

// leakyUpstream answers like reverse_proxy does: it copies the upstream's
// headers into the shared header map, writes the status, then the body. The
// error the last Write returned is stored in *writeErr.
func leakyUpstream(evilHeader bool, writeErr *error) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		if evilHeader {
			w.Header().Set("X-Response-Header", "evil")
		}
		w.Header().Set("X-Upstream", "leaked")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(upstreamSecretBody)))
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(upstreamSecretBody))
		if writeErr != nil {
			*writeErr = err
		}
		return nil
	})
}

type responseBlockCase struct {
	name      string
	phase3    bool // load the Phase 3 rule
	phase4    bool // load a Phase 4 rule (puts the recorder in inspect mode)
	p4Matches bool // the Phase 4 rule matches the upstream body
	evil      bool // the upstream sends the header the Phase 3 rule blocks on
}

var responseBlockCases = []responseBlockCase{
	{name: "phase3_passthrough", phase3: true, evil: true},
	{name: "phase3_inspect", phase3: true, phase4: true, evil: true},
	{name: "phase4", phase4: true, p4Matches: true},
	{name: "phase4_with_phase3_rules", phase3: true, phase4: true, p4Matches: true},
}

func expectedBlock(custom map[int]CustomBlockResponse) (ctype, body string) {
	if custom != nil {
		return "application/json", customBlockBody
	}
	return "text/plain", "Request blocked by WAF. Reason: Rule action is 'block'"
}

func assertOnlyBlockResponse(t *testing.T, code int, h http.Header, body string, custom map[int]CustomBlockResponse) {
	t.Helper()
	ctype, want := expectedBlock(custom)
	assert.Equal(t, http.StatusForbidden, code, "status")
	assert.Equal(t, want, body, "body must be exactly the block response")
	assert.NotContains(t, body, "SECRET", "upstream body bytes reached the client")
	assert.Equal(t, ctype, h.Get("Content-Type"), "Content-Type")
	assert.Empty(t, h.Get("X-Upstream"), "upstream header leaked")
	assert.Empty(t, h.Get("X-Response-Header"), "upstream header leaked")
	assert.Empty(t, h.Get("Content-Encoding"), "upstream Content-Encoding leaked")
	if cl := h.Get("Content-Length"); cl != "" {
		assert.Equal(t, fmt.Sprint(len(want)), cl, "Content-Length must describe the block body")
	}
}

func TestResponsePhaseBlockSendsOnlyTheBlockResponse(t *testing.T) {
	for _, tc := range responseBlockCases {
		for _, resp := range []struct {
			name   string
			custom map[int]CustomBlockResponse
		}{{"default", nil}, {"custom", customBlock}} {
			t.Run(tc.name+"/"+resp.name, func(t *testing.T) {
				m := responsePhaseMiddleware(tc.phase3, tc.phase4, tc.p4Matches, resp.custom)
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.RemoteAddr = localIP
				w := httptest.NewRecorder()
				// A header set before the WAF ran (e.g. by an earlier handler)
				// is not the upstream's and stays on the block response.
				w.Header().Set("X-Before-Waf", "kept")

				var writeErr error
				require.NoError(t, m.ServeHTTP(w, req, leakyUpstream(tc.evil, &writeErr)))

				res := w.Result()
				assertOnlyBlockResponse(t, res.StatusCode, res.Header, w.Body.String(), resp.custom)
				assert.Equal(t, "kept", res.Header.Get("X-Before-Waf"), "a header set before the upstream ran must survive")
				if tc.phase3 && tc.evil && !tc.phase4 {
					// Streaming mode: the block is decided at WriteHeader, so the
					// upstream is told to stop instead of streaming into the void.
					assert.ErrorIs(t, writeErr, errResponseBlocked)
				}

				assert.Equal(t, int64(1), m.totalRequests.Load(), "total")
				assert.Equal(t, int64(1), m.blockedRequests.Load(), "blocked")
				assert.Equal(t, int64(0), m.allowedRequests.Load(), "allowed")
			})
		}
	}
}

// The same cases through a real net/http server and client: what an actual
// client reads off the wire, including framing errors.
func TestResponsePhaseBlockOverRealClient(t *testing.T) {
	for _, tc := range responseBlockCases {
		t.Run(tc.name, func(t *testing.T) {
			m := responsePhaseMiddleware(tc.phase3, tc.phase4, tc.p4Matches, nil)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = localIP
				_ = m.ServeHTTP(w, r, leakyUpstream(tc.evil, nil))
			}))
			defer srv.Close()

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
			require.NoError(t, err)
			// Ask for identity explicitly so the client does not try to gunzip
			// a leaked Content-Encoding and hide the raw bytes from the test.
			req.Header.Set("Accept-Encoding", "identity")
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			b, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			require.NoError(t, readErr, "the client must read a well-framed response")
			assertOnlyBlockResponse(t, resp.StatusCode, resp.Header, string(b), nil)
		})
	}
}

// A clean response under response-phase rules is delivered unchanged, and with
// only Phase 3 rules it still streams: the first body bytes reach the client
// before the upstream returns.
func TestResponsePhaseRulesLetCleanResponsesThrough(t *testing.T) {
	for _, tc := range []struct {
		name   string
		phase4 bool
	}{{"phase3_only_streams", false}, {"phase3_and_phase4", true}} {
		t.Run(tc.name, func(t *testing.T) {
			m := responsePhaseMiddleware(true, tc.phase4, false, nil)
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.RemoteAddr = localIP
			w := httptest.NewRecorder()

			var seenWhileStreaming int
			up := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) error {
				rw.Header().Set("X-Upstream", "fine")
				rw.Header().Set("Content-Length", fmt.Sprint(len(upstreamSecretBody)))
				rw.WriteHeader(http.StatusCreated)
				if _, err := rw.Write([]byte(upstreamSecretBody)); err != nil {
					return err
				}
				seenWhileStreaming = w.Body.Len()
				return nil
			})
			require.NoError(t, m.ServeHTTP(w, req, up))

			res := w.Result()
			assert.Equal(t, http.StatusCreated, res.StatusCode)
			assert.Equal(t, upstreamSecretBody, w.Body.String())
			assert.Equal(t, "fine", res.Header.Get("X-Upstream"))
			assert.Equal(t, fmt.Sprint(len(upstreamSecretBody)), res.Header.Get("Content-Length"))
			if !tc.phase4 {
				assert.Equal(t, len(upstreamSecretBody), seenWhileStreaming, "Phase 3 rules alone must not buffer the body")
			} else {
				assert.Equal(t, 0, seenWhileStreaming, "Phase 4 rules hold the body for inspection")
			}
			assert.Equal(t, int64(1), m.allowedRequests.Load(), "allowed")
			assert.Equal(t, int64(0), m.blockedRequests.Load(), "blocked")
		})
	}
}

// An upstream that commits its headers by flushing, or that sends a 1xx
// informational status before setting the header Phase 3 blocks on, must not
// get its headers past Phase 3.
func TestPhase3SeesTheHeadersActuallyCommitted(t *testing.T) {
	cases := map[string]caddyhttp.Handler{
		"flush_before_write": caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			w.Header().Set("X-Response-Header", "evil")
			w.Header().Set("X-Upstream", "leaked")
			_ = http.NewResponseController(w).Flush()
			_, _ = w.Write([]byte(upstreamSecretBody))
			return nil
		}),
		"informational_then_final": caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("X-Response-Header", "evil")
			w.Header().Set("X-Upstream", "leaked")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(upstreamSecretBody))
			return nil
		}),
	}
	for name, up := range cases {
		for _, phase4 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/phase4=%v", name, phase4), func(t *testing.T) {
				m := responsePhaseMiddleware(true, phase4, false, nil)
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				req.RemoteAddr = localIP
				w := httptest.NewRecorder()
				require.NoError(t, m.ServeHTTP(w, req, up))
				res := w.Result()
				assertOnlyBlockResponse(t, res.StatusCode, res.Header, w.Body.String(), nil)
			})
		}
	}
}

// reverse_proxy panics with http.ErrAbortHandler when a Write fails mid-copy,
// which is what it does once the WAF refuses the upstream's output. Nothing
// reached the client yet, so the block response must still go out.
func TestResponsePhaseBlockSurvivesUpstreamAbort(t *testing.T) {
	m := responsePhaseMiddleware(true, false, false, customBlock)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	up := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) error {
		rw.Header().Set("X-Response-Header", "evil")
		rw.Header().Set("Content-Length", fmt.Sprint(len(upstreamSecretBody)))
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(upstreamSecretBody)); err != nil {
			_ = http.NewResponseController(rw).Flush()
			panic(http.ErrAbortHandler)
		}
		return nil
	})
	require.NotPanics(t, func() { _ = m.ServeHTTP(w, req, up) })
	res := w.Result()
	assertOnlyBlockResponse(t, res.StatusCode, res.Header, w.Body.String(), customBlock)
	assert.Equal(t, int64(1), m.blockedRequests.Load(), "blocked")
	assert.Equal(t, int64(0), m.allowedRequests.Load(), "allowed")
}

// An upstream abort on an allowed, already-streaming response is propagated,
// not turned into a 500 appended to the bytes the client already has.
func TestUpstreamAbortIsPropagated(t *testing.T) {
	m := responsePhaseMiddleware(true, false, false, nil)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = localIP
	w := httptest.NewRecorder()
	up := caddyhttp.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) error {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("partial"))
		panic(http.ErrAbortHandler)
	})
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() { _ = m.ServeHTTP(w, req, up) })
	assert.Equal(t, "partial", w.Body.String())
}

// If a block is decided after bytes already reached the client, the block body
// must not be appended to them: the response is aborted instead, and the block
// stays counted once.
func TestResponseBlockAfterBytesSentAborts(t *testing.T) {
	m := responsePhaseMiddleware(true, false, false, nil)
	w := httptest.NewRecorder()
	rec := NewResponseRecorderWithLimit(w, 0, false)
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.Write([]byte("already-sent"))
	rec.block(http.StatusForbidden, "late")

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() { m.writeResponseBlock(w, rec, "test") })
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "already-sent", w.Body.String(), "nothing may be appended to a response already on the wire")
}
