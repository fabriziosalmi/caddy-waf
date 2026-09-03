package caddywaf

import (
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

func newResolverMW(t *testing.T, trusted []string, header string) *Middleware {
	t.Helper()
	m := &Middleware{logger: zap.NewNop(), ClientIPHeader: header, TrustedProxies: trusted}
	if len(trusted) > 0 {
		trie, _, err := buildIPTrie(trusted, "trusted_proxies")
		require.NoError(t, err)
		m.trustedProxies = trie
	}
	return m
}

func reqWith(remoteAddr, xff string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

// TestResolveClientIP covers the trust boundary: forwarding headers are honoured
// only when the immediate peer is a trusted proxy, and a spoofed X-Forwarded-For
// from an untrusted peer is ignored.
func TestResolveClientIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trusted []string
		header  string
		remote  string
		xff     string
		hdr     map[string]string
		want    string
	}{
		{
			name:   "no trusted_proxies: XFF ignored, peer used",
			remote: "203.0.113.9:4444", xff: "9.9.9.9",
			want: "203.0.113.9",
		},
		{
			name:    "peer trusted: client taken from XFF",
			trusted: []string{"10.0.0.0/8"}, remote: "10.0.0.1:5555", xff: "203.0.113.7",
			want: "203.0.113.7",
		},
		{
			name:    "peer NOT trusted: spoofed XFF ignored",
			trusted: []string{"10.0.0.0/8"}, remote: "203.0.113.9:5555", xff: "203.0.113.7",
			want: "203.0.113.9",
		},
		{
			name:    "trusted proxy chain: first untrusted from the right",
			trusted: []string{"10.0.0.0/8"}, remote: "10.0.0.1:5555",
			xff:  "203.0.113.7, 10.0.0.9, 10.0.0.2",
			want: "203.0.113.7",
		},
		{
			name:    "client_ip_header used when peer trusted",
			trusted: []string{"173.245.48.0/20"}, header: "CF-Connecting-IP",
			remote: "173.245.48.5:5555", xff: "10.9.9.9",
			hdr:  map[string]string{"CF-Connecting-IP": "203.0.113.7"},
			want: "203.0.113.7",
		},
		{
			name:    "client_ip_header ignored when peer NOT trusted",
			trusted: []string{"173.245.48.0/20"}, header: "CF-Connecting-IP",
			remote: "198.51.100.4:5555",
			hdr:    map[string]string{"CF-Connecting-IP": "203.0.113.7"},
			want:   "198.51.100.4",
		},
		{
			name:    "private_ranges token as trusted set",
			trusted: []string{"private_ranges"}, remote: "192.168.1.1:5555", xff: "203.0.113.7",
			want: "203.0.113.7",
		},
		{
			name:    "peer trusted but no forwarding info: peer used",
			trusted: []string{"10.0.0.0/8"}, remote: "10.0.0.1:5555",
			want: "10.0.0.1",
		},
		{
			name:    "all XFF entries trusted: peer used",
			trusted: []string{"10.0.0.0/8"}, remote: "10.0.0.1:5555", xff: "10.0.0.9, 10.0.0.2",
			want: "10.0.0.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newResolverMW(t, tc.trusted, tc.header)
			got := m.resolveClientIP(reqWith(tc.remote, tc.xff, tc.hdr))
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestRemoteIPTargetUnderTrustedProxies proves the security property end to end:
// a rule matching REMOTE_IP sees the real client when it arrives through a
// trusted proxy, but a client spoofing X-Forwarded-For from an untrusted peer
// cannot make the rule see the forged address.
func TestRemoteIPTargetUnderTrustedProxies(t *testing.T) {
	logger := zap.NewNop()
	newMW := func() *Middleware {
		m := &Middleware{
			logger:                logger,
			blacklistLoader:       NewBlacklistLoader(logger),
			AnomalyThreshold:      5,
			ruleCache:             NewRuleCache(),
			ipBlacklist:           iptrie.NewTrie(),
			dnsBlacklist:          map[string]struct{}{},
			ruleHitsByPhase:       map[int]int64{},
			TrustedProxies:        []string{"10.0.0.0/8"},
			requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
			Rules: map[int][]Rule{2: {{
				ID: "block-client", Pattern: `^203\.0\.113\.7$`, Targets: []string{"REMOTE_IP"},
				Phase: 2, Score: 10, Action: "block", regex: regexp.MustCompile(`^203\.0\.113\.7$`),
			}}},
		}
		trie, _, err := buildIPTrie(m.TrustedProxies, "trusted_proxies")
		require.NoError(t, err)
		m.trustedProxies = trie
		return m
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	serve := func(remoteAddr, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		require.NoError(t, newMW().ServeHTTP(rec, req, next))
		return rec.Code
	}

	// Through a trusted proxy: REMOTE_IP resolves to the forwarded client -> blocked.
	assert.Equal(t, http.StatusForbidden, serve("10.0.0.1:5555", "203.0.113.7"),
		"a client arriving through a trusted proxy must be matched on its real IP")

	// Direct/untrusted peer spoofing the same XFF: REMOTE_IP is the peer -> not blocked.
	assert.Equal(t, http.StatusOK, serve("198.51.100.4:5555", "203.0.113.7"),
		"a spoofed X-Forwarded-For from an untrusted peer must not match REMOTE_IP")
}
