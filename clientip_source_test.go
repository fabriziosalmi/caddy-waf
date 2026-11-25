package caddywaf

import (
	"context"
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

// withCaddyClientIP puts the client_ip variable into the request context the
// way Caddy's server does in caddyhttp.PrepareRequest.
func withCaddyClientIP(r *http.Request, ip string) *http.Request {
	vars := map[string]any{caddyhttp.ClientIPVarKey: ip}
	return r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
}

func TestResolveClientIPFromCaddy(t *testing.T) {
	caddySrc := &Middleware{logger: zap.NewNop(), ClientIPSource: clientIPSourceCaddy}

	t.Run("uses the client IP Caddy resolved", func(t *testing.T) {
		r := withCaddyClientIP(reqWith("198.51.100.4:5555", "", nil), "203.0.113.7")
		assert.Equal(t, "203.0.113.7", caddySrc.resolveClientIP(r))
	})
	t.Run("does not read forwarding headers itself", func(t *testing.T) {
		r := withCaddyClientIP(reqWith("198.51.100.4:5555", "192.0.2.99",
			map[string]string{"CF-Connecting-IP": "192.0.2.98"}), "198.51.100.4")
		assert.Equal(t, "198.51.100.4", caddySrc.resolveClientIP(r))
	})
	t.Run("IPv6 is normalised", func(t *testing.T) {
		r := withCaddyClientIP(reqWith("[2001:db8::1]:5555", "", nil), "2001:0db8:0000::0007")
		assert.Equal(t, "2001:db8::7", caddySrc.resolveClientIP(r))
	})
	t.Run("no Caddy variable falls back to the peer", func(t *testing.T) {
		r := reqWith("198.51.100.4:5555", "203.0.113.7", nil)
		assert.Equal(t, "198.51.100.4", caddySrc.resolveClientIP(r))
	})
	t.Run("unparseable Caddy variable falls back to the peer", func(t *testing.T) {
		r := withCaddyClientIP(reqWith("198.51.100.4:5555", "", nil), "not-an-ip")
		assert.Equal(t, "198.51.100.4", caddySrc.resolveClientIP(r))
	})
	t.Run("default source ignores the Caddy variable", func(t *testing.T) {
		wafSrc := newResolverMW(t, nil, "")
		r := withCaddyClientIP(reqWith("198.51.100.4:5555", "", nil), "203.0.113.7")
		assert.Equal(t, "198.51.100.4", wafSrc.resolveClientIP(r))
	})
}

func TestValidateClientIPSource(t *testing.T) {
	cases := []struct {
		name    string
		m       *Middleware
		wantErr bool
	}{
		{"unset", &Middleware{}, false},
		{"waf with trusted proxies", &Middleware{ClientIPSource: "waf", TrustedProxies: []string{"10.0.0.0/8"}}, false},
		{"caddy alone", &Middleware{ClientIPSource: "caddy"}, false},
		{"caddy with trusted_proxies", &Middleware{ClientIPSource: "caddy", TrustedProxies: []string{"10.0.0.0/8"}}, true},
		{"caddy with client_ip_header", &Middleware{ClientIPSource: "caddy", ClientIPHeader: "CF-Connecting-IP"}, true},
		{"unknown value", &Middleware{ClientIPSource: "cloudflare"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.validateClientIPSource()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRemoteIPTargetFromCaddyClientIP drives ServeHTTP: with client_ip_source
// caddy, a REMOTE_IP rule matches the client IP Caddy resolved, not the peer.
func TestRemoteIPTargetFromCaddyClientIP(t *testing.T) {
	logger := zap.NewNop()
	newMW := func(source string) *Middleware {
		return &Middleware{
			logger:                logger,
			blacklistLoader:       NewBlacklistLoader(logger),
			AnomalyThreshold:      5,
			ruleCache:             NewRuleCache(),
			ipBlacklist:           iptrie.NewTrie(),
			dnsBlacklist:          map[string]struct{}{},
			ruleHitsByPhase:       map[int]int64{},
			ClientIPSource:        source,
			requestValueExtractor: NewRequestValueExtractor(logger, false, 0),
			Rules: map[int][]Rule{2: {{
				ID: "block-client", Pattern: `^203\.0\.113\.7$`, Targets: []string{"REMOTE_IP"},
				Phase: 2, Score: 10, Action: "block", regex: regexp.MustCompile(`^203\.0\.113\.7$`),
			}}},
		}
	}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	serve := func(source, caddyClientIP string) int {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "173.245.48.1:443" // a proxy edge address
		req = withCaddyClientIP(req, caddyClientIP)
		rec := httptest.NewRecorder()
		require.NoError(t, newMW(source).ServeHTTP(rec, req, next))
		return rec.Code
	}

	assert.Equal(t, http.StatusForbidden, serve(clientIPSourceCaddy, "203.0.113.7"),
		"client_ip_source caddy must match the client IP Caddy resolved")
	assert.Equal(t, http.StatusOK, serve(clientIPSourceCaddy, "198.51.100.4"),
		"another client resolved by Caddy must not match")
	assert.Equal(t, http.StatusOK, serve("", "203.0.113.7"),
		"the default source must keep using its own resolution (the peer here)")
}
