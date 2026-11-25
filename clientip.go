package caddywaf

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Values of client_ip_source.
const (
	clientIPSourceWAF   = "waf"
	clientIPSourceCaddy = "caddy"
)

// validateClientIPSource rejects an unknown client_ip_source, and the WAF's own
// trust settings next to client_ip_source caddy: they would be silently
// ignored, and an operator reading the config would believe they apply.
func (m *Middleware) validateClientIPSource() error {
	switch m.ClientIPSource {
	case "", clientIPSourceWAF:
		return nil
	case clientIPSourceCaddy:
		if len(m.TrustedProxies) > 0 || m.ClientIPHeader != "" {
			return fmt.Errorf("client_ip_source caddy uses the client IP resolved by Caddy's global trusted_proxies and client_ip_headers options; remove trusted_proxies and client_ip_header from the waf block")
		}
		return nil
	default:
		return fmt.Errorf("client_ip_source must be %q or %q, got %q", clientIPSourceWAF, clientIPSourceCaddy, m.ClientIPSource)
	}
}

// clientIPKey carries the resolved client IP in the request context, so every
// consumer (rate limiter, GeoIP/ASN checks, the REMOTE_IP rule target) uses the
// same value, computed once per request in ServeHTTP.
type clientIPKey struct{}

// resolveClientIP determines the real client IP under a trust boundary.
//
// If no trusted_proxies are configured, or the immediate peer is not one of
// them, the peer address is returned and every forwarding header is ignored --
// a client that is not strictly behind a trusted proxy cannot spoof
// X-Forwarded-For to move its apparent IP past the GeoIP, ASN or REMOTE_IP
// checks. When the peer IS a trusted proxy, the client is taken from
// client_ip_header if configured, otherwise by walking X-Forwarded-For from the
// right and returning the first address that is not itself a trusted proxy --
// the real client at the far end of a trusted proxy chain.
//
// With client_ip_source caddy, the client IP Caddy's server already resolved is
// used instead, and the WAF's own trusted_proxies do not apply.
//
// The returned value is a bare IP (no port).
func (m *Middleware) resolveClientIP(r *http.Request) string {
	peer := extractIP(r.RemoteAddr)
	if m.ClientIPSource == clientIPSourceCaddy {
		// Caddy's server resolved the client under its own trust boundary
		// (global trusted_proxies / client_ip_headers) before any handler ran.
		// Without that variable (a request that did not come through a Caddy
		// server), fall back to the peer: forwarding headers are never read here.
		if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok {
			if addr, err := netip.ParseAddr(v); err == nil {
				return addr.String()
			}
		}
		return peer
	}
	if m.trustedProxies == nil {
		return peer
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !m.trustedProxies.Contains(peerAddr) {
		return peer // peer is not a trusted proxy: never honour forwarding headers
	}

	// Peer is trusted. Prefer an explicit single-IP header (e.g. CF-Connecting-IP).
	if m.ClientIPHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(m.ClientIPHeader)); v != "" {
			if ip := extractIP(v); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Otherwise walk X-Forwarded-For right-to-left; the first address that is
	// not itself a trusted proxy is the real client. Multiple XFF header lines
	// are treated as one list in order.
	var parts []string
	for _, xff := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(xff, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		ip := extractIP(parts[i])
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if !m.trustedProxies.Contains(addr) {
			return ip
		}
	}
	return peer
}

// clientIP returns the resolved client IP for the request, using the value
// computed once in ServeHTTP when present, and resolving on demand otherwise
// (e.g. a test that drives a phase directly).
func (m *Middleware) clientIP(r *http.Request) string {
	if v, ok := r.Context().Value(clientIPKey{}).(string); ok && v != "" {
		return v
	}
	return m.resolveClientIP(r)
}
