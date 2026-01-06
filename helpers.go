package caddywaf

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// fileExists checks if a file exists and is readable.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// isIPv4 - checks if input IP is of type v4
//
//nolint:unused
func isIPv4(addr string) bool {
	return strings.Count(addr, ":") < 2
}

// appendCIDR - appends CIDR for a single IP
func appendCIDR(ip string) string {
	// IPv4
	if strings.Count(ip, ":") < 2 {
		ip += "/32"
		// IPv6
	} else {
		ip += "/64"
	}
	return ip
}

// extractIP extracts the IP address from a remote address string.
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // Assume the input is already an IP address
	}
	return host
}

// getClientIP returns the real client IP, checking X-Forwarded-For header first.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	return r.RemoteAddr
}
