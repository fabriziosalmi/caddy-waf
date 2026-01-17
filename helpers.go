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
// Returns the original input if parsing fails, which allows upstream
// code to handle invalid IPs gracefully.
func extractIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Could be an IP without port, validate it
		if ip := net.ParseIP(remoteAddr); ip != nil {
			return remoteAddr
		}
		// Return as-is for upstream handling
		return remoteAddr
	}
	return host
}

// getClientIP returns the real client IP, checking X-Forwarded-For header first.
// Falls back to RemoteAddr if X-Forwarded-For is empty or contains invalid data.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			// Validate the IP before returning
			if clientIP != "" && net.ParseIP(extractIP(clientIP)) != nil {
				return clientIP
			}
		}
	}
	return r.RemoteAddr
}
