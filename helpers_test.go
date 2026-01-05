package caddywaf

import (
	"net/http"
	"os"
	"testing"
)

func TestFileExists(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty path",
			path: "",
			want: false,
		},
		{
			name: "non-existent file",
			path: "/path/to/nonexistent/file",
			want: false,
		},
		{
			name: "existing file",
			path: tmpFile.Name(),
			want: true,
		},
		{
			name: "directory",
			path: os.TempDir(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileExists(tt.path); got != tt.want {
				t.Errorf("fileExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "no X-Forwarded-For, use RemoteAddr",
			remoteAddr: "192.168.1.1:12345",
			xff:        "",
			want:       "192.168.1.1:12345",
		},
		{
			name:       "single IP in X-Forwarded-For",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "multiple IPs in X-Forwarded-For",
			remoteAddr: "10.0.0.1:12345",
			xff:        "203.0.113.50, 70.41.3.18, 150.172.238.178",
			want:       "203.0.113.50",
		},
		{
			name:       "X-Forwarded-For with spaces",
			remoteAddr: "10.0.0.1:12345",
			xff:        "  203.0.113.50  ,  70.41.3.18  ",
			want:       "203.0.113.50",
		},
		{
			name:       "IPv6 in X-Forwarded-For",
			remoteAddr: "10.0.0.1:12345",
			xff:        "2001:db8::1",
			want:       "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			if got := getClientIP(req); got != tt.want {
				t.Errorf("getClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
