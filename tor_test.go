package caddywaf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestTorConfig_Provision(t *testing.T) {
	// Serve a fake exit-node list locally so provisioning never reaches an
	// external host. This test used to point CustomTORExitNodeURL at a real CDN
	// (torListURL), so a transient TLS/network hiccup on the runner became a red
	// CI run unrelated to any code change -- exactly what bit PR #146.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1\n2.2.2.2\n3.3.3.3\n"))
	}))
	defer ts.Close()

	// Create temp file for testing
	tmpFile, err := os.CreateTemp("", "tor_blacklist_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	logger := zap.NewNop()
	ctx := &caddy.Context{}

	tests := []struct {
		name    string
		config  TorConfig
		wantErr bool
	}{
		{
			name: "disabled config",
			config: TorConfig{
				Enabled:            false,
				TORIPBlacklistFile: tmpFile.Name(),
				UpdateInterval:     "5m",
				logger:             logger,
			},
			wantErr: false,
		},
		{
			name: "enabled config",
			config: TorConfig{
				Enabled:              true,
				CustomTORExitNodeURL: ts.URL,
				TORIPBlacklistFile:   tmpFile.Name(),
				UpdateInterval:       "5m",
				logger:               logger,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Provision(*ctx)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTorConfig_updateTorExitNodes(t *testing.T) {
	// Create mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.1.1.1\n2.2.2.2\n3.3.3.3"))
	}))
	defer ts.Close()

	// Override torExitNodeURL for testing
	originalURL := torExitNodeURL
	torExitNodeURL = ts.URL
	defer func() { torExitNodeURL = originalURL }()

	// Create temp file
	tmpFile, err := os.CreateTemp("", "tor_blacklist_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	config := &TorConfig{
		Enabled:            true,
		TORIPBlacklistFile: tmpFile.Name(),
		UpdateInterval:     "5m",
		logger:             zap.NewNop(),
	}

	err = config.updateTorExitNodes()
	assert.NoError(t, err)

	// Verify file contents
	data, err := os.ReadFile(tmpFile.Name())
	assert.NoError(t, err)
	assert.Contains(t, string(data), "1.1.1.1")
	assert.Contains(t, string(data), "2.2.2.2")
	assert.Contains(t, string(data), "3.3.3.3")
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates",
			input:    []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
			expected: []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
		},
		{
			name:     "with duplicates",
			input:    []string{"1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3", "2.2.2.2"},
			expected: []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unique(tt.input)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}
