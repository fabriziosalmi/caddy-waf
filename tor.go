package caddywaf

import (
	"fmt" // Import fmt for improved error formatting
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

var torExitNodeURL = "https://check.torproject.org/torbulkexitlist"

type TorConfig struct {
	Enabled              bool   `json:"enabled,omitempty"`
	CustomTORExitNodeURL string `json:"custom_tor_exit_node_url"`
	TORIPBlacklistFile   string `json:"tor_ip_blacklist_file,omitempty"`
	UpdateInterval       string `json:"update_interval,omitempty"`
	RetryOnFailure       bool   `json:"retry_on_failure,omitempty"` // Enable/disable retries
	RetryInterval        string `json:"retry_interval,omitempty"`   // Retry interval (e.g., "5m")
	lastUpdated          time.Time
	logger               *zap.Logger
}

// Provision sets up the Tor blocking configuration.
func (t *TorConfig) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()
	if t.Enabled {
		if err := t.updateTorExitNodes(); err != nil {
			return fmt.Errorf("provisioning tor: %w", err) // Improved error wrapping
		}
		go t.scheduleUpdates()
	}
	return nil
}

// updateTorExitNodes fetches the latest Tor exit nodes and updates the IP blacklist.
func (t *TorConfig) updateTorExitNodes() error {
	t.logger.Debug("Updating Tor exit nodes...") // Debug log at start of update

	url := torExitNodeURL
	if t.CustomTORExitNodeURL != "" {
		url = t.CustomTORExitNodeURL
	}

	// Create HTTP client with timeout to avoid hanging requests
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("http get failed for %s: %w", url, err) // Improved error message with URL
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http get returned status %s for %s", resp.Status, url) // Check for non-200 status
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body from %s: %w", url, err) // Improved error message with URL
	}

	torIPs := strings.Split(string(data), "\n")
	existingIPs, err := t.readExistingBlacklist()
	if err != nil {
		return fmt.Errorf("failed to read existing blacklist file %s: %w", t.TORIPBlacklistFile, err) // Improved error message with filename
	}

	// Merge and deduplicate IPs
	allIPs := append(existingIPs, torIPs...)
	sort.Strings(allIPs)
	uniqueIPs := unique(allIPs)

	// Write updated blacklist to file
	if err := t.writeBlacklist(uniqueIPs); err != nil {
		return fmt.Errorf("failed to write updated blacklist to file %s: %w", t.TORIPBlacklistFile, err) // Improved error message with filename
	}

	t.lastUpdated = time.Now()
	t.logger.Info("Tor exit nodes updated", zap.Int("count", len(uniqueIPs))) // Improved log message
	t.logger.Debug("Tor exit node update completed successfully")             // Debug log at end of update
	return nil
}

// scheduleUpdates periodically updates the Tor exit node list.
func (t *TorConfig) scheduleUpdates() {
	interval, err := time.ParseDuration(t.UpdateInterval)
	if err != nil {
		t.logger.Error("Invalid update interval", zap.String("interval", t.UpdateInterval), zap.Error(err))
		return
	}

	var retryInterval time.Duration
	if t.RetryOnFailure {
		retryInterval, err = time.ParseDuration(t.RetryInterval)
		if err != nil {
			t.logger.Error("Invalid retry interval, disabling retries", zap.String("retry_interval", t.RetryInterval), zap.Error(err))
			t.RetryOnFailure = false // Disable retries if the interval is invalid
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Use for range to iterate over the ticker channel
	for range ticker.C {
		if updateErr := t.updateTorExitNodes(); updateErr != nil { // Renamed err to updateErr for clarity
			if t.RetryOnFailure {
				t.logger.Error("Failed to update Tor exit nodes, retrying shortly", zap.Error(updateErr)) // Use updateErr
				time.Sleep(retryInterval)
				continue
			} else {
				t.logger.Error("Failed to update Tor exit nodes, will retry at next scheduled interval", zap.Error(updateErr)) // Use updateErr
			}
		}
	}
}

// readExistingBlacklist reads the current IP blacklist file.
func (t *TorConfig) readExistingBlacklist() ([]string, error) {
	data, err := os.ReadFile(t.TORIPBlacklistFile)
	if err != nil {
		if os.IsNotExist(err) {
			t.logger.Debug("Blacklist file does not exist, assuming empty list", zap.String("path", t.TORIPBlacklistFile)) // Debug log for non-existent file
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read IP blacklist file %s: %w", t.TORIPBlacklistFile, err) // Improved error message with filename
	}
	return strings.Split(string(data), "\n"), nil
}

// writeBlacklist writes the updated IP blacklist to the file atomically: it
// writes to a temp file in the same directory, fsyncs it, then renames it over
// the target. Rename is atomic within a filesystem, so a crash can never leave a
// half-written (truncated) blacklist that loads as valid-but-shorter -- a reader
// ever sees only the old complete file or the new complete file.
func (t *TorConfig) writeBlacklist(ips []string) error {
	data := strings.Join(ips, "\n")
	dir := filepath.Dir(t.TORIPBlacklistFile)

	tmp, err := os.CreateTemp(dir, ".tor-blacklist-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file for IP blacklist in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we return before the rename succeeds.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write([]byte(data)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temp IP blacklist file %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to fsync temp IP blacklist file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp IP blacklist file %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("failed to set permissions on temp IP blacklist file %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, t.TORIPBlacklistFile); err != nil {
		return fmt.Errorf("failed to atomically replace IP blacklist file %s: %w", t.TORIPBlacklistFile, err)
	}
	t.logger.Debug("Blacklist file updated", zap.String("path", t.TORIPBlacklistFile), zap.Int("entry_count", len(ips))) // Debug log for file update
	return nil
}

// unique removes duplicate entries from a slice of strings.
func unique(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			result = append(result, entry)
		}
	}
	return result
}
