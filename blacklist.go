package caddywaf

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// BlacklistLoader handles loading IP and DNS blacklists from files.
type BlacklistLoader struct {
	logger *zap.Logger
}

// NewBlacklistLoader creates a new BlacklistLoader with the provided logger.
func NewBlacklistLoader(logger *zap.Logger) *BlacklistLoader {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &BlacklistLoader{logger: logger}
}

// LoadDNSBlacklistFromFile loads DNS entries from a file into the provided map.
func (bl *BlacklistLoader) LoadDNSBlacklistFromFile(path string, dnsBlacklist map[string]struct{}) error {
	bl.logger.Debug("Loading DNS blacklist", zap.String("path", path))

	file, err := os.Open(path)
	if err != nil {
		bl.logger.Warn("Failed to open DNS blacklist file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("failed to open DNS blacklist file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	validEntries := 0
	totalLines := 0

	for scanner.Scan() {
		totalLines++
		line := scanner.Text()
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		dnsBlacklist[line] = struct{}{}
		validEntries++
	}

	if err := scanner.Err(); err != nil {
		bl.logger.Error("Error reading DNS blacklist file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("error reading DNS blacklist file: %w", err)
	}

	bl.logger.Info("DNS blacklist loaded",
		zap.String("path", path),
		zap.Int("valid_entries", validEntries),
		zap.Int("total_lines", totalLines),
	)
	return nil
}

func (m *Middleware) isIPBlacklisted(addr string) bool {
	ip := extractIP(addr)

	if m.ipBlacklist == nil {
		m.logger.Debug("IP blacklist not initialized, skipping check")
		return false
	}

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		m.logger.Debug("Failed to parse IP address for blacklist check", zap.String("ip", ip), zap.Error(err))
		return false
	}

	if m.ipBlacklist.Contains(parsedIP) {
		m.muIPBlacklistMetrics.Lock()                            // Acquire lock before accessing shared counter
		m.IPBlacklistBlockCount++                                // Increment the counter
		m.muIPBlacklistMetrics.Unlock()                          // Release lock after accessing counter
		m.logger.Debug("IP blacklist hit", zap.String("ip", ip)) // Keep existing debug log
		return true                                              // Indicate that the IP is blacklisted
	}

	return false // Indicate that the IP is NOT blacklisted
}

// isCountryInList checks if the IP's country is in the provided list using the GeoIP database.
func (m *Middleware) isCountryInList(remoteAddr string, countryList []string, geoIP *maxminddb.Reader) (bool, error) {
	if m.geoIPHandler == nil {
		return false, fmt.Errorf("geoip handler not initialized")
	}
	return m.geoIPHandler.IsCountryInList(remoteAddr, countryList, geoIP)
}

// isDNSBlacklisted checks if the given host is in the DNS blacklist.
func (m *Middleware) isDNSBlacklisted(host string) bool {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	if normalizedHost == "" {
		m.logger.Warn("Empty host provided for DNS blacklist check")
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.dnsBlacklist[normalizedHost]; exists {
		m.muDNSBlacklistMetrics.Lock() // Acquire lock before accessing shared counter
		m.DNSBlacklistBlockCount++
		m.muDNSBlacklistMetrics.Unlock() // Release lock after accessing counter
		m.logger.Debug("DNS blacklist hit",
			zap.String("host", host),
			zap.String("blacklisted_domain", normalizedHost),
		)
		return true
	}

	m.logger.Debug("DNS blacklist miss", zap.String("host", host))
	return false
}

// LoadIPBlacklistFromFile loads IP addresses from a file into the provided map.
func (bl *BlacklistLoader) LoadIPBlacklistFromFile(path string, ipBlacklist map[string]struct{}) error {
	bl.logger.Debug("Loading IP blacklist", zap.String("path", path))

	file, err := os.Open(path)
	if err != nil {
		bl.logger.Warn("Failed to open IP blacklist file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("failed to open IP blacklist file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	validEntries := 0
	totalLines := 0
	invalidEntries := 0

	for scanner.Scan() {
		totalLines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		err = bl.addIPEntry(line, ipBlacklist)
		if err != nil {
			bl.logger.Warn("Invalid IP/CIDR entry in blacklist file",
				zap.String("path", path),
				zap.Int("line", totalLines),
				zap.String("entry", line),
			)
			invalidEntries++
			// If you want the entire load to fail if any single IP entry is invalid, uncomment the line below
			// return fmt.Errorf("failed to add IP entry %s : %w", line, err)
		} else {
			validEntries++
		}
	}

	if scanner.Err() != nil {
		bl.logger.Error("Error reading IP blacklist file", zap.String("path", path), zap.Error(scanner.Err()))
		return fmt.Errorf("error reading IP blacklist file: %w", scanner.Err())
	}

	bl.logger.Info("IP blacklist loaded",
		zap.String("path", path),
		zap.Int("valid_entries", validEntries),
		zap.Int("invalid_entries", invalidEntries),
		zap.Int("total_lines", totalLines),
	)
	return nil
}

// Helper function to add an IP entry
func (bl *BlacklistLoader) addIPEntry(line string, ipBlacklist map[string]struct{}) error {
	if _, _, err := net.ParseCIDR(line); err == nil {
		// Valid CIDR range
		ipBlacklist[line] = struct{}{}
		bl.logger.Debug("Added CIDR to IP blacklist", zap.String("cidr", line))
		return nil
	}
	if ip := net.ParseIP(line); ip != nil {
		// Valid IP address
		ipBlacklist[line] = struct{}{}
		bl.logger.Debug("Added IP to IP blacklist", zap.String("ip", line))
		return nil
	}
	return fmt.Errorf("invalid IP/CIDR entry in blacklist: %s", line)
}
