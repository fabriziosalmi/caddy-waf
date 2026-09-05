// Package caddywaf implements a Web Application Firewall (WAF) middleware for Caddy.
//
// This package provides comprehensive security features including:
//   - Regex-based filtering for URLs, data, and headers
//   - IP and DNS blacklisting capabilities
//   - Geographic access control
//   - Rate limiting
//   - Anomaly detection and scoring
//   - Multi-phase request inspection
//   - Real-time metrics and monitoring
//
// The WAF integrates seamlessly with Caddy as an HTTP handler middleware
// and can be configured via Caddyfile or JSON configuration.
//
// Module ID: http.handlers.waf
package caddywaf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/oschwald/maxminddb-golang"
	"github.com/phemmer/go-iptrie"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ==================== Constants and Globals ====================

var (
	_ caddy.Module                = (*Middleware)(nil) // <-- AGGIUNGI QUESTA RIGA!
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil) // Assicurati che anche questa sia presente se hai un metodo Validate()
)

// Add or update the version constant as needed
const wafVersion = "v0.4.14" // update this value to the new release version when tagging

// ==================== Initialization and Setup ====================

// Use new(Middleware) rather than &Middleware{} here. Caddy's package registry
// scans this call with a simple static analyzer that only accepts a composite
// literal or new(); an &-prefixed literal parses as an ast.UnaryExpr and makes
// registration fail with "unable to scan modules in package". The two forms are
// otherwise identical -- both allocate a zeroed Middleware and yield a pointer.
func init() {
	caddy.RegisterModule(new(Middleware)) // Register the module with Caddy
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

func (*Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	logger := zap.L().Named("caddyfile_parser")
	logger.Info("Starting to parse Caddyfile", zap.String("file", h.Dispenser.File()))

	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, fmt.Errorf("caddyfile parse error: %w", err)
	}

	logger.Info("Successfully parsed Caddyfile", zap.String("file", h.Dispenser.File()))
	return &m, nil
}

// ==================== Middleware Lifecycle Methods ====================

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.ruleCache = NewRuleCache()   // Initialize RuleCache
	m.Rules = make(map[int][]Rule) // Initialize Rules map to prevent nil pointer panic
	m.ipBlacklist = iptrie.NewTrie()

	// Normalise the dashboard path so a configured trailing slash ("/waf/") does
	// not desync the injected base path from request matching (#170).
	if m.DashboardEndpoint != "" {
		m.DashboardEndpoint = "/" + strings.Trim(m.DashboardEndpoint, "/")
	}

	// Set default log severity if not provided
	if m.LogSeverity == "" {
		m.LogSeverity = "info"
	}

	// Set default log file path if not provided
	if m.LogFilePath == "" {
		m.LogFilePath = "log.json"
	}

	// Parse log severity level
	var logLevel zapcore.Level
	switch strings.ToLower(m.LogSeverity) {
	case "debug":
		logLevel = zapcore.DebugLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	default:
		logLevel = zapcore.InfoLevel
	}

	// Configure console logging
	consoleCfg := zap.NewProductionConfig()
	consoleCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	consoleCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleCfg.EncoderConfig)
	consoleSync := zapcore.AddSync(os.Stdout)

	// Configure file logging
	fileCfg := zap.NewProductionConfig()
	fileCfg.EncoderConfig.EncodeTime = caddyTimeEncoder
	fileCfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	fileEncoder := zapcore.NewJSONEncoder(fileCfg.EncoderConfig)

	fileSync, err := os.OpenFile(m.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		m.logger.Warn("Failed to open log file, logging only to console", zap.String("path", m.LogFilePath), zap.Error(err))
		m.logger = zap.New(zapcore.NewCore(consoleEncoder, consoleSync, logLevel))
		return nil
	}

	// Create a multi-core logger for both console and file
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleSync, logLevel),
		zapcore.NewCore(fileEncoder, zapcore.AddSync(fileSync), logLevel),
	)

	m.logger = zap.New(core)
	m.logger.Info("Provisioning WAF middleware",
		zap.String("log_level", m.LogSeverity),
		zap.String("log_path", m.LogFilePath),
		zap.Bool("log_json", m.LogJSON),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	// ADDED: Set default anomaly threshold if not provided or invalid
	if m.AnomalyThreshold <= 0 {
		m.AnomalyThreshold = 20 // Use a reasonable default value
		m.logger.Info("Using default anomaly threshold", zap.Int("anomaly_threshold", m.AnomalyThreshold))
	} else {
		m.logger.Info("Using configured anomaly threshold", zap.Int("anomaly_threshold", m.AnomalyThreshold))
	}

	// Start the asynchronous logging worker
	m.StartLogWorker()

	// Provision Tor blocking
	if err := m.Tor.Provision(ctx); err != nil {
		return err
	}

	// Initialize rule hits map
	m.ruleHits = sync.Map{}

	// Log the current version of the middleware
	m.logVersion()

	// Start file watchers for rule files and blacklist files
	// Context cancellation could be added in the future to gracefully stop watchers.
	m.startFileWatcher(m.RuleFiles)
	m.startFileWatcher([]string{m.IPBlacklistFile, m.DNSBlacklistFile, m.IPWhitelistFile})

	// Configure rate limiting
	if m.RateLimit.Requests > 0 {
		if m.RateLimit.Window <= 0 || m.RateLimit.CleanupInterval <= 0 {
			return fmt.Errorf("invalid rate limit configuration: requests, window, and cleanup_interval must be greater than zero")
		}
		m.logger.Info("Rate limit configuration",
			zap.Int("requests", m.RateLimit.Requests),
			zap.Duration("window", m.RateLimit.Window),
			zap.Duration("cleanup_interval", m.RateLimit.CleanupInterval),
			zap.Strings("paths", m.RateLimit.Paths),
			zap.Bool("match_all_paths", m.RateLimit.MatchAllPaths),
		)
		var err error
		m.rateLimiter, err = NewRateLimiter(m.RateLimit)
		if err != nil {
			return fmt.Errorf("failed to create rate limiter: %w", err)
		}
		m.rateLimiter.startCleanup()
	} else {
		m.logger.Info("Rate limiting is disabled")
	}

	// Initialize GeoIP stats
	m.geoIPStats = make(map[string]int64)

	// Observability state for the dashboard (#143 M1).
	m.provisionTime = time.Now()
	m.topIPsBlocked = make(map[string]int64)
	m.blockedByReason = make(map[string]int64)

	// Configure GeoIP-based country blacklisting/whitelisting
	if m.CountryBlacklist.Enabled || m.CountryWhitelist.Enabled {
		geoIPPath := m.CountryBlacklist.GeoIPDBPath
		if m.CountryWhitelist.Enabled && m.CountryWhitelist.GeoIPDBPath != "" {
			geoIPPath = m.CountryWhitelist.GeoIPDBPath
		}

		if !fileExists(geoIPPath) {
			m.logger.Warn("GeoIP database not found. Country blacklisting/whitelisting will be disabled", zap.String("path", geoIPPath))
		} else {
			reader, err := maxminddb.Open(geoIPPath)
			if err != nil {
				m.logger.Error("Failed to load GeoIP database", zap.String("path", geoIPPath), zap.Error(err))
			} else {
				m.logger.Info("GeoIP database loaded successfully", zap.String("path", geoIPPath))
				if m.CountryBlacklist.Enabled {
					m.CountryBlacklist.geoIP = reader
				}
				if m.CountryWhitelist.Enabled {
					m.CountryWhitelist.geoIP = reader
				}
			}
		}
	}

	// Configure ASN blocking
	if m.BlockASNs.Enabled {
		if !fileExists(m.BlockASNs.GeoIPDBPath) {
			m.logger.Warn("ASN GeoIP database not found. ASN blocking will be disabled", zap.String("path", m.BlockASNs.GeoIPDBPath))
		} else {
			reader, err := maxminddb.Open(m.BlockASNs.GeoIPDBPath)
			if err != nil {
				m.logger.Error("Failed to load ASN GeoIP database", zap.String("path", m.BlockASNs.GeoIPDBPath), zap.Error(err))
			} else {
				m.logger.Info("ASN GeoIP database loaded successfully", zap.String("path", m.BlockASNs.GeoIPDBPath))
				m.BlockASNs.geoIP = reader
			}
		}
	}

	// Initialize config and blacklist loaders
	m.configLoader = NewConfigLoader(m.logger)
	m.blacklistLoader = NewBlacklistLoader(m.logger)
	m.geoIPHandler = NewGeoIPHandler(m.logger)
	m.requestValueExtractor = NewRequestValueExtractor(m.logger, m.RedactSensitiveData, m.MaxRequestBodySize)

	// Configure GeoIP handler
	m.geoIPHandler.WithGeoIPCache(m.geoIPCacheTTL)
	m.geoIPHandler.WithGeoIPLookupFallbackBehavior(m.geoIPLookupFallbackBehavior)

	// Initialize TorConfig with default values if not set
	if m.Tor.TORIPBlacklistFile == "" {
		m.Tor.TORIPBlacklistFile = "tor_blacklist.txt"
	}
	if m.Tor.UpdateInterval == "" {
		m.Tor.UpdateInterval = "24h"
	}
	if m.Tor.RetryInterval == "" {
		m.Tor.RetryInterval = "5m"
	}

	// Load IP blacklist
	if m.IPBlacklistFile != "" {
		m.ipBlacklist = iptrie.NewTrie()
		err = m.loadIPBlacklist(m.IPBlacklistFile, m.ipBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load IP blacklist: %w", err)
		}
	}

	// Build the IP whitelist from inline entries and/or the whitelist file.
	if len(m.IPWhitelist) > 0 || m.IPWhitelistFile != "" {
		if err := m.rebuildIPWhitelist(); err != nil {
			return err
		}

		// Warn loudly when private ranges are exempt. The whitelist matches on
		// the peer address, which is correct when caddy-waf is the edge but
		// means the peer is the *proxy* when it is not -- and a proxy on
		// localhost or a private network would exempt every request passing
		// through it, silently turning these controls off.
		for _, entry := range m.IPWhitelist {
			if strings.EqualFold(strings.TrimSpace(entry), PrivateRangesToken) {
				m.logger.Warn("whitelist_ip includes private_ranges: requests whose PEER address is private are exempt from the IP blacklist, country filter and ASN filter. This is only what you want if caddy-waf is the edge. Behind another proxy the peer is that proxy, which would exempt all traffic.")
				break
			}
		}
	}

	// Build the trusted-proxy set: the trust boundary for X-Forwarded-For.
	if len(m.TrustedProxies) > 0 {
		trie, expanded, err := buildIPTrie(m.TrustedProxies, "trusted_proxies")
		if err != nil {
			return err
		}
		m.trustedProxies = trie
		m.logger.Info("Trusted proxies configured",
			zap.Int("entries", len(expanded)),
			zap.String("client_ip_header", m.ClientIPHeader))
	}

	// Load DNS blacklist
	if m.DNSBlacklistFile != "" {
		m.dnsBlacklist = make(map[string]struct{})
		err = m.loadDNSBlacklist(m.DNSBlacklistFile, m.dnsBlacklist)
		if err != nil {
			return fmt.Errorf("failed to load DNS blacklist: %w", err)
		}
	}

	// Load WAF rules - calling the new external loadRules function
	if len(m.RuleFiles) > 0 { // Modified condition to check for rule files before loading
		if err := m.loadRules(m.RuleFiles); err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
	} else {
		m.logger.Warn("No rule files specified, WAF will run without rules.") // Log a warning instead of error
	}

	m.logger.Info("WAF middleware provisioned successfully")
	return nil
}

func (m *Middleware) Shutdown(ctx context.Context) error {
	m.logger.Info("Starting WAF middleware shutdown procedures")
	m.isShuttingDown = true

	// Stop the rate limiter cleanup
	if m.rateLimiter != nil {
		m.logger.Debug("Signaling rate limiter cleanup to stop...")
		m.rateLimiter.signalStopCleanup()
		m.logger.Debug("Rate limiter cleanup signaled.")
	} else {
		m.logger.Debug("Rate limiter is nil, no cleanup signaling needed.")
	}

	// Stop the asynchronous logging worker
	m.logger.Debug("Stopping logging worker...")
	m.StopLogWorker()
	m.logger.Debug("Logging worker stopped.")

	var firstError error

	// Close GeoIP databases
	if m.CountryBlacklist.geoIP != nil {
		m.logger.Debug("Closing country blacklist GeoIP database...")
		if err := m.CountryBlacklist.geoIP.Close(); err != nil {
			m.logger.Error("Error encountered while closing country blacklist GeoIP database", zap.Error(err))
			firstError = fmt.Errorf("error closing country blacklist GeoIP: %w", err)
		} else {
			m.logger.Debug("Country blacklist GeoIP database closed successfully.")
		}
		m.CountryBlacklist.geoIP = nil
	} else {
		m.logger.Debug("Country blacklist GeoIP database was not open, skipping close.")
	}

	if m.CountryWhitelist.geoIP != nil {
		m.logger.Debug("Closing country whitelist GeoIP database...")
		if err := m.CountryWhitelist.geoIP.Close(); err != nil {
			m.logger.Error("Error encountered while closing country whitelist GeoIP database", zap.Error(err))
			if firstError == nil {
				firstError = fmt.Errorf("error closing country whitelist GeoIP: %w", err)
			}
		} else {
			m.logger.Debug("Country whitelist GeoIP database closed successfully.")
		}
		m.CountryWhitelist.geoIP = nil
	} else {
		m.logger.Debug("Country whitelist GeoIP database was not open, skipping close.")
	}

	if m.BlockASNs.geoIP != nil {
		m.logger.Debug("Closing ASN GeoIP database...")
		if err := m.BlockASNs.geoIP.Close(); err != nil {
			m.logger.Error("Error encountered while closing ASN GeoIP database", zap.Error(err))
			if firstError == nil {
				firstError = fmt.Errorf("error closing ASN GeoIP: %w", err)
			}
		} else {
			m.logger.Debug("ASN GeoIP database closed successfully.")
		}
		m.BlockASNs.geoIP = nil
	}

	// Log rule hit statistics
	m.logger.Info("Rule Hit Statistics:")
	m.ruleHits.Range(func(key, value interface{}) bool {
		ruleID, ok := key.(RuleID)
		if !ok {
			m.logger.Error("Invalid type for rule ID in ruleHits map", zap.Any("key", key))
			return true
		}

		atomicCounter, ok := value.(*atomic.Int64)
		if !ok {
			m.logger.Error("Invalid type for hit count in ruleHits map", zap.Any("value", value))
			return true
		}
		hitCount := atomicCounter.Load()

		m.logger.Info("Rule Hit",
			zap.String("rule_id", string(ruleID)),
			zap.Int64("hits", hitCount),
		)
		return true
	})

	m.logger.Info("WAF middleware shutdown procedures completed")
	return firstError
}

// ==================== Helper Functions ====================

func (m *Middleware) logVersion() {
	// Updated to use wafVersion constant
	m.logger.Info("WAF middleware version", zap.String("version", wafVersion))
}

// isRuleFile reports whether path is one of the configured rule files, so the
// watcher can pick ReloadRules vs ReloadConfig by identity rather than by a
// "rule" substring match (which would misroute a blacklist/whitelist file whose
// path happens to contain "rule").
func (m *Middleware) isRuleFile(path string) bool {
	clean := filepath.Clean(path)
	for _, rf := range m.RuleFiles {
		if filepath.Clean(rf) == clean {
			return true
		}
	}
	return false
}

func (m *Middleware) startFileWatcher(filePaths []string) {
	for _, path := range filePaths {
		if strings.TrimSpace(path) == "" {
			continue // unset optional file (e.g. no whitelist_file configured)
		}
		// Watch the parent directory, so the target file need not exist yet: a
		// file created after start (a feed that writes the whitelist/blacklist
		// later) is picked up via its Create event. Only the directory must
		// exist now.
		if _, err := os.Stat(filepath.Dir(path)); err != nil {
			m.logger.Warn("Skipping file watch, directory does not exist",
				zap.String("file", path), zap.String("dir", filepath.Dir(path)), zap.Error(err),
			)
			continue
		}

		// Note: In future, a context may be used here for cancellation.
		go func(file string) {
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				m.logger.Error("Failed to start file watcher", zap.Error(err))
				return
			}
			defer watcher.Close()

			// Watch the parent directory, not the file inode. An atomic update
			// (write a temp file, then os.Rename it over the target -- the standard
			// pattern for blocklist/rule refreshes) replaces the target's inode. A
			// watch on the file itself only ever sees Rename/Remove on the now-dead
			// old inode, never fires for the replacement, and is left permanently
			// deaf. Watching the directory and filtering by basename survives the
			// swap with no re-arming, because the directory inode is stable.
			dir := filepath.Dir(file)
			base := filepath.Base(file)
			if err := watcher.Add(dir); err != nil {
				m.logger.Error("Failed to watch directory", zap.String("dir", dir), zap.String("file", file), zap.Error(err))
				return
			}

			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					// Only react to events for the file we track, not its
					// siblings -- e.g. the temp file an atomic write creates and
					// then renames away during the swap, whose Create/Write/Rename
					// events all carry a different basename.
					if filepath.Base(event.Name) != base {
						continue
					}
					// A plain edit emits Write; an atomic rename-into-place emits
					// Create (inotify IN_MOVED_TO) and sometimes Rename for the
					// target name. Any of the three means the contents changed and we
					// must reload. A bare Remove (deletion, no replacement) is ignored.
					if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
						continue
					}
					m.logger.Info("Detected configuration change. Reloading...",
						zap.String("file", file), zap.String("op", event.Op.String()))
					if m.isRuleFile(file) {
						if err := m.ReloadRules(); err != nil {
							m.logger.Error("Failed to reload rules after change", zap.String("file", file), zap.Error(err))
						} else {
							m.logger.Info("Rules reloaded successfully", zap.String("file", file))
						}
					} else {
						if err := m.ReloadConfig(); err != nil {
							m.logger.Error("Failed to reload config after change", zap.Error(err))
						} else {
							m.logger.Info("Configuration reloaded successfully")
						}
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					m.logger.Error("File watcher error", zap.Error(err))
				}
			}
		}(path)
	}
}

// ReloadRules re-reads the rule files. It is called by the file watcher when a
// path containing "rule" changes, which is the primary hot-reload case.
//
// It must NOT take m.mu: loadRules takes it, and Go's RWMutex is not
// reentrant, so an outer lock self-deadlocked the goroutine while it still
// owned the write lock -- wedging every later request on the RLock in the
// request path. Same defect as the one fixed in ReloadConfig; this branch was
// missed there and is covered by TestReloadRulesDoesNotDeadlock.
func (m *Middleware) ReloadRules() error {
	m.logger.Info("Reloading WAF rules")
	// Call the external loadRules function
	if err := m.loadRules(m.RuleFiles); err != nil {
		m.logger.Error("Failed to reload rules", zap.Error(err))
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	m.logger.Info("WAF rules reloaded successfully")
	return nil
}

// ReloadConfig rebuilds the blacklists and rule set from disk. It is called by
// the file watcher when a blacklist file changes.
//
// The new structures are built off to the side and only swapped in under the
// lock, and m.mu is never held across a call that takes it again. Holding it
// across loadRules used to deadlock the goroutine on Go's non-reentrant
// RWMutex while it still owned the write lock, so every later request blocked
// forever on the RLock in isDNSBlacklisted -- one edit to a blacklist file was
// enough to wedge the whole server.
func (m *Middleware) ReloadConfig() error {
	m.logger.Info("Reloading WAF configuration")

	if m.IPBlacklistFile != "" {
		newIPBlacklist := iptrie.NewTrie()
		if err := m.loadIPBlacklist(m.IPBlacklistFile, newIPBlacklist); err != nil {
			m.logger.Error("Failed to reload IP blacklist", zap.String("file", m.IPBlacklistFile), zap.Error(err))
			return fmt.Errorf("failed to reload IP blacklist: %v", err)
		}
		m.mu.Lock()
		m.ipBlacklist = newIPBlacklist
		m.mu.Unlock()
	}

	if m.DNSBlacklistFile != "" {
		newDNSBlacklist := make(map[string]struct{})
		if err := m.loadDNSBlacklist(m.DNSBlacklistFile, newDNSBlacklist); err != nil {
			m.logger.Error("Failed to reload DNS blacklist", zap.String("file", m.DNSBlacklistFile), zap.Error(err))
			return fmt.Errorf("failed to reload DNS blacklist: %v", err)
		}
		m.mu.Lock()
		m.dnsBlacklist = newDNSBlacklist
		m.mu.Unlock()
	}

	// Rebuild the whitelist (inline entries + file) when a whitelist file is
	// configured. rebuildIPWhitelist swaps the trie under the lock itself, so it
	// must be called without holding m.mu.
	if m.IPWhitelistFile != "" {
		if err := m.rebuildIPWhitelist(); err != nil {
			m.logger.Error("Failed to reload IP whitelist", zap.String("file", m.IPWhitelistFile), zap.Error(err))
			return fmt.Errorf("failed to reload IP whitelist: %v", err)
		}
	}

	// loadRules takes m.mu itself, so it must be called without holding it.
	if err := m.loadRules(m.RuleFiles); err != nil {
		m.logger.Error("Failed to reload rules", zap.Error(err))
		return fmt.Errorf("failed to reload rules: %v", err)
	}

	m.logger.Info("WAF configuration reloaded successfully")
	return nil
}

// loadIPBlacklist parses path and inserts every entry into blacklistTrie.
//
// The trie MUST be taken by pointer. It was previously accepted by value, and
// both callers dereferenced their trie to satisfy that signature, so every
// Insert landed in a copy that was discarded on return. The middleware's own
// trie stayed empty while the loader still logged "IP blacklist loaded" with a
// non-zero entry count -- so the blacklist silently enforced nothing.
func (m *Middleware) loadIPBlacklist(path string, blacklistTrie *iptrie.Trie) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		m.logger.Warn("Skipping IP blacklist load, file does not exist", zap.String("file", path))
		return nil
	}

	blacklist := make(map[string]struct{})
	err := m.blacklistLoader.LoadIPBlacklistFromFile(path, blacklist)
	if err != nil {
		return fmt.Errorf("failed to load IP blacklist: %w", err)
	}

	// Convert the map to CIDRTrie
	for ip := range blacklist {
		var prefix netip.Prefix
		var err error

		if strings.Contains(ip, "/") {
			prefix, err = netip.ParsePrefix(ip)
		} else {
			prefix, err = netip.ParsePrefix(appendCIDR(ip))
		}

		if err != nil {
			m.logger.Warn("Skipping invalid IP in blacklist", zap.String("ip", ip), zap.Error(err))
			continue
		}
		blacklistTrie.Insert(prefix, nil)
	}
	return nil
}

func (m *Middleware) loadDNSBlacklist(path string, blacklistMap map[string]struct{}) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		m.logger.Warn("Skipping DNS blacklist load, file does not exist", zap.String("file", path))
		return nil
	}

	err := m.blacklistLoader.LoadDNSBlacklistFromFile(path, blacklistMap)
	if err != nil {
		return fmt.Errorf("failed to load DNS blacklist: %w", err)
	}
	return nil
}

// ==================== Metrics and Statistics ====================

func (m *Middleware) getRuleHitStats() map[string]int {
	stats := make(map[string]int)
	m.ruleHits.Range(func(key, value interface{}) bool {
		ruleID, ok := key.(RuleID)
		if !ok {
			m.logger.Error("Invalid type for rule ID in ruleHits map", zap.Any("key", key))
			return true // Continue iteration
		}
		// SOTA Pattern: Wait-Free stats collection
		atomicCounter, ok := value.(*atomic.Int64)
		if !ok {
			m.logger.Error("Invalid type for hit count in ruleHits map", zap.Any("value", value))
			return true // Continue iteration
		}
		stats[string(ruleID)] = int(atomicCounter.Load())
		return true
	})
	return stats
}

func (m *Middleware) handleMetricsRequest(w http.ResponseWriter, r *http.Request) error {
	m.logger.Debug("Handling metrics request", zap.String("path", r.URL.Path))
	w.Header().Set("Content-Type", "application/json")

	// Get rate limiter metrics
	var rateLimiterTotalRequests int64
	var rateLimiterBlockedRequests int64
	if m.rateLimiter != nil {
		rateLimiterTotalRequests = m.rateLimiter.GetTotalRequests()
		rateLimiterBlockedRequests = m.rateLimiter.GetBlockedRequests()
	}

	// Collect rule hits using getRuleHitStats
	ruleHits := m.getRuleHitStats()

	// Snapshot the shared counters. The scalar counters are atomic, so each is
	// read with a lock-free Load(). rule_hits_by_phase still needs muMetrics: it
	// is a map, and it used to be handed to json.Marshal by reference so the
	// marshal iterated it while requests wrote to it -- Go's runtime answers that
	// with "concurrent map read and map write", a throw (not a shruggable race)
	// that ServeHTTP's panic recovery turned into a 500. So the map is copied
	// under the lock before it leaves this function.
	totalRequests := m.totalRequests.Load()
	blockedRequests := m.blockedRequests.Load()
	allowedRequests := m.allowedRequests.Load()
	geoIPBlocked := m.geoIPBlocked.Load()
	m.muMetrics.RLock()
	hitsByPhase := make(map[int]int64, len(m.ruleHitsByPhase))
	for phase, hits := range m.ruleHitsByPhase {
		hitsByPhase[phase] = hits
	}
	m.muMetrics.RUnlock()

	// The blacklist counters have their own mutexes.
	m.muIPBlacklistMetrics.Lock()
	ipBlacklistHits := m.IPBlacklistBlockCount
	m.muIPBlacklistMetrics.Unlock()

	m.muDNSBlacklistMetrics.Lock()
	dnsBlacklistHits := m.DNSBlacklistBlockCount
	m.muDNSBlacklistMetrics.Unlock()

	// Collect all metrics
	metrics := map[string]interface{}{
		"total_requests":                totalRequests,
		"blocked_requests":              blockedRequests,
		"allowed_requests":              allowedRequests,
		"rule_hits":                     ruleHits,
		"rule_hits_by_phase":            hitsByPhase,
		"geoip_blocked":                 geoIPBlocked,
		"ip_blacklist_hits":             ipBlacklistHits,
		"dns_blacklist_hits":            dnsBlacklistHits,
		"rate_limiter_requests":         rateLimiterTotalRequests,
		"rate_limiter_blocked_requests": rateLimiterBlockedRequests,
		"version":                       wafVersion,
	}
	for k, v := range m.observabilitySnapshot() {
		metrics[k] = v
	}

	jsonMetrics, err := json.Marshal(metrics)
	if err != nil {
		m.logger.Error("Failed to marshal metrics to JSON", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return fmt.Errorf("failed to marshal metrics to JSON: %v", err)
	}

	_, err = w.Write(jsonMetrics)
	if err != nil {
		m.logger.Error("Failed to write metrics response", zap.Error(err))
		return fmt.Errorf("failed to write metrics response: %v", err)
	}
	return nil
}

// ==================== Utility Functions ====================

func (m *Middleware) extractValue(target string, r *http.Request, w http.ResponseWriter) (string, error) {
	return m.requestValueExtractor.ExtractValue(target, r, w)
}

// ==================== Unimplemented Functions ====================

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if m.configLoader == nil {
		m.configLoader = NewConfigLoader(m.logger)
	}
	return m.configLoader.UnmarshalCaddyfile(d, m)
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	if m.logLevel == 0 {
		m.logLevel = zapcore.InfoLevel // Default log level
	}

	// Validate anomaly threshold
	if m.AnomalyThreshold < 0 {
		return fmt.Errorf("anomaly_threshold cannot be negative: %d", m.AnomalyThreshold)
	}

	// Validate rate limit configuration if enabled
	if m.RateLimit.Requests > 0 {
		if m.RateLimit.Window <= 0 {
			return fmt.Errorf("rate_limit window must be positive when rate limiting is enabled")
		}
		if m.RateLimit.CleanupInterval <= 0 {
			return fmt.Errorf("rate_limit cleanup_interval must be positive when rate limiting is enabled")
		}
	}

	// Validate max request body size
	if m.MaxRequestBodySize < 0 {
		return fmt.Errorf("max_request_body_size cannot be negative: %d", m.MaxRequestBodySize)
	}

	// Validate max response body size
	if m.MaxResponseBodySize < 0 {
		return fmt.Errorf("max_response_body_size cannot be negative: %d", m.MaxResponseBodySize)
	}

	// Validate log buffer
	if m.LogBuffer < 0 {
		return fmt.Errorf("log_buffer cannot be negative: %d", m.LogBuffer)
	}

	return nil
}
