package caddywaf

import (
	"regexp"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/phemmer/go-iptrie"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Package caddywaf is a Caddy module providing web application firewall functionality.

// ==================== Constants and Globals ====================

var (
	_ caddy.Module                = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
)

// Define custom types for rule hits
type (
	RuleID   string
	HitCount int
)

// RuleCache caches compiled regex patterns for rules.
type RuleCache struct {
	mu    sync.RWMutex
	rules map[string]*regexp.Regexp
}

// CountryAccessFilter struct
type CountryAccessFilter struct {
	Enabled     bool              `json:"enabled"`
	CountryList []string          `json:"country_list"`
	GeoIPDBPath string            `json:"geoip_db_path"`
	geoIP       *maxminddb.Reader `json:"-"` // Explicitly mark as not serialized
}

// ASNAccessFilter struct
type ASNAccessFilter struct {
	Enabled     bool              `json:"enabled"`
	BlockedASNs []string          `json:"blocked_asns"`
	GeoIPDBPath string            `json:"geoip_db_path"`
	geoIP       *maxminddb.Reader `json:"-"` // Explicitly mark as not serialized
}

// GeoIPRecord struct
type GeoIPRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// ASNRecord struct
type ASNRecord struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
}

// Rule struct
type Rule struct {
	ID          string   `json:"id"`
	Phase       int      `json:"phase"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Severity    string   `json:"severity"` // Used for logging only
	Score       int      `json:"score"`
	Action      string   `json:"mode"` // CRITICAL FIX: This should map to the "mode" field in JSON
	Description string   `json:"description"`
	regex       *regexp.Regexp
	Priority    int // New field for rule priority
}

// CustomBlockResponse struct
type CustomBlockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// WAFState struct
type WAFState struct {
	TotalScore      int
	Blocked         bool
	StatusCode      int
	ResponseWritten bool
}

// Middleware is the main WAF middleware struct that implements Caddy's
// Module, Provisioner, Validator, and MiddlewareHandler interfaces.
//
// It provides comprehensive web application firewall functionality including:
//   - Rule-based request filtering
//   - IP and DNS blacklisting
//   - Geographic access control
//   - Rate limiting
//   - Anomaly detection
//   - Custom response handling
//   - Real-time metrics and monitoring
//
// The middleware can be configured via Caddyfile or JSON and integrates
// seamlessly into Caddy's request processing pipeline.
type Middleware struct {
	mu sync.RWMutex

	RuleFiles        []string            `json:"rule_files"`
	IPBlacklistFile  string              `json:"ip_blacklist_file"`
	DNSBlacklistFile string              `json:"dns_blacklist_file"`
	AnomalyThreshold int                 `json:"anomaly_threshold"`
	CountryBlacklist CountryAccessFilter `json:"country_blacklist"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	BlockASNs        ASNAccessFilter     `json:"block_asns"`
	Rules            map[int][]Rule      `json:"-"`
	ipBlacklist      *iptrie.Trie        `json:"-"`
	dnsBlacklist     map[string]struct{} `json:"-"` // Changed to map[string]struct{}
	logger           *zap.Logger
	LogSeverity      string `json:"log_severity,omitempty"`
	LogJSON          bool   `json:"log_json,omitempty"`
	logLevel         zapcore.Level
	isShuttingDown   bool

	geoIPCacheTTL               time.Duration
	geoIPLookupFallbackBehavior string

	CustomResponses     map[int]CustomBlockResponse `json:"custom_responses,omitempty"`
	LogFilePath         string
	LogBuffer           int  `json:"log_buffer,omitempty"` // Add the LogBuffer field
	RedactSensitiveData bool `json:"redact_sensitive_data,omitempty"`
	MaxRequestBodySize  int64 `json:"max_request_body_size,omitempty"`
	GeoIPFailOpen       bool  `json:"geoip_fail_open,omitempty"`

	ruleHits        sync.Map `json:"-"`
	MetricsEndpoint string   `json:"metrics_endpoint,omitempty"`

	configLoader          *ConfigLoader
	blacklistLoader       *BlacklistLoader
	geoIPHandler          *GeoIPHandler
	requestValueExtractor *RequestValueExtractor

	RateLimit   RateLimit
	rateLimiter *RateLimiter

	totalRequests   int64
	blockedRequests int64
	allowedRequests int64
	ruleHitsByPhase map[int]int64
	geoIPStats      map[string]int64 // Key: country code, Value: count
	muMetrics       sync.RWMutex     // Mutex for metrics synchronization

	rateLimiterBlockedRequests int64        // Add rate limiter blocked requests metric
	muRateLimiterMetrics       sync.RWMutex // Mutex to protect rate limiter metrics

	geoIPBlocked int

	Tor TorConfig `json:"tor,omitempty"`

	logChan chan LogEntry // Buffered channel for log entries
	logDone chan struct{} // Signal to stop the logging worker

	ruleCache *RuleCache // New field for RuleCache

	IPBlacklistBlockCount  int64 `json:"ip_blacklist_hits"`
	muIPBlacklistMetrics   sync.Mutex
	DNSBlacklistBlockCount int64 `json:"dns_blacklist_hits"`
	muDNSBlacklistMetrics  sync.Mutex
}

// ==================== Constructors (New functions) ====================

// NewRuleCache creates a new RuleCache.
func NewRuleCache() *RuleCache {
	return &RuleCache{
		rules: make(map[string]*regexp.Regexp),
	}
}

// ==================== RuleCache Methods ====================

// Get retrieves a compiled regex pattern from the cache.
func (rc *RuleCache) Get(ruleID string) (*regexp.Regexp, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	regex, exists := rc.rules[ruleID]
	return regex, exists
}

// Set stores a compiled regex pattern in the cache.
func (rc *RuleCache) Set(ruleID string, regex *regexp.Regexp) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.rules[ruleID] = regex
}
