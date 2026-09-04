package caddywaf

import (
	"regexp"
	"sync"
	"sync/atomic"
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
	Action      string   `json:"action"` // "block" or "log"; matches the "action" key in every shipped rule file
	Description string   `json:"description"`
	// Transformations is an optional per-rule ModSecurity/CRS-style pipeline
	// (e.g. ["urlDecodeUni","removeNulls","replaceComments"]) applied to the
	// extracted value before matching. A pointer so JSON can distinguish an
	// absent field (use the per-target default chain) from an explicit empty
	// array (apply no transformation). Names are matched case-insensitively and
	// an optional "t:" prefix is accepted.
	Transformations *[]string `json:"transformations,omitempty"`
	regex           *regexp.Regexp
	Priority        int // New field for rule priority
}

// CustomBlockResponse struct
type CustomBlockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// WAFState struct
type WAFState struct {
	TotalScore      int // score that drives the blocking decision
	AdvisoryScore   int // score contributed by log-action rules (never blocks unless LogScoresBlock)
	Blocked         bool
	StatusCode      int
	ResponseWritten bool
}

// blockRecord is one entry in the recent-blocks ring the metrics endpoint
// exposes for the dashboard (#143). Blocked requests only.
type blockRecord struct {
	TS      int64  `json:"ts_ms"`
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	RuleID  string `json:"rule_id,omitempty"`
	Status  int    `json:"status"`
	Score   int    `json:"score"`
	Country string `json:"country,omitempty"`
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

	RuleFiles       []string `json:"rule_files"`
	IPBlacklistFile string   `json:"ip_blacklist_file"`
	// IPWhitelist holds entries exempt from the IP-reputation checks: bare IPs,
	// CIDR ranges, or the token "private_ranges". See whitelist_ip in
	// docs/configuration.md.
	IPWhitelist []string `json:"ip_whitelist,omitempty"`
	// IPWhitelistFile is an optional file of IP/CIDR entries exempt from the
	// IP-reputation checks, one per line (# comments allowed). It is hot-reloaded
	// on change, the whitelist counterpart to ip_blacklist_file. See whitelist_file.
	IPWhitelistFile string `json:"ip_whitelist_file,omitempty"`
	// TrustedProxies is the trust boundary for X-Forwarded-For: forwarding
	// headers are honoured only when the immediate peer is within this set (bare
	// IPs, CIDR ranges, or the token private_ranges). Empty means the peer
	// address is always used and forwarding headers are ignored. See #94.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	// ClientIPHeader, when set (e.g. CF-Connecting-IP), is consulted for the
	// client IP instead of X-Forwarded-For once the peer is a trusted proxy.
	ClientIPHeader   string       `json:"client_ip_header,omitempty"`
	trustedProxies   *iptrie.Trie `json:"-"`
	DNSBlacklistFile string       `json:"dns_blacklist_file"`
	AnomalyThreshold int          `json:"anomaly_threshold"`
	// LogScoresBlock controls whether a rule with action "log" contributes to
	// the anomaly score that drives the blocking decision. Default false: log
	// rules are observational and never push a request over the threshold on
	// their own -- they are still recorded (advisory score, metrics, logs).
	// Set true to restore the legacy behaviour where every matched rule,
	// regardless of action, accumulates toward the block threshold.
	LogScoresBlock   bool                `json:"log_scores_block,omitempty"`
	CountryBlacklist CountryAccessFilter `json:"country_blacklist"`
	CountryWhitelist CountryAccessFilter `json:"country_whitelist"`
	BlockASNs        ASNAccessFilter     `json:"block_asns"`
	Rules            map[int][]Rule      `json:"-"`
	ipBlacklist      *iptrie.Trie        `json:"-"`
	ipWhitelist      *iptrie.Trie        `json:"-"`
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
	LogBuffer           int   `json:"log_buffer,omitempty"` // Add the LogBuffer field
	RedactSensitiveData bool  `json:"redact_sensitive_data,omitempty"`
	MaxRequestBodySize  int64 `json:"max_request_body_size,omitempty"`
	MaxResponseBodySize int64 `json:"max_response_body_size,omitempty"`
	GeoIPFailOpen       bool  `json:"geoip_fail_open,omitempty"`

	ruleHits        sync.Map `json:"-"`
	MetricsEndpoint string   `json:"metrics_endpoint,omitempty"`
	// DashboardEndpoint, when set (and the binary is built with the `with_ui`
	// tag), serves the built-in read-only dashboard at this path, same-origin
	// with metrics_endpoint. Opt-in at two levels: build tag + this directive.
	DashboardEndpoint string `json:"dashboard_endpoint,omitempty"`
	// PrometheusEndpoint, when set, serves the WAF counters in the Prometheus
	// text exposition format at this path (native scraping, no exporter needed).
	PrometheusEndpoint string `json:"prometheus_endpoint,omitempty"`

	configLoader          *ConfigLoader
	blacklistLoader       *BlacklistLoader
	geoIPHandler          *GeoIPHandler
	requestValueExtractor *RequestValueExtractor

	RateLimit   RateLimit
	rateLimiter *RateLimiter

	// Process-local request counters, incremented on every request. Atomic so
	// the hot path takes no lock for them (#116) -- muMetrics now guards only the
	// ruleHitsByPhase map below.
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	allowedRequests atomic.Int64
	ruleHitsByPhase map[int]int64
	geoIPStats      map[string]int64 // Key: country code, Value: count
	muMetrics       sync.RWMutex     // Guards the ruleHitsByPhase map

	// Observability for the built-in dashboard (#143 M1). geoIPStats above holds
	// per-country BLOCK counts; the fields below and it are all guarded by muObs.
	provisionTime   time.Time
	muObs           sync.Mutex
	recentBlocks    []blockRecord    // bounded ring, oldest first
	topIPsBlocked   map[string]int64 // bounded
	blockedByReason map[string]int64

	// Request-duration histogram (Prometheus), updated lock-free on the hot path.
	latencyBuckets [numLatencyBuckets]atomic.Uint64
	latencySumBits atomic.Uint64
	latencyCount   atomic.Uint64

	rateLimiterBlockedRequests int64        // Add rate limiter blocked requests metric
	muRateLimiterMetrics       sync.RWMutex // Mutex to protect rate limiter metrics

	geoIPBlocked atomic.Int64

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
