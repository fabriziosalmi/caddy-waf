package caddywaf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// ConfigLoader structure to encapsulate loading and parsing logic
type ConfigLoader struct {
	logger *zap.Logger
}

func NewConfigLoader(logger *zap.Logger) *ConfigLoader {
	return &ConfigLoader{logger: logger}
}

// parseMetricsEndpoint parses the metrics_endpoint directive.
func (cl *ConfigLoader) parseMetricsEndpoint(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	m.MetricsEndpoint = d.Val()
	cl.logger.Debug("Metrics endpoint configured",
		zap.String("endpoint", m.MetricsEndpoint),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

// parseLogPath parses the log_path directive.
func (cl *ConfigLoader) parseLogPath(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	m.LogFilePath = d.Val()
	cl.logger.Debug("Log file path configured",
		zap.String("path", m.LogFilePath),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

// parseRateLimit parses the rate_limit directive.
func (cl *ConfigLoader) parseRateLimit(d *caddyfile.Dispenser, m *Middleware) error {
	if m.RateLimit.Requests > 0 {
		return d.Err("rate_limit directive already specified")
	}

	rl := RateLimit{
		Requests:        100,               // Default requests
		Window:          10 * time.Second,  // Default window
		CleanupInterval: 300 * time.Second, // Default cleanup interval
		MatchAllPaths:   false,             // Default to false
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		option := d.Val()
		switch option {
		case "requests":
			reqs, err := cl.parsePositiveInteger(d, "requests")
			if err != nil {
				return err
			}
			rl.Requests = reqs
			cl.logger.Debug("Rate limit requests set", zap.Int("requests", rl.Requests))

		case "window":
			window, err := cl.parseDuration(d, "window")
			if err != nil {
				return err
			}
			rl.Window = window
			cl.logger.Debug("Rate limit window set", zap.Duration("window", rl.Window))

		case "cleanup_interval":
			interval, err := cl.parseDuration(d, "cleanup_interval")
			if err != nil {
				return err
			}
			rl.CleanupInterval = interval
			cl.logger.Debug("Rate limit cleanup interval set", zap.Duration("cleanup_interval", rl.CleanupInterval))

		case "paths":
			paths := d.RemainingArgs()
			if len(paths) == 0 {
				return d.Err("paths option requires at least one path")
			}
			rl.Paths = paths
			cl.logger.Debug("Rate limit paths configured", zap.Strings("paths", rl.Paths))

		case "match_all_paths":
			matchAllPaths, err := cl.parseBool(d, "match_all_paths")
			if err != nil {
				return err
			}
			rl.MatchAllPaths = matchAllPaths
			cl.logger.Debug("Rate limit match_all_paths set", zap.Bool("match_all_paths", rl.MatchAllPaths))

		default:
			return d.Errf("unrecognized rate_limit option: %s", option)
		}
	}

	if rl.Requests <= 0 || rl.Window <= 0 {
		return d.Err("requests and window in rate_limit must be positive values")
	}

	m.RateLimit = rl
	cl.logger.Debug("Rate limit configuration applied", zap.Any("rate_limit", m.RateLimit), zap.String("file", d.File()), zap.Int("line", d.Line()))
	return nil
}

// UnmarshalCaddyfile is the primary parsing function for the middleware configuration.
func (cl *ConfigLoader) UnmarshalCaddyfile(d *caddyfile.Dispenser, m *Middleware) error {
	if cl.logger == nil {
		cl.logger = zap.NewNop()
	}

	// Initialize TorConfig with default values
	m.Tor = TorConfig{
		Enabled:            false,               // Default to disabled
		TORIPBlacklistFile: "tor_blacklist.txt", // Default file
		UpdateInterval:     "24h",               // Default interval
		RetryOnFailure:     false,               // Default to disabled
		RetryInterval:      "5m",                // Default retry interval
	}

	cl.logger.Debug("Parsing WAF configuration", zap.String("file", d.File()), zap.Int("line", d.Line()))

	// Set default values
	m.LogSeverity = "info"
	m.LogJSON = false
	m.AnomalyThreshold = 5
	m.CountryBlacklist.Enabled = false
	m.CountryWhitelist.Enabled = false
	m.LogFilePath = "debug.json"
	m.RedactSensitiveData = false
	m.LogBuffer = 1000
	m.BlockASNs.Enabled = false // Default to false

	directiveHandlers := map[string]func(d *caddyfile.Dispenser, m *Middleware) error{
		"metrics_endpoint":      cl.parseMetricsEndpoint,
		"log_path":              cl.parseLogPath,
		"rate_limit":            cl.parseRateLimit,
		"block_countries":       cl.parseCountryBlockDirective(true),  // Use directive-specific helper
		"whitelist_countries":   cl.parseCountryBlockDirective(false), // Use directive-specific helper
		"block_asns":            cl.parseBlockASNsDirective,           // Add ASN block directive
		"log_severity":          cl.parseLogSeverity,
		"log_json":              cl.parseLogJSON,
		"rule_file":             cl.parseRuleFile,
		"ip_blacklist_file":     cl.parseBlacklistFileDirective(true),  // Use directive-specific helper
		"dns_blacklist_file":    cl.parseBlacklistFileDirective(false), // Use directive-specific helper
		"anomaly_threshold":     cl.parseAnomalyThreshold,
		"custom_response":       cl.parseCustomResponse,
		"redact_sensitive_data": cl.parseRedactSensitiveData,
		"tor":                   cl.parseTorBlock,
		"log_buffer":            cl.parseLogBuffer,
	}

	for d.Next() {
		for d.NextBlock(0) {
			directive := d.Val()
			handler, exists := directiveHandlers[directive]
			if !exists {
				cl.logger.Warn("Unrecognized WAF directive", zap.String("directive", directive), zap.String("file", d.File()), zap.Int("line", d.Line()))
				return d.Errf("unrecognized directive: %s", directive)
			}
			if err := handler(d, m); err != nil {
				return err // Handler already provides context in error
			}
		}
	}

	if len(m.RuleFiles) == 0 {
		return fmt.Errorf("no rule files specified for WAF")
	}

	cl.logger.Debug("WAF configuration parsed successfully", zap.String("file", d.File()))
	return nil
}

func (cl *ConfigLoader) parseRuleFile(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	ruleFile := d.Val()
	m.RuleFiles = append(m.RuleFiles, ruleFile)

	if m.MetricsEndpoint != "" && !strings.HasPrefix(m.MetricsEndpoint, "/") {
		return d.Err("metrics_endpoint must start with a leading '/'")
	}

	cl.logger.Info("Loading WAF rule file",
		zap.String("path", ruleFile),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

func (cl *ConfigLoader) parseCustomResponse(d *caddyfile.Dispenser, m *Middleware) error {
	if m.CustomResponses == nil {
		m.CustomResponses = make(map[int]CustomBlockResponse)
	}

	if !d.NextArg() {
		return d.ArgErr()
	}
	statusCode, err := cl.parseStatusCode(d)
	if err != nil {
		return err
	}

	if _, exists := m.CustomResponses[statusCode]; exists {
		return d.Errf("custom_response for status code %d already defined", statusCode)
	}

	resp := CustomBlockResponse{
		StatusCode: statusCode,
		Headers:    make(map[string]string),
	}

	if !d.NextArg() {
		return d.ArgErr()
	}
	contentTypeOrFile := d.Val()

	if d.NextArg() {
		filePath := d.Val()
		content, err := cl.readResponseFromFile(d, filePath)
		if err != nil {
			return err
		}
		resp.Headers["Content-Type"] = contentTypeOrFile
		resp.Body = content
		cl.logger.Debug("Loaded custom response from file",
			zap.Int("status_code", statusCode),
			zap.String("file_path", filePath),
			zap.String("content_type", contentTypeOrFile),
			zap.String("file", d.File()),
			zap.Int("line", d.Line()),
		)
	} else {
		body, err := cl.parseInlineResponseBody(d)
		if err != nil {
			return err
		}
		resp.Headers["Content-Type"] = contentTypeOrFile
		resp.Body = body
		cl.logger.Debug("Loaded inline custom response",
			zap.Int("status_code", statusCode),
			zap.String("content_type", contentTypeOrFile),
			zap.String("body", body),
			zap.String("file", d.File()),
			zap.Int("line", d.Line()),
		)
	}
	m.CustomResponses[statusCode] = resp
	return nil
}

// parseCountryBlockDirective returns a closure to handle block_countries and whitelist_countries directives.
func (cl *ConfigLoader) parseCountryBlockDirective(isBlock bool) func(d *caddyfile.Dispenser, m *Middleware) error {
	return func(d *caddyfile.Dispenser, m *Middleware) error {
		target := &m.CountryBlacklist
		directiveName := "block_countries"
		if !isBlock {
			target = &m.CountryWhitelist
			directiveName = "whitelist_countries"
		}
		target.Enabled = true

		if !d.NextArg() {
			return d.ArgErr()
		}
		target.GeoIPDBPath = d.Val()
		target.CountryList = []string{}

		for d.NextArg() {
			country := strings.ToUpper(d.Val())
			target.CountryList = append(target.CountryList, country)
		}

		cl.logger.Debug("Country list configured",
			zap.String("directive", directiveName),
			zap.Bool("block_mode", isBlock),
			zap.Strings("countries", target.CountryList),
			zap.String("geoip_db_path", target.GeoIPDBPath),
			zap.String("file", d.File()),
			zap.Int("line", d.Line()),
		)
		return nil
	}
}

// parseBlockASNsDirective handles the block_asns directive
func (cl *ConfigLoader) parseBlockASNsDirective(d *caddyfile.Dispenser, m *Middleware) error {
	target := &m.BlockASNs
	target.Enabled = true

	if !d.NextArg() {
		return d.ArgErr()
	}
	target.GeoIPDBPath = d.Val()
	target.BlockedASNs = []string{}

	for d.NextArg() {
		asn := d.Val()
		target.BlockedASNs = append(target.BlockedASNs, asn)
	}

	cl.logger.Debug("ASN block list configured",
		zap.Strings("asns", target.BlockedASNs),
		zap.String("geoip_db_path", target.GeoIPDBPath),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

func (cl *ConfigLoader) parseLogSeverity(d *caddyfile.Dispenser, m *Middleware) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	severity := d.Val()
	validSeverities := []string{"debug", "info", "warn", "error"} // Define valid severities
	isValid := false
	for _, valid := range validSeverities {
		if severity == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return d.Errf("invalid log_severity value '%s', must be one of: %s", severity, strings.Join(validSeverities, ", "))
	}

	m.LogSeverity = severity
	cl.logger.Debug("Log severity set",
		zap.String("severity", m.LogSeverity),
		zap.String("file", d.File()),
		zap.Int("line", d.Line()),
	)
	return nil
}

// parseBlacklistFileDirective returns a closure to handle ip_blacklist_file and dns_blacklist_file directives.
func (cl *ConfigLoader) parseBlacklistFileDirective(isIP bool) func(d *caddyfile.Dispenser, m *Middleware) error {
	return func(d *caddyfile.Dispenser, m *Middleware) error {
		if !d.NextArg() {
			return d.ArgErr()
		}
		filePath := d.Val()
		directiveName := "dns_blacklist_file"
		if isIP {
			directiveName = "ip_blacklist_file"
		}
		if err := cl.ensureBlacklistFileExists(d, filePath, isIP); err != nil {
			return err
		}
		// Assign the file path to the appropriate field
		if isIP {
			m.IPBlacklistFile = filePath
		} else {
			m.DNSBlacklistFile = filePath
		}
		cl.logger.Info("Blacklist file configured",
			zap.String("directive", directiveName),
			zap.String("path", filePath),
			zap.Bool("is_ip_type", isIP),
		)
		return nil
	}
}

func (cl *ConfigLoader) parseAnomalyThreshold(d *caddyfile.Dispenser, m *Middleware) error {
	threshold, err := cl.parsePositiveInteger(d, "anomaly_threshold")
	if err != nil {
		return err
	}
	m.AnomalyThreshold = threshold
	cl.logger.Debug("Anomaly threshold set", zap.Int("threshold", threshold), zap.String("file", d.File()), zap.Int("line", d.Line()))
	return nil
}

func (cl *ConfigLoader) parseTorBlock(d *caddyfile.Dispenser, m *Middleware) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subDirective := d.Val()
		switch subDirective {
		case "enabled":
			enabled, err := cl.parseBool(d, "tor enabled")
			if err != nil {
				return err
			}
			m.Tor.Enabled = enabled
			cl.logger.Debug("Tor blocking enabled", zap.Bool("enabled", m.Tor.Enabled))

		case "tor_ip_blacklist_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Tor.TORIPBlacklistFile = d.Val()
			cl.logger.Debug("Tor IP blacklist file set", zap.String("file_path", m.Tor.TORIPBlacklistFile))

		case "update_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Tor.UpdateInterval = d.Val()
			cl.logger.Debug("Tor update interval set", zap.String("interval", m.Tor.UpdateInterval))

		case "retry_on_failure":
			retryOnFailure, err := cl.parseBool(d, "tor retry_on_failure")
			if err != nil {
				return err
			}
			m.Tor.RetryOnFailure = retryOnFailure
			cl.logger.Debug("Tor retry on failure set", zap.Bool("retry_on_failure", m.Tor.RetryOnFailure))

		case "retry_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Tor.RetryInterval = d.Val()
			cl.logger.Debug("Tor retry interval set", zap.String("interval", m.Tor.RetryInterval))

		default:
			return d.Errf("unrecognized tor subdirective: %s", subDirective)
		}
	}
	return nil
}

func (cl *ConfigLoader) parseLogJSON(d *caddyfile.Dispenser, m *Middleware) error {
	m.LogJSON = true
	cl.logger.Debug("Log JSON enabled", zap.String("file", d.File()), zap.Int("line", d.Line()))
	return nil
}

func (cl *ConfigLoader) parseRedactSensitiveData(d *caddyfile.Dispenser, m *Middleware) error {
	m.RedactSensitiveData = true
	cl.logger.Debug("Redact sensitive data enabled", zap.String("file", d.File()), zap.Int("line", d.Line()))
	return nil
}

func (cl *ConfigLoader) parseLogBuffer(d *caddyfile.Dispenser, m *Middleware) error {
	buffer, err := cl.parsePositiveInteger(d, "log_buffer")
	if err != nil {
		return err
	}
	m.LogBuffer = buffer
	cl.logger.Debug("Log buffer size set", zap.Int("size", buffer), zap.String("file", d.File()), zap.Int("line", d.Line()))
	return nil
}

// --- Helper Functions ---

// parsePositiveInteger parses a directive argument as a positive integer.
func (cl *ConfigLoader) parsePositiveInteger(d *caddyfile.Dispenser, directiveName string) (int, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	valStr := d.Val()
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return 0, d.Errf("invalid %s value '%s': %v", directiveName, valStr, err)
	}
	if val <= 0 {
		return 0, d.Errf("%s must be a positive integer, but got '%d'", directiveName, val)
	}
	return val, nil
}

// parseDuration parses a directive argument as a time duration.
func (cl *ConfigLoader) parseDuration(d *caddyfile.Dispenser, directiveName string) (time.Duration, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	durationStr := d.Val()
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return 0, d.Errf("invalid %s value '%s': %v", directiveName, durationStr, err)
	}
	return duration, nil
}

// parseBool parses a directive argument as a boolean.
func (cl *ConfigLoader) parseBool(d *caddyfile.Dispenser, directiveName string) (bool, error) {
	if !d.NextArg() {
		return false, d.ArgErr()
	}
	boolStr := d.Val()
	val, err := strconv.ParseBool(boolStr)
	if err != nil {
		return false, d.Errf("invalid %s value '%s': %v, must be 'true' or 'false'", directiveName, boolStr, err)
	}
	return val, nil
}

// parseStatusCode parses a directive argument as an HTTP status code.
func (cl *ConfigLoader) parseStatusCode(d *caddyfile.Dispenser) (int, error) {
	statusCodeStr := d.Val()
	statusCode, err := strconv.Atoi(statusCodeStr)
	if err != nil {
		return 0, d.Errf("invalid status code '%s': %v", statusCodeStr, err)
	}
	if statusCode < 100 || statusCode > 599 {
		return 0, d.Errf("status code '%d' out of range, must be between 100 and 599", statusCode)
	}
	return statusCode, nil
}

// readResponseFromFile reads custom response body from file.
func (cl *ConfigLoader) readResponseFromFile(d *caddyfile.Dispenser, filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", d.Errf("could not read custom response file '%s': %v", filePath, err)
	}
	return string(content), nil
}

// parseInlineResponseBody parses inline custom response body.
func (cl *ConfigLoader) parseInlineResponseBody(d *caddyfile.Dispenser) (string, error) {
	remaining := d.RemainingArgs()
	if len(remaining) == 0 {
		return "", d.Err("missing custom response body")
	}
	return strings.Join(remaining, " "), nil
}

// ensureBlacklistFileExists checks if blacklist file exists and creates it if not.
func (cl *ConfigLoader) ensureBlacklistFileExists(d *caddyfile.Dispenser, filePath string, isIP bool) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			fileType := "DNS"
			if isIP {
				fileType = "IP"
			}
			return d.Errf("could not create %s blacklist file '%s': %v", fileType, filePath, err)
		}
		file.Close()
		fileType := "DNS"
		if isIP {
			fileType = "IP"
		}
		cl.logger.Warn("%s blacklist file does not exist, created an empty file", zap.String("type", fileType), zap.String("path", filePath))
	} else if err != nil {
		fileType := "DNS"
		if isIP {
			fileType = "IP"
		}
		return d.Errf("could not access %s blacklist file '%s': %v", fileType, filePath, err)
	}
	return nil
}
