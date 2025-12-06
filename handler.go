package caddywaf

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type (
	ContextKeyLogId string
	ContextKeyRule  string
)

// ServeHTTP implements caddyhttp.Handler.
// handler.go
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logID := uuid.New().String()

	// Add panic recovery to catch and log panics
	defer func() {
		if rec := recover(); rec != nil {
			m.logger.Error("PANIC in ServeHTTP",
				zap.String("log_id", logID),
				zap.Any("panic", rec),
				zap.Stack("stack"),
			)
			// Return 500 error to client
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("Internal Server Error")); err != nil {
				m.logger.Error(err.Error(),
					zap.String("log_id", logID),
					zap.Any("panic", rec),
					zap.Stack("stack"),
				)
				return
			}
		}
	}()

	m.logRequestStart(r, logID)

	// Propagate log ID within the request context for logging
	ctx := context.WithValue(r.Context(), ContextKeyLogId("logID"), logID)
	r = r.WithContext(ctx)

	m.incrementTotalRequestsMetric()

	// Initialize WAF state for this request
	state := m.initializeWAFState()

	// Phase 1: Pre-request checks and blocking
	if m.isPhaseBlocked(w, r, 1, state) {
		return nil // Request blocked, short-circuit
	}

	// Phase 2: Request analysis and blocking
	if m.isPhaseBlocked(w, r, 2, state) {
		return nil // Request blocked, short-circuit
	}

	// Response capture and processing
	recorder := NewResponseRecorder(w)
	err := next.ServeHTTP(recorder, r)

	// Phase 3: Response Header analysis
	if m.isPhaseBlocked(recorder, r, 3, state) {
		return nil // Request blocked in Phase 3, short-circuit
	}

	// Phase 4: Response Body analysis (if not already blocked)
	m.handleResponseBodyPhase(recorder, r, state)

	if state.Blocked {
		// Metrics and response handling if blocked after headers phase
		m.incrementBlockedRequestsMetric()
		m.writeCustomResponse(recorder, state.StatusCode)
		return nil
	}

	// Handle metrics request separately
	if m.isMetricsRequest(r) {
		return m.handleMetricsRequest(w, r)
	}

	// If not blocked, copy recorded response back to original writer
	// Moved this inside if check to call only if not blocked
	if !state.Blocked {
		m.incrementAllowedRequestsMetric() // Increment here only if not blocked
		m.copyResponse(w, recorder, r)
	}
	m.logRequestCompletion(logID, state)

	return err // Return any error from the next handler
}

// isPhaseBlocked encapsulates the phase handling and blocking check logic.
func (m *Middleware) isPhaseBlocked(w http.ResponseWriter, r *http.Request, phase int, state *WAFState) bool {
	m.handlePhase(w, r, phase, state)

	if state.Blocked {
		m.incrementBlockedRequestsMetric()

		// IMPORTANT: Log the block event with details
		m.logger.Warn("Request blocked in phase evaluation",
			zap.Int("phase", phase),
			zap.Int("status_code", state.StatusCode),
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
		)

		// Only write the status if not already written
		if !state.ResponseWritten {
			w.WriteHeader(state.StatusCode)
			state.ResponseWritten = true
		}

		return true
	}

	return false
}

// logRequestStart logs the start of WAF evaluation.
func (m *Middleware) logRequestStart(r *http.Request, logID string) {
	m.logger.Info("WAF request evaluation started",
		zap.String("log_id", logID),
		zap.String("method", r.Method),
		zap.String("uri", r.RequestURI),
		zap.String("remote_address", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)
}

// incrementTotalRequestsMetric increments the total requests metric.
func (m *Middleware) incrementTotalRequestsMetric() {
	m.muMetrics.Lock()
	m.totalRequests++
	m.muMetrics.Unlock()
}

// initializeWAFState initializes the WAF state.
func (m *Middleware) initializeWAFState() *WAFState {
	return &WAFState{
		TotalScore:      0,
		Blocked:         false,
		StatusCode:      http.StatusOK,
		ResponseWritten: false,
	}
}

// getLogID extracts the logID from the request context.
func getLogID(ctx context.Context) string {
	if logID, ok := ctx.Value(ContextKeyLogId("logID")).(string); ok {
		return logID
	}
	return "unknown"
}

// handleResponseBodyPhase processes Phase 4 (response body).
func (m *Middleware) handleResponseBodyPhase(recorder *responseRecorder, r *http.Request, state *WAFState) {
	// No need to check if recorder.body is nil here, it's always initialized in NewResponseRecorder
	body := recorder.BodyString()
	logID := getLogID(r.Context())
	if logID == "unknown" {
		m.logger.Error("Log ID missing in context")
		return
	}
	m.logger.Debug("Response body captured for Phase 4 analysis", zap.String("log_id", logID))

	// Check if rules exist for Phase 4 before iterating
	rules, ok := m.Rules[4]
	if !ok || len(rules) == 0 {
		m.logger.Debug("No rules found for Phase 4")
		return
	}

	for _, rule := range rules {
		if rule.regex.MatchString(body) {
			if m.processRuleMatch(recorder, r, &rule, "RESPONSE_BODY", body, state) { // Pass RESPONSE_BODY as target
				return
			}
		}
	}
}

// incrementBlockedRequestsMetric increments the blocked requests metric.
func (m *Middleware) incrementBlockedRequestsMetric() {
	m.muMetrics.Lock()
	m.blockedRequests++
	m.muMetrics.Unlock()
}

// incrementAllowedRequestsMetric increments the allowed requests metric.
func (m *Middleware) incrementAllowedRequestsMetric() {
	m.muMetrics.Lock()
	m.allowedRequests++
	m.muMetrics.Unlock()
}

// isMetricsRequest checks if it's a metrics request.
func (m *Middleware) isMetricsRequest(r *http.Request) bool {
	return m.MetricsEndpoint != "" && r.URL.Path == m.MetricsEndpoint
}

// writeCustomResponse writes a custom response.
func (m *Middleware) writeCustomResponse(w http.ResponseWriter, statusCode int) {
	if customResponse, ok := m.CustomResponses[statusCode]; ok {
		for key, value := range customResponse.Headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(customResponse.StatusCode)
		if _, err := w.Write([]byte(customResponse.Body)); err != nil {
			m.logger.Error("Failed to write custom response body", zap.Error(err))
		}
	}
}

// logRequestCompletion logs the completion of WAF evaluation.
func (m *Middleware) logRequestCompletion(logID string, state *WAFState) {
	m.logger.Info("WAF request evaluation completed",
		zap.String("log_id", logID),
		zap.Int("total_score", state.TotalScore),
		zap.Bool("blocked", state.Blocked),
		zap.Int("status_code", state.StatusCode),
	)
}

// copyResponse copies the captured response from the recorder to the original writer
func (m *Middleware) copyResponse(w http.ResponseWriter, recorder *responseRecorder, r *http.Request) {
	header := w.Header()
	for key, values := range recorder.Header() {
		for _, value := range values {
			header.Add(key, value)
		}
	}
	w.WriteHeader(recorder.StatusCode())

	logID := getLogID(r.Context())
	if logID == "unknown" {
		m.logger.Error("Log ID not found in context during response copy") // added error log for clarity
	}
	_, err := w.Write(recorder.body.Bytes()) // Copy body from recorder to original writer
	if err != nil {
		m.logger.Error("Failed to write recorded response body to client", zap.Error(err), zap.String("log_id", logID))
	}
}

func (m *Middleware) handlePhase(w http.ResponseWriter, r *http.Request, phase int, state *WAFState) {
	m.logger.Debug("Starting phase evaluation",
		zap.Int("phase", phase),
		zap.String("source_ip", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	if phase == 1 {
		// IP blacklisting - the highest priority
		m.logger.Debug("Checking for IP blacklisting", zap.String("remote_addr", r.RemoteAddr)) // Added log for checking before to isIPBlacklisted call
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			if len(ips) > 0 {
				firstIP := strings.TrimSpace(ips[0])
				m.logger.Debug("Checking IP blacklist with X-Forwarded-For", zap.String("remote_addr_xff", firstIP), zap.String("r.RemoteAddr", r.RemoteAddr))
				if m.isIPBlacklisted(firstIP) {
					m.logger.Debug("Starting IP blacklist phase")
					m.blockRequest(w, r, state, http.StatusForbidden, "ip_blacklist", "ip_blacklist_rule",
						zap.String("message", "Request blocked by IP blacklist"),
					)
					if m.CustomResponses != nil {
						m.writeCustomResponse(w, state.StatusCode)
					}
					return
				}
			} else {
				m.logger.Debug("X-Forwarded-For header present but empty or invalid")
			}
		} else {
			m.logger.Debug("X-Forwarded-For header not present using r.RemoteAddr")
			if m.isIPBlacklisted(r.RemoteAddr) {
				m.logger.Debug("Starting IP blacklist phase")
				m.blockRequest(w, r, state, http.StatusForbidden, "ip_blacklist", "ip_blacklist_rule",
					zap.String("message", "Request blocked by IP blacklist"),
				)
				if m.CustomResponses != nil {
					m.writeCustomResponse(w, state.StatusCode)
				}
				return
			}
		}

		// DNS blacklisting
		if m.isDNSBlacklisted(r.Host) {
			m.logger.Debug("Starting DNS blacklist phase")
			m.blockRequest(w, r, state, http.StatusForbidden, "dns_blacklist", "dns_blacklist_rule",
				zap.String("message", "Request blocked by DNS blacklist"),
				zap.String("host", r.Host),
			)
			if m.CustomResponses != nil {
				m.writeCustomResponse(w, state.StatusCode)
			}
			return
		}

		// Rate limiting
		if m.rateLimiter != nil {
			m.logger.Debug("Starting rate limiting phase")
			ip := extractIP(r.RemoteAddr) // Pass the logger here
			path := r.URL.Path            // Get the request path
			if m.rateLimiter.isRateLimited(ip, path) {
				m.incrementRateLimiterBlockedRequestsMetric() // Increment the counter in the Middleware
				m.blockRequest(w, r, state, http.StatusTooManyRequests, "rate_limit", "rate_limit_rule",
					zap.String("message", "Request blocked by rate limit"),
				)
				if m.CustomResponses != nil {
					m.writeCustomResponse(w, state.StatusCode)
				}
				return
			}
			m.logger.Debug("Rate limiting phase completed - not blocked")
		}

		// Whitelisting
		if m.CountryWhitelist.Enabled {
			m.logger.Debug("Starting country whitelisting phase")
			allowed, err := m.isCountryInList(r.RemoteAddr, m.CountryWhitelist.CountryList, m.CountryWhitelist.geoIP)
			if err != nil {
				m.logRequest(zapcore.ErrorLevel, "Failed to check country whitelist",
					r,
					zap.Error(err),
				)
				m.blockRequest(w, r, state, http.StatusForbidden, "internal_error", "country_block_rule",
					zap.String("message", "Request blocked due to internal error"),
				)
				m.logger.Debug("Country whitelisting phase completed - blocked due to error")
				m.incrementGeoIPRequestsMetric(false) // Increment with false for error
				return
			} else if !allowed {
				m.blockRequest(w, r, state, http.StatusForbidden, "country_block", "country_block_rule",
					zap.String("message", "Request blocked by country"))
				m.incrementGeoIPRequestsMetric(true) // Increment with true for blocked
				if m.CustomResponses != nil {
					m.writeCustomResponse(w, state.StatusCode)
				}
				return
			}
			m.logger.Debug("Country whitelisting phase completed - not blocked")
			m.incrementGeoIPRequestsMetric(false) // Increment with false for no block
		}

		// ASN Blocking
		if m.BlockASNs.Enabled {
			m.logger.Debug("Starting ASN blocking phase")
			blocked, err := m.geoIPHandler.IsASNInList(r.RemoteAddr, m.BlockASNs.BlockedASNs, m.BlockASNs.geoIP)
			if err != nil {
				m.logRequest(zapcore.ErrorLevel, "Failed to check ASN blocking",
					r,
					zap.Error(err),
				)
				m.blockRequest(w, r, state, http.StatusForbidden, "internal_error", "asn_block_rule",
					zap.String("message", "Request blocked due to internal error"),
				)
				m.logger.Debug("ASN blocking phase completed - blocked due to error")
				m.incrementGeoIPRequestsMetric(false) // Increment with false for error
				return
			} else if blocked {
				asnInfo := m.geoIPHandler.GetASN(r.RemoteAddr, m.BlockASNs.geoIP)
				m.blockRequest(w, r, state, http.StatusForbidden, "asn_block", "asn_block_rule",
					zap.String("message", "Request blocked by ASN"),
					zap.String("asn", asnInfo),
				)
				m.incrementGeoIPRequestsMetric(true) // Increment with true for blocked
				if m.CustomResponses != nil {
					m.writeCustomResponse(w, state.StatusCode)
				}
				return
			}
			m.logger.Debug("ASN blocking phase completed - not blocked")
		}

		// Blacklisting
		if m.CountryBlacklist.Enabled {
			m.logger.Debug("Starting country blacklisting phase")
			blocked, err := m.isCountryInList(r.RemoteAddr, m.CountryBlacklist.CountryList, m.CountryBlacklist.geoIP)
			if err != nil {
				m.logRequest(zapcore.ErrorLevel, "Failed to check country blacklisting",
					r,
					zap.Error(err),
				)
				m.blockRequest(w, r, state, http.StatusForbidden, "internal_error", "country_block_rule",
					zap.String("message", "Request blocked due to internal error"),
				)
				m.logger.Debug("Country blacklisting phase completed - blocked due to error")
				m.incrementGeoIPRequestsMetric(false) // Increment with false for error
				return
			} else if blocked {
				m.blockRequest(w, r, state, http.StatusForbidden, "country_block", "country_block_rule",
					zap.String("message", "Request blocked by country"))
				m.incrementGeoIPRequestsMetric(true) // Increment with true for blocked
				if m.CustomResponses != nil {
					m.writeCustomResponse(w, state.StatusCode)
				}
				return
			}
			m.logger.Debug("Country blacklisting phase completed - not blocked")
			m.incrementGeoIPRequestsMetric(false) // Increment with false for no block
		}
	}

	rules, ok := m.Rules[phase]
	if !ok {
		m.logger.Debug("No rules found for phase", zap.Int("phase", phase))
		// Don't block on empty rules. There may be no rules specified
		// return
	}

	m.logger.Debug("Starting rule evaluation for phase", zap.Int("phase", phase), zap.Int("rule_count", len(rules)))

	for _, rule := range rules {
		m.logger.Debug("Processing rule", zap.String("rule_id", rule.ID), zap.Int("target_count", len(rule.Targets)))

		// Use the custom type as the key
		ctx := context.WithValue(r.Context(), ContextKeyRule("rule_id"), rule.ID)
		r = r.WithContext(ctx)

		for _, target := range rule.Targets {
			m.logger.Debug("Extracting value for target", zap.String("target", target), zap.String("rule_id", rule.ID))
			var value string
			var err error

			if phase == 3 || phase == 4 {
				if recorder, ok := w.(*responseRecorder); ok {
					value, err = m.extractValue(target, r, recorder)
				} else {
					m.logger.Error("response recorder is not available in phase 3 or 4 when required")
					value, err = m.extractValue(target, r, nil)
				}
			} else {
				value, err = m.extractValue(target, r, nil)
			}

			if err != nil {
				m.logger.Debug("Failed to extract value for target, skipping rule for this target",
					zap.String("target", target),
					zap.String("rule_id", rule.ID),
					zap.Error(err),
				)
				continue
			}

			redactedValue := m.requestValueExtractor.RedactValueIfSensitive(target, value)

			m.logger.Debug("Extracted value",
				zap.String("rule_id", rule.ID),
				zap.String("target", target),
				zap.String("value", redactedValue),
			)

			if rule.regex.MatchString(value) {
				m.logger.Debug("Rule matched",
					zap.String("rule_id", rule.ID),
					zap.String("target", target),
					zap.String("value", redactedValue),
				)

				// FIXED: Correctly interpret processRuleMatch return value
				var shouldContinue bool
				if phase == 3 || phase == 4 {
					if recorder, ok := w.(*responseRecorder); ok {
						shouldContinue = m.processRuleMatch(recorder, r, &rule, target, value, state)
					} else {
						shouldContinue = m.processRuleMatch(w, r, &rule, target, value, state)
					}
				} else {
					shouldContinue = m.processRuleMatch(w, r, &rule, target, value, state)
				}

				// If processRuleMatch returned false or state is now blocked, stop processing
				if !shouldContinue || state.Blocked || state.ResponseWritten {
					m.logger.Debug("Rule evaluation stopping due to blocking or rule directive",
						zap.Int("phase", phase),
						zap.String("rule_id", rule.ID),
						zap.Bool("continue", shouldContinue),
						zap.Bool("blocked", state.Blocked),
					)

					if m.CustomResponses != nil {
						m.writeCustomResponse(w, state.StatusCode)
					}
					return
				}
			} else {
				m.logger.Debug("Rule did not match",
					zap.String("rule_id", rule.ID),
					zap.String("target", target),
					zap.String("value", redactedValue),
				)
			}
		}
	}

	m.logger.Debug("Rule evaluation completed for phase", zap.Int("phase", phase))

	if phase == 3 {
		m.logger.Debug("Starting response headers phase")
		if _, ok := w.(*responseRecorder); ok {
			m.logger.Debug("Response headers phase completed")
		}
	}

	if phase == 4 {
		m.logger.Debug("Starting response body phase")
		if _, ok := w.(*responseRecorder); ok {
			m.logger.Debug("Response body phase completed")
		}
	}

	m.logger.Debug("Completed phase evaluation",
		zap.Int("phase", phase),
		zap.Int("total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	m.allowRequest(state)
}

// incrementRateLimiterBlockedRequestsMetric increments the blocked requests metric for the rate limiter.
func (m *Middleware) incrementRateLimiterBlockedRequestsMetric() {
	m.muRateLimiterMetrics.Lock()
	defer m.muRateLimiterMetrics.Unlock()
	m.rateLimiterBlockedRequests++
}

// incrementGeoIPRequestsMetric increments the GeoIP requests metric.
func (m *Middleware) incrementGeoIPRequestsMetric(blocked bool) {
	m.muMetrics.Lock()
	defer m.muMetrics.Unlock()
	if blocked {
		m.geoIPBlocked++
	}
}
