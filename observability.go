package caddywaf

import (
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Observability limits for the built-in dashboard (#143 M1). All bounded so the
// metrics endpoint stays cheap and memory cannot grow with attacker traffic.
const (
	metricsSchemaVersion = 2
	recentBlocksCap      = 256  // recent-blocks ring size
	topIPsCap            = 1000 // distinct offending IPs tracked
	topIPsEmit           = 50   // offenders returned, by block count
	topRulesEmit         = 20   // rules returned, by hit count
	recentPathMax        = 256  // path length stored per recent entry
)

// recordBlock captures one blocked decision for the dashboard. It is called from
// blockRequest, the single choke point every block passes through, so each
// blocked request is recorded exactly once.
func (m *Middleware) recordBlock(r *http.Request, state *WAFState, statusCode int, reason, ruleID string) {
	cat := reasonCategory(reason)
	ip := m.clientIP(r)
	country := m.lookupCountry(ip)

	rec := blockRecord{
		TS:      time.Now().UnixMilli(),
		ID:      getLogID(r.Context()),
		IP:      ip,
		Method:  r.Method,
		Path:    truncate(r.URL.RequestURI(), recentPathMax),
		Reason:  cat,
		Status:  statusCode,
		Score:   state.TotalScore,
		Country: country,
	}
	if cat == "rule" {
		rec.RuleID = ruleID
	}

	m.muObs.Lock()
	m.recentBlocks = append(m.recentBlocks, rec)
	if len(m.recentBlocks) > recentBlocksCap {
		m.recentBlocks = m.recentBlocks[len(m.recentBlocks)-recentBlocksCap:]
	}
	if m.blockedByReason != nil {
		m.blockedByReason[cat]++
	}
	// Count the offender, but stop admitting new IPs once the map is full so a
	// flood of distinct sources cannot grow it without bound.
	if m.topIPsBlocked != nil {
		if _, seen := m.topIPsBlocked[ip]; seen || len(m.topIPsBlocked) < topIPsCap {
			m.topIPsBlocked[ip]++
		}
	}
	if country != "" && m.geoIPStats != nil {
		m.geoIPStats[country]++
	}
	m.muObs.Unlock()
}

// reasonCategory maps the free-form block reason blockRequest receives onto a
// small stable set for blocked_by_reason and the recent tail.
func reasonCategory(reason string) string {
	switch {
	case strings.Contains(reason, "ip_blacklist"):
		return "ip_blacklist"
	case strings.Contains(reason, "dns_blacklist"):
		return "dns_blacklist"
	case strings.Contains(reason, "rate_limit"):
		return "rate_limit"
	case strings.Contains(reason, "country"):
		return "country"
	case strings.Contains(reason, "asn"):
		return "asn"
	case strings.Contains(reason, "internal_error"):
		return "error"
	case strings.Contains(reason, "Anomaly threshold"), strings.Contains(reason, "Rule action"):
		return "rule"
	default:
		return "other"
	}
}

// lookupCountry best-effort resolves the ISO country of ip using whichever GeoIP
// reader is configured. Returns "" when no country database is available.
func (m *Middleware) lookupCountry(ip string) string {
	if m.geoIPHandler == nil {
		return ""
	}
	reader := m.CountryBlacklist.geoIP
	if reader == nil {
		reader = m.CountryWhitelist.geoIP
	}
	if reader == nil {
		reader = m.BlockASNs.geoIP
	}
	if reader == nil {
		return ""
	}
	return m.geoIPHandler.GetCountryCode(ip, reader)
}

// observabilitySnapshot builds the dashboard fields added to the /waf_metrics
// payload. Shared structures are copied under muObs and everything is sorted and
// serialised outside the lock.
func (m *Middleware) observabilitySnapshot() map[string]interface{} {
	type ruleHit struct {
		ID   string `json:"id"`
		Hits int64  `json:"hits"`
	}
	rules := []ruleHit{}
	m.ruleHits.Range(func(k, v interface{}) bool {
		id, _ := k.(RuleID)
		if c, ok := v.(*atomic.Int64); ok && c != nil {
			rules = append(rules, ruleHit{ID: string(id), Hits: c.Load()})
		}
		return true
	})
	sort.Slice(rules, func(i, j int) bool { return rules[i].Hits > rules[j].Hits })
	if len(rules) > topRulesEmit {
		rules = rules[:topRulesEmit]
	}

	type ipCount struct {
		IP      string `json:"ip"`
		Blocked int64  `json:"blocked"`
	}
	type countryCount struct {
		Country string `json:"country"`
		Blocked int64  `json:"blocked"`
	}

	m.muObs.Lock()
	recent := make([]blockRecord, len(m.recentBlocks)) // newest first
	for i, rec := range m.recentBlocks {
		recent[len(m.recentBlocks)-1-i] = rec
	}
	reasons := make(map[string]int64, len(m.blockedByReason))
	for k, v := range m.blockedByReason {
		reasons[k] = v
	}
	ips := make([]ipCount, 0, len(m.topIPsBlocked))
	for ip, c := range m.topIPsBlocked {
		ips = append(ips, ipCount{ip, c})
	}
	distinctIPs := len(m.topIPsBlocked)
	countries := make([]countryCount, 0, len(m.geoIPStats))
	for cc, c := range m.geoIPStats {
		countries = append(countries, countryCount{cc, c})
	}
	m.muObs.Unlock()

	sort.Slice(ips, func(i, j int) bool { return ips[i].Blocked > ips[j].Blocked })
	if len(ips) > topIPsEmit {
		ips = ips[:topIPsEmit]
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Blocked > countries[j].Blocked })

	return map[string]interface{}{
		"schema_version":    metricsSchemaVersion,
		"server_time_ms":    time.Now().UnixMilli(),
		"uptime_seconds":    int64(time.Since(m.provisionTime).Seconds()),
		"top_rules":         rules,
		"top_ips":           map[string]interface{}{"cap": topIPsEmit, "distinct_seen": distinctIPs, "items": ips},
		"by_country":        countries,
		"blocked_by_reason": reasons,
		"recent":            map[string]interface{}{"cap": recentBlocksCap, "items": recent},
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
