package caddywaf

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// latencyBounds are the upper edges (seconds) of the request-duration histogram
// exposed to Prometheus. numLatencyBuckets must equal len(latencyBounds); it is
// a constant so the per-bucket counters can live in a fixed array on Middleware.
var latencyBounds = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

const numLatencyBuckets = 14

// observeLatency records one request duration into the histogram. It runs on the
// hot path for every request, so it uses atomics and never takes a lock.
func (m *Middleware) observeLatency(seconds float64) {
	for i, b := range latencyBounds {
		if seconds <= b {
			m.latencyBuckets[i].Add(1)
			break
		}
	}
	m.latencyCount.Add(1)
	for {
		old := m.latencySumBits.Load()
		nw := math.Float64bits(math.Float64frombits(old) + seconds)
		if m.latencySumBits.CompareAndSwap(old, nw) {
			return
		}
	}
}

// isPrometheusRequest reports whether r targets the Prometheus endpoint.
func (m *Middleware) isPrometheusRequest(r *http.Request) bool {
	return m.PrometheusEndpoint != "" && r.URL.Path == m.PrometheusEndpoint
}

// handlePrometheusRequest serves the WAF counters in the Prometheus text
// exposition format, so Prometheus can scrape natively without the JSON exporter.
func (m *Middleware) handlePrometheusRequest(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, err := w.Write([]byte(m.renderPrometheus()))
	return err
}

func (m *Middleware) renderPrometheus() string {
	var b strings.Builder

	// Base counters are atomic; read each independently (metrics don't need a
	// cross-counter-consistent snapshot).
	total, blocked, allowed, geo := m.totalRequests.Load(), m.blockedRequests.Load(), m.allowedRequests.Load(), m.geoIPBlocked.Load()
	m.muIPBlacklistMetrics.Lock()
	ipHits := m.IPBlacklistBlockCount
	m.muIPBlacklistMetrics.Unlock()
	m.muDNSBlacklistMetrics.Lock()
	dnsHits := m.DNSBlacklistBlockCount
	m.muDNSBlacklistMetrics.Unlock()
	var rlReq, rlBlocked int64
	if m.rateLimiter != nil {
		rlReq, rlBlocked = m.rateLimiter.GetTotalRequests(), m.rateLimiter.GetBlockedRequests()
	}

	counter := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP caddywaf_%s %s\n# TYPE caddywaf_%s counter\ncaddywaf_%s %d\n", name, help, name, name, v)
	}
	counter("total_requests", "Total requests processed (process-local).", total)
	counter("blocked_requests", "Total requests blocked (process-local).", blocked)
	counter("allowed_requests", "Total requests allowed (process-local).", allowed)
	counter("geoip_blocked", "Requests blocked by country/ASN (process-local).", int64(geo))
	counter("ip_blacklist_hits", "IP blacklist hits (process-local).", ipHits)
	counter("dns_blacklist_hits", "DNS blacklist hits (process-local).", dnsHits)
	counter("rate_limiter_requests", "Requests counted by the rate limiter (process-local).", rlReq)
	counter("rate_limiter_blocked_requests", "Requests blocked by the rate limiter (process-local).", rlBlocked)

	// Labelled series.
	writeLabelled(&b, "rule_hits", "Per-rule hit count.", "rule_id", i64map(m.getRuleHitStats()))
	m.muMetrics.RLock()
	phases := map[string]int64{}
	for p, h := range m.ruleHitsByPhase {
		phases[strconv.Itoa(p)] = h
	}
	m.muMetrics.RUnlock()
	writeLabelled(&b, "rule_hits_by_phase", "Per-phase hit count.", "phase", phases)

	m.muObs.Lock()
	reasons := map[string]int64{}
	for k, v := range m.blockedByReason {
		reasons[k] = v
	}
	countries := map[string]int64{}
	for k, v := range m.geoIPStats {
		countries[k] = v
	}
	m.muObs.Unlock()
	writeLabelled(&b, "blocked_by_reason", "Blocks by reason category.", "reason", reasons)
	writeLabelled(&b, "blocks_by_country", "Blocks by ISO country.", "country", countries)

	// Request-duration histogram.
	fmt.Fprintf(&b, "# HELP caddywaf_request_duration_seconds WAF request handling duration.\n# TYPE caddywaf_request_duration_seconds histogram\n")
	var cumulative uint64
	for i, bound := range latencyBounds {
		cumulative += m.latencyBuckets[i].Load()
		fmt.Fprintf(&b, "caddywaf_request_duration_seconds_bucket{le=\"%s\"} %d\n", strconv.FormatFloat(bound, 'g', -1, 64), cumulative)
	}
	count := m.latencyCount.Load()
	sum := math.Float64frombits(m.latencySumBits.Load())
	fmt.Fprintf(&b, "caddywaf_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", count)
	fmt.Fprintf(&b, "caddywaf_request_duration_seconds_sum %s\n", strconv.FormatFloat(sum, 'g', -1, 64))
	fmt.Fprintf(&b, "caddywaf_request_duration_seconds_count %d\n", count)

	// Build info.
	fmt.Fprintf(&b, "# HELP caddywaf_build_info Build information.\n# TYPE caddywaf_build_info gauge\ncaddywaf_build_info{version=\"%s\"} 1\n", promLabel(wafVersion))

	return b.String()
}

func writeLabelled(b *strings.Builder, name, help, label string, values map[string]int64) {
	fmt.Fprintf(b, "# HELP caddywaf_%s %s\n# TYPE caddywaf_%s counter\n", name, help, name)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "caddywaf_%s{%s=\"%s\"} %d\n", name, label, promLabel(k), values[k])
	}
}

func i64map(m map[string]int) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = int64(v)
	}
	return out
}

// promLabel escapes a Prometheus label value (backslash, double-quote, newline).
func promLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, "\n", `\n`)
}
