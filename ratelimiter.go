package caddywaf

import (
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"
)

// requestCounter struct
type requestCounter struct {
	count  int
	window time.Time
}

// RateLimit struct
type RateLimit struct {
	Requests        int              `json:"requests"`
	Window          time.Duration    `json:"window"`
	CleanupInterval time.Duration    `json:"cleanup_interval"`
	Paths           []string         `json:"paths,omitempty"` // Optional paths to apply rate limit
	PathRegexes     []*regexp.Regexp `json:"-"`               // Compiled regexes for the given paths
	MatchAllPaths   bool             `json:"match_all_paths,omitempty"`
}

// RateLimiter struct
type RateLimiter struct {
	sync.RWMutex
	requests        map[string]map[string]*requestCounter // Nested map for path-based rate limiting
	config          RateLimit
	stopCleanup     chan struct{} // Channel to signal cleanup goroutine to stop
	totalRequests   int64         // Total requests received by this rate limiter
	blockedRequests int64         // Total requests blocked by this rate limiter
	muMetrics       sync.RWMutex  // Mutex to protect metrics access
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(config RateLimit) (*RateLimiter, error) {
	// Compile path regexes if paths are provided
	if len(config.Paths) > 0 {
		config.PathRegexes = make([]*regexp.Regexp, len(config.Paths))
		for i, path := range config.Paths {
			var err error
			config.PathRegexes[i], err = regexp.Compile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex for path %s: %v", path, err)
			}
		}
	}

	return &RateLimiter{
		requests:    make(map[string]map[string]*requestCounter),
		config:      config,
		stopCleanup: make(chan struct{}), // Initialize the stopCleanup channel
	}, nil
}

// isRateLimited checks if a given IP is rate limited for a specific path.
func (rl *RateLimiter) isRateLimited(ip, path string) bool {
	// SOTA Pattern: Reduce Lock Contention (move expensive regex out of critical section)
	matched := false
	var key string

	// 1. Determine if this path needs limiting (Read-only config access, safe without lock if config is immutable)
	if rl.config.MatchAllPaths {
		matched = true
		key = ip
	} else {
		if len(rl.config.PathRegexes) > 0 {
			for _, regex := range rl.config.PathRegexes {
				if regex.MatchString(path) {
					matched = true
					break
				}
			}
			if matched {
				key = ip + path
			}
		}
	}

	if !matched && !rl.config.MatchAllPaths {
		// Optimization: If no path matched, we don't need to track this request
		rl.incrementTotalRequestsMetric()
		return false
	}

	now := time.Now()

	rl.Lock() // Critical Section Start
	defer rl.Unlock()

	rl.incrementTotalRequestsMetric() // Metric under lock to ensure consistency (or use atomic outside)

	// Initialize the nested map if it doesn't exist
	if _, exists := rl.requests[ip]; !exists {
		rl.requests[ip] = make(map[string]*requestCounter)
	}

	// Get or create the counter for the specific key (path + ip)
	counter, exists := rl.requests[ip][key]
	if exists {
		if now.Sub(counter.window) > rl.config.Window {
			// Window expired, reset the counter
			rl.requests[ip][key] = &requestCounter{count: 1, window: now}
			return false
		}

		// Window not expired, increment the counter
		counter.count++
		if counter.count > rl.config.Requests {
			rl.incrementBlockedRequestsMetric() // Increment if the request is going to be blocked.
			return true
		}
		return false
	}

	// IP and path combination doesn't exist, add it
	rl.requests[ip][key] = &requestCounter{count: 1, window: now}
	return false
}

// cleanupExpiredEntries removes expired entries from the rate limiter.
func (rl *RateLimiter) cleanupExpiredEntries() {
	now := time.Now()

	rl.Lock()
	defer rl.Unlock()

	for ip, pathCounters := range rl.requests {
		for path, counter := range pathCounters {
			if now.Sub(counter.window) > rl.config.Window {
				delete(pathCounters, path)
			}
		}
		if len(pathCounters) == 0 {
			delete(rl.requests, ip)
		}
	}
}

// startCleanup starts the goroutine to periodically clean up expired entries.
func (rl *RateLimiter) startCleanup() {
	go func() {
		// log.Println("[INFO] Starting rate limiter cleanup goroutine")
		ticker := time.NewTicker(rl.config.CleanupInterval)
		defer func() {
			ticker.Stop()
			// log.Println("[INFO] Rate limiter cleanup goroutine stopped")
		}()

		for {
			select {
			case <-ticker.C:
				rl.cleanupExpiredEntries()
			case <-rl.stopCleanup:
				return
			}
		}
	}()
}

// signalStopCleanup signals the cleanup goroutine to stop.
func (rl *RateLimiter) signalStopCleanup() {
	rl.Lock()
	defer rl.Unlock()

	select {
	case <-rl.stopCleanup:
		// Channel already closed, do nothing
	default:
		log.Println("[INFO] Signaling rate limiter cleanup goroutine to stop")
		close(rl.stopCleanup)
	}
}

// GetTotalRequests returns the total number of requests received by this rate limiter.
func (rl *RateLimiter) GetTotalRequests() int64 {
	rl.muMetrics.RLock()
	defer rl.muMetrics.RUnlock()
	return rl.totalRequests
}

// GetBlockedRequests returns the total number of requests blocked by this rate limiter.
func (rl *RateLimiter) GetBlockedRequests() int64 {
	rl.muMetrics.RLock()
	defer rl.muMetrics.RUnlock()
	return rl.blockedRequests
}

// incrementTotalRequestsMetric increments the total requests counter
func (rl *RateLimiter) incrementTotalRequestsMetric() {
	rl.muMetrics.Lock()
	defer rl.muMetrics.Unlock()
	rl.totalRequests++
}

// incrementBlockedRequestsMetric increments the blocked requests counter
func (rl *RateLimiter) incrementBlockedRequestsMetric() {
	rl.muMetrics.Lock()
	defer rl.muMetrics.Unlock()
	rl.blockedRequests++
}
