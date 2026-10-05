package caddywaf

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRateLimiter_DefaultMaxEntries verifies that an unset (or non-positive)
// max_entries falls back to the package default rather than 0, which would
// otherwise refuse to track any key.
func TestRateLimiter_DefaultMaxEntries(t *testing.T) {
	for _, configured := range []int{0, -1, -1000} {
		rl, err := NewRateLimiter(RateLimit{
			Requests:        100,
			Window:          time.Minute,
			CleanupInterval: time.Minute,
			MatchAllPaths:   true,
			MaxEntries:      configured,
		})
		assert.NoError(t, err)
		assert.Equal(t, defaultRateLimiterMaxEntries, rl.maxEntries,
			"max_entries=%d should fall back to the default", configured)
	}

	rl, err := NewRateLimiter(RateLimit{
		Requests:        100,
		Window:          time.Minute,
		CleanupInterval: time.Minute,
		MatchAllPaths:   true,
		MaxEntries:      250,
	})
	assert.NoError(t, err)
	assert.Equal(t, 250, rl.maxEntries, "an explicit positive max_entries should be honoured")
}

// TestRateLimiter_MaxEntriesCap is the regression test for the SCAL-01 memory
// bound: a flood of distinct source IPs must never grow the key table past
// max_entries. Overflow keys are simply not tracked (so they are not limited by
// this instance), but memory stays bounded.
func TestRateLimiter_MaxEntriesCap(t *testing.T) {
	const cap = 100
	rl, err := NewRateLimiter(RateLimit{
		Requests:        1_000_000, // high, so counting never blocks here
		Window:          time.Hour, // long, so nothing expires mid-test
		CleanupInterval: time.Hour,
		MatchAllPaths:   true, // key == ip
		MaxEntries:      cap,
	})
	assert.NoError(t, err)

	// Ten times as many distinct IPs as the cap allows.
	for i := 0; i < cap*10; i++ {
		rl.isRateLimited(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), "/")
	}

	assert.Equal(t, cap, rl.entryCount, "entryCount must stop growing at max_entries")
	assert.LessOrEqual(t, rl.entryCount, rl.maxEntries, "entryCount must never exceed max_entries")

	// An already-tracked key keeps being counted even once the table is full.
	tracked := "10.0.0.0"
	for i := 0; i < 5; i++ {
		rl.isRateLimited(tracked, "/")
	}
	assert.Equal(t, cap, rl.entryCount, "updating an existing key must not add an entry")
}

// TestRateLimiter_CleanupFreesCapacity verifies that once expired keys are
// swept, the freed capacity is available to new keys again — i.e. the cap is a
// steady-state bound, not a permanent ceiling on lifetime distinct IPs.
func TestRateLimiter_CleanupFreesCapacity(t *testing.T) {
	const cap = 50
	rl, err := NewRateLimiter(RateLimit{
		Requests:        1_000_000,
		Window:          20 * time.Millisecond,
		CleanupInterval: time.Hour, // we drive cleanup manually
		MatchAllPaths:   true,
		MaxEntries:      cap,
	})
	assert.NoError(t, err)

	for i := 0; i < cap*4; i++ {
		rl.isRateLimited(fmt.Sprintf("172.16.%d.%d", i/256, i%256), "/")
	}
	assert.Equal(t, cap, rl.entryCount, "table should be full")

	// Let every window expire, then sweep.
	time.Sleep(40 * time.Millisecond)
	rl.cleanupExpiredEntries()
	assert.Equal(t, 0, rl.entryCount, "cleanup should free all expired keys")

	// New keys are tracked again after capacity was freed.
	rl.isRateLimited("192.0.2.1", "/")
	assert.Equal(t, 1, rl.entryCount, "freed capacity should accept new keys")
}

// TestRateLimiter_ConcurrentAccessBounded hammers isRateLimited from many
// goroutines with a mix of shared and distinct keys. Run under -race in CI, it
// guards both the lock discipline (no data race on the map / entryCount) and
// the invariant that concurrent inserts never breach the cap.
func TestRateLimiter_ConcurrentAccessBounded(t *testing.T) {
	const (
		cap        = 500
		goroutines = 64
		perG       = 2000
	)
	rl, err := NewRateLimiter(RateLimit{
		Requests:        1_000_000,
		Window:          time.Hour,
		CleanupInterval: time.Hour,
		MatchAllPaths:   true,
		MaxEntries:      cap,
	})
	assert.NoError(t, err)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				// Far more distinct keys than the cap, interleaved across goroutines.
				ip := fmt.Sprintf("10.%d.%d.%d", g, (i/256)%256, i%256)
				rl.isRateLimited(ip, "/")
			}
		}(g)
	}
	wg.Wait()

	assert.LessOrEqual(t, rl.entryCount, rl.maxEntries,
		"concurrent inserts must never push entryCount past max_entries")
	assert.Greater(t, rl.entryCount, 0, "some keys should have been tracked")
	// The metric counts every call that reached the limiter body.
	assert.Equal(t, int64(goroutines*perG), rl.GetTotalRequests(),
		"every call should be counted exactly once")
}
