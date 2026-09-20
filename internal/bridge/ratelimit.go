// Per-token rate limiting for the bridge gateway (issue #61).
//
// Each token gets two token buckets: a per-minute bucket (burst 5,
// refill 10/min) and a per-hour bucket (capacity 100, refill 100/hr).
// A send must pass both. State is in-memory: a gateway restart resets
// quotas (fail-open on restart is acceptable for a localhost service;
// the relay's own per-sender limits remain as defense in depth).
package bridge

import (
	"sync"
	"time"
)

// Rate limits, per the user-confirmed plan.
const (
	RatePerMinute = 10
	RatePerHour   = 100
	RateBurst     = 5
	RateHourCap   = 100
)

// bucket is a single token bucket.
type bucket struct {
	capacity float64
	refill   float64 // tokens per second
	tokens   float64
	last     time.Time
}

// take tries to consume one token. It reports whether one was
// available and, if not, how long until one refills.
func (b *bucket) take(now time.Time) (bool, time.Duration) {
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.refill
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	deficit := 1 - b.tokens
	return false, time.Duration(deficit / b.refill * float64(time.Second))
}

// tokenBuckets is the pair of buckets for one token.
type tokenBuckets struct {
	minute bucket
	hour   bucket
}

// RateLimiter enforces per-token rate limits.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBuckets
	now     func() time.Time // overridable in tests
}

// NewRateLimiter builds a limiter with the plan's confirmed limits.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: map[string]*tokenBuckets{}, now: time.Now}
}

// Allow consumes one send of quota for key (the token id). It returns
// false with a Retry-After duration when the limit is exceeded. Both
// buckets are only decremented when both allow the send, so a
// minute-bucket rejection never eats hour quota.
func (r *RateLimiter) Allow(key string) (bool, time.Duration) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	tb, ok := r.buckets[key]
	if !ok {
		tb = &tokenBuckets{
			minute: bucket{capacity: RateBurst, refill: float64(RatePerMinute) / 60, tokens: RateBurst, last: now},
			hour:   bucket{capacity: RateHourCap, refill: float64(RatePerHour) / 3600, tokens: RateHourCap, last: now},
		}
		r.buckets[key] = tb
	}
	okMin, waitMin := tb.minute.take(now)
	if !okMin {
		// The hour bucket is untouched on this path, so there is
		// nothing to refund; the minute bucket's time-based refill
		// accounting in take() is correct as-is.
		return false, ceilSeconds(waitMin)
	}
	okHour, waitHour := tb.hour.take(now)
	if !okHour {
		// Refund the minute token: the send didn't happen.
		tb.minute.tokens++
		if tb.minute.tokens > tb.minute.capacity {
			tb.minute.tokens = tb.minute.capacity
		}
		return false, ceilSeconds(waitHour)
	}
	return true, 0
}

func ceilSeconds(d time.Duration) time.Duration {
	s := d / time.Second
	if d%time.Second != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return s * time.Second
}

// Remaining reports the whole tokens currently available in each
// bucket, for the status endpoint's quota display.
func (r *RateLimiter) Remaining(key string) (perMinute, perHour int) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	tb, ok := r.buckets[key]
	if !ok {
		return RateBurst, RateHourCap
	}
	for _, b := range []*bucket{&tb.minute, &tb.hour} {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * b.refill
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	return int(tb.minute.tokens), int(tb.hour.tokens)
}
