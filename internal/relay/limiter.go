package relay

import (
	"sync"
	"time"
)

// tokenBucket is a single token bucket: tokens refill continuously up to
// burst, and each allowed action consumes one token.
type tokenBucket struct {
	tokens   float64
	lastSeen time.Time // last refill; also used for stale-bucket eviction
}

// Limiter is a per-key token-bucket rate limiter. It is used for
// metadata-only abuse control on the relay: senders are limited by how
// often they may act, never by what they say (the relay cannot see
// plaintext). Limits are deliberately generous — legitimate agent
// traffic is bursty — and rejections are explicit 429s, never silent.
type Limiter struct {
	mu         sync.Mutex
	buckets    map[string]*tokenBucket
	burst      float64 // bucket capacity: maximum burst size
	perSec     float64 // sustained refill rate, tokens per second
	maxBuckets int     // cap on tracked keys; stalest bucket is evicted
	now        func() time.Time
}

// NewLimiter returns a Limiter allowing bursts of burst actions and a
// sustained rate of perSec actions per second, tracked independently per
// key.
func NewLimiter(burst, perSec float64) *Limiter {
	return &Limiter{
		buckets:    make(map[string]*tokenBucket),
		burst:      burst,
		perSec:     perSec,
		maxBuckets: 10000,
		now:        time.Now,
	}
}

// Allow reports whether key may act now, consuming one token if so.
// The first time a key is seen its bucket starts full, so new senders
// are never penalized for having no history.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxBuckets {
			l.evictStalest(now)
		}
		b = &tokenBucket{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.perSec
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictStalest drops the least-recently-seen bucket to bound memory.
// Callers hold l.mu.
func (l *Limiter) evictStalest(now time.Time) {
	var (
		stalestKey string
		stalest    time.Time
		first      = true
	)
	for k, b := range l.buckets {
		if first || b.lastSeen.Before(stalest) {
			stalestKey, stalest, first = k, b.lastSeen, false
		}
	}
	delete(l.buckets, stalestKey)
}

// Exhausted reports whether key would be rate-limited right now,
// without consuming a token. Keys never seen before start full, so
// this only fires for senders actively bursting at the limit. Used to
// attach advisory sender-reputation flags to inbox responses.
func (l *Limiter) Exhausted(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return false
	}
	tokens := b.tokens
	if elapsed := now.Sub(b.lastSeen).Seconds(); elapsed > 0 {
		tokens += elapsed * l.perSec
		if tokens > l.burst {
			tokens = l.burst
		}
	}
	return tokens < 1
}
