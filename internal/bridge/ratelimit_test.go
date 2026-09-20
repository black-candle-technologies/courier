package bridge

import (
	"testing"
	"time"
)

func TestRateLimiterBurst(t *testing.T) {
	r := NewRateLimiter()
	// Burst of 5 allowed.
	for i := 0; i < RateBurst; i++ {
		if ok, _ := r.Allow("k"); !ok {
			t.Fatalf("burst send %d rejected", i)
		}
	}
	// Sixth is rejected with a Retry-After.
	ok, wait := r.Allow("k")
	if ok {
		t.Fatal("6th send allowed within burst window")
	}
	if wait <= 0 {
		t.Fatal("no Retry-After on 429")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	now := time.Now()
	r := &RateLimiter{buckets: map[string]*tokenBuckets{}, now: func() time.Time { return now }}
	for i := 0; i < RateBurst; i++ {
		if ok, _ := r.Allow("k"); !ok {
			t.Fatal("burst rejected")
		}
	}
	if ok, _ := r.Allow("k"); ok {
		t.Fatal("over-burst allowed")
	}
	// 10/min refill: 6s per token. Advance 7s → one token back.
	now = now.Add(7 * time.Second)
	if ok, _ := r.Allow("k"); !ok {
		t.Fatal("refilled token rejected")
	}
	if ok, _ := r.Allow("k"); ok {
		t.Fatal("second send allowed without refill time")
	}
}

func TestRateLimiterPerTokenIsolation(t *testing.T) {
	r := NewRateLimiter()
	for i := 0; i < RateBurst; i++ {
		if ok, _ := r.Allow("a"); !ok {
			t.Fatal("token a burst rejected")
		}
	}
	if ok, _ := r.Allow("a"); ok {
		t.Fatal("token a over-burst allowed")
	}
	// Token b is unaffected.
	for i := 0; i < RateBurst; i++ {
		if ok, _ := r.Allow("b"); !ok {
			t.Fatalf("token b burst send %d rejected", i)
		}
	}
}

func TestRateLimiterHourBucket(t *testing.T) {
	now := time.Now()
	r := &RateLimiter{buckets: map[string]*tokenBuckets{}, now: func() time.Time { return now }}
	// Send at the max minute rate (1 per 6s): the minute bucket stays
	// satisfied (refill = 1 token per 6s) while the hour bucket drains
	// net ~0.83 per send. After ~119 sends the hour bucket trips.
	sent := 0
	for sent < 130 {
		ok, _ := r.Allow("k")
		if !ok {
			break
		}
		sent++
		now = now.Add(6 * time.Second)
	}
	if sent >= 130 {
		t.Fatal("hour bucket never tripped")
	}
	if sent < 100 {
		t.Fatalf("hour bucket tripped early after %d sends", sent)
	}
	// The minute bucket has refilled (6s elapsed), so the rejection is
	// the hour bucket. Advancing an hour restores quota.
	now = now.Add(time.Hour)
	if ok, _ := r.Allow("k"); !ok {
		t.Fatal("send rejected after hourly refill")
	}
}

func TestRateLimiterRemaining(t *testing.T) {
	r := NewRateLimiter()
	pm, ph := r.Remaining("new")
	if pm != RateBurst || ph != RateHourCap {
		t.Fatalf("fresh quota = %d/%d, want %d/%d", pm, ph, RateBurst, RateHourCap)
	}
	r.Allow("new")
	pm, _ = r.Remaining("new")
	if pm != RateBurst-1 {
		t.Fatalf("quota after one send = %d, want %d", pm, RateBurst-1)
	}
}
