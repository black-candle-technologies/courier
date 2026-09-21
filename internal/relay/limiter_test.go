package relay

import (
	"testing"
	"time"
)

// fakeClock lets tests move time deterministically.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func TestLimiterEnforcesBurst(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(3, 1000) // burst 3, refill effectively instant for recovery test below
	l.now = fc.now

	for i := 0; i < 3; i++ {
		if !l.Allow("alice") {
			t.Fatalf("burst action %d denied, want allowed", i+1)
		}
	}
	if l.Allow("alice") {
		t.Fatal("4th action within burst allowed, want denied")
	}
}

func TestLimiterRecoversOverTime(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(2, 1) // burst 2, 1 token/sec
	l.now = fc.now

	if !l.Allow("alice") {
		t.Fatal("initial burst denied")
	}
	if !l.Allow("alice") {
		t.Fatal("initial burst denied")
	}
	if l.Allow("alice") {
		t.Fatal("over-burst action allowed")
	}
	fc.t = fc.t.Add(1500 * time.Millisecond) // 1.5 tokens refill
	if !l.Allow("alice") {
		t.Fatal("action after refill denied, want allowed (recovered)")
	}
	if l.Allow("alice") {
		t.Fatal("second action after partial refill allowed, want denied")
	}
}

func TestLimiterIsPerKey(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(1, 0) // burst 1, no refill
	l.now = fc.now

	if !l.Allow("alice") {
		t.Fatal("alice denied")
	}
	if l.Allow("alice") {
		t.Fatal("alice second action allowed")
	}
	if !l.Allow("bob") {
		t.Fatal("bob denied: limits must be per-sender, not global")
	}
}

func TestLimiterNewKeysStartFull(t *testing.T) {
	l := NewLimiter(5, 1)
	// A sender with no history gets a full bucket, never a penalty.
	for i := 0; i < 5; i++ {
		if !l.Allow("brand-new-sender") {
			t.Fatalf("new sender action %d denied", i+1)
		}
	}
}

func TestLimiterEvictsStalest(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(1, 1000)
	l.now = fc.now
	l.maxBuckets = 3

	l.Allow("a") // oldest
	fc.t = fc.t.Add(time.Second)
	l.Allow("b")
	fc.t = fc.t.Add(time.Second)
	l.Allow("c")
	fc.t = fc.t.Add(time.Second)
	l.Allow("d") // evicts "a"

	if len(l.buckets) != 3 {
		t.Fatalf("want 3 buckets after eviction, got %d", len(l.buckets))
	}
	if _, ok := l.buckets["a"]; ok {
		t.Fatal("stalest bucket was not evicted")
	}
}
