package relay

import (
	"testing"
	"time"
)

// fakeClock is defined in limiter_test.go; tests here reuse it via the
// package scope.

// TestLimiterAllowBytesConsumesBytes checks the byte-priced bucket
// (issue #100): each transfer consumes its declared byte count.
func TestLimiterAllowBytesConsumesBytes(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(100, 1000) // 100-byte bucket; refill fast for recovery
	l.now = fc.now

	if !l.AllowBytes("alice", 60) {
		t.Fatal("first 60-byte transfer denied")
	}
	if l.AllowBytes("alice", 50) {
		t.Fatal("50-byte transfer allowed with only 40 bytes left")
	}
	if !l.AllowBytes("alice", 40) {
		t.Fatal("40-byte transfer denied with exactly 40 bytes left")
	}
	if l.AllowBytes("alice", 1) {
		t.Fatal("transfer allowed on an empty byte bucket")
	}
}

func TestLimiterAllowBytesRefills(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(100, 10) // 10 bytes/sec sustained
	l.now = fc.now

	if !l.AllowBytes("alice", 100) {
		t.Fatal("initial burst denied")
	}
	if l.AllowBytes("alice", 1) {
		t.Fatal("transfer allowed on an empty bucket")
	}
	fc.t = fc.t.Add(5 * time.Second) // 50 bytes refill
	if !l.AllowBytes("alice", 50) {
		t.Fatal("transfer after refill denied, want allowed")
	}
	if l.AllowBytes("alice", 1) {
		t.Fatal("over-refill transfer allowed, want denied")
	}
}

// A single transfer larger than the whole bucket can never succeed.
func TestLimiterAllowBytesOverBurstNever(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(100, 1000)
	l.now = fc.now

	if l.AllowBytes("alice", 101) {
		t.Fatal("101-byte transfer allowed against a 100-byte bucket")
	}
}

func TestLimiterAllowBytesZeroIsFree(t *testing.T) {
	l := NewLimiter(1, 0)
	if !l.AllowBytes("alice", 0) {
		t.Fatal("zero-byte transfer denied")
	}
	if !l.AllowBytes("alice", -5) {
		t.Fatal("negative-byte transfer denied")
	}
}

func TestLimiterAllowBytesIsPerKey(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(10, 0) // burst 10, no refill
	l.now = fc.now

	if !l.AllowBytes("alice", 10) {
		t.Fatal("alice denied")
	}
	if !l.AllowBytes("bob", 10) {
		t.Fatal("bob denied: byte buckets must be per-key, not global")
	}
	if l.AllowBytes("alice", 1) {
		t.Fatal("alice second transfer allowed on an empty bucket")
	}
}

// Allow still consumes exactly one token after the byte-bucket
// refactor — the send/report paths must not change behavior.
func TestLimiterAllowUnchangedAfterRefactor(t *testing.T) {
	fc := &fakeClock{t: time.Now()}
	l := NewLimiter(2, 0)
	l.now = fc.now

	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("burst denied")
	}
	if l.Allow("a") {
		t.Fatal("over-burst action allowed")
	}
}
