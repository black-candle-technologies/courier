package bridge

import (
	"strings"
	"testing"
)

func TestWrapBodyIdempotent(t *testing.T) {
	once := WrapBody("hello")
	if !HasBanner(once) {
		t.Fatal("wrapped body lacks banner")
	}
	if !strings.HasSuffix(once, "hello") {
		t.Fatal("original body lost")
	}
	twice := WrapBody(once)
	if twice != once {
		t.Fatal("WrapBody is not idempotent")
	}
	if n := strings.Count(twice, BridgeBannerHeader); n != 1 {
		t.Fatalf("banner appears %d times, want 1", n)
	}
}

func TestStripBanner(t *testing.T) {
	if got := StripBanner(WrapBody("hi")); got != "hi" {
		t.Fatalf("strip = %q, want %q", got, "hi")
	}
	if got := StripBanner("plain"); got != "plain" {
		t.Fatalf("strip of unbannered = %q", got)
	}
}
