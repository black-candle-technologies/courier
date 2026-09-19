package update

import "testing"

func TestNewerThan(t *testing.T) {
	cases := []struct {
		current, tag string
		want         bool
	}{
		{"0.5.0", "v0.5.1", true},
		{"v0.5.0", "v0.5.1", true},
		{"0.5.0", "0.5.0", false},
		{"v0.5.1", "v0.5.0", false},
		{"0.5.0", "v0.6.0", true},
		{"0.5.0", "v1.0.0", true},
		{"0.5.10", "v0.5.9", false}, // numeric, not lexicographic
		{"0.5.9", "v0.5.10", true},
		{"1.0", "v1.0.1", true},
		{"bogus", "v0.5.1", false},
		{"0.5.0", "bogus", false},
	}
	for _, c := range cases {
		if got := NewerThan(c.current, c.tag); got != c.want {
			t.Errorf("NewerThan(%q, %q) = %v, want %v", c.current, c.tag, got, c.want)
		}
	}
}
