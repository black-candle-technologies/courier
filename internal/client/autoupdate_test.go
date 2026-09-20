package client

import (
	"encoding/json"
	"testing"
)

// TestAutoUpdateEnabled covers the v0.6.12 tri-state default: an unset
// auto_update means auto-install (the default), while an explicit
// true/false is honored.
func TestAutoUpdateEnabled(t *testing.T) {
	tru, fals := true, false
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"unset defaults to enabled", Config{}, true},
		{"explicit true stays enabled", Config{AutoUpdate: &tru}, true},
		{"explicit false opts out", Config{AutoUpdate: &fals}, false},
	}
	for _, tc := range cases {
		if got := tc.cfg.AutoUpdateEnabled(); got != tc.want {
			t.Errorf("%s: AutoUpdateEnabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAutoUpdateJSONRoundTrip ensures old configs keep working: a config
// written before v0.6.12 has no auto_update key (nil -> enabled), and
// explicit values survive a save/load round trip.
func TestAutoUpdateJSONRoundTrip(t *testing.T) {
	var unset Config
	if err := json.Unmarshal([]byte(`{}`), &unset); err != nil {
		t.Fatal(err)
	}
	if !unset.AutoUpdateEnabled() {
		t.Error("config without auto_update key should default to enabled")
	}

	var off Config
	if err := json.Unmarshal([]byte(`{"auto_update":false}`), &off); err != nil {
		t.Fatal(err)
	}
	if off.AutoUpdateEnabled() {
		t.Error("auto_update:false should opt out of auto-install")
	}

	var on Config
	if err := json.Unmarshal([]byte(`{"auto_update":true}`), &on); err != nil {
		t.Fatal(err)
	}
	if !on.AutoUpdateEnabled() {
		t.Error("auto_update:true should stay enabled")
	}
}
