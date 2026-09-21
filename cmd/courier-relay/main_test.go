package main

import "testing"

// parseBridgeOrigins must fail loudly on malformed entries (issue
// #98) so a broken --bridge-origins flag stops the relay at startup
// instead of silently disabling the advisory flag.
func TestParseBridgeOrigins(t *testing.T) {
	const addr = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	m, err := parseBridgeOrigins(addr + "=chatgpt-web")
	if err != nil {
		t.Fatalf("valid entry: %v", err)
	}
	if m[addr] != "chatgpt-web" {
		t.Fatalf("valid entry lost: %v", m)
	}
	if _, err := parseBridgeOrigins(""); err != nil {
		t.Fatalf("empty input: %v", err)
	}

	for _, bad := range []string{
		"no-equals-sign",
		"=chatgpt-web",                              // empty address
		addr + "=",                                  // empty label
		"not-an-address=chatgpt-web",                // bad address
		addr + "=ChatGPT Web",                       // unsafe label: uppercase + space
		addr + "=chatgpt web",                       // unsafe label: space
		addr + "=bridged:chatgpt-web",               // unsafe label: would inject a second flag
		addr + "=abcdefghijklmnopqrstuvwxyz0123456", // unsafe label: 33 chars, over the limit
	} {
		if _, err := parseBridgeOrigins(bad); err == nil {
			t.Fatalf("entry %q: want error, got nil", bad)
		}
	}
}
