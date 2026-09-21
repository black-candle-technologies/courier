package envelope

import (
	"strings"
	"testing"
)

// FuzzParseGroupID feeds arbitrary strings to the group-ID parser
// ("group:<base64url>" carrying 16 bytes). Invariants: never panic; a
// successfully parsed ID re-formats to a string that re-parses to the
// same bytes (format / parse stability). Like ParseAddress this does not
// require byte-identical re-formatting: Go's base64 decoder accepts
// non-canonical trailing bits, so distinct strings can decode to the
// same ID bytes (same canonicalization note as in crypto's address
// fuzz target).
func FuzzParseGroupID(f *testing.F) {
	f.Add("group:AQIDBAUGBwgJCgsMDQ4PEA")   // valid (16 bytes)
	f.Add("")                               // empty
	f.Add("group:")                         // prefix only
	f.Add("group:AQID")                     // short (3 bytes)
	f.Add("group:AQIDBAUGBwgJCgsMDQ4PEAE")  // long (17 bytes)
	f.Add("ed25519:AQIDBAUGBwgJCgsMDQ4PEA") // wrong prefix
	f.Add("group:!!!not-base64!!!")
	f.Add("GROUP:AQIDBAUGBwgJCgsMDQ4PEA")  // wrong-case prefix
	f.Add("group:AQIDBAUGBwgJCgsMDQ4PEA ") // trailing space
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := ParseGroupID(s)
		if err != nil {
			return
		}
		formatted := FormatGroupID(raw)
		raw2, err := ParseGroupID(formatted)
		if err != nil || raw2 != raw {
			t.Fatalf("ParseGroupID(%q): re-parse of formatted %q failed or mismatched", s, formatted)
		}
	})
}

// FuzzNormalizeHandle feeds arbitrary strings to the directory-handle
// normalizer. Invariants: never panic; a successfully normalized handle
// is idempotent (normalizing again is a no-op) and lowercase.
func FuzzNormalizeHandle(f *testing.F) {
	f.Add("alice")                 // valid
	f.Add("Alice_99-x")            // valid, mixed case
	f.Add("  bob  ")               // valid with whitespace
	f.Add("")                      // empty
	f.Add("ab")                    // too short
	f.Add("a")                     // way too short
	f.Add(strings.Repeat("a", 33)) // too long
	f.Add("-leading")              // bad first char
	f.Add("has space")             // bad charset
	f.Add("UPPER")                 // uppercase only
	f.Add("a/b")                   // separator
	f.Add("dots.are.bad")          // dots not allowed
	f.Fuzz(func(t *testing.T, s string) {
		h, err := NormalizeHandle(s)
		if err != nil {
			return
		}
		if h != strings.ToLower(h) {
			t.Fatalf("NormalizeHandle(%q) = %q, not lowercase", s, h)
		}
		h2, err := NormalizeHandle(h)
		if err != nil || h2 != h {
			t.Fatalf("NormalizeHandle(%q) = %q, not idempotent", s, h)
		}
	})
}

// FuzzValidateCapabilities feeds arbitrary capability-token lists (NUL-
// separated in the fuzz input) to the directory capability validator.
// Invariant: never panic, and validation is deterministic.
func FuzzValidateCapabilities(f *testing.F) {
	f.Add("fs\x00dm")                  // valid pair
	f.Add("fs")                        // single valid
	f.Add("")                          // empty -> one empty token
	f.Add("HAS space")                 // bad charset
	f.Add("UPPER")                     // uppercase is lowered first
	f.Add(strings.Repeat("a", 33))     // too long
	f.Add("ok\x00\x00bad!")            // empty + bad token
	f.Add(strings.Repeat("x\x00", 20)) // too many capabilities
	f.Fuzz(func(t *testing.T, data string) {
		caps := strings.Split(data, "\x00")
		err1 := ValidateCapabilities(caps)
		err2 := ValidateCapabilities(caps)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("ValidateCapabilities not deterministic for %q", data)
		}
	})
}
