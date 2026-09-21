package crypto

import (
	"bytes"
	"testing"
)

// FuzzParseAddress exercises the Courier address parser
// ("ed25519:<base64url>") with arbitrary input.
//
// Invariants: the parser must never panic; a successfully parsed address
// must re-format to a string that parses to the same key bytes (format /
// parse stability). Note this deliberately does NOT require
// FormatAddress(ParseAddress(s)) == s: Go's base64 decoder accepts
// non-canonical trailing bits, so distinct strings can decode to the
// same key. That canonicalization wart is noted for the maintainers; the
// fuzz target pins the weaker stability property so it cannot regress.
func FuzzParseAddress(f *testing.F) {
	f.Add("ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw")        // valid
	f.Add("")                                                           // empty
	f.Add("ed25519:")                                                   // prefix only
	f.Add("x25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw")         // wrong scheme: v0.1.0 bare X25519
	f.Add("ed25519:!!!not-base64!!!")                                   // bad base64
	f.Add("ed25519:6kpsY-KcUgq-9VB7Ey7F")                               // short key (24 bytes)
	f.Add("ed25519:" + b64.EncodeToString(bytes.Repeat([]byte{1}, 33))) // 33 bytes: too long
	f.Add("ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw ")       // trailing space
	f.Add("ED25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw")        // wrong-case prefix
	f.Add("ed25519:6kpsY+KcUgq/9VB7Ey7F+ZVHdq6/vnuSQh7qaRRG0iw")        // std alphabet, not url
	f.Add("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")        // non-canonical trailing bits
	f.Fuzz(func(t *testing.T, s string) {
		key, err := ParseAddress(s)
		if err != nil {
			return
		}
		// The formatted address must re-parse to the same key.
		formatted := FormatAddress(key[:])
		key2, err := ParseAddress(formatted)
		if err != nil {
			t.Fatalf("ParseAddress(%q) succeeded but re-parse of formatted %q failed: %v", s, formatted, err)
		}
		if key2 != key {
			t.Fatalf("ParseAddress(%q): re-parse mismatch", s)
		}
	})
}

// FuzzEd25519PubToX25519 feeds arbitrary 32-byte (and other-length)
// blobs into the Ed25519->X25519 birational map, which explicitly
// rejects non-canonical encodings. Invariants: never panic, deterministic
// (same input -> same output / error).
func FuzzEd25519PubToX25519(f *testing.F) {
	id, err := IdentityFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(id.EdPub[:])                    // valid key
	f.Add(bytes.Repeat([]byte{0}, 32))    // identity point encoding (non-canonical low-order)
	f.Add(bytes.Repeat([]byte{0xff}, 32)) // out of range
	f.Add([]byte{})                       // empty
	f.Add(bytes.Repeat([]byte{1}, 31))    // short
	f.Add(bytes.Repeat([]byte{1}, 33))    // long
	f.Add(bytes.Repeat([]byte{1}, 64))    // very long
	f.Fuzz(func(t *testing.T, raw []byte) {
		out1, err1 := Ed25519PubToX25519(raw)
		out2, err2 := Ed25519PubToX25519(raw)
		if (err1 == nil) != (err2 == nil) || out1 != out2 {
			t.Fatalf("Ed25519PubToX25519 not deterministic for %x", raw)
		}
	})
}
