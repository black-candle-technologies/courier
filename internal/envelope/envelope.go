// Package envelope defines the canonical signed payload for Courier
// envelopes (v0.2.0+). Both the client and the relay use it, so a signature
// made by one is verifiable by the other.
package envelope

import "encoding/binary"

// Domain separates Courier envelope signatures from every other use of the
// sender's Ed25519 key.
var domain = []byte("courier-envelope-sig-v1\x00")

// Canonical returns the exact bytes covered by the sender's signature.
// All fields except ct are fixed length, and ct is last, so the encoding
// is unambiguous.
func Canonical(to, from, eph, nonce []byte, sentAt int64, ct []byte) []byte {
	out := make([]byte, 0, len(domain)+32+32+32+24+8+len(ct))
	out = append(out, domain...)
	out = append(out, to...)    // 32 bytes Ed25519 (address key)
	out = append(out, from...)  // 32 bytes Ed25519 (address key)
	out = append(out, eph...)   // 32 bytes X25519 ephemeral
	out = append(out, nonce...) // 24 bytes
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(sentAt))
	out = append(out, ts[:]...)
	out = append(out, ct...)
	return out
}
