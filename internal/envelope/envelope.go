// Package envelope defines the canonical signed payloads for Courier
// (v0.2.0+). Both the client and the relay use these, so a signature made
// by one is verifiable by the other.
package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Domain separates Courier envelope signatures from every other use of the
// sender's Ed25519 key.
var domain = []byte("courier-envelope-sig-v1\x00")

// announceDomain separates key-announcement signatures (v0.5.0+) from
// envelope signatures: a signature for one can never validate as the other.
var announceDomain = []byte("courier-key-announce-v1\x00")

// dashboardRegisterDomain separates dashboard registration signatures
// (v0.6.0+) from every other use of the identity key. Registering binds a
// dashboard username to the Courier address that signed.
var dashboardRegisterDomain = []byte("courier-dashboard-register-v1\x00")

// inboxRequestDomain separates inbox-request signatures (v0.6.11+) from
// every other use of the identity key: a signature for one can never
// validate as another.
var inboxRequestDomain = []byte("courier-inbox-req-v1\x00")

// InboxRequest builds the canonical bytes a recipient signs to authorize
// reading their own inbox (v0.6.11, F10). The relay verifies the
// signature against the requested address, so only the address owner can
// read their ciphertext and metadata. ts is unix seconds; the relay
// enforces a freshness window.
func InboxRequest(address []byte, after, limit, ts int64) []byte {
	out := make([]byte, 0, len(inboxRequestDomain)+32+8+8+8)
	out = append(out, inboxRequestDomain...)
	out = append(out, address...) // 32 bytes Ed25519 (recipient address)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(after))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(limit))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

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

// DashboardRegister returns the exact bytes covered by a dashboard
// registration signature (v0.6.0+): it binds a dashboard username to the
// Courier address (Ed25519 identity) that will own the account. The
// dashboard verifies this before creating the user, so only the holder of
// the identity's private key can register that address.
func DashboardRegister(username string, addressEd25519 []byte) []byte {
	out := make([]byte, 0, len(dashboardRegisterDomain)+len(username)+1+32)
	out = append(out, dashboardRegisterDomain...)
	out = append(out, username...)
	out = append(out, 0x00)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (address key)
	return out
}

// KeyAnnounce returns the exact bytes covered by a key-announcement
// signature (v0.5.0+). An announcement binds an Ed25519 identity (address)
// to a current X25519 encryption public key at a given epoch. The relay
// only accepts announcements with a strictly increasing epoch, so a
// captured old announcement cannot be replayed to downgrade the key.
func KeyAnnounce(addressEd25519, x25519Pub []byte, epoch int64) []byte {
	out := make([]byte, 0, len(announceDomain)+32+32+8)
	out = append(out, announceDomain...)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (address key)
	out = append(out, x25519Pub...)      // 32 bytes X25519 encryption key
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], uint64(epoch))
	out = append(out, ep[:]...)
	return out
}

// DedupHash identifies an envelope for replay suppression, independent of
// any relay-assigned id or receive timestamp (v0.6.11, F3). It covers
// every sender-controlled field: the recipient, sender, ephemeral key,
// nonce, ciphertext, sender timestamp, and signature. The Ed25519
// signature is deterministic over the rest, so identical bytes always
// hash identically, and any mutation breaks signature verification
// before dedup even matters.
func DedupHash(to, from, eph, nonce string, sentAt int64, ct, sig string) string {
	h := sha256.New()
	for _, s := range []string{to, from, eph, nonce, ct, sig} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(sentAt))
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil))
}
