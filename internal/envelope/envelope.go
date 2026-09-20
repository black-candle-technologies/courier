// Package envelope defines the canonical signed payloads for Courier
// (v0.2.0+). Both the client and the relay use these, so a signature made
// by one is verifiable by the other.
package envelope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
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

// blobUploadDomain separates blob-upload authorization signatures: the
// uploader signs the blob id, recipient, byte size, and timestamp, so the
// relay can attribute stored blobs to an identity.
var blobUploadDomain = []byte("courier-blob-upload-v1\x00")

// blobRequestDomain separates blob-download authorization signatures,
// mirroring inbox requests: only the blob's recipient can fetch it.
var blobRequestDomain = []byte("courier-blob-req-v1\x00")

// BlobUpload builds the canonical bytes an uploader signs to authorize
// storing a blob: it binds the uploader, the intended recipient, the
// random blob id, the exact byte size, and a timestamp. The relay verifies
// this before accepting the bytes, so blob storage is attributable, not
// anonymous.
func BlobUpload(from, to, blobID []byte, size, ts int64) []byte {
	out := make([]byte, 0, len(blobUploadDomain)+32+32+32+8+8)
	out = append(out, blobUploadDomain...)
	out = append(out, from...)   // 32 bytes Ed25519 (uploader)
	out = append(out, to...)     // 32 bytes Ed25519 (recipient)
	out = append(out, blobID...) // 32 bytes random blob id
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(size))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// BlobRequest builds the canonical bytes a recipient signs to authorize
// downloading a blob, mirroring InboxRequest. The relay verifies the
// signature against the blob's stored recipient, so only the address the
// blob was uploaded for can fetch its ciphertext.
func BlobRequest(address, blobID []byte, ts int64) []byte {
	out := make([]byte, 0, len(blobRequestDomain)+32+32+8)
	out = append(out, blobRequestDomain...)
	out = append(out, address...) // 32 bytes Ed25519 (recipient)
	out = append(out, blobID...)  // 32 bytes random blob id
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

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

// ---- Group messaging (issue #32) ----

// GroupIDPrefix marks group identifiers. A group ID is
// "group:<base64url>" carrying 128 bits of randomness.
const GroupIDPrefix = "group:"

// GroupIDLen is the raw group-ID length in bytes (128 bits).
const GroupIDLen = 16

// ParseGroupID validates a group ID string and returns its raw bytes.
func ParseGroupID(s string) ([16]byte, error) {
	var out [16]byte
	if !strings.HasPrefix(s, GroupIDPrefix) {
		return out, fmt.Errorf("group id must start with %q", GroupIDPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, GroupIDPrefix))
	if err != nil {
		return out, fmt.Errorf("invalid group id: %w", err)
	}
	if len(raw) != GroupIDLen {
		return out, fmt.Errorf("invalid group id: want %d bytes, got %d", GroupIDLen, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// FormatGroupID renders raw group-ID bytes in "group:<base64url>" form.
func FormatGroupID(raw [16]byte) string {
	return GroupIDPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
}

// groupEnvelopeDomain separates group-message signatures from every other
// use of the sender's Ed25519 key.
var groupEnvelopeDomain = []byte("courier-group-envelope-v1\x00")

// groupIDHashDomain separates the group-ID hashing used inside
// GroupCanonical.
var groupIDHashDomain = []byte("courier-group-id-v1\x00")

// GroupCanonical returns the exact bytes covered by a group-message sender
// signature. The recipient is the group ID, hashed to 32 bytes so the
// encoding stays fixed-length and unambiguous; the sender-key epoch is
// covered so a captured envelope cannot be replayed under a different
// epoch. The eph field is 32 random bytes (kept for envelope-shape
// compatibility); group messages use symmetric sender keys, not X25519.
func GroupCanonical(groupID string, from []byte, keyEpoch int64, eph, nonce []byte, sentAt int64, ct []byte) []byte {
	out := make([]byte, 0, len(groupEnvelopeDomain)+32+32+8+32+24+8+len(ct))
	out = append(out, groupEnvelopeDomain...)
	gid := sha256.Sum256(append(groupIDHashDomain, groupID...))
	out = append(out, gid[:]...) // 32 bytes
	out = append(out, from...)   // 32 bytes Ed25519 (sender address key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(keyEpoch))
	out = append(out, b[:]...)
	out = append(out, eph...)   // 32 bytes
	out = append(out, nonce...) // 24 bytes
	binary.BigEndian.PutUint64(b[:], uint64(sentAt))
	out = append(out, b[:]...)
	out = append(out, ct...)
	return out
}

// Group membership-control actions.
const (
	GroupControlCreate        = "create"
	GroupControlAdd           = "add"
	GroupControlRemove        = "remove"
	GroupControlTransferAdmin = "transfer-admin"
)

// groupControlDomain separates group membership-control signatures from
// every other use of the signer's Ed25519 key.
var groupControlDomain = []byte("courier-group-control-v1\x00")

// GroupControl returns the exact bytes covered by a group membership
// control signature. Controls are signed by the group admin (create: by
// the creator, who becomes the initial admin). The epoch strictly
// increases by 1 per control, so replays and reorderings are rejected by
// the relay.
func GroupControl(groupID, action, target, admin string, epoch int64) []byte {
	out := make([]byte, 0, len(groupControlDomain)+len(groupID)+len(action)+len(target)+len(admin)+4+8)
	out = append(out, groupControlDomain...)
	for _, s := range []string{groupID, action, target, admin} {
		out = append(out, s...)
		out = append(out, 0x00)
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	out = append(out, b[:]...)
	return out
}

// groupInboxRequestDomain separates group-read authorization signatures
// from every other use of the member's Ed25519 key.
var groupInboxRequestDomain = []byte("courier-group-inbox-req-v1\x00")

// GroupInboxRequest builds the canonical bytes a member signs to authorize
// reading a group's envelopes. The relay verifies the signature against
// the member's address key and checks current membership, so only current
// members can read the group's ciphertext and control feed.
func GroupInboxRequest(groupID string, member []byte, after, limit, ts int64) []byte {
	out := make([]byte, 0, len(groupInboxRequestDomain)+len(groupID)+1+32+8+8+8)
	out = append(out, groupInboxRequestDomain...)
	out = append(out, groupID...)
	out = append(out, 0x00)
	out = append(out, member...) // 32 bytes Ed25519 (requesting member)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(after))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(limit))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}
