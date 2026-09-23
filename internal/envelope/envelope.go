// Package envelope defines the canonical signed payloads for Courier
// (v0.2.0+). Both the client and the relay use these, so a signature made
// by one is verifiable by the other.
//
// Crypto-suite versioning (issue #138): every signature domain below ends
// in "-v1", and that suffix IS the version marker for the crypto suite
// (SuiteV1: Ed25519 signatures, X25519 key exchange, NaCl box). A future
// suite (e.g. post-quantum, issue #54) gets "-v2" domains with new
// canonical layouts; v1 canonical bytes are frozen forever so existing
// signatures keep verifying. The suite is therefore authenticated by the
// signature itself — a v1 signature can never validate as a v2 signature
// or vice versa, which rules out downgrade attacks at the signing layer.
package envelope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
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

// subscribeRequestDomain separates inbox-subscription signatures (issue
// #42) from every other use of the identity key: a subscription
// signature can never validate as an inbox read, and vice versa.
var subscribeRequestDomain = []byte("courier-subscribe-req-v1\x00")

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

// SubscribeRequest builds the canonical bytes a recipient signs to
// authorize a long-poll inbox subscription (issue #42). It binds the
// recipient address, the resume cursor, and a timestamp; the relay
// enforces the same freshness window as inbox reads. Domain-separated
// from InboxRequest so the two authorizations are not interchangeable.
func SubscribeRequest(address []byte, cursor, ts int64) []byte {
	out := make([]byte, 0, len(subscribeRequestDomain)+32+8+8)
	out = append(out, subscribeRequestDomain...)
	out = append(out, address...) // 32 bytes Ed25519 (recipient address)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(cursor))
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

// spamReportDomain separates spam-report signatures from every other use
// of the identity key: a signature for one can never validate as another.
var spamReportDomain = []byte("courier-spam-report-v1\x00")

// SpamReport builds the canonical bytes a recipient signs to report an
// envelope as spam. The relay verifies the signature against the
// reporter's address and requires the reporter to be the envelope's
// recipient, so only the party that actually received the message can
// file a report against its sender.
func SpamReport(reporter []byte, envelopeID, ts int64) []byte {
	out := make([]byte, 0, len(spamReportDomain)+32+8+8)
	out = append(out, spamReportDomain...)
	out = append(out, reporter...) // 32 bytes Ed25519 (reporter address)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(envelopeID))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// ---- Contact discovery (issue #39, v0.8.0) ----

// directoryRegisterDomain separates directory-registration signatures
// from every other use of the identity key: a signature for one can never
// validate as another.
var directoryRegisterDomain = []byte("courier-directory-register-v1\x00")

// Directory visibilities.
const (
	DirectoryPublic   = "public"
	DirectoryUnlisted = "unlisted"
	DirectoryPrivate  = "private"
)

// DirectoryContactPolicies mirrors the #34 dm_policy values; the lookup
// response carries the target's policy so the sender's client can warn
// before first contact.
const (
	DirectoryPolicyOpen     = "open"
	DirectoryPolicyContacts = "contacts"
)

// MaxDirectoryCapabilities bounds the capability token list; each token is
// bounded by MaxDirectoryCapabilityLen. Tokens are matched
// opportunistically by clients; there is no curated registry.
const (
	MaxDirectoryCapabilities  = 8
	MaxDirectoryCapabilityLen = 32
	DirectorySearchMinLen     = 2
	DirectorySearchMaxResults = 20
)

// handlePattern validates directory handles: same charset as contacts and
// dashboard usernames, 3-32 chars.
var handlePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// NormalizeHandle lowercases and validates a directory handle.
func NormalizeHandle(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	if !handlePattern.MatchString(h) {
		return "", fmt.Errorf("invalid handle %q: 3-32 chars, [a-z0-9_-], must start with [a-z0-9]", h)
	}
	return h, nil
}

// capabilityPattern validates capability tokens: 1-32 chars of
// [a-z0-9_-], starting with [a-z0-9]. Tokens are matched
// opportunistically by clients; there is no curated registry.
var capabilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidateCapabilities checks the bounded free-form capability tokens.
func ValidateCapabilities(caps []string) error {
	if len(caps) > MaxDirectoryCapabilities {
		return fmt.Errorf("too many capabilities: max %d", MaxDirectoryCapabilities)
	}
	for _, c := range caps {
		c = strings.ToLower(strings.TrimSpace(c))
		if !capabilityPattern.MatchString(c) {
			return fmt.Errorf("invalid capability %q: 1-32 chars, [a-z0-9_-]", c)
		}
	}
	return nil
}

// DirectoryRegister builds the canonical bytes a handle owner signs to
// register or update a directory entry. It binds handle, address, epoch,
// visibility, contact policy, and capabilities, mirroring
// courier-key-announce-v1 and courier-dashboard-register-v1.
func DirectoryRegister(handle string, addressEd25519 []byte, epoch int64, visibility, contactPolicy string, capabilities []string) []byte {
	out := make([]byte, 0, len(directoryRegisterDomain)+len(handle)+32+8+64)
	out = append(out, directoryRegisterDomain...)
	out = append(out, handle...)
	out = append(out, 0x00)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (owner identity)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	out = append(out, b[:]...)
	out = append(out, 0x00)
	out = append(out, visibility...)
	out = append(out, 0x00)
	out = append(out, contactPolicy...)
	out = append(out, 0x00)
	out = append(out, strings.Join(capabilities, "\x00")...)
	return out
}

// directoryTransferDomain separates handle-transfer signatures from every
// other use of the identity key.
var directoryTransferDomain = []byte("courier-directory-transfer-v1\x00")

// DirectoryTransfer builds the canonical bytes the current handle holder
// signs to transfer a handle to a new address. Only the current holder
// can authorize a transfer, so there is no release-and-re-register race a
// squatter could win.
func DirectoryTransfer(handle string, newAddressEd25519 []byte, epoch int64) []byte {
	out := make([]byte, 0, len(directoryTransferDomain)+len(handle)+32+8+2)
	out = append(out, directoryTransferDomain...)
	out = append(out, handle...)
	out = append(out, 0x00)
	out = append(out, newAddressEd25519...) // 32 bytes Ed25519 (new owner)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	out = append(out, b[:]...)
	return out
}

// directoryQueryDomain separates directory-query signatures (lookup,
// search, reverse lookup) from every other use of the identity key,
// mirroring the F10 inbox-request pattern: signed queries make
// enumeration attributable and rate-limitable per identity.
var directoryQueryDomain = []byte("courier-directory-query-v1\x00")

// DirectoryQuery builds the canonical bytes a querier signs to authorize
// a directory lookup/search/reverse query. The signature is verified
// against the querier's address key, binding every query to an identity.
func DirectoryQuery(querierEd25519 []byte, op, query string, ts int64) []byte {
	out := make([]byte, 0, len(directoryQueryDomain)+32+len(op)+len(query)+8+3)
	out = append(out, directoryQueryDomain...)
	out = append(out, querierEd25519...) // 32 bytes Ed25519 (querier)
	out = append(out, 0x00)
	out = append(out, op...) // "lookup", "search", or "reverse"
	out = append(out, 0x00)
	out = append(out, query...)
	out = append(out, 0x00)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// introductionRequestDomain separates introduction-request signatures
// from every other use of the identity key.
var introductionRequestDomain = []byte("courier-introduction-req-v1\x00")

// IntroductionRequest builds the canonical bytes a requester signs when
// asking a mutual contact to introduce them to a private handle's owner.
// It travels inside the normal E2E-encrypted DM to the mutual contact.
func IntroductionRequest(requester, introducer []byte, handle string, ts int64) []byte {
	out := make([]byte, 0, len(introductionRequestDomain)+32+32+len(handle)+8+3)
	out = append(out, introductionRequestDomain...)
	out = append(out, requester...)  // 32 bytes Ed25519 (requester)
	out = append(out, introducer...) // 32 bytes Ed25519 (mutual contact)
	out = append(out, handle...)
	out = append(out, 0x00)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// introductionDomain separates introduction signatures from every other
// use of the identity key.
var introductionDomain = []byte("courier-introduction-v1\x00")

// Introduction builds the canonical bytes an introducer signs when
// forwarding an introduction to the target. It binds introducer,
// subject (requester), and recipient, and travels inside the normal
// E2E-encrypted DM to the target.
func Introduction(introducer, subject, recipient []byte, ts int64) []byte {
	out := make([]byte, 0, len(introductionDomain)+32+32+32+8)
	out = append(out, introductionDomain...)
	out = append(out, introducer...) // 32 bytes Ed25519 (mutual contact)
	out = append(out, subject...)    // 32 bytes Ed25519 (requester)
	out = append(out, recipient...)  // 32 bytes Ed25519 (target)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// directoryDeregisterDomain separates handle-deregistration signatures
// from every other use of the identity key. Deregistration MUST NOT
// reuse the registration canonical bytes: registration signatures are
// public (served in lookup responses), so a distinct domain is required
// to keep a registration from being replayed as a deregistration.
var directoryDeregisterDomain = []byte("courier-directory-deregister-v1\x00")

// DirectoryDeregister builds the canonical bytes a handle owner signs to
// delete their own registration. Only the owning address can deregister;
// operator takedowns use tombstones instead (visible, §11 Q3).
func DirectoryDeregister(handle string, addressEd25519 []byte, epoch int64) []byte {
	out := make([]byte, 0, len(directoryDeregisterDomain)+len(handle)+32+8+2)
	out = append(out, directoryDeregisterDomain...)
	out = append(out, handle...)
	out = append(out, 0x00)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (owner identity)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	out = append(out, b[:]...)
	return out
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
