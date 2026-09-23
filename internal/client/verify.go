// Contact verification (issue #48, phase 1).
//
// The safety number lets two parties confirm, over an out-of-band
// channel, that they agree on each other's identity and current
// encryption keys. Both sides compute the same number independently:
//
//	safety = digits(SHA512("courier-safety-v1" ||
//	    min(addrA,addrB) || max(addrA,addrB) ||
//	    xA || epochA || xB || epochB)[0:36])
//
// addrA/addrB are the raw 32-byte Ed25519 public keys (sorted); (x,epoch)
// pairs are each party's current X25519 encryption key and its epoch,
// ordered to match the sorted addresses. The contact's key comes from the
// relay key directory with the same signature/rollback verification as
// recipientKey; a contact that never published a key contributes the
// address-derived key with epoch 0 (deterministic, so both sides agree).
//
// Rendered as 60 decimal digits in 12 groups of 5 (30 hash bytes, 20 bits
// per group), Signal-style.
package client

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// safetyNumberDomain separates the safety-number hash from every other
// hash in the protocol.
const safetyNumberDomain = "courier-safety-v1"

// ContactVerification records one out-of-band identity verification: the
// safety number that was confirmed, and the address + key epoch it was
// computed over. If either changes later, the verification is stale.
type ContactVerification struct {
	VerifiedAt   int64  `json:"verified_at"`
	SafetyNumber string `json:"safety_number"`
	KeyEpoch     int64  `json:"key_epoch"`
	Address      string `json:"address"`
}

// TrustState is the live verification state of a contact.
type TrustState int

const (
	// TrustUnverified: no verification record.
	TrustUnverified TrustState = iota
	// TrustVerified: record exists and address + key epoch still match.
	TrustVerified
	// TrustStale: the contact's address or encryption key epoch changed
	// since verification — re-verify before trusting.
	TrustStale
)

// String renders the trust state for CLI output.
func (t TrustState) String() string {
	switch t {
	case TrustVerified:
		return "verified"
	case TrustStale:
		return "stale"
	default:
		return "unverified"
	}
}

// SafetyNumber computes the mutual safety number for ownAddr and
// contactAddr given each side's current X25519 encryption key and epoch.
// The result is identical no matter which side computes it.
func SafetyNumber(ownAddr, contactAddr string, ownPub, contactPub [32]byte, ownEpoch, contactEpoch int64) (string, error) {
	ownEd, err := crypto.ParseAddress(ownAddr)
	if err != nil {
		return "", fmt.Errorf("bad own address: %w", err)
	}
	contactEd, err := crypto.ParseAddress(contactAddr)
	if err != nil {
		return "", fmt.Errorf("bad contact address: %w", err)
	}
	var firstEd, secondEd [32]byte
	var firstPub, secondPub [32]byte
	var firstEpoch, secondEpoch int64
	if bytes.Compare(ownEd[:], contactEd[:]) <= 0 {
		firstEd, secondEd = ownEd, contactEd
		firstPub, secondPub = ownPub, contactPub
		firstEpoch, secondEpoch = ownEpoch, contactEpoch
	} else {
		firstEd, secondEd = contactEd, ownEd
		firstPub, secondPub = contactPub, ownPub
		firstEpoch, secondEpoch = contactEpoch, ownEpoch
	}
	h := sha512.New()
	h.Write([]byte(safetyNumberDomain))
	h.Write(firstEd[:])
	h.Write(secondEd[:])
	h.Write(firstPub[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(firstEpoch))
	h.Write(buf[:])
	h.Write(secondPub[:])
	binary.BigEndian.PutUint64(buf[:], uint64(secondEpoch))
	h.Write(buf[:])
	sum := h.Sum(nil)[:36] // 12 groups x 3 bytes
	var groups []string
	for i := 0; i < 12; i++ {
		v := uint32(sum[3*i])<<16 | uint32(sum[3*i+1])<<8 | uint32(sum[3*i+2])
		v >>= 4 // 20 bits
		groups = append(groups, fmt.Sprintf("%05d", v%100000))
	}
	return strings.Join(groups, " "), nil
}

// SafetyNumberForContact resolves the contact and computes the mutual
// safety number with them, fetching both sides' current encryption keys
// (own locally, theirs from the signature-verified key directory).
func (c *Client) SafetyNumberForContact(name string) (number, address string, err error) {
	address, err = c.cfg.LookupContact(name)
	if err != nil {
		return "", "", err
	}
	ownPub, _, ownEpoch, err := c.cfg.currentEncKey()
	if err != nil {
		return "", "", fmt.Errorf("no local encryption key: %w", err)
	}
	_, contactPub, contactEpoch, err := c.recipientKeyWithEpoch(address)
	if err != nil {
		return "", "", err
	}
	number, err = SafetyNumber(c.cfg.Address, address, ownPub, contactPub, ownEpoch, contactEpoch)
	if err != nil {
		return "", "", err
	}
	return number, address, nil
}

// VerifyContact records an out-of-band verification of the contact: the
// caller asserts the safety number was compared over a separate channel.
// The record pins the address and key epoch the number was computed over,
// so a later rotation invalidates it. Verification changes reset the
// dashboard label refresh timer so the next push carries the new state.
func (c *Client) VerifyContact(name string) error {
	number, address, err := c.SafetyNumberForContact(name)
	if err != nil {
		return err
	}
	_, _, contactEpoch, err := c.recipientKeyWithEpoch(address)
	if err != nil {
		return err
	}
	rec := ContactVerification{
		VerifiedAt:   time.Now().Unix(),
		SafetyNumber: number,
		KeyEpoch:     contactEpoch,
		Address:      address,
	}
	return c.cfg.Update(func(fresh *Config) error {
		if fresh.ContactVerifications == nil {
			fresh.ContactVerifications = map[string]ContactVerification{}
		}
		fresh.ContactVerifications[name] = rec
		fresh.HandleRefreshAt = 0 // push the new trust state promptly
		return nil
	})
}

// UnverifyContact clears a contact's verification record, e.g. on
// suspected compromise. Not an error if there was no record.
func (c *Client) UnverifyContact(name string) error {
	return c.cfg.Update(func(fresh *Config) error {
		delete(fresh.ContactVerifications, name)
		fresh.HandleRefreshAt = 0
		return nil
	})
}

// StoredVerification returns the raw verification record, if any.
func (c *Config) StoredVerification(name string) (ContactVerification, bool) {
	rec, ok := c.ContactVerifications[name]
	return rec, ok
}

// ContactTrust evaluates the live trust state of a contact: the stored
// record is fresh only if the contact's address and current key epoch
// still match what was verified. The key-directory fetch is best-effort:
// if the relay is unreachable, the stored state is reported with a note
// instead of failing.
func (c *Client) ContactTrust(name string) (TrustState, string) {
	address, err := c.cfg.LookupContact(name)
	if err != nil {
		return TrustUnverified, "unknown contact"
	}
	rec, ok := c.cfg.StoredVerification(name)
	if !ok {
		return TrustUnverified, "never verified out of band"
	}
	if rec.Address != address {
		return TrustStale, "contact address changed since verification"
	}
	_, _, epoch, err := c.recipientKeyWithEpoch(address)
	if err != nil {
		if rec.KeyEpoch >= 0 {
			return TrustVerified, "verified (could not revalidate: relay unreachable)"
		}
		return TrustUnverified, "never verified out of band"
	}
	if epoch != rec.KeyEpoch {
		return TrustStale, "contact rotated encryption keys since verification"
	}
	return TrustVerified, "safety number confirmed out of band"
}

// MarkContactVerifiedByAddress records a verification for whichever named
// contact (if any) holds the address, computing the current safety
// number. This is the phase-2 OOB bootstrap: proving possession of a join
// code received out of band *is* the verification ceremony. It is a no-op
// when the address is not a named contact.
func (c *Client) MarkContactVerifiedByAddress(address string) error {
	var name string
	for n, a := range c.cfg.Contacts {
		if a == address {
			name = n
			break
		}
	}
	if name == "" {
		return nil
	}
	if st, _ := c.ContactTrust(name); st == TrustVerified {
		return nil // already verified and fresh
	}
	return c.VerifyContact(name)
}

// TrustBadge is the short CLI trust indicator for a contact.
func (c *Client) TrustBadge(name string) string {
	st, detail := c.ContactTrust(name)
	switch st {
	case TrustVerified:
		return "✓ verified"
	case TrustStale:
		return "⚠ " + detail
	default:
		return "• unverified"
	}
}
