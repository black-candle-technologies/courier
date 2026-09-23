package vhl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

// SessionToken is the Tier 1 attestation (issue #142): a human did a
// presence ceremony for this session, so routine instructions sent
// under it are attested. The token is a signed bearer credential —
// guard it like one. It carries only references (ids, timestamps,
// scope) and the issuer signature: never any secret key material.
type SessionToken struct {
	Version   int    `json:"v"`
	ID        string `json:"id"`         // base64url 16 random bytes
	Issuer    string `json:"issuer"`     // approver Courier address (the human)
	SessionID string `json:"session_id"` // base64url 16 random bytes
	IssuedAt  int64  `json:"issued_at"`  // unix seconds
	ExpiresAt int64  `json:"expires_at"` // unix seconds
	Scope     string `json:"scope"`      // counterparty address, or "" for any
	Presence  string `json:"presence"`   // ceremony strength at mint
	BootID    string `json:"boot_id"`    // issuer boot id; restart revokes by construction
	Sig       string `json:"sig"`        // base64url Ed25519 by the issuer key
}

const sessionTokenVersion = 1

// DefaultSessionTTL is the default session-token lifetime (issue #142:
// 8h). Short enough to bound a stolen token, long enough to cover a
// working session without re-ceremony.
const DefaultSessionTTL = 8 * time.Hour

// ClockSkewGrace is the receiver-side grace for clock skew when
// evaluating token/attestation lifetimes in receiver-local time.
const ClockSkewGrace = 5 * time.Minute

// MintSessionToken creates a session token after a human presence
// ceremony. presence names the ceremony that just happened; scope
// binds the token to one counterparty address ("" = any); bootID is
// the issuer's current boot id (a restart must mint fresh tokens).
func MintSessionToken(issuer, scope string, presence PresenceStrength, ttl time.Duration, bootID string, priv ed25519.PrivateKey) (*SessionToken, error) {
	if issuer == "" {
		return nil, fmt.Errorf("session token without issuer")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("session token ttl must be positive")
	}
	var id, sid [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	now := time.Now().Unix()
	t := &SessionToken{
		Version:   sessionTokenVersion,
		ID:        b64.EncodeToString(id[:]),
		Issuer:    issuer,
		SessionID: b64.EncodeToString(sid[:]),
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl/time.Second),
		Scope:     scope,
		Presence:  presence.String(),
		BootID:    bootID,
	}
	if err := t.sign(priv); err != nil {
		return nil, err
	}
	return t, nil
}

// canonical builds the signed bytes for the token.
func (t *SessionToken) canonical() ([]byte, error) {
	if t.Version != sessionTokenVersion {
		return nil, fmt.Errorf("session token version %d (want %d)", t.Version, sessionTokenVersion)
	}
	id, err := b64.DecodeString(t.ID)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	sid, err := b64.DecodeString(t.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	out := make([]byte, 0, 192)
	out = append(out, tokenDomain...)
	out = append(out, byte(t.Version))
	out = append(out, id...)
	out = append(out, []byte(t.Issuer)...)
	out = append(out, []byte{0}...)
	out = append(out, sid...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t.IssuedAt))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(t.ExpiresAt))
	out = append(out, b[:]...)
	out = append(out, []byte(t.Scope)...)
	out = append(out, []byte{0}...)
	out = append(out, []byte(t.Presence)...)
	out = append(out, []byte{0}...)
	out = append(out, []byte(t.BootID)...)
	return out, nil
}

func (t *SessionToken) sign(priv ed25519.PrivateKey) error {
	canon, err := t.canonical()
	if err != nil {
		return err
	}
	t.Sig = b64.EncodeToString(ed25519.Sign(priv, canon))
	return nil
}

// verifySignature checks the issuer signature.
func (t *SessionToken) verifySignature(pub []byte) error {
	canon, err := t.canonical()
	if err != nil {
		return err
	}
	sig, err := b64.DecodeString(t.Sig)
	if err != nil {
		return fmt.Errorf("sig: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bad key/signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canon, sig) {
		return fmt.Errorf("session token signature invalid")
	}
	return nil
}

// Validate checks structural invariants.
func (t *SessionToken) Validate() error {
	if t.Version != sessionTokenVersion {
		return fmt.Errorf("session token version %d (want %d)", t.Version, sessionTokenVersion)
	}
	if t.Issuer == "" {
		return fmt.Errorf("session token without issuer")
	}
	if t.IssuedAt <= 0 || t.ExpiresAt <= t.IssuedAt {
		return fmt.Errorf("session token has invalid lifetime")
	}
	idRaw, err := b64.DecodeString(t.ID)
	if err != nil {
		return fmt.Errorf("session token id: %w", err)
	}
	if len(idRaw) != 16 {
		return fmt.Errorf("session token id is %d bytes (want 16)", len(idRaw))
	}
	if _, err := b64.DecodeString(t.SessionID); err != nil {
		return fmt.Errorf("session token session_id: %w", err)
	}
	if _, err := ParsePresence(t.Presence); err != nil {
		return fmt.Errorf("session token presence: %w", err)
	}
	return nil
}

// LiveAt reports whether the token is live at time now (unix
// seconds), evaluated in receiver-local time with a small grace for
// clock skew (issue #142). Not-yet-valid tokens are rejected: the
// grace applies to expiry only, never to backdating issued-at.
func (t *SessionToken) LiveAt(now int64) bool {
	if now < t.IssuedAt {
		return false
	}
	return now <= t.ExpiresAt+int64(ClockSkewGrace/time.Second)
}

// MintPresence returns the ceremony strength at mint.
func (t *SessionToken) MintPresence() (PresenceStrength, error) {
	return ParsePresence(t.Presence)
}

// MayRemint reports whether a new token may be minted to replace t
// with ceremony strength p. Re-mint requires the same presence
// strength as the original mint or stronger — a FIDO2-born token
// must never be renewable with a PIN (no downgrade path).
func (t *SessionToken) MayRemint(p PresenceStrength) bool {
	cur, err := t.MintPresence()
	if err != nil {
		return false
	}
	return p.AtLeast(cur)
}

// --- sealed storage ---
//
// Session tokens are bearer credentials: whoever holds one can attest
// Tier 1 messages for the session. On headless runtimes they live in
// the sealed agent keystore: secretbox-encrypted under a key derived
// from the agent's identity seed (HKDF-SHA256, domain-separated),
// stored 0600. Production hardening is a TPM/KMS-wrapped key; the
// derivation matches the envelope-encryption shape so the upgrade is
// a key-source swap, not a format change.

// SealKeyDomain derives the keystore seal key from the identity seed.
var SealKeyDomain = []byte("courier-vhl-keystore-v1")

// DeriveSealKey derives the token-keystore seal key from the 32-byte
// identity seed.
func DeriveSealKey(seed [32]byte) [32]byte {
	var out [32]byte
	kdf := hkdf.New(sha256.New, seed[:], nil, SealKeyDomain)
	// hkdf.New with a 32-byte key never fails to fill 32 bytes.
	_, _ = kdf.Read(out[:])
	return out
}

// SealTokens encrypts the JSON-encoded token list for storage.
func SealTokens(plain []byte, key [32]byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	sealed := secretbox.Seal(nonce[:], plain, &nonce, &key)
	return sealed, nil
}

// OpenTokens decrypts a sealed token list. A wrong key fails closed.
func OpenTokens(sealed []byte, key [32]byte) ([]byte, error) {
	if len(sealed) < 24+secretbox.Overhead {
		return nil, fmt.Errorf("sealed token store too short")
	}
	var nonce [24]byte
	copy(nonce[:], sealed[:24])
	plain, ok := secretbox.Open(nil, sealed[24:], &nonce, &key)
	if !ok {
		return nil, fmt.Errorf("sealed token store failed to open (wrong key or corrupt)")
	}
	return plain, nil
}
