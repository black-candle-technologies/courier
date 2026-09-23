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
// under it are attested. The token is a signed credential — guard it
// like one. It carries only references (ids, timestamps, scope), the
// WebAuthn assertion that proves the mint-time human ceremony, and
// the issuer signature: never any secret key material.
//
// The embedded assertion is what makes the token unforgeable by a
// process holding the issuer's identity key: the receiver verifies
// the authenticator's signature over the mint challenge against the
// enrolled WebAuthn credential, independently of the issuer
// signature. A token whose assertion is missing or fails
// verification is rejected, so minting can never be reduced to a
// caller-supplied presence claim.
type SessionToken struct {
	Version      int    `json:"v"`
	ID           string `json:"id"`            // base64url 16 random bytes
	Issuer       string `json:"issuer"`        // approver Courier address (the human)
	SessionID    string `json:"session_id"`    // base64url 16 random bytes
	IssuedAt     int64  `json:"issued_at"`     // unix seconds
	ExpiresAt    int64  `json:"expires_at"`    // unix seconds
	Scope        string `json:"scope"`         // counterparty address, or "" for any
	Presence     string `json:"presence"`      // ceremony strength at mint (always fido2_uv)
	CredentialID string `json:"credential_id"` // enrolled WebAuthn credential used at mint
	Assertion    string `json:"assertion"`     // base64url WebAuthn assertion over the mint challenge
	BootID       string `json:"boot_id"`       // issuer boot id; restart revokes by construction
	Sig          string `json:"sig"`           // base64url Ed25519 by the issuer key
}

const sessionTokenVersion = 2

// DefaultSessionTTL is the default session-token lifetime (issue #142:
// 8h). Short enough to bound a stolen token, long enough to cover a
// working session without re-ceremony.
const DefaultSessionTTL = 8 * time.Hour

// ClockSkewGrace is the receiver-side grace for clock skew when
// evaluating token/attestation lifetimes in receiver-local time.
const ClockSkewGrace = 5 * time.Minute

// PendingSessionMint is the first phase of session-token minting: it
// holds everything the ceremony needs bound together — issuer,
// scope, lifetime, and the random ids — and produces the challenge
// the authenticator must sign. It carries no credential or
// assertion yet, and it is NOT a usable token: there is no issuer
// signature and no presence claim until Finish verifies the
// authenticator's assertion.
type PendingSessionMint struct {
	Issuer    string
	Scope     string
	ID        string // base64url 16 random bytes
	SessionID string // base64url 16 random bytes
	IssuedAt  int64  // unix seconds
	ExpiresAt int64  // unix seconds
	BootID    string
}

// BeginSessionMint starts minting a session token. scope binds the
// token to one counterparty address ("" = any); bootID is the
// issuer's current boot id (a restart must mint fresh tokens). The
// returned pending holds the challenge for the WebAuthn ceremony;
// call Finish with the authenticator's assertion to complete the
// mint. There is intentionally no presence parameter: the ceremony
// strength is established by the assertion Finish verifies, never by
// a caller-supplied claim.
func BeginSessionMint(issuer, scope string, ttl time.Duration, bootID string) (*PendingSessionMint, error) {
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
	return &PendingSessionMint{
		Issuer:    issuer,
		Scope:     scope,
		ID:        b64.EncodeToString(id[:]),
		SessionID: b64.EncodeToString(sid[:]),
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl/time.Second),
		BootID:    bootID,
	}, nil
}

// tokenForChallenge builds the token shape the mint challenge is
// derived from: every field that will be signed, with the assertion
// and credential id zeroed (they are the ceremony's answer, not its
// question).
func (p *PendingSessionMint) tokenForChallenge() *SessionToken {
	return &SessionToken{
		Version:   sessionTokenVersion,
		ID:        p.ID,
		Issuer:    p.Issuer,
		SessionID: p.SessionID,
		IssuedAt:  p.IssuedAt,
		ExpiresAt: p.ExpiresAt,
		Scope:     p.Scope,
		Presence:  PresenceFIDO2UV.String(),
		BootID:    p.BootID,
	}
}

// Challenge returns the bytes the authenticator must sign: the
// SHA-256 of the token's canonical form with assertion and
// credential id zeroed. Binding the challenge to the full token
// bytes means the assertion cannot be transplanted onto a token
// with different scope, lifetime, or ids.
func (p *PendingSessionMint) Challenge() []byte {
	canon, err := p.tokenForChallenge().canonical()
	if err != nil {
		// tokenForChallenge is built from BeginSessionMint's own
		// validated fields; canonical cannot fail here.
		panic(fmt.Sprintf("vhl: mint challenge: %v", err))
	}
	sum := sha256.Sum256(canon)
	return sum[:]
}

// Finish completes the mint: it verifies the WebAuthn assertion
// against the enrolled credential (UV required — a session token is
// only ever minted at fido2_uv strength), embeds the credential id
// and assertion in the token, and signs it with the issuer key. The
// assertion is verified BEFORE anything is signed, so a process
// holding the issuer key cannot mint without a real authenticator
// signature: the receiver re-verifies the same assertion
// independently, and a forged one fails there even though the
// issuer signature is valid.
func (p *PendingSessionMint) Finish(cred *Credential, assertionB64 string, rp WebAuthnRP, priv ed25519.PrivateKey) (*SessionToken, error) {
	if cred == nil {
		return nil, fmt.Errorf("session mint without enrolled credential")
	}
	if cred.Kind != "webauthn" {
		return nil, fmt.Errorf("session mint credential %q is %s (want webauthn)", cred.ID, cred.Kind)
	}
	if rp.ID == "" || len(rp.Origins) == 0 {
		return nil, fmt.Errorf("session mint without relying party configuration")
	}
	if assertionB64 == "" {
		return nil, fmt.Errorf("session mint without authenticator assertion")
	}
	t := p.tokenForChallenge()
	t.CredentialID = cred.ID
	t.Assertion = assertionB64
	if err := t.verifyMintAssertion(cred, rp); err != nil {
		return nil, fmt.Errorf("session mint assertion: %w", err)
	}
	if err := t.sign(priv); err != nil {
		return nil, err
	}
	return t, nil
}

// verifyMintAssertion checks the embedded WebAuthn assertion
// against the enrolled credential and the mint challenge. It is
// shared by Finish (minter side) and the receiver verifier
// (policy.go): both must agree on what a valid mint ceremony is.
func (t *SessionToken) verifyMintAssertion(cred *Credential, rp WebAuthnRP) error {
	if t.CredentialID == "" || t.Assertion == "" {
		return fmt.Errorf("token without mint assertion")
	}
	if cred.ID != t.CredentialID {
		return fmt.Errorf("credential mismatch")
	}
	rawKey, err := b64.DecodeString(cred.PublicKey)
	if err != nil {
		return fmt.Errorf("credential key: %w", err)
	}
	pub, err := credentialKey(rawKey)
	if err != nil {
		return fmt.Errorf("credential key: %w", err)
	}
	challenge := t.mintChallenge()
	if _, err := verifyWebAuthnAssertion(pub, t.Assertion, challenge, rp, true); err != nil {
		return err
	}
	// No signature-counter enforcement here: the assertion is a
	// one-time mint ceremony, not a replayable approval. The
	// challenge binds this exact token (scope, lifetime, ids), so
	// the assertion cannot be re-wrapped onto another token, and
	// counter checks would only break multi-message sessions.
	return nil
}

// mintChallenge recomputes the challenge this token's assertion must
// be over: the SHA-256 of the canonical bytes with assertion and
// credential id zeroed. A receiver uses it to verify the embedded
// assertion independently of the issuer signature.
func (t *SessionToken) mintChallenge() []byte {
	blank := *t
	blank.Assertion = ""
	blank.CredentialID = ""
	canon, err := blank.canonical()
	if err != nil {
		// The token's own fields produced the canonical form when
		// minted; a failure here means the token is malformed and
		// will be rejected by Validate before this matters.
		return nil
	}
	sum := sha256.Sum256(canon)
	return sum[:]
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
	out = append(out, []byte(t.CredentialID)...)
	out = append(out, []byte{0}...)
	out = append(out, []byte(t.Assertion)...)
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
	// A token is only valid if it carries the mint ceremony's
	// authenticator assertion: without it the receiver has no
	// independent proof a human was involved, and the token is
	// rejected outright (it cannot be a v1 token — the version
	// check above already rules those out).
	if t.CredentialID == "" {
		return fmt.Errorf("session token without mint credential")
	}
	if t.Assertion == "" {
		return fmt.Errorf("session token without mint assertion")
	}
	if _, err := b64.DecodeString(t.Assertion); err != nil {
		return fmt.Errorf("session token assertion: %w", err)
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
