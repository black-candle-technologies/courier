package vhl

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"
)

// Challenge is a challenge-response ceremony record (issue #142).
// The ceremony authenticates the human to their *own device*: the
// device mints the challenge bound to the exact action hash, the
// one-time code travels out-of-band (e.g. Discord) to the human, and
// the human types it back into their device. The requesting agent
// never sees or verifies the code — if the agent requesting
// authorization also verified the code, a malicious agent would just
// claim the code arrived.
//
// On a correct code the device mints the Tier 2 attestation with a
// challenge proof. The receiver verifies the attestation signature
// offline; the challenge id rides along for audit.
type Challenge struct {
	Version    int    `json:"v"`
	ID         string `json:"id"`          // base64url 16 random bytes
	ActionHash string `json:"action_hash"` // base64url SHA256 of the exact action bytes
	CodeHash   string `json:"code_hash"`   // base64url SHA256(code); the code itself is never stored
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Used       bool   `json:"used,omitempty"`
}

const challengeVersion = 1

// ChallengeTTL bounds a challenge: codes are for rare sensitive
// actions, and a short window limits the useful life of an
// intercepted code.
const ChallengeTTL = 10 * time.Minute

// codeAlphabet avoids ambiguous characters (no 0/O, 1/l/I) so a
// human reading the code off one screen and typing it into another
// does not mis-transcribe it.
const codeAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

const challengeCodeLen = 8

// MintChallenge creates a challenge bound to the exact action bytes
// and returns the challenge plus the one-time code. The code is
// returned once, at mint; only its hash is retained. Deliver the
// code to the human out-of-band.
func MintChallenge(action []byte, ttl time.Duration) (*Challenge, string, error) {
	if len(action) == 0 {
		return nil, "", fmt.Errorf("cannot mint a challenge for empty action bytes")
	}
	if ttl <= 0 {
		ttl = ChallengeTTL
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, "", fmt.Errorf("rand: %w", err)
	}
	code := make([]byte, challengeCodeLen)
	var rb [challengeCodeLen]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return nil, "", fmt.Errorf("rand: %w", err)
	}
	for i := range code {
		code[i] = codeAlphabet[int(rb[i])%len(codeAlphabet)]
	}
	ah := sha256.Sum256(action)
	ch := sha256.Sum256(code)
	now := time.Now().Unix()
	c := &Challenge{
		Version:    challengeVersion,
		ID:         b64.EncodeToString(id[:]),
		ActionHash: b64.EncodeToString(ah[:]),
		CodeHash:   b64.EncodeToString(ch[:]),
		IssuedAt:   now,
		ExpiresAt:  now + int64(ttl/time.Second),
	}
	return c, string(code), nil
}

// ActionHash returns the raw action hash bytes.
func (c *Challenge) ActionHashBytes() ([]byte, error) {
	return b64.DecodeString(c.ActionHash)
}

// Verify checks a presented code against the challenge. It fails
// closed on expiry, reuse, or mismatch, and marks the challenge
// used — codes are single-use. Comparison is constant-time.
func (c *Challenge) Verify(code string, now int64) error {
	if c.Version != challengeVersion {
		return fmt.Errorf("challenge version %d (want %d)", c.Version, challengeVersion)
	}
	if c.Used {
		return fmt.Errorf("challenge already used")
	}
	if now < c.IssuedAt || now > c.ExpiresAt {
		return fmt.Errorf("challenge expired")
	}
	want, err := b64.DecodeString(c.CodeHash)
	if err != nil {
		return fmt.Errorf("challenge code_hash: %w", err)
	}
	got := sha256.Sum256([]byte(code))
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return fmt.Errorf("challenge code mismatch")
	}
	c.Used = true
	return nil
}

// BindsAction reports whether the challenge was minted for exactly
// these action bytes.
func (c *Challenge) BindsAction(action []byte) bool {
	ah := sha256.Sum256(action)
	want, err := b64.DecodeString(c.ActionHash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(ah[:], want) == 1
}
