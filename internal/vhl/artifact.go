package vhl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

var b64 = base64.RawURLEncoding

// Attestation wire version. Versioned so future proof kinds can extend
// the schema without breaking old verifiers (unknown versions are
// rejected loudly, never parsed optimistically). The canonical form
// length-prefixes every variable field in the canonical bytes.
const attestationVersion = 2

// Domain separators keep VHL signatures distinct from every other use
// of an approver's Ed25519 key: a signature for one can never validate
// as another. The "-v1" suffix is the scheme version; the separator is
// shared across attestation versions because the version byte in the
// canonical form already disambiguates them.
var (
	attestDomain = []byte("courier-vhl-attest-v1\x00")
	tokenDomain  = []byte("courier-vhl-token-v1\x00")
	revokeDomain = []byte("courier-vhl-revoke-v1\x00")
)

// ProofKind names the human-presence proof carried by an attestation.
type ProofKind string

const (
	// ProofSession references a session token (Tier 1). The signed
	// token is embedded — never a bare token id.
	ProofSession ProofKind = "session"
	// ProofFIDO2 carries a WebAuthn assertion. The challenge is the
	// action hash (what-you-sign-is-what-you-saw).
	ProofFIDO2 ProofKind = "fido2"
	// ProofChallenge references a challenge-response ceremony: the
	// one-time code was minted and verified on the human's own device,
	// outside the requesting agent.
	ProofChallenge ProofKind = "challenge"
	// ProofPIN records local-device presence (PIN-equivalent).
	ProofPIN ProofKind = "pin"
)

// Strength maps a proof kind to the maximum ceremony strength that
// kind can deliver. It is the ceiling for the claimed strength in
// Attestation.Validate: a proof must never claim more than its kind
// can prove (a PIN proof claiming fido2_uv would otherwise skip FIDO2
// verification while the receiver trusts the claim). FIDO2 covers
// both touch-only and user-verified ceremonies; the claimed strength
// picks which, and the UV flag is cryptographically enforced when
// fido2_uv is claimed.
func (k ProofKind) Strength() PresenceStrength {
	switch k {
	case ProofFIDO2:
		return PresenceFIDO2UV
	case ProofChallenge:
		return PresenceChallenge
	case ProofPIN:
		return PresencePIN
	default:
		return PresencePIN - 1 // invalid: weaker than everything
	}
}

// Proof is the human-presence evidence inside an attestation. Exactly
// one kind's fields are populated; the signer key is always bound to
// the enrolled approver identity (without key binding, the artifact is
// portable across keys).
type Proof struct {
	Kind ProofKind `json:"kind"`
	// Strength is the ceremony strength, ranked by PresenceStrength.
	// For session proofs this is the strength at token mint.
	Strength string `json:"strength"`
	// Session: the signed session token (Tier 1). Embedded whole —
	// the receiver verifies the issuer signature offline.
	Token *SessionToken `json:"token,omitempty"`
	// FIDO2: enrolled credential id plus the base64url WebAuthn
	// assertion JSON. The assertion challenge must be the action
	// hash. (Ceremony/dashboard flow: follow-up; the schema is
	// stable now so artifacts stay forward-compatible.)
	CredentialID string `json:"credential_id,omitempty"`
	Assertion    string `json:"assertion,omitempty"`
	// Challenge: the challenge id minted on the human's device for
	// this action. The code itself never appears in the artifact.
	ChallengeID string `json:"challenge_id,omitempty"`
}

// Attestation is the VHL approval artifact (issue #142). It travels
// in-band as a native Courier message type and is retained on the
// audit trail.
//
// Tier 2 attestations bind MsgHash: SHA256 over the exact message
// body bytes the human reviewed. Tier 1 attestations carry the
// session token instead and leave MsgHash empty (session-scoped, not
// per-message).
type Attestation struct {
	Version   int    `json:"v"`
	ID        string `json:"id"`         // base64url 16 random bytes; the replay-set key
	Tier      int    `json:"tier"`       // 1 or 2
	MsgHash   string `json:"msg_hash"`   // base64url SHA256 of reviewed body bytes (tier 2)
	Approver  string `json:"approver"`   // Courier address of the human approver
	IssuedAt  int64  `json:"issued_at"`  // unix seconds
	ExpiresAt int64  `json:"expires_at"` // unix seconds; tier 2 is short-lived
	Proof     Proof  `json:"proof"`
	RequestID string `json:"request_id,omitempty"` // approval-request this answers, if any
	// ApprovalNonce is the base64url-encoded 32-byte fresh nonce
	// for a Tier 2 FIDO2 approval (issue #142 review). The
	// WebAuthn challenge is ApprovalChallenge(actionHash, nonce);
	// the nonce is covered by the attestation signature and the
	// receiver consumes it exactly once (see NonceSet), so a
	// captured assertion re-wrapped in a fresh attestation is
	// still a replay. Empty for non-FIDO2 proofs.
	ApprovalNonce string `json:"approval_nonce,omitempty"`
	Sig           string `json:"sig"` // base64url Ed25519 by the approver key
}

// MsgHashOf hashes the exact message body bytes the human reviewed.
// The hash covers the body text only — not the envelope, not the
// attestation itself (which would be circular). The receiver
// recomputes it over the received body and compares.
func MsgHashOf(body []byte) [32]byte { return sha256.Sum256(body) }

// attestationCanonical builds the signed bytes for an attestation.
// Every field that matters to a verifier is covered; nothing is
// left to unsigned JSON parsing. The canonical form
// length-prefixes every variable-length field so field boundaries
// are unambiguous.
func attestationCanonical(a *Attestation) ([]byte, error) {
	switch a.Version {
	case attestationVersion:
		return attestationCanonicalV2(a)
	default:
		return nil, fmt.Errorf("attestation version %d (want %d)", a.Version, attestationVersion)
	}
}

// lpField appends a length-prefixed field: an 8-byte big-endian
// length followed by the bytes. Fixed-width fields (version, tier,
// timestamps) need no prefix; everything variable-length gets one.
func lpField(out, b []byte) []byte {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	out = append(out, l[:]...)
	return append(out, b...)
}

// attestationCanonicalV2 is the current canonical form: every
// variable-length field is length-prefixed so no two distinct field
// tuples can sign identical bytes.
func attestationCanonicalV2(a *Attestation) ([]byte, error) {
	msgHash, err := b64.DecodeString(a.MsgHash)
	if err != nil && a.MsgHash != "" {
		return nil, fmt.Errorf("msg_hash: %w", err)
	}
	if a.MsgHash != "" && len(msgHash) != 32 {
		return nil, fmt.Errorf("msg_hash: want 32 bytes, got %d", len(msgHash))
	}
	id, err := b64.DecodeString(a.ID)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	out := make([]byte, 0, 256)
	out = append(out, attestDomain...)
	out = append(out, byte(a.Version))
	out = append(out, byte(a.Tier))
	out = lpField(out, id)
	out = lpField(out, msgHash)
	out = lpField(out, []byte(a.Approver))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(a.IssuedAt))
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], uint64(a.ExpiresAt))
	out = append(out, b[:]...)
	out = lpField(out, []byte(a.Proof.Kind))
	out = lpField(out, []byte(a.Proof.Strength))
	switch a.Proof.Kind {
	case ProofSession:
		if a.Proof.Token == nil {
			return nil, fmt.Errorf("session proof without token")
		}
		tc, err := a.Proof.Token.canonical()
		if err != nil {
			return nil, err
		}
		out = lpField(out, tc)
	case ProofFIDO2:
		out = lpField(out, []byte(a.Proof.CredentialID))
		out = lpField(out, []byte(a.Proof.Assertion))
	case ProofChallenge:
		out = lpField(out, []byte(a.Proof.ChallengeID))
	case ProofPIN:
		// Presence is the ceremony; nothing further to bind.
	default:
		return nil, fmt.Errorf("unknown proof kind %q", a.Proof.Kind)
	}
	out = lpField(out, []byte(a.RequestID))
	return out, nil
}

// SignAttestation signs the attestation with the approver's Ed25519
// private key, filling Sig. The caller must have already populated
// every other field.
func SignAttestation(a *Attestation, priv ed25519.PrivateKey) error {
	canon, err := attestationCanonical(a)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, canon)
	a.Sig = b64.EncodeToString(sig)
	return nil
}

// VerifyAttestationSignature checks the attestation's signature under
// the approver's public key. It does not check enrollment, expiry, or
// replay — see policy.go for the full verification.
func VerifyAttestationSignature(a *Attestation, pub []byte) error {
	canon, err := attestationCanonical(a)
	if err != nil {
		return err
	}
	sig, err := b64.DecodeString(a.Sig)
	if err != nil {
		return fmt.Errorf("sig: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bad key/signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canon, sig) {
		return fmt.Errorf("attestation signature invalid")
	}
	return nil
}

// NewAttestationID mints a fresh random attestation id.
func NewAttestationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b64.EncodeToString(b[:]), nil
}

// NewTier1Attestation wraps a live session token in a fresh
// per-message attestation. The token attests the session; the
// attestation id makes each message's artifact unique for the
// replay set.
func NewTier1Attestation(tok *SessionToken, priv ed25519.PrivateKey) (*Attestation, error) {
	if err := tok.Validate(); err != nil {
		return nil, fmt.Errorf("cannot attest with invalid token: %w", err)
	}
	id, err := NewAttestationID()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	a := &Attestation{
		Version:   attestationVersion,
		ID:        id,
		Tier:      1,
		Approver:  tok.Issuer,
		IssuedAt:  now,
		ExpiresAt: tok.ExpiresAt,
		Proof: Proof{
			Kind:     ProofSession,
			Strength: tok.Presence,
			Token:    tok,
		},
	}
	if err := SignAttestation(a, priv); err != nil {
		return nil, err
	}
	return a, nil
}

// NewTier2Attestation mints a per-message human approval for the
// exact body bytes reviewed. presence names the ceremony that just
// happened; kind selects the proof shape (fido2, challenge, or pin).
// requestID binds the approval to the request that carried the draft;
// it is part of the signed bytes, so it must be set before signing.
func NewTier2Attestation(body []byte, approver string, requestID string, kind ProofKind, presence PresenceStrength, proofExtras Proof, priv ed25519.PrivateKey) (*Attestation, error) {
	switch kind {
	case ProofFIDO2, ProofChallenge, ProofPIN:
	default:
		return nil, fmt.Errorf("tier 2 proof kind %q invalid (want fido2|challenge|pin)", kind)
	}
	if approver == "" {
		return nil, fmt.Errorf("tier 2 attestation without approver")
	}
	id, err := NewAttestationID()
	if err != nil {
		return nil, err
	}
	h := MsgHashOf(body)
	now := time.Now().Unix()
	proofExtras.Kind = kind
	proofExtras.Strength = presence.String()
	a := &Attestation{
		Version:   attestationVersion,
		ID:        id,
		Tier:      2,
		MsgHash:   b64.EncodeToString(h[:]),
		Approver:  approver,
		RequestID: requestID,
		IssuedAt:  now,
		ExpiresAt: now + int64(Tier2Expiry/time.Second),
		Proof:     proofExtras,
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if err := SignAttestation(a, priv); err != nil {
		return nil, err
	}
	return a, nil
}

// Tier2Expiry is the default lifetime of a Tier 2 attestation: long
// enough for the agent to send the approved message, short enough
// that a stolen artifact is quickly useless. Deny/timeout fail closed.
const Tier2Expiry = 15 * time.Minute

// Validate checks the attestation's structural invariants without
// touching signatures or enrollment.
func (a *Attestation) Validate() error {
	if a.Version != attestationVersion {
		return fmt.Errorf("attestation version %d (want %d)", a.Version, attestationVersion)
	}
	if a.Tier != 1 && a.Tier != 2 {
		return fmt.Errorf("attestation tier %d (want 1 or 2)", a.Tier)
	}
	if a.Approver == "" {
		return fmt.Errorf("attestation without approver")
	}
	if a.IssuedAt <= 0 || a.ExpiresAt <= a.IssuedAt {
		return fmt.Errorf("attestation has invalid lifetime")
	}
	idRaw, err := b64.DecodeString(a.ID)
	if err != nil {
		return fmt.Errorf("attestation id: %w", err)
	}
	if len(idRaw) != 16 {
		return fmt.Errorf("attestation id is %d bytes (want 16)", len(idRaw))
	}
	switch ProofKind(a.Proof.Kind) {
	case ProofSession:
		if a.Tier != 1 {
			return fmt.Errorf("session proof on tier %d attestation", a.Tier)
		}
		if a.Proof.Token == nil {
			return fmt.Errorf("session proof without token")
		}
		if err := a.Proof.Token.Validate(); err != nil {
			return fmt.Errorf("session token: %w", err)
		}
	case ProofFIDO2, ProofChallenge, ProofPIN:
		if a.Tier != 2 {
			return fmt.Errorf("%s proof on tier %d attestation", a.Proof.Kind, a.Tier)
		}
		if a.MsgHash == "" {
			return fmt.Errorf("tier 2 attestation without message hash")
		}
		if a.Proof.Kind == ProofFIDO2 && a.Proof.CredentialID == "" {
			return fmt.Errorf("fido2 proof without credential id")
		}
		if a.Proof.Kind == ProofChallenge && a.Proof.ChallengeID == "" {
			return fmt.Errorf("challenge proof without challenge id")
		}
	default:
		return fmt.Errorf("unknown proof kind %q", a.Proof.Kind)
	}
	claimed, err := ParsePresence(a.Proof.Strength)
	if err != nil {
		return fmt.Errorf("proof strength: %w", err)
	}
	// The claimed strength must not exceed what the proof kind can
	// deliver. Without this, a PIN proof could claim fido2_uv and
	// the receiver would trust the claim while skipping FIDO2
	// verification entirely.
	if a.Proof.Kind == ProofSession {
		// Session proofs are bound to the token: the claimed
		// strength is exactly the strength at token mint.
		if a.Proof.Token == nil {
			return fmt.Errorf("session proof without token")
		}
		if a.Proof.Strength != a.Proof.Token.Presence {
			return fmt.Errorf("session proof strength %q does not match token presence %q", a.Proof.Strength, a.Proof.Token.Presence)
		}
	} else if ceiling := a.Proof.Kind.Strength(); !ceiling.Valid() || claimed > ceiling {
		return fmt.Errorf("proof strength %q exceeds %s proof maximum %q", a.Proof.Strength, a.Proof.Kind, ceiling)
	}
	return nil
}
