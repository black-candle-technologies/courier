package vhl

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Tier 2 approval nonce binding (issue #142 review).
//
// The WebAuthn challenge for a Tier 2 approval is
// ApprovalChallenge(actionHash, nonce): the SHA-256 of a domain
// separator, the action hash, and a fresh 32-byte nonce generated
// per approval. The nonce is embedded in the attestation
// (Attestation.ApprovalNonce, base64url) and covered by the
// attestation's Ed25519 signature, so a captured assertion cannot
// be re-wrapped in a fresh attestation: the receiver recomputes the
// challenge from the signed nonce and rejects any nonce already
// consumed (see NonceSet). The deterministic action-hash-only
// challenge it replaces allowed unbounded replay against
// counterless authenticators and concurrent verifiers.

var vhlApproveDomain = []byte("courier-vhl-approve-v1\x00")

// ApprovalChallenge returns the WebAuthn challenge a Tier 2
// approval assertion must answer: SHA-256 over the approval domain,
// the action hash, and the fresh per-approval nonce.
func ApprovalChallenge(actionHash, nonce []byte) [32]byte {
	h := sha256.New()
	h.Write(vhlApproveDomain)
	h.Write([]byte{0x00})
	h.Write(actionHash)
	h.Write(nonce)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ApprovalNonceKey returns the receiver-side replay key for one
// approval: the approver identity bound to the base64url nonce.
// Two different approvers never collide; the same nonce from the
// same approver is a replay.
func ApprovalNonceKey(approver, nonceB64 string) string {
	return approver + "\x00" + nonceB64
}

// DecodeApprovalNonce decodes the base64url approval nonce carried
// in an attestation, requiring exactly 32 bytes.
func DecodeApprovalNonce(nonceB64 string) ([]byte, error) {
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	if len(nonce) != 32 {
		return nil, errApprovalNonceLength
	}
	return nonce, nil
}

// errApprovalNonceLength reports a malformed approval nonce.
var errApprovalNonceLength = errors.New("vhl: approval nonce must be 32 bytes")
