package vhl

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// In-band VHL frame types. Frames ride inside the E2E-encrypted DM
// plaintext (like the FS/group/channel protocol frames): the relay
// sees ciphertext and metadata only, never approval plaintext.
//
//   - approval-request: agent -> human. "Here is the exact action I
//     want to take; please review and approve."
//   - attest: human -> agent (or agent -> recipient, when the
//     attestation is delivered standalone). Carries the Attestation.
//   - revoke: human -> counterparties. Revokes session tokens and/or
//     attestation ids.
const (
	FrameMagic = "courier-vhl"

	FrameApprovalRequest = "vhl-approval-request"
	FrameAttest          = "vhl-attest"
	FrameRevoke          = "vhl-revoke"
)

// frameVersion versions the frame envelope.
const frameVersion = 1

// Frame is the parsed VHL in-band frame.
type Frame struct {
	Type string
	// ApprovalRequest is set for FrameApprovalRequest.
	ApprovalRequest *ApprovalRequest
	// Attestation is set for FrameAttest.
	Attestation *Attestation
	// Revocation is set for FrameRevoke.
	Revocation *Revocation
}

// wireFrame is the JSON envelope.
type wireFrame struct {
	Magic   string          `json:"magic"`
	Type    string          `json:"t"`
	Version int             `json:"v"`
	Payload json.RawMessage `json:"p"`
}

// ApprovalRequest asks a human to review and approve an exact action
// (issue #142 §"Web approval flow", CLI form). The human's approval
// page/command MUST recompute the hash of the decrypted draft bytes
// and check it against MsgHash before displaying anything —
// what-you-see-is-what-you-sign, enforced in code.
type ApprovalRequest struct {
	ID           string `json:"id"`            // base64url 16 random bytes
	Tier         int    `json:"tier"`          // requested tier (1 or 2)
	MsgHash      string `json:"msg_hash"`      // base64url SHA256 of the exact draft bytes
	Draft        string `json:"draft"`         // the exact bytes the human reviews
	AgentNote    string `json:"agent_note"`    // agent's description (advisory only; the hash covers Draft)
	WantPresence string `json:"want_presence"` // minimum ceremony strength requested
	ExpiresAt    int64  `json:"expires_at"`    // unix seconds; unanswered requests die quietly
}

// Revocation broadcasts revoked token/attestation ids, signed by the
// issuer. Receivers add the ids to their revoked set; the ids stay
// listed until they would have expired anyway.
type Revocation struct {
	Version     int      `json:"v"`
	Issuer      string   `json:"issuer"` // approver address
	IssuedAt    int64    `json:"issued_at"`
	TokenIDs    []string `json:"token_ids,omitempty"`
	ArtifactIDs []string `json:"artifact_ids,omitempty"`
	Sig         string   `json:"sig"`
}

// revocationCanonical builds the signed bytes for a revocation.
func revocationCanonical(r *Revocation) ([]byte, error) {
	if r.Version != 1 {
		return nil, fmt.Errorf("revocation version %d (want 1)", r.Version)
	}
	out := make([]byte, 0, 128)
	out = append(out, revokeDomain...)
	out = append(out, byte(r.Version))
	out = append(out, []byte(r.Issuer)...)
	out = append(out, []byte{0}...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(r.IssuedAt))
	out = append(out, b[:]...)
	for _, id := range r.TokenIDs {
		out = append(out, []byte(id)...)
		out = append(out, []byte{0}...)
	}
	out = append(out, []byte{0xff}...)
	for _, id := range r.ArtifactIDs {
		out = append(out, []byte(id)...)
		out = append(out, []byte{0}...)
	}
	return out, nil
}

// encodeFrame marshals a typed frame.
func encodeFrame(typ string, payload any) ([]byte, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wireFrame{Magic: FrameMagic, Type: typ, Version: frameVersion, Payload: p})
}

// EncodeApprovalRequest builds an approval-request frame.
func EncodeApprovalRequest(r *ApprovalRequest) ([]byte, error) {
	return encodeFrame(FrameApprovalRequest, r)
}

// EncodeAttestation builds an attest frame.
func EncodeAttestation(a *Attestation) ([]byte, error) {
	return encodeFrame(FrameAttest, a)
}

// EncodeRevocation builds a revoke frame.
func EncodeRevocation(r *Revocation) ([]byte, error) {
	return encodeFrame(FrameRevoke, r)
}

// ParseFrame returns the VHL frame if plain is one, false otherwise.
// Only well-formed frames with the VHL magic and a recognized type
// are intercepted; anything else falls through as an ordinary
// message — never silently swallowed.
func ParseFrame(plain []byte) (*Frame, bool) {
	var w wireFrame
	if err := json.Unmarshal(plain, &w); err != nil {
		return nil, false
	}
	if w.Magic != FrameMagic || w.Version != frameVersion {
		return nil, false
	}
	f := &Frame{Type: w.Type}
	switch w.Type {
	case FrameApprovalRequest:
		var r ApprovalRequest
		if err := json.Unmarshal(w.Payload, &r); err != nil {
			return nil, false
		}
		f.ApprovalRequest = &r
	case FrameAttest:
		var a Attestation
		if err := json.Unmarshal(w.Payload, &a); err != nil {
			return nil, false
		}
		f.Attestation = &a
	case FrameRevoke:
		var r Revocation
		if err := json.Unmarshal(w.Payload, &r); err != nil {
			return nil, false
		}
		f.Revocation = &r
	default:
		return nil, false
	}
	return f, true
}

// Validate checks an approval request's structural invariants. It
// does not authenticate the requester — approval requests are
// untrusted input until the human reviews them.
func (r *ApprovalRequest) Validate(now int64) error {
	if r.Draft == "" || r.MsgHash == "" {
		return fmt.Errorf("approval request missing draft or hash")
	}
	idRaw, err := b64.DecodeString(r.ID)
	if err != nil {
		return fmt.Errorf("approval request id: %w", err)
	}
	if len(idRaw) != 16 {
		return fmt.Errorf("approval request id is %d bytes (want 16)", len(idRaw))
	}
	if r.Tier != 1 && r.Tier != 2 {
		return fmt.Errorf("approval request tier %d (want 1 or 2)", r.Tier)
	}
	if _, err := ParsePresence(r.WantPresence); err != nil {
		return fmt.Errorf("approval request: %w", err)
	}
	if r.ExpiresAt <= now {
		return fmt.Errorf("approval request expired")
	}
	// The human MUST check this before displaying anything.
	got := MsgHashOf([]byte(r.Draft))
	want, err := b64.DecodeString(r.MsgHash)
	if err != nil {
		return fmt.Errorf("approval request hash: %w", err)
	}
	if string(got[:]) != string(want) {
		return fmt.Errorf("approval request hash does not match draft bytes")
	}
	return nil
}

// NewRequestID mints a fresh approval-request id.
func NewRequestID() (string, error) { return NewAttestationID() }

// RequestTTL bounds an unanswered approval request.
const RequestTTL = 24 * time.Hour

// SignRevocation signs the revocation with the issuer's Ed25519 key.
func SignRevocation(r *Revocation, priv ed25519.PrivateKey) error {
	canon, err := revocationCanonical(r)
	if err != nil {
		return err
	}
	r.Sig = b64.EncodeToString(ed25519.Sign(priv, canon))
	return nil
}

// VerifyRevocationSignature checks the revocation's issuer signature.
func VerifyRevocationSignature(r *Revocation, pub []byte) error {
	canon, err := revocationCanonical(r)
	if err != nil {
		return err
	}
	sig, err := b64.DecodeString(r.Sig)
	if err != nil {
		return fmt.Errorf("sig: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bad key/signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canon, sig) {
		return fmt.Errorf("revocation signature invalid")
	}
	return nil
}
