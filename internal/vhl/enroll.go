package vhl

import (
	"fmt"
	"time"
)

// Credential is one enrolled human-presence credential for an
// approver. The trust root is the local receiver registry — a shared
// directory may exist for discovery but is strictly advisory and can
// never override local enrollment (directory poisoning then buys an
// attacker nothing, issue #142).
type Credential struct {
	// ID names the credential: for "ed25519" it is the Courier
	// address; for "webauthn" it is the base64url credential id.
	ID string `json:"id"`
	// Kind is "ed25519" (approver's Courier identity key) or
	// "webauthn" (a WebAuthn credential enrolled alongside it).
	Kind string `json:"kind"`
	// PublicKey is base64url-encoded key material. For "ed25519" it
	// is the 32-byte Ed25519 key; for "webauthn" it is the
	// credential public key in the enrollment record format.
	PublicKey  string `json:"public_key"`
	EnrolledAt int64  `json:"enrolled_at"`
	// Device labels the human's device ("yubikey", "laptop-passkey",
	// "this-machine"). Per-device enrollment is allowed so
	// revocation is surgical.
	Device string `json:"device,omitempty"`
	// AAGUID optionally records the authenticator model for audit.
	AAGUID string `json:"aaguid,omitempty"`
	// SignCount is the latest WebAuthn authenticator signature
	// counter seen for this credential (webauthn credentials only).
	// The verifier requires the counter to strictly increase per
	// credential as the FIDO2 assertion-replay control (a captured
	// assertion re-wrapped in a fresh attestation still carries the
	// old counter and is rejected). Authenticators without a
	// counter report 0 forever; 0 is only accepted when the stored
	// value is also 0, per the WebAuthn spec.
	SignCount uint32 `json:"sign_count,omitempty"`
}

// Approver is one enrolled human in the local registry.
type Approver struct {
	// Identity is the human's Courier address.
	Identity string `json:"identity"`
	// Name is a local display label, never trusted for identity.
	Name        string       `json:"name,omitempty"`
	Credentials []Credential `json:"credentials"`
	EnrolledAt  int64        `json:"enrolled_at"`
	// EnrolledTier2 records that enrollment happened as a Tier 2
	// human-approved event during pairing (issue #142). The registry
	// is populated by the human operator directly; agent-driven
	// enrollment must itself carry a Tier 2 attestation.
	EnrolledTier2 bool `json:"enrolled_tier2"`
	Revoked       bool `json:"revoked,omitempty"`
}

// Registry is the local approver enrollment registry.
type Registry struct {
	Approvers map[string]*Approver `json:"approvers"` // identity -> approver
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{Approvers: map[string]*Approver{}}
}

// Enroll adds or updates an approver. tier2HumanApproved must be true:
// enrollment is a Tier 2 human-approved event (during pairing, that is
// the human operator running the command themselves).
func (r *Registry) Enroll(identity, name string, cred Credential, tier2HumanApproved bool) error {
	if identity == "" {
		return fmt.Errorf("cannot enroll an empty identity")
	}
	if !tier2HumanApproved {
		return fmt.Errorf("enrollment requires a Tier 2 human-approved event")
	}
	if cred.ID == "" || cred.PublicKey == "" {
		return fmt.Errorf("credential needs an id and a public key")
	}
	switch cred.Kind {
	case "ed25519", "webauthn":
	default:
		return fmt.Errorf("unknown credential kind %q", cred.Kind)
	}
	if r.Approvers == nil {
		r.Approvers = map[string]*Approver{}
	}
	a := r.Approvers[identity]
	now := time.Now().Unix()
	if a == nil {
		a = &Approver{Identity: identity, EnrolledAt: now, EnrolledTier2: true}
		r.Approvers[identity] = a
	}
	if name != "" {
		a.Name = name
	}
	if a.Revoked {
		// Re-enrolling a revoked approver starts from a clean
		// slate: the old credentials were revoked as compromised
		// (or at least untrusted), and silently resurrecting them
		// would let KeysFor return a previously compromised key.
		// Re-enrolling a non-revoked approver preserves existing
		// credentials (the loop below replaces by id).
		a.Credentials = nil
	}
	a.Revoked = false
	if cred.EnrolledAt == 0 {
		cred.EnrolledAt = now
	}
	for i, c := range a.Credentials {
		if c.ID == cred.ID && c.Kind == cred.Kind {
			// Re-enrollment must never rewind the FIDO2
			// signature counter: keep the greater of the
			// stored and incoming values.
			if c.SignCount > cred.SignCount {
				cred.SignCount = c.SignCount
			}
			a.Credentials[i] = cred
			return nil
		}
	}
	a.Credentials = append(a.Credentials, cred)
	return nil
}

// RevokeCredential surgically revokes one credential of an approver.
func (r *Registry) RevokeCredential(identity, credID string) error {
	a := r.Approvers[identity]
	if a == nil {
		return fmt.Errorf("approver %q is not enrolled", identity)
	}
	kept := a.Credentials[:0]
	found := false
	for _, c := range a.Credentials {
		if c.ID == credID {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		return fmt.Errorf("credential %q not enrolled for %q", credID, identity)
	}
	a.Credentials = kept
	return nil
}

// RevokeApprover revokes all credentials of an approver.
func (r *Registry) RevokeApprover(identity string) error {
	a := r.Approvers[identity]
	if a == nil {
		return fmt.Errorf("approver %q is not enrolled", identity)
	}
	a.Revoked = true
	return nil
}

// KeysFor returns the enrolled, unrevoked Ed25519 public keys for an
// approver identity, for attestation/token signature verification.
// WebAuthn credentials are returned separately: their assertions
// verify under the WebAuthn ceremony (dashboard flow, follow-up), not
// raw Ed25519.
func (r *Registry) KeysFor(identity string) (edKeys [][]byte, webAuthn []Credential, err error) {
	a := r.Approvers[identity]
	if a == nil {
		return nil, nil, fmt.Errorf("approver %q is not enrolled", identity)
	}
	if a.Revoked {
		return nil, nil, fmt.Errorf("approver %q is revoked", identity)
	}
	for _, c := range a.Credentials {
		switch c.Kind {
		case "ed25519":
			pub, derr := b64.DecodeString(c.PublicKey)
			if derr != nil {
				return nil, nil, fmt.Errorf("credential %q: %w", c.ID, derr)
			}
			edKeys = append(edKeys, pub)
		case "webauthn":
			webAuthn = append(webAuthn, c)
		}
	}
	if len(edKeys) == 0 && len(webAuthn) == 0 {
		return nil, nil, fmt.Errorf("approver %q has no usable credentials", identity)
	}
	return edKeys, webAuthn, nil
}

// NoteSignCount records the latest authenticator signature counter
// seen for a WebAuthn credential. The caller must have already
// decided the new count is acceptable (strictly increasing, or 0/0
// for counter-less authenticators); this only persists the value so
// the next assertion is checked against it.
func (r *Registry) NoteSignCount(identity, credID string, n uint32) {
	a := r.Approvers[identity]
	if a == nil {
		return
	}
	for i := range a.Credentials {
		if a.Credentials[i].ID == credID {
			a.Credentials[i].SignCount = n
			return
		}
	}
}

// Enrolled reports whether identity is an enrolled, unrevoked approver.
func (r *Registry) Enrolled(identity string) bool {
	a := r.Approvers[identity]
	return a != nil && !a.Revoked && len(a.Credentials) > 0
}
