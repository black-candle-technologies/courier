// Package vhl implements VHL — Verified Human in the Loop (issue #142).
//
// Courier lets agents message each other, which means a malicious (or
// compromised) agent can send instructions that other agents follow. VHL
// is the countermeasure: a way to verify that an agent-sent message was
// actually reviewed and approved by a human.
//
// Core principle: approval is an attestation, enforced by the receiver.
// VHL is not a sending gate — it is a trust signal the receiving agent's
// policy acts on. An instruction from another agent that carries a valid
// human attestation can be acted on; one without it is not. Routine
// chatter flows unattested; anything instructing action on sensitive
// things carries the attestation; the receiver decides the threshold.
// Explicit human approval stays the default; autonomy is per-operator
// policy, never a protocol guarantee.
//
// Tiers (receiver-enforced):
//
//	Tier 0 — chat, status: unattested.
//	Tier 1 — routine instructions, file reads: session-token attestation.
//	Tier 2 — spending, merging/releasing, irreversible sends, anything
//	         policy marks sensitive: per-message human approval.
//
// Every message carries a small VHL tier tag (inside the E2E plaintext,
// so it is authenticated — no silent downgrades by a middlebox).
//
// Ceremony ladder (ranked, strongest first):
//
//	fido2_uv   — FIDO2/WebAuthn with user verification (key PIN/biometric).
//	             Required at the high tier: touch proves a human held the
//	             key; user verification proves the enrolled human did.
//	fido2      — FIDO2/WebAuthn with touch only.
//	challenge  — challenge-response one-time code delivered out-of-band
//	             (e.g. Discord), for rare sensitive actions only.
//	pin        — local-device presence (PIN-equivalent); low-friction fallback.
//
// Drawn signatures are ceremony/UX only: they do not prove human
// presence and are forgeable, so they are never a VHL proof kind.
//
// The approval artifact (Attestation) carries the message/action hash,
// the tier, the approver identity, a timestamp, and the human-presence
// proof, signed by a key bound to the enrolled approver identity.
// Artifacts travel in-band as native Courier message types (see frame.go)
// and are retained on the audit trail.
//
// The relay never sees approval plaintext — approval metadata only,
// same as all relay metadata. The relay needs no changes for VHL.
package vhl

import "fmt"

// Tier is the VHL attestation tier covering a message. Tier tags ride
// inside the E2E plaintext, so a middlebox can neither forge nor strip
// them — a missing tag means tier 0, never a higher tier.
type Tier int

const (
	// Tier0 covers chat and status traffic. Unattested.
	Tier0 Tier = 0
	// Tier1 covers routine instructions and file reads. Attested by a
	// session token (see token.go).
	Tier1 Tier = 1
	// Tier2 covers spending, merging/releasing, irreversible sends, and
	// anything the receiver's policy marks sensitive. Attested by a
	// per-message human approval (see artifact.go).
	Tier2 Tier = 2
)

// Valid reports whether t is a defined tier.
func (t Tier) Valid() bool { return t >= Tier0 && t <= Tier2 }

// String names the tier for logs and audit trails.
func (t Tier) String() string {
	switch t {
	case Tier0:
		return "tier0/chat"
	case Tier1:
		return "tier1/session"
	case Tier2:
		return "tier2/approval"
	default:
		return fmt.Sprintf("tier%d/unknown", int(t))
	}
}

// PresenceStrength ranks human-presence ceremonies, strongest first.
// Session-token re-mint requires the same strength or stronger — a
// FIDO2-born token must never be renewable with a PIN (no downgrade
// path, issue #142).
type PresenceStrength int

const (
	// PresencePIN is local-device presence (PIN-equivalent): the human
	// operated their own enrolled device. Low-friction fallback.
	PresencePIN PresenceStrength = 0
	// PresenceChallenge is a challenge-response one-time code delivered
	// out-of-band. For rare sensitive actions only — frequent use
	// trains fatigue, and fatigue kills the security.
	PresenceChallenge PresenceStrength = 1
	// PresenceFIDO2 is a FIDO2/WebAuthn assertion with touch. Proves a
	// human held the key.
	PresenceFIDO2 PresenceStrength = 2
	// PresenceFIDO2UV is a FIDO2/WebAuthn assertion with user
	// verification (key PIN/biometric). Proves the enrolled human did
	// it. Required at the high tier.
	PresenceFIDO2UV PresenceStrength = 3
)

// ParsePresence parses a presence-strength name.
func ParsePresence(s string) (PresenceStrength, error) {
	switch s {
	case "pin":
		return PresencePIN, nil
	case "challenge":
		return PresenceChallenge, nil
	case "fido2":
		return PresenceFIDO2, nil
	case "fido2_uv":
		return PresenceFIDO2UV, nil
	default:
		return PresencePIN, fmt.Errorf("unknown presence strength %q (want pin|challenge|fido2|fido2_uv)", s)
	}
}

// String names the strength for artifacts and audit trails.
func (p PresenceStrength) String() string {
	switch p {
	case PresencePIN:
		return "pin"
	case PresenceChallenge:
		return "challenge"
	case PresenceFIDO2:
		return "fido2"
	case PresenceFIDO2UV:
		return "fido2_uv"
	default:
		return "unknown"
	}
}

// AtLeast reports whether p is at least as strong as min.
func (p PresenceStrength) AtLeast(min PresenceStrength) bool { return p >= min }

// Valid reports whether p names a real ceremony.
func (p PresenceStrength) Valid() bool {
	switch p {
	case PresencePIN, PresenceChallenge, PresenceFIDO2, PresenceFIDO2UV:
		return true
	}
	return false
}
