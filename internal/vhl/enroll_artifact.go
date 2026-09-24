package vhl

import (
	"crypto/sha256"
	"encoding/binary"
)

// Approver-enrollment ceremony artifact (issue #142 review).
//
// Enrolling a trust root (an approver identity in the local
// registry) must be a human-controlled cryptographic ceremony, not
// a typed confirmation a compromised process driving a PTY could
// reproduce. The agent creates a relay-hosted WebAuthn assertion
// ceremony over ApproverEnrollmentChallenge(agent, approver, issuedAt);
// the human approves the pairing in their browser with their
// enrolled security key; the resulting assertion is the enrollment
// artifact. The registry validates the artifact — the challenge
// recomputes from the claimed addresses and timestamp, and the
// assertion verifies against the human's enrolled credential —
// before the identity is trusted.

var vhlEnrollApproverDomain = []byte("courier-vhl-enroll-approver-v1\x00")

// EnrollmentArtifact is the cryptographic proof that a human
// approved enrolling approverAddress as a trust root.
type EnrollmentArtifact struct {
	Address      string `json:"address"`       // approver address being enrolled
	AgentAddress string `json:"agent_address"` // local agent address authorizing the enrollment
	CredentialID string `json:"credential_id"` // human's WebAuthn credential that signed the assertion
	Challenge    string `json:"challenge"`     // base64url(ApproverEnrollmentChallenge(AgentAddress, Address, IssuedAt))
	Assertion    string `json:"assertion"`     // base64url JSON of the WebAuthn assertion
	IssuedAt     int64  `json:"issued_at"`     // unix time the challenge was created
}

// EnrollmentChallenge returns the WebAuthn challenge an
// approver-enrollment ceremony must answer: SHA-256 over the
// enrollment domain, the authorizing agent address, the approver
// address being enrolled, and the unix timestamp. Binding both
// addresses stops a ceremony for one pairing from authorizing
// another; the timestamp bounds the ceremony lifetime.
func ApproverEnrollmentChallenge(agentAddress, approverAddress string, issuedAt int64) [32]byte {
	h := sha256.New()
	h.Write(vhlEnrollApproverDomain)
	h.Write([]byte{0x00})
	h.Write([]byte(agentAddress))
	h.Write([]byte{0x00})
	h.Write([]byte(approverAddress))
	h.Write([]byte{0x00})
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(issuedAt))
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
