package vhl

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// schemaTier2 is for tests of outer signature/framing gates, not a verified assertion.
func schemaTier2(body []byte, addr, requestID string, priv ed25519.PrivateKey) (*Attestation, error) {
	return NewTier2Attestation(body, addr, requestID, ProofFIDO2, PresenceFIDO2UV, Proof{CredentialID: "test-cred"}, make([]byte, 32), priv)
}

// legacyTier2 models an already-stored artifact without using the now-closed mint API.
func legacyTier2(t *testing.T, body []byte, addr string, kind ProofKind, priv ed25519.PrivateKey) *Attestation {
	t.Helper()
	a, err := schemaTier2(body, addr, "legacy-request", priv)
	if err != nil {
		t.Fatal(err)
	}
	a.Proof = Proof{Kind: kind, Strength: kind.Strength().String(), ChallengeID: "old-challenge"}
	a.ApprovalNonce = ""
	if err := SignAttestation(a, priv); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestTier2HardwareGate(t *testing.T) {
	addr, _, priv := testIdentity(t)
	for _, kind := range []ProofKind{ProofPIN, ProofChallenge} {
		t.Run(string(kind), func(t *testing.T) {
			if _, err := NewTier2Attestation([]byte("action"), addr, "request", kind, kind.Strength(), Proof{ChallengeID: "old"}, nil, priv); err == nil {
				t.Fatal("typed proof minted")
			}
			a := legacyTier2(t, []byte("action"), addr, kind, priv)
			if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "requires FIDO2") {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
	if _, err := NewTier2Attestation([]byte("action"), addr, "request", ProofFIDO2, PresenceFIDO2, Proof{CredentialID: "test-cred"}, make([]byte, 32), priv); err == nil {
		t.Fatal("UP-only proof minted")
	}
	a, err := schemaTier2([]byte("action"), addr, "request", priv)
	if err != nil {
		t.Fatal(err)
	}
	a.Proof.Strength = PresenceFIDO2.String()
	if err := a.Validate(); err == nil {
		t.Fatal("UP-only artifact accepted")
	}
	id, _ := NewRequestID()
	h := MsgHashOf([]byte("action"))
	for _, p := range []string{"pin", "challenge", "fido2"} {
		r := &ApprovalRequest{ID: id, Tier: 2, Draft: "action", MsgHash: b64.EncodeToString(h[:]), WantPresence: p, ExpiresAt: time.Now().Add(time.Hour).Unix()}
		if err := r.Validate(time.Now().Unix()); err == nil {
			t.Fatalf("request accepted %s", p)
		}
	}
}
