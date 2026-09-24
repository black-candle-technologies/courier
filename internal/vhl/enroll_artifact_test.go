package vhl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// enrollArtifactFixture enrolls the local human's WebAuthn ceremony
// credential and returns the registry, the credential private key,
// and the test RP. The human's own Courier identity is humanAddr.
func enrollArtifactFixture(t *testing.T, reg *Registry, humanAddr string) (*ecdsa.PrivateKey, string, WebAuthnRP) {
	t.Helper()
	credPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := "enroll-ceremony-cred"
	if err := reg.Enroll(humanAddr, "operator", Credential{
		ID:         credID,
		Kind:       "webauthn",
		PublicKey:  b64.EncodeToString(coseEncodeKey(t, &credPriv.PublicKey)),
		EnrolledAt: time.Now().Unix(),
		Device:     "yubikey",
	}); err != nil {
		t.Fatal(err)
	}
	rp := WebAuthnRP{ID: "dashboard.test", Origins: []string{"https://dashboard.test"}}
	return credPriv, credID, rp
}

// makeEnrollArtifact builds a well-formed enrollment artifact for
// (agentAddr -> approverAddr), signed by credPriv over the correct
// enrollment challenge with user verification.
func makeEnrollArtifact(t *testing.T, credPriv *ecdsa.PrivateKey, credID, agentAddr, approverAddr string, issuedAt int64) *EnrollmentArtifact {
	t.Helper()
	challenge := ApproverEnrollmentChallenge(agentAddr, approverAddr, issuedAt)
	assertion := craftAssertion(t, credPriv, challenge[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	return &EnrollmentArtifact{
		Address:      approverAddr,
		AgentAddress: agentAddr,
		CredentialID: credID,
		Challenge:    b64.EncodeToString(challenge[:]),
		Assertion:    assertion,
		IssuedAt:     issuedAt,
	}
}

func TestEnrollWithArtifact(t *testing.T) {
	humanAddr, _, _ := testIdentity(t)
	agentAddr, _, _ := testIdentity(t)
	approverAddr, approverPub, _ := testIdentity(t)
	reg := NewRegistry()
	credPriv, credID, rp := enrollArtifactFixture(t, reg, humanAddr)
	issuedAt := time.Now().Unix()
	art := makeEnrollArtifact(t, credPriv, credID, agentAddr, approverAddr, issuedAt)

	if err := reg.EnrollWithArtifact(approverAddr, "approver", Credential{
		ID: approverAddr, Kind: "ed25519", PublicKey: b64.EncodeToString(approverPub),
	}, agentAddr, art, rp, issuedAt); err != nil {
		t.Fatalf("EnrollWithArtifact: %v", err)
	}
	if !reg.Enrolled(approverAddr) {
		t.Fatal("approver should be enrolled")
	}
	keys, _, err := reg.KeysFor(approverAddr)
	if err != nil || len(keys) != 1 || string(keys[0]) != string(approverPub) {
		t.Fatalf("enrolled key mismatch: %v", err)
	}
	// The ceremony credential's signature counter advanced.
	var stored uint32
	for _, a := range reg.Approvers {
		for _, c := range a.Credentials {
			if c.ID == credID {
				stored = c.SignCount
			}
		}
	}
	if stored != 1 {
		t.Fatalf("sign count = %d, want 1 (the assertion's counter)", stored)
	}
}

func TestEnrollWithArtifactRejects(t *testing.T) {
	humanAddr, _, _ := testIdentity(t)
	agentAddr, _, _ := testIdentity(t)
	approverAddr, approverPub, _ := testIdentity(t)
	otherAddr, _, _ := testIdentity(t)

	setup := func(t *testing.T) (*Registry, *ecdsa.PrivateKey, string, WebAuthnRP, *EnrollmentArtifact, Credential) {
		reg := NewRegistry()
		credPriv, credID, rp := enrollArtifactFixture(t, reg, humanAddr)
		issuedAt := time.Now().Unix()
		art := makeEnrollArtifact(t, credPriv, credID, agentAddr, approverAddr, issuedAt)
		cred := Credential{ID: approverAddr, Kind: "ed25519", PublicKey: b64.EncodeToString(approverPub)}
		return reg, credPriv, credID, rp, art, cred
	}

	t.Run("nil artifact", func(t *testing.T) {
		reg, _, _, rp, _, cred := setup(t)
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, nil, rp, time.Now().Unix()); err == nil {
			t.Fatal("nil artifact should fail")
		}
	})
	t.Run("wrong approver address", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		if err := reg.EnrollWithArtifact(otherAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("artifact for another approver should fail")
		}
	})
	t.Run("wrong agent address", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, otherAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("artifact authorized by another agent should fail")
		}
	})
	t.Run("tampered challenge", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		art.Challenge = b64.EncodeToString(make([]byte, 32))
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("tampered challenge should fail")
		}
	})
	t.Run("expired artifact", func(t *testing.T) {
		reg, credPriv, credID, rp, _, cred := setup(t)
		issuedAt := time.Now().Unix() - 400
		art := makeEnrollArtifact(t, credPriv, credID, agentAddr, approverAddr, issuedAt)
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("expired artifact should fail")
		}
	})
	t.Run("unknown ceremony credential", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		art.CredentialID = "no-such-cred"
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("unknown ceremony credential should fail")
		}
	})
	t.Run("non-webauthn ceremony credential", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		// Point the artifact at an enrolled ed25519 identity
		// credential instead of the human's security key.
		if err := reg.Enroll(humanAddr, "operator", Credential{
			ID: humanAddr, Kind: "ed25519", PublicKey: b64.EncodeToString(approverPub),
		}); err != nil {
			t.Fatal(err)
		}
		art.CredentialID = humanAddr
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("non-webauthn ceremony credential should fail")
		}
	})
	t.Run("assertion over wrong challenge", func(t *testing.T) {
		reg, credPriv, _, rp, art, cred := setup(t)
		// Sign a different challenge than the artifact claims.
		other := ApproverEnrollmentChallenge(agentAddr, otherAddr, art.IssuedAt)
		art.Assertion = craftAssertion(t, credPriv, other[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("assertion over the wrong challenge should fail")
		}
	})
	t.Run("revoked human credential", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		if err := reg.RevokeApprover(humanAddr); err != nil {
			t.Fatal(err)
		}
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("revoked ceremony credential should fail")
		}
	})
	t.Run("assertion replay", func(t *testing.T) {
		reg, _, _, rp, art, cred := setup(t)
		now := time.Now().Unix()
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, now); err != nil {
			t.Fatalf("first enrollment: %v", err)
		}
		// The same artifact replayed: the challenge is still fresh,
		// but the authenticator counter did not advance.
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, now); err == nil {
			t.Fatal("replayed enrollment assertion should fail")
		}
	})
	t.Run("no user verification", func(t *testing.T) {
		reg, credPriv, _, rp, art, cred := setup(t)
		// Touch-only (UP without UV): enrollment requires UV.
		challenge := ApproverEnrollmentChallenge(agentAddr, approverAddr, art.IssuedAt)
		art.Assertion = craftAssertion(t, credPriv, challenge[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent)
		if err := reg.EnrollWithArtifact(approverAddr, "", cred, agentAddr, art, rp, time.Now().Unix()); err == nil {
			t.Fatal("assertion without user verification should fail")
		}
	})
}
