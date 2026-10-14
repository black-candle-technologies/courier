package client

import (
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/vhl"
)

func legacyApproval(t *testing.T, c *Client, body string, kind vhl.ProofKind) *vhl.Attestation {
	t.Helper()
	id, err := c.cfg.Identity()
	if err != nil {
		t.Fatal(err)
	}
	a, err := vhl.NewTier2Attestation([]byte(body), c.cfg.Address, "legacy-request", vhl.ProofFIDO2, vhl.PresenceFIDO2UV, vhl.Proof{CredentialID: "test-cred"}, make([]byte, 32), id.EdPriv)
	if err != nil {
		t.Fatal(err)
	}
	a.Proof = vhl.Proof{Kind: kind, Strength: kind.Strength().String(), ChallengeID: "old-challenge"}
	a.ApprovalNonce = ""
	if err := vhl.SignAttestation(a, id.EdPriv); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestVHLTier2HardwareGate(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()
	for _, kind := range []vhl.ProofKind{vhl.ProofPIN, vhl.ProofChallenge} {
		t.Run(string(kind), func(t *testing.T) {
			req, h := requestFixture(t, env.sender, "action", vhl.PresenceFIDO2UV)
			for _, presence := range []vhl.PresenceStrength{kind.Strength(), vhl.PresenceFIDO2UV} {
				_, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, vhl.Proof{Kind: kind, ChallengeID: "old"}, presence, nil)
				if err == nil || !strings.Contains(err.Error(), "requires FIDO2") {
					t.Fatalf("mint: %v", err)
				}
				if _, err := env.sender.VHLGetRequest(req.ID); err != nil {
					t.Fatalf("rejection consumed request: %v", err)
				}
			}
			a := legacyApproval(t, env.sender, "action", kind)
			if _, err := env.sender.vhlAttestForSend(vhl.Tier2, "action", a, env.recipCfg.Address); err == nil {
				t.Fatal("typed artifact accepted for send")
			}
			if err := env.sender.cfg.local().updateVHL(func(ff *vhlFile) error { ff.Attestations[a.ID] = a; return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := env.sender.VHLGetAttestation(a.ID); err == nil {
				t.Fatal("stored typed artifact offered for send")
			}
			if _, err := env.sender.SendTiered(env.recipCfg.Address, "action", vhl.Tier2, a); err == nil {
				t.Fatal("typed artifact sent")
			}
		})
	}
	req, h := requestFixture(t, env.sender, "valid action", vhl.PresenceFIDO2UV)
	att, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, vhl.Proof{Kind: vhl.ProofFIDO2, CredentialID: "test-cred"}, vhl.PresenceFIDO2UV, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*vhl.Attestation){
		func(a *vhl.Attestation) { a.Proof.Strength = "fido2" },
		func(a *vhl.Attestation) { a.ApprovalNonce = "" },
		func(a *vhl.Attestation) { a.Proof.CredentialID = "" },
		func(a *vhl.Attestation) { a.Version = 99 },
	} {
		bad := *att
		mutate(&bad)
		if _, err := env.sender.vhlAttestForSend(vhl.Tier2, "valid action", &bad, env.recipCfg.Address); err == nil {
			t.Fatal("malformed FIDO2 artifact accepted for send")
		}
	}
	// A stored legacy request cannot request a weaker ceremony even when
	// the caller supplies a FIDO2 proof; refusal must leave it pending.
	for _, p := range []vhl.PresenceStrength{vhl.PresencePIN, vhl.PresenceChallenge, vhl.PresenceFIDO2} {
		if _, err := env.sender.VHLRequestApproval("", vhl.Tier2, "action", p); err == nil {
			t.Fatalf("weak request accepted: %s", p)
		}
		r, h := requestFixture(t, env.sender, "old request", vhl.PresenceFIDO2UV)
		if err := env.sender.cfg.local().updateVHL(func(ff *vhlFile) error { ff.Requests[r.ID].Request.WantPresence = p.String(); return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := env.sender.VHLApproveMint(r.ID, h, env.senderCfg.Address, vhl.Proof{Kind: vhl.ProofFIDO2, CredentialID: "test-cred"}, vhl.PresenceFIDO2UV, make([]byte, 32)); err == nil {
			t.Fatal("legacy weak request approved")
		}
		if _, err := env.sender.VHLGetRequest(r.ID); err != nil {
			t.Fatalf("legacy request consumed: %v", err)
		}
	}
}
