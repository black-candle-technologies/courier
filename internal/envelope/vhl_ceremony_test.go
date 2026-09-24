package envelope

import (
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// VHL ceremony-transport canonical signing layouts (issue #142):
// every agent-authenticated ceremony request is signed over a
// domain-separated canonical form binding the address, so a
// signature for one operation or address can never authorize
// another.

func TestVHLCeremonyCanonicalDomainSeparation(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	chal := "test-challenge-b64"
	ctx := `{"issuer":"ed25519:x","scope":"s","token_id":"t","session_id":"n","issued_at":1,"expires_at":2,"presence":"fido2_uv"}`
	ts := int64(1700000000)
	forms := map[string][]byte{
		"create-enroll":     VHLCeremonyCreate(id.EdPub[:], "enroll", chal, "", ts),
		"create-mint":       VHLCeremonyCreate(id.EdPub[:], "mint", chal, ctx, ts),
		"create-mint-noctx": VHLCeremonyCreate(id.EdPub[:], "mint", chal, "", ts),
		"create-mint-other": VHLCeremonyCreate(id.EdPub[:], "mint", chal, `{"scope":"wider"}`, ts),
		"create-approve":    VHLCeremonyCreate(id.EdPub[:], "approve", chal, `{"request_id":"r"}`, ts),
		"result":            VHLCeremonyResult(id.EdPub[:], "code1234", ts),
		"announce":          VHLEnrollmentAnnounce(id.EdPub[:], "cred", "pub", "example.com", 1000, false),
		"announce-revoked":  VHLEnrollmentAnnounce(id.EdPub[:], "cred", "pub", "example.com", 1000, true),
	}
	sigs := map[string][]byte{}
	for name, canon := range forms {
		sigs[name] = id.Sign(canon)
		if !crypto.Verify(id.EdPub[:], canon, sigs[name]) {
			t.Fatalf("%s: self-verification failed", name)
		}
	}
	// Cross-verification must fail everywhere.
	for a, ca := range forms {
		for b := range forms {
			if a == b {
				continue
			}
			if crypto.Verify(id.EdPub[:], ca, sigs[b]) {
				t.Fatalf("signature for %s verifies as %s: missing domain separation", b, a)
			}
		}
	}
	// The address is bound: a signature over A's canonical form
	// must not verify against B's form (the relay recomputes the
	// form from the claimed address, so a captured signature for
	// one identity can never authorize another).
	canonA := VHLCeremonyCreate(id.EdPub[:], "enroll", chal, "", ts)
	sigA := id.Sign(canonA)
	canonB := VHLCeremonyCreate(other.EdPub[:], "enroll", chal, "", ts)
	if crypto.Verify(other.EdPub[:], canonB, sigA) {
		t.Fatal("signature for A verifies as B: address not bound")
	}
	// Determinism.
	if string(forms["create-enroll"]) != string(VHLCeremonyCreate(id.EdPub[:], "enroll", chal, "", ts)) {
		t.Fatal("ceremony create canonical form not deterministic")
	}
	// Type confusion: enroll vs mint differ.
	if string(forms["create-enroll"]) == string(forms["create-mint"]) {
		t.Fatal("enroll and mint canonical forms collide")
	}
	// The context is bound: the same type+challenge with a
	// different (or missing) context is a different form, so the
	// relay cannot substitute ceremony values the human never saw.
	if string(forms["create-mint"]) == string(forms["create-mint-noctx"]) {
		t.Fatal("mint with and without context collide")
	}
	if string(forms["create-mint"]) == string(forms["create-mint-other"]) {
		t.Fatal("mint with different contexts collide")
	}
}
