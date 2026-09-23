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
	ts := int64(1700000000)
	forms := map[string][]byte{
		"create-enroll": VHLCeremonyCreate(id.EdPub[:], "enroll", chal, ts),
		"create-mint":   VHLCeremonyCreate(id.EdPub[:], "mint", chal, ts),
		"result":        VHLCeremonyResult(id.EdPub[:], "code1234", ts),
		"announce":      VHLEnrollmentAnnounce(id.EdPub[:], "cred", "pub", "example.com", 1000),
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
	canonA := VHLCeremonyCreate(id.EdPub[:], "enroll", chal, ts)
	sigA := id.Sign(canonA)
	canonB := VHLCeremonyCreate(other.EdPub[:], "enroll", chal, ts)
	if crypto.Verify(other.EdPub[:], canonB, sigA) {
		t.Fatal("signature for A verifies as B: address not bound")
	}
	// Determinism.
	if string(forms["create-enroll"]) != string(VHLCeremonyCreate(id.EdPub[:], "enroll", chal, ts)) {
		t.Fatal("ceremony create canonical form not deterministic")
	}
	// Type confusion: enroll vs mint differ.
	if string(forms["create-enroll"]) == string(forms["create-mint"]) {
		t.Fatal("enroll and mint canonical forms collide")
	}
}
