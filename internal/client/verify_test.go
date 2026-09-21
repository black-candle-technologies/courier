// Contact verification tests (issue #48, phase 1).
package client

import (
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func testIDs(t *testing.T) (a, b *crypto.Identity) {
	t.Helper()
	var err error
	if a, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if b, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func testAddr(id *crypto.Identity) string {
	return crypto.FormatAddress(id.EdPub[:])
}

func testX25519(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

var safetyRe = regexp.MustCompile(`^(\d{5} ){11}\d{5}$`)

// TestSafetyNumberSymmetric: both sides compute the same number no matter
// which side is "own".
func TestSafetyNumberSymmetric(t *testing.T) {
	a, b := testIDs(t)
	ax, bx := testX25519(t), testX25519(t)
	n1, err := SafetyNumber(testAddr(a), testAddr(b), ax, bx, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := SafetyNumber(testAddr(b), testAddr(a), bx, ax, 200, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != n2 {
		t.Fatalf("asymmetric safety numbers:\n%s\n%s", n1, n2)
	}
	if !safetyRe.MatchString(n1) {
		t.Fatalf("bad format: %q", n1)
	}
}

// TestSafetyNumberSensitive: any key or epoch change alters the number.
func TestSafetyNumberSensitive(t *testing.T) {
	a, b := testIDs(t)
	ax, bx := testX25519(t), testX25519(t)
	base, err := SafetyNumber(testAddr(a), testAddr(b), ax, bx, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	ax2 := testX25519(t)
	changed, err := SafetyNumber(testAddr(a), testAddr(b), ax2, bx, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	if changed == base {
		t.Fatal("safety number did not change with the key")
	}
	changed, err = SafetyNumber(testAddr(a), testAddr(b), ax, bx, 101, 200)
	if err != nil {
		t.Fatal(err)
	}
	if changed == base {
		t.Fatal("safety number did not change with the epoch")
	}
}

// TestSafetyNumberRejectsBadAddresses verifies fail-closed parsing.
func TestSafetyNumberRejectsBadAddresses(t *testing.T) {
	a, _ := testIDs(t)
	ax, bx := testX25519(t), testX25519(t)
	for _, bad := range []string{"", "ed25519:!!!", "nope"} {
		if _, err := SafetyNumber(bad, testAddr(a), ax, bx, 1, 1); err == nil {
			t.Fatalf("bad address %q accepted", bad)
		}
		if _, err := SafetyNumber(testAddr(a), bad, ax, bx, 1, 1); err == nil {
			t.Fatalf("bad address %q accepted", bad)
		}
	}
}

// verifyTestEnv wires two identities through a fake key directory.
type verifyTestEnv struct {
	t       *testing.T
	alice   *Client
	aCfg    *Config
	bobAddr string
	bobID   *crypto.Identity
	anns    map[string]fakeAnn
}

func newVerifyTestEnv(t *testing.T) *verifyTestEnv {
	t.Helper()
	aCfg := testConfig(t)
	bobID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobAddr := testAddr(bobID)
	bx := testX25519(t)
	anns := map[string]fakeAnn{
		bobAddr: {pub: b64x(bx), epoch: 100, signer: bobID},
	}
	srv := keyDirServer(t, anns)
	aCfg.RelayURL = srv.URL
	if err := aCfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := aCfg.AddContact("bob", bobAddr); err != nil {
		t.Fatal(err)
	}
	return &verifyTestEnv{t: t, alice: New(aCfg), aCfg: aCfg, bobAddr: bobAddr, bobID: bobID, anns: anns}
}

func b64x(k [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(k[:])
}

// TestVerifyContactFlow: verify -> trusted; key rotation -> stale;
// unverify -> unverified; remove clears the record.
func TestVerifyContactFlow(t *testing.T) {
	e := newVerifyTestEnv(t)

	if st, _ := e.alice.ContactTrust("bob"); st != TrustUnverified {
		t.Fatalf("initial trust = %v, want unverified", st)
	}
	if err := e.alice.VerifyContact("bob"); err != nil {
		t.Fatalf("VerifyContact: %v", err)
	}
	// The stored safety number must match a fresh computation.
	number, _, err := e.alice.SafetyNumberForContact("bob")
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := e.aCfg.StoredVerification("bob")
	if !ok {
		t.Fatal("no verification record stored")
	}
	if rec.SafetyNumber != number {
		t.Fatalf("stored %q != computed %q", rec.SafetyNumber, number)
	}
	if st, _ := e.alice.ContactTrust("bob"); st != TrustVerified {
		t.Fatalf("trust = %v, want verified", st)
	}
	if badge := e.alice.TrustBadge("bob"); !strings.HasPrefix(badge, "✓") {
		t.Fatalf("badge = %q", badge)
	}

	// Bob rotates his encryption key: trust must go stale.
	bx2 := testX25519(t)
	e.anns[e.bobAddr] = fakeAnn{pub: b64x(bx2), epoch: 200, signer: e.bobID}
	if st, detail := e.alice.ContactTrust("bob"); st != TrustStale {
		t.Fatalf("trust after rotation = %v (%s), want stale", st, detail)
	}

	// Unverify clears back to unverified.
	if err := e.alice.UnverifyContact("bob"); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.alice.ContactTrust("bob"); st != TrustUnverified {
		t.Fatalf("trust after unverify = %v, want unverified", st)
	}

	// Re-verify, then remove the contact: the record must not survive.
	if err := e.alice.VerifyContact("bob"); err != nil {
		t.Fatal(err)
	}
	if err := e.aCfg.RemoveContact("bob"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.aCfg.StoredVerification("bob"); ok {
		t.Fatal("verification record survived contact removal")
	}
}

// TestVerifyUnknownContact fails closed.
func TestVerifyUnknownContact(t *testing.T) {
	e := newVerifyTestEnv(t)
	if err := e.alice.VerifyContact("mallory"); err == nil {
		t.Fatal("expected error verifying unknown contact")
	}
}
