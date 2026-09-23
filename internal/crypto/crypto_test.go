package crypto

import (
	"bytes"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func testSeed() []byte {
	return bytes.Repeat([]byte{0x42}, SeedLen)
}

// The birational map must agree with libsodium's private-key derivation:
// converting the Ed25519 public key must equal X25519(clamp(SHA512(seed))).
func TestEd25519PubToX25519SelfConsistent(t *testing.T) {
	id, err := IdentityFromSeed(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	converted, err := Ed25519PubToX25519(id.EdPub[:])
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.Sum512(testSeed())
	clamp(h[:SeedLen])
	direct, err := curve25519.X25519(h[:SeedLen], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(converted[:], direct) {
		t.Fatalf("map mismatch:\nconverted %x\ndirect    %x", converted, direct)
	}
	// And it must equal the identity's own derived X25519 key.
	if !equalBytes(converted[:], id.XPub[:]) {
		t.Fatal("converted key != identity X25519 key")
	}
}

func TestAddressRoundtrip(t *testing.T) {
	id, _ := IdentityFromSeed(testSeed())
	addr := FormatAddress(id.EdPub[:])
	pub, err := ParseAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(pub[:], id.EdPub[:]) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestParseAddressRejectsLegacy(t *testing.T) {
	// A bare v0.1.0-style X25519 address must fail loudly, never silently
	// encrypt to a misinterpreted key.
	if _, err := ParseAddress("nqzNmuqgxGUuA4CWQsL8AKxKiChPm1LVbiFl6lyXviE"); err == nil {
		t.Fatal("expected rejection of legacy bare address")
	}
	if _, err := ParseAddress("ed25519:not-base64!!"); err == nil {
		t.Fatal("expected rejection of bad base64")
	}
}

func TestSignVerify(t *testing.T) {
	id, _ := IdentityFromSeed(testSeed())
	msg := []byte("hello courier")
	sig := id.Sign(msg)
	if !Verify(id.EdPub[:], msg, sig) {
		t.Fatal("valid signature rejected")
	}
	sig[0] ^= 1
	if Verify(id.EdPub[:], msg, sig) {
		t.Fatal("tampered signature accepted")
	}
	if Verify(id.EdPub[:], []byte("other"), id.Sign(msg)) {
		t.Fatal("wrong message accepted")
	}
}

func TestSealOpenViaConvertedKey(t *testing.T) {
	sender, _ := GenerateIdentity()
	recipient, _ := IdentityFromSeed(testSeed())

	// Sender only knows the recipient's address (Ed25519).
	edPub, err := ParseAddress(FormatAddress(recipient.EdPub[:]))
	if err != nil {
		t.Fatal(err)
	}
	xPub, err := Ed25519PubToX25519(edPub[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, nonce, ct, err := Seal(&xPub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(recipient.XPriv[:], eph, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatal("decrypt mismatch")
	}
	_ = sender
}

func TestValidSuite(t *testing.T) {
	if !ValidSuite(SuiteV1) {
		t.Fatal("SuiteV1 must be valid")
	}
	if ValidSuite("") {
		t.Fatal("empty suite must be invalid")
	}
	if ValidSuite("pq-hybrid-v1") {
		t.Fatal("unknown suite must be invalid")
	}
	// KnownSuites is derived from the registry: every entry must have
	// a descriptor (a name with no implementation is not "known"), and
	// SuiteV1 must always be present.
	foundV1 := false
	for _, s := range KnownSuites {
		if s == SuiteV1 {
			foundV1 = true
		}
		if !ValidSuite(s) {
			t.Fatalf("KnownSuites entry %q has no descriptor", s)
		}
	}
	if !foundV1 {
		t.Fatalf("KnownSuites = %v, want SuiteV1 present", KnownSuites)
	}
}

func TestParseAddressSuite(t *testing.T) {
	id, _ := IdentityFromSeed(testSeed())
	addr := FormatAddress(id.EdPub[:])

	pa, err := ParseAddressSuite(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(pa.PublicKey, id.EdPub[:]) {
		t.Fatal("pubkey mismatch")
	}
	if pa.Suite != SuiteV1 {
		t.Fatalf("suite = %q, want %q", pa.Suite, SuiteV1)
	}

	// An unknown address prefix fails closed: it can never be mistaken
	// for SuiteV1.
	if _, err := ParseAddressSuite("pq:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("expected rejection of unknown suite prefix")
	}
	// Legacy bare addresses still fail.
	if _, err := ParseAddressSuite("nqzNmuqgxGUuA4CWQsL8AKxKiChPm1LVbiFl6lyXviE"); err == nil {
		t.Fatal("expected rejection of legacy bare address")
	}
}
