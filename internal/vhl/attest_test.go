package vhl

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/vhltest"
)

var attestB64 = base64.RawURLEncoding

func testRP(pki *vhltest.PKI, rpID string) WebAuthnRP {
	return WebAuthnRP{
		ID:               rpID,
		Origins:          []string{"https://example.com"},
		AttestationRoots: []string{attestB64.EncodeToString(pki.RootDER)},
	}
}

// freshChallenge uses the real enrollment-challenge generator so the
// tests exercise the exact bytes the client will send.
func freshChallenge(t *testing.T) []byte {
	t.Helper()
	chal, err := EnrollmentChallenge("ed25519:test", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	return chal
}

func TestEnrollmentChallenge(t *testing.T) {
	c1, err := EnrollmentChallenge("ed25519:alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(c1) != 32 {
		t.Fatalf("challenge length %d, want 32", len(c1))
	}
	c2, err := EnrollmentChallenge("ed25519:alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("challenges must be fresh per call")
	}
	// Bound to the identity: a different address must not collide.
	c3, err := EnrollmentChallenge("ed25519:bob", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c3) {
		t.Fatal("challenge not bound to address")
	}
	if _, err := EnrollmentChallenge("", "example.com"); err == nil {
		t.Fatal("empty address accepted")
	}
	if _, err := EnrollmentChallenge("ed25519:alice", ""); err == nil {
		t.Fatal("empty rp id accepted")
	}
}

func TestVerifyRegistrationPackedHappyPath(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.Enroll(t, "example.com", "https://example.com", chal)
	res, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com"))
	if err != nil {
		t.Fatalf("happy path failed: %v", err)
	}
	if res.CredentialID != attestB64.EncodeToString(cer.CredID) {
		t.Fatalf("credential id mismatch: %q", res.CredentialID)
	}
	fields, err := parseCOSEKey(res.PublicKey)
	if err != nil {
		t.Fatalf("returned public key does not parse: %v", err)
	}
	if alg, _ := fields[3].(int64); alg != -7 {
		t.Fatalf("alg = %v, want -7", alg)
	}
	if res.SignCount != 1 {
		t.Fatalf("sign count = %d, want 1", res.SignCount)
	}
}

func TestVerifyRegistrationFidoU2FHappyPath(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.EnrollFidoU2F(t, "example.com", "https://example.com", chal)
	res, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com"))
	if err != nil {
		t.Fatalf("fido-u2f happy path failed: %v", err)
	}
	if res.CredentialID != attestB64.EncodeToString(cer.CredID) {
		t.Fatalf("credential id mismatch: %q", res.CredentialID)
	}
}

func TestVerifyRegistrationRejectsWrongChallenge(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.Enroll(t, "example.com", "https://example.com", chal)
	other := freshChallenge(t)
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, other, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong challenge accepted")
	}
	// Tampered challenge bytes inside clientDataJSON.
	tampered := append([]byte{}, chal...)
	tampered[0] ^= 0xff
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, tampered, testRP(pki, "example.com")); err == nil {
		t.Fatal("tampered challenge accepted")
	}
}

func TestVerifyRegistrationRejectsWrongOriginAndRPID(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	// Wrong origin in the ceremony.
	cer := pki.Enroll(t, "example.com", "https://evil.com", chal)
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong origin accepted")
	}
	// Right origin, wrong RP id baked into authData.
	cer2 := pki.Enroll(t, "other.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer2.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong rpIdHash accepted")
	}
	// RP config with the wrong origin list.
	cer3 := pki.Enroll(t, "example.com", "https://example.com", chal)
	rp := testRP(pki, "example.com")
	rp.Origins = []string{"https://other.com"}
	if _, err := VerifyRegistrationAttestation(cer3.OuterB64, chal, rp); err == nil {
		t.Fatal("origin not in allowlist accepted")
	}
}

func TestVerifyRegistrationRejectsUntrustedAttestation(t *testing.T) {
	pki := vhltest.NewPKI(t)
	otherPKI := vhltest.NewPKI(t)
	chal := freshChallenge(t)

	// x5c chained to an unknown root: rejected.
	cer2 := otherPKI.Enroll(t, "example.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer2.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("untrusted attestation chain accepted")
	}

	// No attestation roots configured: fail closed.
	cer3 := pki.Enroll(t, "example.com", "https://example.com", chal)
	rp := testRP(pki, "example.com")
	rp.AttestationRoots = nil
	if _, err := VerifyRegistrationAttestation(cer3.OuterB64, chal, rp); err == nil {
		t.Fatal("empty attestation roots accepted")
	}

	// Signature made by a key the certificate does not know (wrong
	// signer, right chain): rejected.
	cer4 := pki.EnrollWith(t, "example.com", "https://example.com", chal, otherPKI.AttestKey, pki.AttestDER)
	if _, err := VerifyRegistrationAttestation(cer4.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong-signer attestation accepted")
	}

	// Packed attestation with no x5c at all (self attestation):
	// rejected — anyone holding the challenge could forge it.
	cer5 := pki.EnrollSelf(t, "example.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer5.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("self attestation accepted")
	}
}

func TestVerifyRegistrationRejectsNoneAttestation(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	// A hand-built "none" attestation object with empty attStmt must
	// be rejected even though its challenge/origin/rpId check out:
	// "none" carries no authenticator proof.
	cer := pki.EnrollNone(t, "example.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("\"none\" attestation accepted")
	} else if got := fmt.Sprint(err); !strings.Contains(got, "none") {
		t.Fatalf("expected a none-attestation rejection, got: %v", err)
	}
}

func TestVerifyRegistrationRejectsGarbage(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	rp := testRP(pki, "example.com")
	for name, input := range map[string]string{
		"bad base64": "!!!",
		"bad json":   attestB64.EncodeToString([]byte("not json")),
		"empty":      "",
		"wrong type": attestB64.EncodeToString([]byte(`{"type":"weird"}`)),
		"truncated":  attestB64.EncodeToString([]byte(`{"type":"public-key","id":"eA","rawId":"eA","response":{"clientDataJSON":"QQ","attestationObject":"QQ"}}`)),
		"no rp":      "",
	} {
		in := input
		if name == "no rp" {
			badRP := rp
			badRP.ID = ""
			if _, err := VerifyRegistrationAttestation(
				attestB64.EncodeToString([]byte(`{"type":"public-key"}`)), chal, badRP); err == nil {
				t.Fatalf("%s accepted", name)
			}
			continue
		}
		if _, err := VerifyRegistrationAttestation(in, chal, rp); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// FuzzCborDecoder feeds hostile bytes into every decoder entry point:
// the decoder must return an error, never panic or loop forever.
func FuzzCborDecoder(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x80},
		{0xa3, 0x63, 0x66, 0x6d, 0x74}, // map{1: "fmt"} truncated
		{0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64}, // map{"fmt":"packed"}
		{0x5f, 0xff}, // indefinite-length (unsupported)
		{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d := &cborDecoder{buf: data}
		_ = d.skipValue()
		d = &cborDecoder{buf: data}
		_, _ = d.readBstr()
		d = &cborDecoder{buf: data}
		_, _ = d.readTstr()
		d = &cborDecoder{buf: data}
		_, _ = d.readArrayLen()
		d = &cborDecoder{buf: data}
		_, _ = d.readMapLen()
		d = &cborDecoder{buf: data}
		_, _ = d.readInt()
		_, _ = parseAttestationObject(data)
	})
}
