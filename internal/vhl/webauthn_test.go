package vhl

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// coseEncodeKey builds a COSE_Key for a P-256 public key (test helper).
func coseEncodeKey(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	xp := make([]byte, 32)
	yp := make([]byte, 32)
	copy(xp[32-len(xb):], xb)
	copy(yp[32-len(yb):], yb)
	var out []byte
	out = append(out, 0xa5)       // map(5)
	out = append(out, 0x01, 0x02) // 1: 2 (kty EC2)
	out = append(out, 0x03, 0x26) // 3: -7 (alg ES256)
	out = append(out, 0x20, 0x01) // -1: 1 (crv P-256)
	out = append(out, 0x21)       // -2:
	out = append(out, 0x58, 0x20) // bytes(32)
	out = append(out, xp...)
	out = append(out, 0x22)       // -3:
	out = append(out, 0x58, 0x20) // bytes(32)
	out = append(out, yp...)
	return out
}

// craftAssertion builds a real WebAuthn get-assertion for the test
// credential: clientDataJSON with the given challenge and origin,
// authenticatorData for rpID with the given flags, and a valid ECDSA
// signature from priv.
func craftAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, origin, rpID string, flags byte) string {
	t.Helper()
	clientData := map[string]string{
		"type":      "webauthn.get",
		"challenge": b64.EncodeToString(challenge),
		"origin":    origin,
	}
	cdJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, flags)
	sc := make([]byte, 4)
	binary.BigEndian.PutUint32(sc, 1)
	authData = append(authData, sc...)

	cdHash := sha256.Sum256(cdJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	r, s, err := ecdsa.Sign(rand.Reader, priv, signed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		t.Fatal(err)
	}
	cred := map[string]any{
		"type": "public-key",
		"response": map[string]string{
			"authenticatorData": b64.EncodeToString(authData),
			"clientDataJSON":    b64.EncodeToString(cdJSON),
			"signature":         b64.EncodeToString(sig),
		},
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(raw)
}

// fido2TestSetup enrolls a WebAuthn credential for addr and returns a
// verifier configured with the test RP, the credential private key,
// the identity private key (for re-signing mutated attestations), and
// a valid attestation for body.
func fido2TestSetup(t *testing.T, body []byte, presence PresenceStrength) (*Verifier, *ecdsa.PrivateKey, ed25519.PrivateKey, *Attestation) {
	t.Helper()
	addr, pub, idPriv := testIdentity(t)
	credPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry()
	// The approver enrolls both their Courier identity key (outer
	// attestation signature) and the WebAuthn credential (the
	// ceremony proof) — see enroll.go.
	if err := reg.Enroll(addr, "human", Credential{
		ID:         addr,
		Kind:       "ed25519",
		PublicKey:  b64.EncodeToString(pub),
		EnrolledAt: time.Now().Unix(),
		Device:     "courier-identity",
	}, true); err != nil {
		t.Fatal(err)
	}
	credID := "test-cred-1"
	if err := reg.Enroll(addr, "human", Credential{
		ID:         credID,
		Kind:       "webauthn",
		PublicKey:  b64.EncodeToString(coseEncodeKey(t, &credPriv.PublicKey)),
		EnrolledAt: time.Now().Unix(),
		Device:     "yubikey",
	}, true); err != nil {
		t.Fatal(err)
	}
	rp := WebAuthnRP{ID: "dashboard.test", Origins: []string{"https://dashboard.test"}}
	v := &Verifier{Registry: reg, Seen: NewSeenSet(), Revoked: NewRevocationSet(), WebAuthn: rp}

	h := MsgHashOf(body)
	assertion := craftAssertion(t, credPriv, h[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	a, err := NewTier2Attestation(body, addr, "req-1", ProofFIDO2, presence,
		Proof{CredentialID: credID, Assertion: assertion}, idPriv)
	if err != nil {
		t.Fatal(err)
	}
	return v, credPriv, idPriv, a
}

// resignAttestation re-signs a mutated attestation with the
// approver's identity key, so the failure under test is the
// assertion check rather than the attestation signature.
func resignAttestation(t *testing.T, a *Attestation, idPriv ed25519.PrivateKey) {
	t.Helper()
	a.Sig = ""
	if err := SignAttestation(a, idPriv); err != nil {
		t.Fatal(err)
	}
}

func TestFIDO2VerificationAccepts(t *testing.T) {
	body := []byte("transfer the funds")
	v, _, _, a := fido2TestSetup(t, body, PresenceFIDO2UV)
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: time.Now().Unix(), EnvelopeID: 1})
	if out.Verdict != VerdictAttested {
		t.Fatalf("verdict = %s (%s), want attested", out.Verdict, out.Reason)
	}
}

func TestFIDO2VerificationRejects(t *testing.T) {
	body := []byte("transfer the funds")
	cases := []struct {
		name   string
		mutate func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey)
	}{
		{
			name: "wrong challenge",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				other := MsgHashOf([]byte("something else"))
				a.Proof.Assertion = craftAssertion(t, credPriv, other[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name: "wrong origin",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				h := MsgHashOf(body)
				a.Proof.Assertion = craftAssertion(t, credPriv, h[:], "https://evil.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name: "wrong rp id",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				h := MsgHashOf(body)
				a.Proof.Assertion = craftAssertion(t, credPriv, h[:], "https://dashboard.test", "other.test", authFlagUserPresent|authFlagUserVerified)
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name: "missing user-presence flag",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				h := MsgHashOf(body)
				a.Proof.Assertion = craftAssertion(t, credPriv, h[:], "https://dashboard.test", "dashboard.test", 0)
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name: "missing user-verification flag when UV required",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				h := MsgHashOf(body)
				a.Proof.Assertion = craftAssertion(t, credPriv, h[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent)
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name: "unenrolled credential id",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				a.Proof.CredentialID = "not-enrolled"
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name: "unconfigured relying party",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				v.WebAuthn = WebAuthnRP{}
			},
		},
		{
			name: "assertion signed by a different key",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				evil, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				h := MsgHashOf(body)
				a.Proof.Assertion = craftAssertion(t, evil, h[:], "https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
				resignAttestation(t, a, idPriv)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, credPriv, idPriv, a := fido2TestSetup(t, body, PresenceFIDO2UV)
			tc.mutate(t, v, a, credPriv, idPriv)
			out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: time.Now().Unix(), EnvelopeID: 1})
			if out.Verdict != VerdictInvalid {
				t.Fatalf("verdict = %s (%s), want invalid", out.Verdict, out.Reason)
			}
		})
	}
}
