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
	"strings"
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
// signature from priv. The signature is over the digest
// SHA-256(authData || SHA-256(clientDataJSON)), as WebAuthn ES256
// requires.
func craftAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, origin, rpID string, flags byte) string {
	t.Helper()
	return craftAssertionWithCount(t, priv, challenge, origin, rpID, flags, 1)
}

// craftAssertionWithCount is craftAssertion with an explicit
// authenticator signature counter.
func craftAssertionWithCount(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, origin, rpID string, flags byte, signCount uint32) string {
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
	binary.BigEndian.PutUint32(sc, signCount)
	authData = append(authData, sc...)

	cdHash := sha256.Sum256(cdJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
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
	}); err != nil {
		t.Fatal(err)
	}
	credID := "test-cred-1"
	if err := reg.Enroll(addr, "human", Credential{
		ID:         credID,
		Kind:       "webauthn",
		PublicKey:  b64.EncodeToString(coseEncodeKey(t, &credPriv.PublicKey)),
		EnrolledAt: time.Now().Unix(),
		Device:     "yubikey",
	}); err != nil {
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

// TestFIDO2SameEnvelopeReevaluation pins the same-envelope
// idempotency: two consumers (inbox CLI vs. dashboard push)
// evaluating the same envelope must both see attested. The second
// pass must not trip the FIDO2 signature-counter check — the first
// pass already advanced the stored counter.
func TestFIDO2SameEnvelopeReevaluation(t *testing.T) {
	body := []byte("transfer the funds")
	v, _, _, a := fido2TestSetup(t, body, PresenceFIDO2UV)
	in := EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: time.Now().Unix(), EnvelopeID: 7}
	first := v.Evaluate(in)
	if first.Verdict != VerdictAttested {
		t.Fatalf("first verdict = %s (%s), want attested", first.Verdict, first.Reason)
	}
	second := v.Evaluate(in)
	if second.Verdict != VerdictAttested {
		t.Fatalf("second verdict = %s (%s), want attested", second.Verdict, second.Reason)
	}
}

func TestFIDO2VerificationRejects(t *testing.T) {
	body := []byte("transfer the funds")
	cases := []struct {
		name       string
		wantReason string // when set, the rejection must come from this check
		mutate     func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey)
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
		{
			name:       "clientDataJSON bytes changed, challenge kept",
			wantReason: "fido2: signature invalid",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				// Keep the valid signature but swap the
				// clientDataJSON for different bytes carrying the
				// SAME challenge and origin: every field check
				// passes, so only the signature check can reject
				// the assertion. (The previous version of this
				// case swapped the challenge, which the challenge
				// check rejects before the signature is ever
				// verified — it could not catch a signature that
				// fails to bind clientDataJSON.)
				raw, err := b64.DecodeString(a.Proof.Assertion)
				if err != nil {
					t.Fatal(err)
				}
				var cred map[string]any
				if err := json.Unmarshal(raw, &cred); err != nil {
					t.Fatal(err)
				}
				resp, ok := cred["response"].(map[string]any)
				if !ok {
					t.Fatal("assertion has no response object")
				}
				h := MsgHashOf(body)
				cdJSON, err := json.Marshal(map[string]string{
					"type":        "webauthn.get",
					"challenge":   b64.EncodeToString(h[:]),
					"origin":      "https://dashboard.test",
					"crossOrigin": "false",
				})
				if err != nil {
					t.Fatal(err)
				}
				resp["clientDataJSON"] = b64.EncodeToString(cdJSON)
				raw2, err := json.Marshal(cred)
				if err != nil {
					t.Fatal(err)
				}
				a.Proof.Assertion = b64.EncodeToString(raw2)
				resignAttestation(t, a, idPriv)
			},
		},
		{
			name:       "authenticatorData bit flip",
			wantReason: "fido2: signature invalid",
			mutate: func(t *testing.T, v *Verifier, a *Attestation, credPriv *ecdsa.PrivateKey, idPriv ed25519.PrivateKey) {
				// Flip a bit inside authenticatorData (in the
				// signature-counter bytes; the UP/UV flags at
				// byte 32 stay set): every field check passes, so
				// only the signature check can reject the
				// assertion.
				raw, err := b64.DecodeString(a.Proof.Assertion)
				if err != nil {
					t.Fatal(err)
				}
				var cred map[string]any
				if err := json.Unmarshal(raw, &cred); err != nil {
					t.Fatal(err)
				}
				resp, ok := cred["response"].(map[string]any)
				if !ok {
					t.Fatal("assertion has no response object")
				}
				authDataB64, ok := resp["authenticatorData"].(string)
				if !ok {
					t.Fatal("assertion has no authenticatorData")
				}
				authData, err := b64.DecodeString(authDataB64)
				if err != nil {
					t.Fatal(err)
				}
				if len(authData) < 37 {
					t.Fatal("authenticatorData too short")
				}
				authData[36] ^= 0x01
				resp["authenticatorData"] = b64.EncodeToString(authData)
				raw2, err := json.Marshal(cred)
				if err != nil {
					t.Fatal(err)
				}
				a.Proof.Assertion = b64.EncodeToString(raw2)
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
			if tc.wantReason != "" && !strings.Contains(out.Reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to contain %q", out.Reason, tc.wantReason)
			}
		})
	}
}

func TestFIDO2SignCountReplay(t *testing.T) {
	// A captured assertion re-wrapped in a fresh attestation (new
	// id, new envelope) defeats the envelope-layer replay dedup —
	// the authenticator signature counter must catch it: the
	// counter did not strictly increase.
	body := []byte("transfer the funds")
	v, _, idPriv, a := fido2TestSetup(t, body, PresenceFIDO2UV)
	now := time.Now().Unix()
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: now, EnvelopeID: 1})
	if out.Verdict != VerdictAttested {
		t.Fatalf("first evaluation should attest, got %v (%s)", out.Verdict, out.Reason)
	}
	rewrapped, err := NewTier2Attestation(body, a.Approver, "req-2", ProofFIDO2, PresenceFIDO2UV,
		Proof{CredentialID: a.Proof.CredentialID, Assertion: a.Proof.Assertion}, idPriv)
	if err != nil {
		t.Fatal(err)
	}
	out2 := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: rewrapped, Receiver: "r", Now: now, EnvelopeID: 2})
	if out2.Verdict != VerdictInvalid {
		t.Fatalf("re-wrapped assertion should be invalid, got %v (%s)", out2.Verdict, out2.Reason)
	}
}

func TestFIDO2SignCountIncrease(t *testing.T) {
	// A strictly increasing counter is accepted and persisted: the
	// next assertion must beat the new stored value.
	body := []byte("transfer the funds")
	v, credPriv, idPriv, a := fido2TestSetup(t, body, PresenceFIDO2UV)
	now := time.Now().Unix()
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: now, EnvelopeID: 1})
	if out.Verdict != VerdictAttested {
		t.Fatalf("first evaluation should attest, got %v (%s)", out.Verdict, out.Reason)
	}
	h := MsgHashOf(body)
	next, err := NewTier2Attestation(body, a.Approver, "req-2", ProofFIDO2, PresenceFIDO2UV,
		Proof{CredentialID: a.Proof.CredentialID, Assertion: craftAssertionWithCount(t, credPriv, h[:],
			"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified, 2)}, idPriv)
	if err != nil {
		t.Fatal(err)
	}
	out2 := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: next, Receiver: "r", Now: now, EnvelopeID: 2})
	if out2.Verdict != VerdictAttested {
		t.Fatalf("increased counter should attest, got %v (%s)", out2.Verdict, out2.Reason)
	}
}

func TestFIDO2ZeroCounterAuthenticator(t *testing.T) {
	// Authenticators without a counter report 0 forever; the
	// WebAuthn spec permits 0 while the stored value is also 0.
	body := []byte("transfer the funds")
	v, credPriv, idPriv, setup := fido2TestSetup(t, body, PresenceFIDO2UV)
	approver, credID := setup.Approver, setup.Proof.CredentialID
	h := MsgHashOf(body)
	now := time.Now().Unix()
	for env := int64(1); env <= 2; env++ {
		assertion := craftAssertionWithCount(t, credPriv, h[:],
			"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified, 0)
		a, err := NewTier2Attestation(body, approver, "req-zero", ProofFIDO2, PresenceFIDO2UV,
			Proof{CredentialID: credID, Assertion: assertion}, idPriv)
		if err != nil {
			t.Fatal(err)
		}
		out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: now, EnvelopeID: env})
		if out.Verdict != VerdictAttested {
			t.Fatalf("zero-counter evaluation %d should attest, got %v (%s)", env, out.Verdict, out.Reason)
		}
	}
}

func TestCBORByteStringHugeLength(t *testing.T) {
	// A byte string declaring a 0xffffffffffffffff length must fail
	// with an error, not panic: the old bounds check computed
	// uint64(off)+n, which wraps for huge n, and the int(n)
	// conversion then went negative and panicked the slice.
	malicious := []byte{0xa1, 0x01, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, err := parseCOSEKey(malicious); err == nil {
		t.Fatal("huge byte-string length should fail, not panic")
	}
}
