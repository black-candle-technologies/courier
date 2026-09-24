package vhl

// Regression tests for the issue #142 security-review findings:
//
//  1. Receiver-enforced minimum tier (EvalInput.RequiredTier).
//  2. PIN/challenge proofs fail closed at Tier 2.
//  3. WebAuthn approval replay via the nonce-bound challenge.
//
// Finding 4 (attestation certificate profile) is covered in
// attest_test.go.

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// --- Finding 3: WebAuthn approval replay ---
//
// The Tier 2 WebAuthn challenge is ApprovalChallenge(actionHash,
// nonce): a captured assertion answers only its own ceremony's
// challenge, and the receiver consumes the nonce exactly once
// (Verifier.Nonces). These tests pin the replay behavior end to
// end.

func TestApprovalReplaySameAttestationDifferentEnvelope(t *testing.T) {
	// (a) The exact same attestation delivered in two different
	// envelopes: the second is a replay (attestation-id dedup).
	body := []byte("transfer the funds")
	v, _, _, a, _ := fido2TestSetup(t, body, PresenceFIDO2UV)
	now := time.Now().Unix()
	first := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: now, EnvelopeID: 1})
	if first.Verdict != VerdictAttested {
		t.Fatalf("first = %s (%s), want attested", first.Verdict, first.Reason)
	}
	second := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: now, EnvelopeID: 2})
	if second.Verdict != VerdictInvalid || second.Reason != "replay" {
		t.Fatalf("second = %s (%s), want invalid/replay", second.Verdict, second.Reason)
	}
}

func TestApprovalReplayRewrappedSameNonce(t *testing.T) {
	// (b) A captured assertion re-wrapped in a FRESH attestation
	// (new outer id, same nonce, new envelope): the nonce was
	// consumed by the first delivery, so the second is a replay —
	// even though the attestation id is new and the authenticator
	// counter would allow it.
	body := []byte("transfer the funds")
	v, credPriv, idPriv, a, nonce := fido2TestSetup(t, body, PresenceFIDO2UV)
	now := time.Now().Unix()
	first := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: now, EnvelopeID: 1})
	if first.Verdict != VerdictAttested {
		t.Fatalf("first = %s (%s), want attested", first.Verdict, first.Reason)
	}
	// Same nonce, same captured assertion bytes, fresh
	// attestation id. Counter 1 again — exactly the captured
	// assertion replayed.
	rewrapped, _ := mintFIDO2Attestation(t, body, a.Approver, "req-2", PresenceFIDO2UV,
		a.Proof.CredentialID, credPriv, nonce, 1, idPriv)
	rewrapped.Proof.Assertion = a.Proof.Assertion
	resignAttestation(t, rewrapped, idPriv)
	second := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: rewrapped, Receiver: "r", Now: now, EnvelopeID: 2})
	if second.Verdict != VerdictInvalid || !strings.Contains(second.Reason, "replay") {
		t.Fatalf("rewrapped = %s (%s), want invalid/replay", second.Verdict, second.Reason)
	}
}

func TestApprovalReplayCounterlessAuthenticator(t *testing.T) {
	// (c) Counterless authenticator (counter always 0): the old
	// deterministic-challenge scheme attested the replay — 0/0 is
	// spec-legal, a fresh attestation id defeats the envelope
	// dedup, and concurrent verifiers race the counter. With the
	// nonce-bound challenge the first approval attests and the
	// replay is rejected on the consumed nonce.
	body := []byte("transfer the funds")
	v, credPriv, idPriv, setup, _ := fido2TestSetup(t, body, PresenceFIDO2UV)
	approver, credID := setup.Approver, setup.Proof.CredentialID
	now := time.Now().Unix()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	first, _ := mintFIDO2Attestation(t, body, approver, "req-1", PresenceFIDO2UV,
		credID, credPriv, nonce, 0, idPriv)
	out1 := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: first, Receiver: "r", Now: now, EnvelopeID: 1})
	if out1.Verdict != VerdictAttested {
		t.Fatalf("first = %s (%s), want attested", out1.Verdict, out1.Reason)
	}
	// Attacker replays the captured assertion in a fresh
	// attestation, new envelope. Counter 0 again — legal for
	// counterless authenticators — so only the nonce check can
	// catch it.
	replay, _ := mintFIDO2Attestation(t, body, approver, "req-2", PresenceFIDO2UV,
		credID, credPriv, nonce, 0, idPriv)
	replay.Proof.Assertion = first.Proof.Assertion
	resignAttestation(t, replay, idPriv)
	out2 := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: replay, Receiver: "r", Now: now, EnvelopeID: 2})
	if out2.Verdict != VerdictInvalid || !strings.Contains(out2.Reason, "replay") {
		t.Fatalf("replay = %s (%s), want invalid/replay", out2.Verdict, out2.Reason)
	}
}

func TestApprovalRejectsLegacyDeterministicChallenge(t *testing.T) {
	// (d) An assertion crafted over the OLD deterministic
	// challenge (the raw action hash) no longer verifies: the
	// verifier expects ApprovalChallenge(actionHash, nonce).
	// This proves the challenge scheme actually changed —
	// pre-change captured assertions are dead.
	body := []byte("transfer the funds")
	v, credPriv, idPriv, a, _ := fido2TestSetup(t, body, PresenceFIDO2UV)
	h := MsgHashOf(body)
	a.Proof.Assertion = craftAssertion(t, credPriv, h[:],
		"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	resignAttestation(t, a, idPriv)
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: time.Now().Unix(), EnvelopeID: 9})
	if out.Verdict != VerdictInvalid {
		t.Fatalf("legacy-challenge assertion = %s (%s), want invalid", out.Verdict, out.Reason)
	}
	if !strings.Contains(out.Reason, "challenge") {
		t.Fatalf("want a challenge rejection, got %q", out.Reason)
	}
}

func TestApprovalNonceCoveredBySignature(t *testing.T) {
	// The nonce is part of the signed canonical bytes: swapping it
	// after signing invalidates the attestation signature (it
	// cannot be stripped or replaced to dodge the replay set).
	body := []byte("transfer the funds")
	v, _, _, a, _ := fido2TestSetup(t, body, PresenceFIDO2UV)
	other := make([]byte, 32)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	a.ApprovalNonce = b64.EncodeToString(other)
	// Deliberately NOT re-signed: the signature was made over the
	// original nonce.
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "r", Now: time.Now().Unix(), EnvelopeID: 1})
	if out.Verdict != VerdictInvalid || out.Reason != "bad-signature" {
		t.Fatalf("swapped nonce = %s (%s), want invalid/bad-signature", out.Verdict, out.Reason)
	}
}

// --- Finding 1: receiver-enforced minimum tier ---

func TestRequiredTierEnforced(t *testing.T) {
	now := time.Now().Unix()
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("hello")

	// A sender-asserted Tier 0 below a Tier 2 requirement is
	// invalid — never silently delivered as unattested chatter.
	out := v.Evaluate(EvalInput{Tier: Tier0, RequiredTier: Tier2, Body: body, Receiver: "x", Now: now})
	if out.Verdict != VerdictInvalid || out.Reason != "below-required-tier" {
		t.Fatalf("tier0 below required tier2 = %s (%s), want invalid/below-required-tier", out.Verdict, out.Reason)
	}

	// Tier 1 with a genuinely valid attestation still fails a
	// Tier 2 requirement.
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	mv := mc.mintVerifier(reg)
	tok := mc.mint(t, addr, "r", priv)
	a1, err := NewTier1Attestation(tok, priv)
	if err != nil {
		t.Fatal(err)
	}
	out1 := mv.Evaluate(EvalInput{Tier: Tier1, RequiredTier: Tier2, Body: []byte("read"), Attestation: a1, Receiver: "r", Now: now})
	if out1.Verdict != VerdictInvalid || out1.Reason != "below-required-tier" {
		t.Fatalf("tier1 below required tier2 = %s (%s), want invalid/below-required-tier", out1.Verdict, out1.Reason)
	}

	// Tier 2 with a valid attestation meets a Tier 2 requirement.
	fv, _, _, fa, _ := fido2TestSetup(t, []byte("spend"), PresenceFIDO2UV)
	out2 := fv.Evaluate(EvalInput{Tier: Tier2, RequiredTier: Tier2, Body: []byte("spend"), Attestation: fa, Receiver: "r", Now: now, EnvelopeID: 3})
	if out2.Verdict != VerdictAttested {
		t.Fatalf("tier2 meeting required tier2 = %s (%s), want attested", out2.Verdict, out2.Reason)
	}

	// Zero RequiredTier preserves the historical behavior: Tier 0
	// is unattested, and a higher tier than required still
	// attests.
	out3 := v.Evaluate(EvalInput{Tier: Tier0, Body: body, Receiver: "x", Now: now})
	if out3.Verdict != VerdictUnattested {
		t.Fatalf("tier0 with no requirement = %s (%s), want unattested", out3.Verdict, out3.Reason)
	}
	out4 := mv.Evaluate(EvalInput{Tier: Tier1, RequiredTier: Tier0, Body: []byte("read"), Attestation: a1, Receiver: "r", Now: now, EnvelopeID: 9})
	if out4.Verdict != VerdictAttested {
		t.Fatalf("tier1 with no requirement = %s (%s), want attested", out4.Verdict, out4.Reason)
	}
}

func TestEvaluatedSetOnEveryPath(t *testing.T) {
	// Every Evaluate return path marks the outcome evaluated, so
	// downstream can distinguish "explicitly evaluated as Tier 0"
	// from "never evaluated".
	now := time.Now().Unix()
	addr, pub, priv := testIdentity(t)
	_, _, evilPriv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("do the thing")

	freshPIN := func() *Attestation {
		a, err := NewTier2Attestation(body, addr, "req-e", ProofPIN, PresencePIN, Proof{}, priv)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	expired := freshPIN()
	expired.IssuedAt = now - 7200
	expired.ExpiresAt = now - 3600
	if err := SignAttestation(expired, priv); err != nil {
		t.Fatal(err)
	}
	malformed := freshPIN()
	malformed.Version = 99
	badSig := freshPIN()
	badSig.Sig = ""
	if err := SignAttestation(badSig, evilPriv); err != nil {
		t.Fatal(err)
	}
	pinAtt := freshPIN()

	// FIDO2 attested path (PIN can no longer attest at Tier 2).
	fv, _, _, fa, _ := fido2TestSetup(t, []byte("spend"), PresenceFIDO2UV)

	// Tier 1 attested path.
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	mv := mc.mintVerifier(reg)
	tok := mc.mint(t, addr, "r", priv)
	t1att, err := NewTier1Attestation(tok, priv)
	if err != nil {
		t.Fatal(err)
	}

	unenrolledV := &Verifier{Registry: NewRegistry(), Seen: NewSeenSet(), Revoked: NewRevocationSet()}

	cases := []struct {
		name string
		ver  *Verifier
		in   EvalInput
	}{
		{"bad tier tag", v, EvalInput{Tier: Tier(9), Body: body, Receiver: "x", Now: now}},
		{"below required tier", v, EvalInput{Tier: Tier0, RequiredTier: Tier2, Body: body, Receiver: "x", Now: now}},
		{"tier0", v, EvalInput{Tier: Tier0, Body: body, Receiver: "x", Now: now}},
		{"attestation on tier0", v, EvalInput{Tier: Tier0, Body: body, Attestation: pinAtt, Receiver: "x", Now: now}},
		{"missing attestation", v, EvalInput{Tier: Tier2, Body: body, Receiver: "x", Now: now}},
		{"malformed attestation", v, EvalInput{Tier: Tier2, Body: body, Attestation: malformed, Receiver: "x", Now: now}},
		{"tier mismatch", v, EvalInput{Tier: Tier1, Body: body, Attestation: pinAtt, Receiver: "x", Now: now}},
		{"approver not enrolled", unenrolledV, EvalInput{Tier: Tier2, Body: body, Attestation: pinAtt, Receiver: "x", Now: now}},
		{"bad signature", v, EvalInput{Tier: Tier2, Body: body, Attestation: badSig, Receiver: "x", Now: now}},
		{"expired", v, EvalInput{Tier: Tier2, Body: body, Attestation: expired, Receiver: "x", Now: now}},
		{"hash mismatch", v, EvalInput{Tier: Tier2, Body: []byte("something else"), Attestation: pinAtt, Receiver: "x", Now: now}},
		{"unverifiable proof", v, EvalInput{Tier: Tier2, Body: body, Attestation: pinAtt, Receiver: "x", Now: now, EnvelopeID: 21}},
		{"tier2 attested", fv, EvalInput{Tier: Tier2, Body: []byte("spend"), Attestation: fa, Receiver: "r", Now: now, EnvelopeID: 22}},
		{"tier1 attested", mv, EvalInput{Tier: Tier1, Body: []byte("read"), Attestation: t1att, Receiver: "r", Now: now, EnvelopeID: 23}},
	}
	for _, tc := range cases {
		out := tc.ver.Evaluate(tc.in)
		if !out.Evaluated {
			t.Errorf("%s: Evaluated = false, want true (verdict %s, reason %q)", tc.name, out.Verdict, out.Reason)
		}
	}
}

// --- Finding 2: PIN/challenge proofs fail closed at Tier 2 ---
//
// Only FIDO2 assertions are cryptographically verifiable at Tier 2:
// PIN and challenge proofs rest on the Ed25519 attestation
// signature alone, which the requesting agent itself can produce.
// That is self-attestation, not human presence.

func TestTier2PINProofNeverAttests(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("spend 10 BTC")
	a, err := NewTier2Attestation(body, addr, "req-pin", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: time.Now().Unix(), EnvelopeID: 11})
	if out.Verdict == VerdictAttested {
		t.Fatal("PIN proof at tier 2 must never attest: the attestation signature is self-producible by the requesting agent")
	}
	if out.Verdict != VerdictInvalid || out.Reason != "unverifiable-proof" {
		t.Fatalf("got %s (%s), want invalid/unverifiable-proof", out.Verdict, out.Reason)
	}
}

func TestTier2ChallengeProofNeverAttests(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("release v0.14.0")
	a, err := NewTier2Attestation(body, addr, "req-ch", ProofChallenge, PresenceChallenge,
		Proof{ChallengeID: "ch-123"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: time.Now().Unix(), EnvelopeID: 12})
	if out.Verdict == VerdictAttested {
		t.Fatal("challenge proof at tier 2 must never attest: the attestation signature is self-producible by the requesting agent")
	}
	if out.Verdict != VerdictInvalid || out.Reason != "unverifiable-proof" {
		t.Fatalf("got %s (%s), want invalid/unverifiable-proof", out.Verdict, out.Reason)
	}
}
