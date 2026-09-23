package vhl

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// testIdentity makes a fresh Ed25519 identity for tests.
func testIdentity(t *testing.T) (addr string, pub []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr = "ed25519:test-" + b64.EncodeToString(pub[:8])
	return addr, pub, priv
}

// testRegistry enrolls addr's key and returns the registry.
func testRegistry(t *testing.T, addr string, pub []byte) *Registry {
	t.Helper()
	r := NewRegistry()
	err := r.Enroll(addr, "test-human", Credential{
		ID:        addr,
		Kind:      "ed25519",
		PublicKey: b64.EncodeToString(pub),
		Device:    "test-device",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testVerifier(t *testing.T, addr string, pub []byte) *Verifier {
	t.Helper()
	return &Verifier{Registry: testRegistry(t, addr, pub), Seen: NewSeenSet(), Revoked: NewRevocationSet()}
}

func TestTierString(t *testing.T) {
	if !Tier0.Valid() || !Tier1.Valid() || !Tier2.Valid() {
		t.Fatal("tiers should be valid")
	}
	if Tier(7).Valid() {
		t.Fatal("tier 7 should be invalid")
	}
}

func TestPresenceRanking(t *testing.T) {
	if !PresenceFIDO2UV.AtLeast(PresencePIN) {
		t.Fatal("fido2_uv should outrank pin")
	}
	if PresencePIN.AtLeast(PresenceFIDO2) {
		t.Fatal("pin should not outrank fido2")
	}
	if _, err := ParsePresence("yubikey"); err == nil {
		t.Fatal("unknown presence should fail")
	}
}

func TestSessionTokenRoundTrip(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	tok, err := MintSessionToken(addr, "", PresencePIN, DefaultSessionTTL, "boot-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := tok.verifySignature(pub); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if !tok.LiveAt(now) {
		t.Fatal("fresh token should be live")
	}
	if tok.LiveAt(now + int64(DefaultSessionTTL/time.Second) + 3600) {
		t.Fatal("long-expired token should not be live")
	}
	// Backdated issued-at is rejected even within grace.
	if tok.LiveAt(tok.IssuedAt - 1) {
		t.Fatal("pre-issued token should not be live")
	}
	// Re-mint: same strength OK, weaker not.
	if !tok.MayRemint(PresencePIN) {
		t.Fatal("same-strength re-mint should be allowed")
	}
	if !tok.MayRemint(PresenceFIDO2UV) {
		t.Fatal("stronger re-mint should be allowed")
	}
	uvTok, err := MintSessionToken(addr, "", PresenceFIDO2UV, DefaultSessionTTL, "boot-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if uvTok.MayRemint(PresencePIN) {
		t.Fatal("fido2_uv token must not be re-mintable with pin")
	}
	if uvTok.MayRemint(PresenceChallenge) {
		t.Fatal("fido2_uv token must not be re-mintable with challenge")
	}
}

func TestSealRoundTrip(t *testing.T) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	key := DeriveSealKey(seed)
	plain := []byte(`[{"id":"abc"}]`)
	sealed, err := SealTokens(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenTokens(sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != string(plain) {
		t.Fatal("seal round-trip mismatch")
	}
	var other [32]byte
	if _, err := rand.Read(other[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTokens(sealed, DeriveSealKey(other)); err == nil {
		t.Fatal("wrong key should fail closed")
	}
	if _, err := OpenTokens([]byte("short"), key); err == nil {
		t.Fatal("truncated store should fail")
	}
}

func TestTier2AttestationVerify(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("please merge PR #141")
	a, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "someone", Now: time.Now().Unix(), EnvelopeID: 7})
	if out.Verdict != VerdictAttested {
		t.Fatalf("want attested, got %v (%s)", out.Verdict, out.Reason)
	}
	if out.Approver != addr {
		t.Fatal("approver should be reported")
	}
	// The same envelope re-evaluated (another consumer, e.g.
	// dashboard push vs. inbox) is not a replay.
	outSame := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "someone", Now: time.Now().Unix(), EnvelopeID: 7})
	if outSame.Verdict != VerdictAttested {
		t.Fatalf("same envelope should re-attest, got %v (%s)", outSame.Verdict, outSame.Reason)
	}
	// Exact replay of the same attestation in a different envelope fails.
	out2 := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "someone", Now: time.Now().Unix(), EnvelopeID: 8})
	if out2.Verdict != VerdictInvalid || out2.Reason != "replay" {
		t.Fatalf("replay should fail, got %v (%s)", out2.Verdict, out2.Reason)
	}
	// Tampered body fails the hash binding.
	a2, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out3 := v.Evaluate(EvalInput{Tier: Tier2, Body: []byte("please merge PR #999"), Attestation: a2, Receiver: "someone", Now: time.Now().Unix()})
	if out3.Verdict != VerdictInvalid || out3.Reason != "hash-mismatch" {
		t.Fatalf("bait-and-switch should fail, got %v (%s)", out3.Verdict, out3.Reason)
	}
}

func TestAttestationBadSignature(t *testing.T) {
	addr, pub, _ := testIdentity(t)
	_, _, evilPriv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("spend 10 BTC")
	// Signed by a key that is not enrolled.
	a, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresencePIN, Proof{}, evilPriv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: time.Now().Unix()})
	if out.Verdict != VerdictInvalid || out.Reason != "bad-signature" {
		t.Fatalf("forged attestation should fail, got %v (%s)", out.Verdict, out.Reason)
	}
}

func TestAttestationUnknownApprover(t *testing.T) {
	addr, _, priv := testIdentity(t)
	v := &Verifier{Registry: NewRegistry(), Seen: NewSeenSet(), Revoked: NewRevocationSet()}
	body := []byte("do the thing")
	a, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: time.Now().Unix()})
	if out.Verdict != VerdictInvalid || out.Reason != "approver-not-enrolled" {
		t.Fatalf("unenrolled approver should fail, got %v (%s)", out.Verdict, out.Reason)
	}
}

func TestTierClaimWithoutAttestation(t *testing.T) {
	addr, pub, _ := testIdentity(t)
	v := testVerifier(t, addr, pub)
	for _, tier := range []Tier{Tier1, Tier2} {
		out := v.Evaluate(EvalInput{Tier: tier, Body: []byte("sensitive"), Receiver: "x", Now: time.Now().Unix()})
		if out.Verdict != VerdictMissing {
			t.Fatalf("tier %v without attestation should be missing, got %v", tier, out.Verdict)
		}
	}
	out := v.Evaluate(EvalInput{Tier: Tier0, Body: []byte("hello"), Receiver: "x", Now: time.Now().Unix()})
	if out.Verdict != VerdictUnattested {
		t.Fatalf("tier 0 should be unattested, got %v", out.Verdict)
	}
}

func TestTier1SessionFlow(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	receiver := "ed25519:receiver"
	// Mint a token scoped to the receiver.
	tok, err := MintSessionToken(addr, receiver, PresencePIN, DefaultSessionTTL, "boot-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := v.VerifyTokenStandalone(tok, receiver, now); err != nil {
		t.Fatal(err)
	}
	// Wrong scope fails.
	if err := v.VerifyTokenStandalone(tok, "ed25519:someone-else", now); err == nil {
		t.Fatal("out-of-scope token should fail")
	}
	// Attach to two different messages: both attest (fresh
	// attestation ids), and neither is a replay.
	for _, body := range []string{"read file A", "read file B"} {
		a, err := NewTier1Attestation(tok, priv)
		if err != nil {
			t.Fatal(err)
		}
		out := v.Evaluate(EvalInput{Tier: Tier1, Body: []byte(body), Attestation: a, Receiver: receiver, Now: now})
		if out.Verdict != VerdictAttested {
			t.Fatalf("tier 1 message %q should attest, got %v (%s)", body, out.Verdict, out.Reason)
		}
	}
	// Expired token fails: backdate both ends so the token is
	// structurally valid but past its lifetime.
	old := *tok
	old.IssuedAt = now - 7200
	old.ExpiresAt = now - 3600
	if err := old.sign(priv); err != nil {
		t.Fatal(err)
	}
	a, err := NewTier1Attestation(&old, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier1, Body: []byte("read file C"), Attestation: a, Receiver: receiver, Now: now})
	if out.Verdict != VerdictInvalid {
		t.Fatalf("expired token should fail, got %v", out.Verdict)
	}
}

func TestChallengeFlow(t *testing.T) {
	action := []byte("merge pull request #141")
	ch, code, err := MintChallenge(action, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.BindsAction(action) {
		t.Fatal("challenge should bind the action")
	}
	if ch.BindsAction([]byte("merge pull request #142")) {
		t.Fatal("challenge must not bind other actions")
	}
	now := time.Now().Unix()
	if err := ch.Verify(code, now); err != nil {
		t.Fatal(err)
	}
	// Single-use.
	if err := ch.Verify(code, now); err == nil {
		t.Fatal("challenge code must be single-use")
	}
	// Wrong code fails (mint a fresh one since the first is used).
	ch2, _, err := MintChallenge(action, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch2.Verify("wrongcode", now); err == nil {
		t.Fatal("wrong code should fail")
	}
	// Expired fails.
	if err := ch2.Verify("whatever", ch2.ExpiresAt+1); err == nil {
		t.Fatal("expired challenge should fail")
	}
}

func TestChallengeProofAttestation(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("release v0.14.0")
	a, err := NewTier2Attestation(body, addr, "req-test", ProofChallenge, PresenceChallenge,
		Proof{ChallengeID: "ch-123"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: time.Now().Unix()})
	if out.Verdict != VerdictAttested {
		t.Fatalf("challenge-proof attestation should verify, got %v (%s)", out.Verdict, out.Reason)
	}
}

func TestFrames(t *testing.T) {
	// Approval request round-trip + hash-then-display check.
	draft := "transfer 1.5 BTC to 1A2b..."
	h := MsgHashOf([]byte(draft))
	reqID, err := NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	req := &ApprovalRequest{
		ID: reqID, Tier: 2, MsgHash: b64.EncodeToString(h[:]),
		Draft: draft, AgentNote: "payment", WantPresence: "pin",
		ExpiresAt: time.Now().Add(RequestTTL).Unix(),
	}
	raw, err := EncodeApprovalRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := ParseFrame(raw)
	if !ok || f.Type != FrameApprovalRequest {
		t.Fatal("approval request frame should parse")
	}
	if err := f.ApprovalRequest.Validate(time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	// Tampered draft fails the hash check.
	bad := *f.ApprovalRequest
	bad.Draft = "transfer 15 BTC to 1A2b..."
	if err := bad.Validate(time.Now().Unix()); err == nil {
		t.Fatal("tampered draft must fail validation")
	}
	// Non-VHL plaintext falls through.
	if _, ok := ParseFrame([]byte("hello world")); ok {
		t.Fatal("plain text must not parse as a VHL frame")
	}
	if _, ok := ParseFrame([]byte(`{"magic":"nope","t":"vhl-attest","v":1,"p":{}}`)); ok {
		t.Fatal("wrong magic must not parse")
	}
	// Attest frame round-trip.
	addr, _, priv := testIdentity(t)
	a, err := NewTier2Attestation([]byte(draft), addr, "req-test", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	araw, err := EncodeAttestation(a)
	if err != nil {
		t.Fatal(err)
	}
	af, ok := ParseFrame(araw)
	if !ok || af.Type != FrameAttest {
		t.Fatal("attest frame should parse")
	}
	if af.Attestation.ID != a.ID {
		t.Fatal("attestation id should survive the frame")
	}
}

func TestRevocation(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	receiver := "ed25519:receiver"
	tok, err := MintSessionToken(addr, receiver, PresencePIN, DefaultSessionTTL, "boot-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	// Revoke the token.
	rev := &Revocation{Version: 1, Issuer: addr, IssuedAt: now, TokenIDs: []string{tok.ID}}
	if err := SignRevocation(rev, priv); err != nil {
		t.Fatal(err)
	}
	// A forged revocation (wrong key) must not verify.
	_, _, evilPriv := testIdentity(t)
	badRev := &Revocation{Version: 1, Issuer: addr, IssuedAt: now, TokenIDs: []string{tok.ID}}
	if err := SignRevocation(badRev, evilPriv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationSignature(badRev, pub); err == nil {
		t.Fatal("forged revocation should fail")
	}
	if err := VerifyRevocationSignature(rev, pub); err != nil {
		t.Fatal(err)
	}
	v.Revoked.Apply(rev, now)
	if err := v.VerifyTokenStandalone(tok, receiver, now); err == nil {
		t.Fatal("revoked token should not verify")
	}
	// Revocation frame round-trip.
	raw, err := EncodeRevocation(rev)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := ParseFrame(raw)
	if !ok || f.Type != FrameRevoke {
		t.Fatal("revoke frame should parse")
	}
}

func TestEnrollmentRules(t *testing.T) {
	r := NewRegistry()
	addr, pub, _ := testIdentity(t)
	// Enrollment without the Tier 2 human-approved event fails.
	err := r.Enroll(addr, "", Credential{ID: addr, Kind: "ed25519", PublicKey: b64.EncodeToString(pub)}, false)
	if err == nil {
		t.Fatal("enrollment without tier2 approval should fail")
	}
	// Unknown credential kind fails.
	err = r.Enroll(addr, "", Credential{ID: "x", Kind: "magic", PublicKey: "eA"}, true)
	if err == nil {
		t.Fatal("unknown credential kind should fail")
	}
	// Happy path.
	if err := r.Enroll(addr, "riley", Credential{ID: addr, Kind: "ed25519", PublicKey: b64.EncodeToString(pub), Device: "yubikey"}, true); err != nil {
		t.Fatal(err)
	}
	if !r.Enrolled(addr) {
		t.Fatal("approver should be enrolled")
	}
	keys, _, err := r.KeysFor(addr)
	if err != nil || len(keys) != 1 {
		t.Fatal("should return the enrolled key")
	}
	// Surgical credential revocation.
	if err := r.RevokeCredential(addr, addr); err != nil {
		t.Fatal(err)
	}
	if r.Enrolled(addr) {
		t.Fatal("approver with no credentials should not count as enrolled")
	}
}

func TestAttestationExpiry(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("sensitive action")
	a, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	// Within grace after expiry: still valid.
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: a.ExpiresAt + 60})
	if out.Verdict != VerdictAttested {
		t.Fatalf("within grace should attest, got %v (%s)", out.Verdict, out.Reason)
	}
	_ = now
	// Well past expiry: invalid.
	a2, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresencePIN, Proof{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out2 := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a2, Receiver: "x", Now: a2.ExpiresAt + 3600})
	if out2.Verdict != VerdictInvalid || out2.Reason != "expired" {
		t.Fatalf("past grace should expire, got %v (%s)", out2.Verdict, out2.Reason)
	}
}

func TestFIDO2ProofSchema(t *testing.T) {
	// The schema carries FIDO2 proofs; the verifier checks the
	// assertion cryptographically (see webauthn_test.go). The
	// ceremony that *produces* assertions (dashboard driving
	// navigator.credentials.get) is the follow-up. Structural
	// validation must accept a well-formed fido2 proof and reject
	// one without a credential id.
	addr, _, priv := testIdentity(t)
	body := []byte("high-stakes action")
	a, err := NewTier2Attestation(body, addr, "req-test", ProofFIDO2, PresenceFIDO2UV,
		Proof{CredentialID: "cred-abc", Assertion: "eyJ9"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	bad, err := NewTier2Attestation(body, addr, "req-test", ProofFIDO2, PresenceFIDO2UV, Proof{}, priv)
	if err == nil {
		t.Fatal("fido2 proof without credential id should fail construction")
	} else if bad != nil {
		t.Fatal("failed construction should not return an attestation")
	}
}
