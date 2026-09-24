package vhl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
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

// mintCeremony is the test fixture for a complete session-token
// mint ceremony: an enrolled WebAuthn credential plus the RP the
// ceremony runs under. The authenticator private key stays
// test-side, standing in for the human's security key.
type mintCeremony struct {
	cred *Credential
	rp   WebAuthnRP
	priv *ecdsa.PrivateKey
}

// newMintCeremony enrolls a fresh WebAuthn credential for addr in
// reg and returns the ceremony fixture.
func newMintCeremony(t *testing.T, reg *Registry, addr string) *mintCeremony {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var idRaw [6]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		t.Fatal(err)
	}
	mc := &mintCeremony{
		rp:   WebAuthnRP{ID: "dashboard.test", Origins: []string{"https://dashboard.test"}},
		priv: priv,
	}
	mc.cred = &Credential{
		ID:         "mint-cred-" + b64.EncodeToString(idRaw[:]),
		Kind:       "webauthn",
		PublicKey:  b64.EncodeToString(coseEncodeKey(t, &priv.PublicKey)),
		EnrolledAt: time.Now().Unix(),
		Device:     "test-yubikey",
	}
	if err := reg.Enroll(addr, "test-human", *mc.cred, true); err != nil {
		t.Fatal(err)
	}
	return mc
}

// mint completes a session-token mint through the real ceremony:
// begin, craft a genuine UV assertion over the pending's
// challenge, finish.
func (mc *mintCeremony) mint(t *testing.T, addr, scope string, idPriv ed25519.PrivateKey) *SessionToken {
	t.Helper()
	pending, err := BeginSessionMint(addr, scope, DefaultSessionTTL, "boot-1")
	if err != nil {
		t.Fatal(err)
	}
	assertion := craftAssertion(t, mc.priv, pending.Challenge(),
		"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	tok, err := pending.Finish(mc.cred, assertion, mc.rp, idPriv)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mintVerifier returns a Verifier configured the way a real
// receiver must be: registry plus the relying party the mint
// ceremony ran under.
func (mc *mintCeremony) mintVerifier(reg *Registry) *Verifier {
	return &Verifier{Registry: reg, Seen: NewSeenSet(), Revoked: NewRevocationSet(), WebAuthn: mc.rp}
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
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	tok := mc.mint(t, addr, "", priv)
	if err := tok.Validate(); err != nil {
		t.Fatal(err)
	}
	if tok.Presence != PresenceFIDO2UV.String() {
		t.Fatalf("mint presence = %q, want fido2_uv: the ceremony, not a caller claim, sets the strength", tok.Presence)
	}
	if tok.CredentialID != mc.cred.ID {
		t.Fatalf("credential id = %q, want %q", tok.CredentialID, mc.cred.ID)
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
	// Re-mint guard: a fido2_uv token is renewable at the same
	// strength, never weaker. (Minting itself only ever produces
	// fido2_uv, so the guard is pinned on struct-shaped tokens.)
	uv := &SessionToken{Presence: PresenceFIDO2UV.String()}
	pin := &SessionToken{Presence: PresencePIN.String()}
	if !uv.MayRemint(PresenceFIDO2UV) {
		t.Fatal("same-strength re-mint should be allowed")
	}
	if !pin.MayRemint(PresenceFIDO2UV) {
		t.Fatal("stronger re-mint should be allowed")
	}
	if uv.MayRemint(PresencePIN) {
		t.Fatal("fido2_uv token must not be re-mintable with pin")
	}
	if uv.MayRemint(PresenceChallenge) {
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
	// Tier 2 attests only on a cryptographically verified FIDO2
	// assertion over the nonce-bound approval challenge (issue
	// #142 review): PIN/challenge proofs fail closed, so the
	// happy path here uses a genuine FIDO2 ceremony.
	body := []byte("please merge PR #141")
	v, credPriv, idPriv, a, _ := fido2TestSetup(t, body, PresenceFIDO2UV)
	approver, credID := a.Approver, a.Proof.CredentialID
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "someone", Now: time.Now().Unix(), EnvelopeID: 7})
	if out.Verdict != VerdictAttested {
		t.Fatalf("want attested, got %v (%s)", out.Verdict, out.Reason)
	}
	if out.Approver != approver {
		t.Fatal("approver should be reported")
	}
	if !out.Evaluated {
		t.Fatal("outcome must be marked evaluated")
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
	a2, _ := mintFIDO2Attestation(t, body, approver, "req-test", PresenceFIDO2UV,
		credID, credPriv, nil, 2, idPriv)
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
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	v := mc.mintVerifier(reg)
	receiver := "ed25519:receiver"
	// Mint a token scoped to the receiver, through the real
	// ceremony.
	tok := mc.mint(t, addr, receiver, priv)
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
	// Expired token fails: backdate the token so it is structurally
	// valid but past its lifetime, then give the wrapping
	// attestation a live lifetime and re-sign it, so evaluation
	// reaches the token-expiry check (not the attestation-lifetime
	// check).
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
	a.IssuedAt = now - 60
	a.ExpiresAt = now + 600
	if err := SignAttestation(a, priv); err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier1, Body: []byte("read file C"), Attestation: a, Receiver: receiver, Now: now})
	if out.Verdict != VerdictInvalid || out.Reason != "token-expired" {
		t.Fatalf("expired token should fail with token-expired, got %v (%s)", out.Verdict, out.Reason)
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

func TestTier2ChallengeProofRejected(t *testing.T) {
	// Challenge proofs fail closed at Tier 2 (issue #142 review):
	// only FIDO2 assertions are cryptographically verifiable, and
	// the Ed25519 attestation signature alone is self-producible
	// by the requesting agent. Construction still works — the
	// rejection happens at evaluation.
	addr, pub, priv := testIdentity(t)
	v := testVerifier(t, addr, pub)
	body := []byte("release v0.14.0")
	a, err := NewTier2Attestation(body, addr, "req-test", ProofChallenge, PresenceChallenge,
		Proof{ChallengeID: "ch-123"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: time.Now().Unix()})
	if out.Verdict != VerdictInvalid || out.Reason != "unverifiable-proof" {
		t.Fatalf("challenge-proof tier 2 attestation should be rejected, got %v (%s)", out.Verdict, out.Reason)
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
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	v := mc.mintVerifier(reg)
	receiver := "ed25519:receiver"
	tok := mc.mint(t, addr, receiver, priv)
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
	// Tier 2 happy path is FIDO2 (PIN no longer attests at Tier
	// 2); the expiry checks sit before the proof gate, so they
	// behave the same.
	body := []byte("sensitive action")
	v, credPriv, idPriv, a, _ := fido2TestSetup(t, body, PresenceFIDO2UV)
	approver, credID := a.Approver, a.Proof.CredentialID
	now := time.Now().Unix()
	// Within grace after expiry: still valid.
	out := v.Evaluate(EvalInput{Tier: Tier2, Body: body, Attestation: a, Receiver: "x", Now: a.ExpiresAt + 60})
	if out.Verdict != VerdictAttested {
		t.Fatalf("within grace should attest, got %v (%s)", out.Verdict, out.Reason)
	}
	_ = now
	// Well past expiry: invalid.
	a2, _ := mintFIDO2Attestation(t, body, approver, "req-test", PresenceFIDO2UV,
		credID, credPriv, nil, 2, idPriv)
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
	// validation must accept a well-formed fido2 proof — including
	// its approval nonce — and reject one without a credential id
	// or without a valid nonce.
	addr, _, priv := testIdentity(t)
	body := []byte("high-stakes action")
	h := MsgHashOf(body)
	now := time.Now().Unix()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	id, err := NewAttestationID()
	if err != nil {
		t.Fatal(err)
	}
	a := &Attestation{
		Version:       attestationVersion,
		ID:            id,
		Tier:          2,
		MsgHash:       b64.EncodeToString(h[:]),
		Approver:      addr,
		RequestID:     "req-test",
		IssuedAt:      now,
		ExpiresAt:     now + 900,
		ApprovalNonce: b64.EncodeToString(nonce),
		Proof: Proof{
			Kind:         ProofFIDO2,
			Strength:     PresenceFIDO2UV.String(),
			CredentialID: "cred-abc",
			Assertion:    "eyJ9",
		},
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := SignAttestation(a, priv); err != nil {
		t.Fatal(err)
	}
	bad, err := NewAttestationID()
	if err != nil {
		t.Fatal(err)
	}
	// No credential id: rejected.
	noCred := *a
	noCred.ID = bad
	noCred.Proof.CredentialID = ""
	if err := noCred.Validate(); err == nil {
		t.Fatal("fido2 proof without credential id should fail validation")
	}
	// No approval nonce: rejected — the challenge cannot be
	// verified without it.
	noNonce := *a
	noNonce.ApprovalNonce = ""
	if err := noNonce.Validate(); err == nil {
		t.Fatal("fido2 proof without approval nonce should fail validation")
	}
	// Malformed approval nonce: rejected.
	shortNonce := *a
	shortNonce.ApprovalNonce = "short"
	if err := shortNonce.Validate(); err == nil {
		t.Fatal("fido2 proof with malformed approval nonce should fail validation")
	}
}

func TestReenrollRevokedApproverDropsCredentials(t *testing.T) {
	r := NewRegistry()
	addr, pub, _ := testIdentity(t)
	oldKeyID := "old-key"
	if err := r.Enroll(addr, "human", Credential{ID: oldKeyID, Kind: "ed25519", PublicKey: b64.EncodeToString(pub)}, true); err != nil {
		t.Fatal(err)
	}
	if err := r.RevokeApprover(addr); err != nil {
		t.Fatal(err)
	}
	// Re-enrolling a revoked approver must not resurrect the
	// compromised credentials: KeysFor must return only the new key.
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Enroll(addr, "human", Credential{ID: "new-key", Kind: "ed25519", PublicKey: b64.EncodeToString(pub2)}, true); err != nil {
		t.Fatal(err)
	}
	keys, _, err := r.KeysFor(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !bytes.Equal(keys[0], []byte(pub2)) {
		t.Fatal("re-enrolling a revoked approver must drop the old credentials")
	}
	// Re-enrolling a non-revoked approver preserves credentials.
	pub3, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Enroll(addr, "human", Credential{ID: "third-key", Kind: "ed25519", PublicKey: b64.EncodeToString(pub3)}, true); err != nil {
		t.Fatal(err)
	}
	keys, _, err = r.KeysFor(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("non-revoked re-enroll should preserve credentials, got %d keys", len(keys))
	}
}

func TestProofStrengthCeiling(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	body := []byte("high-stakes action")
	// A PIN proof claiming fido2_uv must fail validation: the
	// claim would otherwise skip FIDO2 verification while the
	// receiver trusts it.
	if _, err := NewTier2Attestation(body, addr, "req-test", ProofPIN, PresenceFIDO2UV, Proof{}, priv); err == nil {
		t.Fatal("pin proof claiming fido2_uv should fail validation")
	}
	// A fido2 proof with strength fido2_uv validates (given valid
	// fields, including the approval nonce): FIDO2 covers both
	// touch-only and user-verified ceremonies, and the UV flag is
	// enforced cryptographically at verification time.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	fidoid, err := NewAttestationID()
	if err != nil {
		t.Fatal(err)
	}
	fh := MsgHashOf(body)
	fnow := time.Now().Unix()
	a := &Attestation{
		Version:       attestationVersion,
		ID:            fidoid,
		Tier:          2,
		MsgHash:       b64.EncodeToString(fh[:]),
		Approver:      addr,
		RequestID:     "req-test",
		IssuedAt:      fnow,
		ExpiresAt:     fnow + 900,
		ApprovalNonce: b64.EncodeToString(nonce),
		Proof: Proof{
			Kind:         ProofFIDO2,
			Strength:     PresenceFIDO2UV.String(),
			CredentialID: "cred-abc",
			Assertion:    "eyJ9",
		},
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fido2 proof with fido2_uv strength should validate: %v", err)
	}
	// A challenge proof claiming fido2 must fail: it exceeds the
	// challenge kind's ceiling.
	if _, err := NewTier2Attestation(body, addr, "req-test", ProofChallenge, PresenceFIDO2,
		Proof{ChallengeID: "ch-1"}, priv); err == nil {
		t.Fatal("challenge proof claiming fido2 should fail validation")
	}
	// A session proof's strength must equal the token's mint presence.
	_, _, tokPriv := testIdentity(t)
	tokReg := testRegistry(t, addr, pub)
	tokMC := newMintCeremony(t, tokReg, addr)
	tok := tokMC.mint(t, addr, "", tokPriv)
	sa, err := NewTier1Attestation(tok, tokPriv)
	if err != nil {
		t.Fatal(err)
	}
	sa.Proof.Strength = PresencePIN.String()
	if err := sa.Validate(); err == nil {
		t.Fatal("session proof strength differing from token presence should fail validation")
	}
}

// TestSessionMintFailsClosed pins the fail-closed mint: without a
// genuine authenticator assertion over the pending's challenge,
// verified against an enrolled WebAuthn credential and a configured
// RP, Finish must refuse. No parameter combination may produce a
// token from a caller-supplied presence claim — there is no
// presence parameter at all.
func TestSessionMintFailsClosed(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)

	begin := func(t *testing.T) *PendingSessionMint {
		t.Helper()
		p, err := BeginSessionMint(addr, "", DefaultSessionTTL, "boot-1")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	goodAssertion := func(t *testing.T, p *PendingSessionMint) string {
		t.Helper()
		return craftAssertion(t, mc.priv, p.Challenge(),
			"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	}

	// No relying party configured.
	if _, err := begin(t).Finish(mc.cred, goodAssertion(t, begin(t)), WebAuthnRP{}, priv); err == nil {
		t.Fatal("finish without relying party should fail")
	}
	// Empty assertion.
	if _, err := begin(t).Finish(mc.cred, "", mc.rp, priv); err == nil {
		t.Fatal("finish without assertion should fail")
	}
	// Assertion over the wrong challenge.
	p := begin(t)
	wrong := craftAssertion(t, mc.priv, []byte("not-the-mint-challenge-padded-to-32b"),
		"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	if _, err := p.Finish(mc.cred, wrong, mc.rp, priv); err == nil {
		t.Fatal("finish with assertion over wrong challenge should fail")
	}
	// Assertion from a different key than the enrolled credential.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p2 := begin(t)
	forged := craftAssertion(t, other, p2.Challenge(),
		"https://dashboard.test", "dashboard.test", authFlagUserPresent|authFlagUserVerified)
	if _, err := p2.Finish(mc.cred, forged, mc.rp, priv); err == nil {
		t.Fatal("finish with assertion from unenrolled key should fail")
	}
	// Non-WebAuthn credential kind.
	p3 := begin(t)
	edCred := &Credential{ID: "ed-cred", Kind: "ed25519", PublicKey: b64.EncodeToString(make([]byte, 32))}
	if _, err := p3.Finish(edCred, goodAssertion(t, p3), mc.rp, priv); err == nil {
		t.Fatal("finish with non-webauthn credential should fail")
	}
	// Missing origin (UV) flag: a touch-only assertion must not mint
	// a session token.
	p4 := begin(t)
	touchOnly := craftAssertion(t, mc.priv, p4.Challenge(),
		"https://dashboard.test", "dashboard.test", authFlagUserPresent)
	if _, err := p4.Finish(mc.cred, touchOnly, mc.rp, priv); err == nil {
		t.Fatal("finish with touch-only assertion should fail: session mint requires UV")
	}
	// Begin validation.
	if _, err := BeginSessionMint("", "", DefaultSessionTTL, "boot-1"); err == nil {
		t.Fatal("begin without issuer should fail")
	}
	if _, err := BeginSessionMint(addr, "", 0, "boot-1"); err == nil {
		t.Fatal("begin with non-positive TTL should fail")
	}
}

// TestTier1RejectsTransplantedAssertion is the residual-finding
// regression test: a process holding the issuer's identity key
// takes a valid token's assertion, transplants it onto a forged
// token with different bytes, and re-signs with the identity key.
// The receiver must reject it, because the assertion is bound to
// the original token's mint challenge — the issuer signature alone
// is not sufficient.
func TestTier1RejectsTransplantedAssertion(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	v := mc.mintVerifier(reg)
	receiver := "ed25519:receiver"

	good := mc.mint(t, addr, receiver, priv)

	// Forge: fresh token ids (so the token is structurally valid
	// and live), the victim's assertion transplanted in, re-signed
	// with the real identity key — exactly what a co-located
	// process with the key can do.
	p, err := BeginSessionMint(addr, receiver, DefaultSessionTTL, "boot-1")
	if err != nil {
		t.Fatal(err)
	}
	evil := p.tokenForChallenge()
	evil.CredentialID = good.CredentialID
	evil.Assertion = good.Assertion
	if err := evil.sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := evil.Validate(); err != nil {
		t.Fatalf("forged token should be structurally valid (the attack is semantic): %v", err)
	}
	a, err := NewTier1Attestation(evil, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := v.Evaluate(EvalInput{Tier: Tier1, Body: []byte("attacker orders"), Attestation: a, Receiver: receiver, Now: time.Now().Unix()})
	if out.Verdict != VerdictInvalid {
		t.Fatalf("transplanted assertion should be rejected, got %v (%s)", out.Verdict, out.Reason)
	}
	if !strings.HasPrefix(out.Reason, "token-mint:") {
		t.Fatalf("want token-mint rejection, got %q", out.Reason)
	}
}

// TestTier1RejectsStrippedAssertion: stripping the assertion and
// re-signing with the identity key must not produce a usable token
// — structural validation rejects it before any signature is
// trusted.
func TestTier1RejectsStrippedAssertion(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)

	good := mc.mint(t, addr, "", priv)
	stripped := *good
	stripped.Assertion = ""
	if err := stripped.sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := stripped.Validate(); err == nil {
		t.Fatal("token without mint assertion should fail structural validation")
	}
	if _, err := NewTier1Attestation(&stripped, priv); err == nil {
		t.Fatal("attestation wrapping an assertion-less token should fail construction")
	}
}

// TestTier1RejectsLegacyV1Token: v1 tokens (issuer signature only,
// caller-supplied presence) are dead. The version check rejects
// them structurally, so no v1 token can ever evaluate.
func TestTier1RejectsLegacyV1Token(t *testing.T) {
	addr, _, _ := testIdentity(t)
	now := time.Now().Unix()
	legacy := &SessionToken{
		Version:   1,
		ID:        b64.EncodeToString(make([]byte, 16)),
		Issuer:    addr,
		SessionID: b64.EncodeToString(make([]byte, 16)),
		IssuedAt:  now,
		ExpiresAt: now + 3600,
		Presence:  PresencePIN.String(),
		BootID:    "boot-1",
	}
	// v1 tokens cannot even be signed (canonical rejects the
	// version); structural validation rejects them regardless.
	if err := legacy.Validate(); err == nil {
		t.Fatal("v1 token should fail structural validation")
	}
}

// TestTier1FailsClosedWithoutRP: a receiver with no relying party
// configured rejects even a genuinely minted token — there is
// nothing trustworthy to verify the mint assertion against.
func TestTier1FailsClosedWithoutRP(t *testing.T) {
	addr, pub, priv := testIdentity(t)
	reg := testRegistry(t, addr, pub)
	mc := newMintCeremony(t, reg, addr)
	// Note: this verifier deliberately has no relying party —
	// it is built straight from the registry, not via mintVerifier.
	verifier := &Verifier{Registry: reg, Seen: NewSeenSet(), Revoked: NewRevocationSet()}
	receiver := "ed25519:receiver"

	tok := mc.mint(t, addr, receiver, priv)
	now := time.Now().Unix()
	if err := verifier.VerifyTokenStandalone(tok, receiver, now); err == nil {
		t.Fatal("token verification without relying party should fail closed")
	}
	a, err := NewTier1Attestation(tok, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := verifier.Evaluate(EvalInput{Tier: Tier1, Body: []byte("orders"), Attestation: a, Receiver: receiver, Now: now})
	if out.Verdict != VerdictInvalid || !strings.HasPrefix(out.Reason, "token-mint:") {
		t.Fatalf("want token-mint rejection without RP, got %v (%s)", out.Verdict, out.Reason)
	}
}
