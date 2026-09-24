package vhl

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Verdict is the receiver-side outcome of VHL evaluation for one
// message. VHL is enforced by the receiver: the verdict tells the
// receiving agent's policy what the tier tag and attestation are
// worth. Verdicts never authorize action by themselves — they are
// the trust signal the agent's policy acts on.
type Verdict int

const (
	// VerdictUnattested: tier 0 message, or no tier tag. Routine
	// chatter flows here.
	VerdictUnattested Verdict = iota
	// VerdictAttested: the claimed tier is backed by a valid
	// attestation (signature, enrollment, lifetime, scope, proof,
	// and no replay).
	VerdictAttested
	// VerdictMissing: the message claims tier 1 or 2 but carries no
	// attestation. Held for review — never acted on.
	VerdictMissing
	// VerdictInvalid: the attestation failed verification (bad
	// signature, unknown/revoked approver, expired, wrong scope,
	// replayed, or hash mismatch). Held for review — never acted on.
	VerdictInvalid
)

// String names the verdict for logs and audit trails.
func (v Verdict) String() string {
	switch v {
	case VerdictUnattested:
		return "unattested"
	case VerdictAttested:
		return "attested"
	case VerdictMissing:
		return "missing-attestation"
	case VerdictInvalid:
		return "invalid-attestation"
	default:
		return "unknown"
	}
}

// EvalInput is everything the verifier needs for one message.
type EvalInput struct {
	// Tier is the tier tag from inside the E2E plaintext (0 when absent).
	Tier Tier
	// RequiredTier is the minimum tier the receiver's policy
	// demands for this message (issue #142 review). The tier tag
	// is sender-asserted and Tier 0 short-circuits evaluation, so
	// without this a sender could self-label Tier 0 and get
	// normal delivery even when the receiver requires Tier 2. A
	// message below the required tier is VerdictInvalid — never
	// actionable. Zero value (Tier0) means no requirement, which
	// preserves the historical behavior.
	RequiredTier Tier
	// Body is the decrypted message body bytes (for hash binding).
	Body []byte
	// Attestation is the inline attestation, if the sender attached one.
	Attestation *Attestation
	// Receiver is this agent's own address (for token scope checks).
	Receiver string
	// Now is receiver-local unix time.
	Now int64
	// EnvelopeID is the relay envelope id carrying this message. The
	// replay guard keys on (attestation id, envelope id) so two
	// consumers evaluating the same envelope do not false-positive.
	EnvelopeID int64
}

// EvalOutcome pairs the verdict with the details an agent's policy
// and audit trail need.
type EvalOutcome struct {
	Verdict  Verdict
	Tier     Tier
	Approver string // attesting approver identity, when verified
	Reason   string // machine-readable detail for logs
	// Evaluated is true when this outcome came out of Evaluate.
	// It lets downstream distinguish "explicitly evaluated as
	// Tier 0" from "never evaluated" (e.g. a fallback outcome
	// constructed without running the verifier).
	Evaluated bool
}

// Verifier evaluates VHL tier tags and attestations. It is built on
// the local enrollment registry (the trust root), the seen-artifact
// set (replay), and the revocation set. All time checks use
// receiver-local time with the standard clock-skew grace.
type Verifier struct {
	Registry *Registry
	Seen     *SeenSet
	Revoked  *RevocationSet
	// WebAuthn configures the relying party for fido2 proof
	// verification. When empty, fido2 proofs fail closed — the
	// schema alone never counts as verified presence.
	WebAuthn WebAuthnRP
	// Nonces is the consumed-approval-nonce set for Tier 2 FIDO2
	// approval replay (issue #142 review). Nil-safe: a nil set
	// records nothing and the nonce-replay check is skipped — the
	// assertion is still cryptographically verified against the
	// nonce-bound challenge and the authenticator sign counter is
	// still enforced. Wire a persisted NonceSet for the full
	// replay protection; the check-and-consume must be atomic
	// with persistence by the caller.
	Nonces *NonceSet
	// RequiredTier is the receiver's minimum-tier floor for inbound
	// evaluation (issue #142 review). The tier tag is
	// sender-asserted, so the floor must apply to every message —
	// including untagged Tier 0 — or a sender could omit the tag
	// to dodge it. Loaded once with the rest of the verifier
	// state; the zero value (Tier0) means no requirement.
	RequiredTier Tier
}

// maxSeenArtifacts bounds the replay set; the message-hash binding
// already defeats cut-and-paste onto another message, so the set only
// needs to catch exact replays within a generous window.
const maxSeenArtifacts = 5000

// SeenSet is the seen-artifact set against exact replays. The value
// is the envelope id where the id was first seen, so the same
// envelope re-derived by another consumer (dashboard push vs.
// inbox) is not mistaken for a replay — only the same attestation
// arriving in a *different* envelope is.
type SeenSet struct {
	IDs map[string]int64 `json:"ids"` // attestation/token id -> envelope id first seen in
}

// NewSeenSet returns an empty set.
func NewSeenSet() *SeenSet { return &SeenSet{IDs: map[string]int64{}} }

// Seen reports whether id was already consumed in a different
// envelope. The same envelope re-evaluated is not a replay.
func (s *SeenSet) Seen(id string, envelopeID int64) bool {
	if s.IDs == nil {
		return false
	}
	env, ok := s.IDs[id]
	return ok && env != envelopeID
}

// Mark records id as consumed in envelopeID, evicting oldest entries
// past the bound.
func (s *SeenSet) Mark(id string, envelopeID int64) {
	if s.IDs == nil {
		s.IDs = map[string]int64{}
	}
	if _, ok := s.IDs[id]; !ok {
		s.IDs[id] = envelopeID
	}
	for len(s.IDs) > maxSeenArtifacts {
		oldest, oe := "", int64(0)
		first := true
		for k, v := range s.IDs {
			if first || v < oe {
				oldest, oe, first = k, v, false
			}
		}
		delete(s.IDs, oldest)
	}
}

// SeenInEnvelope reports whether id was already recorded against
// exactly this envelope id. Unlike Seen (which flags a *different*
// envelope as a replay), this identifies a re-evaluation of the
// same envelope by another consumer.
func (s *SeenSet) SeenInEnvelope(id string, envelopeID int64) bool {
	if s == nil || s.IDs == nil {
		return false
	}
	env, ok := s.IDs[id]
	return ok && env == envelopeID
}

// RevocationSet tracks revoked token and attestation ids.
type RevocationSet struct {
	Tokens    map[string]int64 `json:"tokens,omitempty"`    // token id -> revoked unix time
	Artifacts map[string]int64 `json:"artifacts,omitempty"` // attestation id -> revoked unix time
}

// NewRevocationSet returns an empty set.
func NewRevocationSet() *RevocationSet {
	return &RevocationSet{Tokens: map[string]int64{}, Artifacts: map[string]int64{}}
}

// Revoked reports whether a token or attestation id is revoked.
func (r *RevocationSet) Revoked(tokenID, artifactID string) bool {
	if r == nil {
		return false
	}
	if tokenID != "" {
		if _, ok := r.Tokens[tokenID]; ok {
			return true
		}
	}
	if artifactID != "" {
		if _, ok := r.Artifacts[artifactID]; ok {
			return true
		}
	}
	return false
}

// Apply merges a verified revocation into the set.
func (r *RevocationSet) Apply(rev *Revocation, now int64) {
	if r.Tokens == nil {
		r.Tokens = map[string]int64{}
	}
	if r.Artifacts == nil {
		r.Artifacts = map[string]int64{}
	}
	for _, id := range rev.TokenIDs {
		r.Tokens[id] = now
	}
	for _, id := range rev.ArtifactIDs {
		r.Artifacts[id] = now
	}
}

// Evaluate verifies one message's VHL tier tag and attestation.
//
// The checks, in order: tier tag valid; receiver-required minimum
// tier (a sender-asserted Tier 0 never satisfies a higher
// requirement); tier 0 → unattested; higher tiers require an
// attestation (missing → VerdictMissing); the attestation validates
// structurally, its signer key is enrolled for the claimed approver,
// the signature verifies, the id is neither seen nor revoked, the
// lifetime covers now (receiver-local, with grace), and the
// tier-specific binding holds (tier 2: message hash matches and the
// proof is a cryptographically verified FIDO2 assertion over the
// nonce-bound approval challenge; tier 1: session token live, scope
// covers this receiver, presence recorded).
//
// A single failure yields VerdictInvalid with a machine-readable
// reason. The message itself is never dropped here — the caller's
// policy maps the verdict to delivery (attested), hold-for-review
// (missing/invalid), or plain delivery (unattested tier 0).
// Every return path sets Evaluated on the outcome.
func (v *Verifier) Evaluate(in EvalInput) (out EvalOutcome) {
	// Evaluated marks every outcome that came out of this
	// function, so downstream can tell "explicitly evaluated as
	// Tier 0" from "never evaluated". The defer covers every
	// return path — including ones added later.
	defer func() { out.Evaluated = true }()
	tier := in.Tier
	if !tier.Valid() {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Reason: "bad-tier-tag"}
	}
	// Receiver-enforced minimum tier (issue #142 review): the tier
	// tag is sender-asserted and Tier 0 short-circuits below, so
	// without this check a sender could self-label Tier 0 to get
	// normal delivery when the receiver requires Tier 2. Below
	// the requirement the message is invalid, never actionable.
	if tier < in.RequiredTier {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Reason: "below-required-tier"}
	}
	if tier == Tier0 {
		// A Tier 0 message must not carry an attestation: an
		// unattested tier tag with a smuggled artifact is a
		// downgrade/evasiveness signal, never harmless (issue #142).
		if in.Attestation != nil {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Reason: "attestation-on-tier0"}
		}
		return EvalOutcome{Verdict: VerdictUnattested, Tier: tier, Reason: "tier0"}
	}
	if in.Attestation == nil {
		return EvalOutcome{Verdict: VerdictMissing, Tier: tier, Reason: "no-attestation"}
	}
	a := in.Attestation
	if err := a.Validate(); err != nil {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Reason: "malformed:" + err.Error()}
	}
	if Tier(a.Tier) != tier {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Reason: "tier-mismatch"}
	}
	if v.Registry == nil || !v.Registry.Enrolled(a.Approver) {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "approver-not-enrolled"}
	}
	edKeys, _, err := v.Registry.KeysFor(a.Approver)
	if err != nil {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "no-verification-key"}
	}
	sigOK := false
	for _, k := range edKeys {
		if VerifyAttestationSignature(a, k) == nil {
			sigOK = true
			break
		}
	}
	if !sigOK {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "bad-signature"}
	}
	if v.Revoked.Revoked("", a.ID) {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "revoked"}
	}
	if v.Seen.Seen(a.ID, in.EnvelopeID) {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "replay"}
	}
	now := in.Now
	if now == 0 {
		now = time.Now().Unix()
	}
	grace := int64(ClockSkewGrace / time.Second)
	if now < a.IssuedAt || now > a.ExpiresAt+grace {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "expired"}
	}
	switch tier {
	case Tier2:
		h := MsgHashOf(in.Body)
		want, err := b64.DecodeString(a.MsgHash)
		if err != nil || subtle.ConstantTimeCompare(h[:], want) != 1 {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "hash-mismatch"}
		}
		// Only FIDO2 proofs are cryptographically verifiable at
		// Tier 2 (issue #142 review): PIN and challenge proofs
		// pass on the Ed25519 attestation signature alone, which
		// the requesting agent itself can produce — that is
		// self-attestation, not human presence. Fail closed.
		// (ProofSession cannot appear on Tier 2: Validate
		// rejects it.)
		if a.Proof.Kind != ProofFIDO2 {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "unverifiable-proof"}
		}
		// FIDO2 proofs are cryptographically verified here — the
		// assertion must be a real WebAuthn get-assertion over
		// the nonce-bound approval challenge, signed by the
		// enrolled credential. Presence of the assertion fields
		// alone never suffices.
		// Same-envelope re-evaluation (e.g. the inbox CLI and
		// the dashboard push deriving the same message): the
		// first evaluation already advanced the stored
		// signature counter, so the counter-increase check is
		// skipped — otherwise a valid attestation would flip
		// to invalid on re-check. The assertion itself is
		// still fully verified cryptographically.
		skipCounter := v.Seen.SeenInEnvelope(a.ID, in.EnvelopeID)
		if err := v.verifyFIDO2Proof(a, h[:], in.EnvelopeID, skipCounter); err != nil {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: err.Error()}
		}
	case Tier1:
		tok := a.Proof.Token
		if tok == nil {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "no-token"}
		}
		if tok.Issuer != a.Approver {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "token-issuer-mismatch"}
		}
		if v.Revoked.Revoked(tok.ID, "") {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "token-revoked"}
		}
		// Note: the token id is deliberately NOT consumed here. A
		// session token is meant to attest many messages over the
		// session; each message carries a fresh attestation id
		// wrapping the token, and exact replays are caught by the
		// attestation id below.
		if !tok.LiveAt(now) {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "token-expired"}
		}
		if tok.Scope != "" && tok.Scope != in.Receiver {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "token-scope"}
		}
		// The token's own signature is covered by the attestation
		// signature over the canonical token bytes (see
		// attestationCanonical): a token that failed its issuer
		// signature could not be wrapped in a valid attestation.
		// Belt and suspenders for tokens evaluated standalone:
		tokOK := false
		for _, k := range edKeys {
			if tok.verifySignature(k) == nil {
				tokOK = true
				break
			}
		}
		if !tokOK {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "token-bad-signature"}
		}
		// The mint ceremony proof is verified independently of the
		// issuer signature: the embedded WebAuthn assertion must
		// be a real authenticator signature over the mint
		// challenge for an enrolled WebAuthn credential. This is
		// the check that stops a process holding the issuer's
		// identity key from minting Tier 1 tokens with no human
		// involved — re-signing a forged token is not enough.
		if err := v.verifyMintAssertion(tok); err != nil {
			return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: "token-mint: " + err.Error()}
		}
	}
	// All checks passed: consume the attestation id so exact
	// replays fail. (The session token id is not consumed: it
	// attests the whole session, not one message.)
	v.Seen.Mark(a.ID, in.EnvelopeID)
	return EvalOutcome{Verdict: VerdictAttested, Tier: tier, Approver: a.Approver, Reason: "ok"}
}

// VerifyTokenStandalone verifies a session token outside an
// attestation (e.g. the issuer's own keystore hygiene checks).
func (v *Verifier) VerifyTokenStandalone(tok *SessionToken, receiver string, now int64) error {
	if err := tok.Validate(); err != nil {
		return err
	}
	if v.Registry == nil || !v.Registry.Enrolled(tok.Issuer) {
		return fmt.Errorf("issuer %q is not enrolled", tok.Issuer)
	}
	edKeys, _, err := v.Registry.KeysFor(tok.Issuer)
	if err != nil {
		return err
	}
	ok := false
	for _, k := range edKeys {
		if tok.verifySignature(k) == nil {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("session token signature invalid")
	}
	if now == 0 {
		now = time.Now().Unix()
	}
	if !tok.LiveAt(now) {
		return fmt.Errorf("session token not live")
	}
	if tok.Scope != "" && tok.Scope != receiver {
		return fmt.Errorf("session token scoped elsewhere")
	}
	if v.Revoked.Revoked(tok.ID, "") {
		return fmt.Errorf("session token revoked")
	}
	if err := v.verifyMintAssertion(tok); err != nil {
		return fmt.Errorf("mint assertion: %w", err)
	}
	return nil
}

// verifyMintAssertion verifies the WebAuthn assertion embedded in a
// session token: the credential must be an enrolled WebAuthn
// credential for the token's issuer, and the assertion must be a
// genuine authenticator signature over the token's mint challenge
// (UV required). The mint challenge binds the full token bytes, so
// the assertion cannot be transplanted onto a different token. An
// unconfigured relying party fails closed: without it there is
// nothing trustworthy to verify against.
func (v *Verifier) verifyMintAssertion(tok *SessionToken) error {
	if v.WebAuthn.ID == "" || len(v.WebAuthn.Origins) == 0 {
		return fmt.Errorf("no relying party configured")
	}
	_, webAuthn, err := v.Registry.KeysFor(tok.Issuer)
	if err != nil {
		return fmt.Errorf("no credentials: %w", err)
	}
	var enrolled *Credential
	for i := range webAuthn {
		if webAuthn[i].ID == tok.CredentialID {
			enrolled = &webAuthn[i]
			break
		}
	}
	if enrolled == nil {
		return fmt.Errorf("mint credential %q not enrolled for %q", tok.CredentialID, tok.Issuer)
	}
	if enrolled.Kind != "webauthn" {
		return fmt.Errorf("mint credential %q is %s (want webauthn)", tok.CredentialID, enrolled.Kind)
	}
	return tok.verifyMintAssertion(enrolled, v.WebAuthn)
}

// verifyFIDO2Proof cryptographically verifies the WebAuthn assertion
// for a Tier 2 attestation. When skipCounterCheck is set (a
// re-evaluation of an envelope this attestation was already
// recorded against), the signature-counter increase check is
// skipped — the first evaluation already advanced the counter —
// but the assertion itself is still fully verified.
//
// Challenge scheme (issue #142 review): the challenge is
// ApprovalChallenge(actionHash, nonce) — the action hash bound to a
// fresh per-approval nonce — not the bare action hash. The nonce
// rides in the attestation, covered by the attestation signature,
// and the receiver consumes it exactly once (see NonceSet). A
// captured assertion answers only its own ceremony's challenge, so
// re-wrapping it in a fresh attestation (new id, new envelope) is
// still a replay: the nonce is already consumed. This defeats
// replay against counterless authenticators (counter stuck at 0)
// and concurrent verifiers, where the sign-counter check alone
// cannot. The counter check stays as defense in depth.
func (v *Verifier) verifyFIDO2Proof(a *Attestation, actionHash []byte, envelopeID int64, skipCounterCheck bool) error {
	if a.Proof.CredentialID == "" {
		return fmt.Errorf("missing credential id")
	}
	if a.Proof.Assertion == "" {
		return fmt.Errorf("missing assertion")
	}
	// Decode the ceremony nonce first: without a valid nonce the
	// expected challenge cannot be computed, so fail closed. (The
	// nonce is covered by the attestation signature — verified
	// before this runs — so it cannot be swapped without
	// invalidating the attestation.)
	nonce, err := DecodeApprovalNonce(a.ApprovalNonce)
	if err != nil {
		return fmt.Errorf("fido2: approval nonce: %w", err)
	}
	expectedChallenge := ApprovalChallenge(actionHash, nonce)
	_, webAuthn, err := v.Registry.KeysFor(a.Approver)
	if err != nil {
		return fmt.Errorf("no credentials: %w", err)
	}
	var enrolled *Credential
	for i := range webAuthn {
		if webAuthn[i].ID == a.Proof.CredentialID {
			enrolled = &webAuthn[i]
			break
		}
	}
	if enrolled == nil {
		return fmt.Errorf("credential %q not enrolled", a.Proof.CredentialID)
	}
	rawKey, err := b64.DecodeString(enrolled.PublicKey)
	if err != nil {
		return fmt.Errorf("credential key: %w", err)
	}
	credPub, err := credentialKey(rawKey)
	if err != nil {
		return fmt.Errorf("credential key: %w", err)
	}
	// FIDO2UV (user verification) demands the UV flag; plain FIDO2
	// presence needs the UP flag.
	requireUV := a.Proof.Strength == PresenceFIDO2UV.String()
	signCount, err := verifyWebAuthnAssertion(credPub, a.Proof.Assertion, expectedChallenge[:], v.WebAuthn, requireUV)
	if err != nil {
		return err
	}
	// Consume the nonce exactly once. The assertion's challenge is
	// bound to this nonce, so a captured assertion re-wrapped in a
	// fresh attestation still carries the same nonce — the second
	// delivery in a different envelope is a replay. Same-envelope
	// re-evaluation is not a replay: Consumed only reports a
	// *different* envelope, and re-consuming the same envelope is
	// a no-op. A nil NonceSet records nothing (nil-safe); the
	// assertion is still cryptographically verified above.
	// Check-and-consume must be atomic with persistence by the
	// caller.
	if v.Nonces != nil {
		key := ApprovalNonceKey(a.Approver, a.ApprovalNonce)
		if v.Nonces.Consumed(key, envelopeID) {
			return fmt.Errorf("fido2: replay: approval nonce already consumed")
		}
		v.Nonces.Consume(key, envelopeID)
	}
	// Standard WebAuthn replay control: the counter must strictly
	// increase per credential. A counter-less authenticator reports
	// 0 forever, which the spec permits only while the stored value
	// is also 0. Skipped on same-envelope re-evaluation: the first
	// pass already advanced the stored counter, and re-checking
	// would reject a valid attestation.
	if !skipCounterCheck {
		if stored := enrolled.SignCount; signCount <= stored && (stored != 0 || signCount != 0) {
			return fmt.Errorf("fido2: signature counter did not increase (got %d, want > %d)", signCount, stored)
		}
		// KeysFor returns copies, so persist against the registry itself.
		v.Registry.NoteSignCount(a.Approver, enrolled.ID, signCount)
	}
	return nil
}
