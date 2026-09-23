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
// The checks, in order: tier tag valid; tier 0 → unattested; higher
// tiers require an attestation (missing → VerdictMissing); the
// attestation validates structurally, its signer key is enrolled for
// the claimed approver, the signature verifies, the id is neither
// seen nor revoked, the lifetime covers now (receiver-local, with
// grace), and the tier-specific binding holds (tier 2: message hash
// matches; tier 1: session token live, scope covers this receiver,
// presence recorded).
//
// A single failure yields VerdictInvalid with a machine-readable
// reason. The message itself is never dropped here — the caller's
// policy maps the verdict to delivery (attested), hold-for-review
// (missing/invalid), or plain delivery (unattested tier 0).
func (v *Verifier) Evaluate(in EvalInput) EvalOutcome {
	tier := in.Tier
	if !tier.Valid() {
		return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Reason: "bad-tier-tag"}
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
		// FIDO2 proofs are cryptographically verified here — the
		// assertion must be a real WebAuthn get-assertion over the
		// action hash, signed by the enrolled credential. Presence
		// of the assertion fields alone never suffices.
		if a.Proof.Kind == ProofFIDO2 {
			// Same-envelope re-evaluation (e.g. the inbox CLI and
			// the dashboard push deriving the same message): the
			// first evaluation already advanced the stored
			// signature counter, so the counter-increase check is
			// skipped — otherwise a valid attestation would flip
			// to invalid on re-check. The assertion itself is
			// still fully verified cryptographically.
			skipCounter := v.Seen.SeenInEnvelope(a.ID, in.EnvelopeID)
			if err := v.verifyFIDO2Proof(a, h[:], skipCounter); err != nil {
				return EvalOutcome{Verdict: VerdictInvalid, Tier: tier, Approver: a.Approver, Reason: err.Error()}
			}
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
// in a Tier 2 fido2 proof: the credential must be enrolled for the
// approver, and the assertion must be a genuine get-assertion over
// the action hash from that credential.
//
// Challenge scheme (deliberate, issue #142): the challenge is the
// deterministic action hash — what-you-sign-is-what-you-saw — not a
// receiver-issued nonce. There is no challenge round-trip in this
// asynchronous protocol, and a receiver-issued challenge would add
// one. Replay of a captured assertion (re-wrapped in a fresh
// attestation for the same body) is defeated at two layers instead:
// the envelope-layer attestation-id dedup catches exact replays, and
// the authenticator's signature counter below must strictly increase
// per credential.
// verifyFIDO2Proof cryptographically verifies the WebAuthn assertion
// for a Tier 2 attestation. When skipCounterCheck is set (a
// re-evaluation of an envelope this attestation was already
// recorded against), the signature-counter increase check is
// skipped — the first evaluation already advanced the counter —
// but the assertion itself is still fully verified.
func (v *Verifier) verifyFIDO2Proof(a *Attestation, actionHash []byte, skipCounterCheck bool) error {
	if a.Proof.CredentialID == "" {
		return fmt.Errorf("missing credential id")
	}
	if a.Proof.Assertion == "" {
		return fmt.Errorf("missing assertion")
	}
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
	signCount, err := verifyWebAuthnAssertion(credPub, a.Proof.Assertion, actionHash, v.WebAuthn, requireUV)
	if err != nil {
		return err
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
