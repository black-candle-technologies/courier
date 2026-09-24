package client

// ---- Human workflows (issue #142) ----
//
// The methods below are the human-facing VHL operations. Interactive
// ceremony steps (the human typing a confirmation, or relaying a
// challenge code out-of-band) live in the CLI; these methods take the
// ceremony result as input and do the cryptography and state changes.

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// VHLMintChallenge mints an out-of-band challenge bound to the exact
// action bytes and returns the challenge plus its one-time code. The
// code is shown once: deliver it to the approver over an
// out-of-band channel; the response step is VHLVerifyChallenge.
func (c *Client) VHLMintChallenge(action []byte) (*vhl.Challenge, string, error) {
	if len(action) == 0 {
		return nil, "", fmt.Errorf("action bytes required")
	}
	key, err := c.vhlSealKey()
	if err != nil {
		return nil, "", err
	}
	ch, code, err := vhl.MintChallenge(action, 0)
	if err != nil {
		return nil, "", err
	}
	// Open, append, and reseal inside one lock-protected critical
	// section: two concurrent mints must not lose one another's
	// challenge (issue #142 review).
	if err := updateVHL(func(ff *vhlFile) error {
		chs, err := openChallengesLocked(ff.SealedChall, key)
		if err != nil {
			return err
		}
		live := append(vhlLiveChallenges(chs, time.Now().Unix()), ch)
		sealed, err := sealChallengesLocked(live, key)
		if err != nil {
			return err
		}
		ff.SealedChall = sealed
		return nil
	}); err != nil {
		return nil, "", err
	}
	return ch, code, nil
}

// VHLVerifyChallenge checks a challenge response code. Any attempt —
// success or failure — consumes the challenge (single-use, no
// brute-force retries against the code).
func (c *Client) VHLVerifyChallenge(challengeID, code string) error {
	key, err := c.vhlSealKey()
	if err != nil {
		return err
	}
	var verr error
	// The lookup, the single-use consume, and the reseal happen in
	// one lock-protected critical section: two concurrent
	// verifications of the same challenge cannot both succeed
	// (issue #142 review). Only the seal key derivation happens
	// outside the lock — never network I/O.
	if err := updateVHL(func(ff *vhlFile) error {
		chs, err := openChallengesLocked(ff.SealedChall, key)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		var found *vhl.Challenge
		var rest []*vhl.Challenge
		for _, ch := range vhlLiveChallenges(chs, now) {
			if ch.ID == challengeID {
				found = ch
				continue
			}
			rest = append(rest, ch)
		}
		if found == nil {
			return fmt.Errorf("unknown or expired challenge")
		}
		sealed, err := sealChallengesLocked(rest, key)
		if err != nil {
			return err
		}
		ff.SealedChall = sealed
		verr = found.Verify(code, now)
		return nil
	}); err != nil {
		return err
	}
	return verr
}

// VHLRequestApproval records an approval request for the human. When
// humanAddr is empty or this agent's own address, the request is
// stored locally (same-machine fast path); otherwise it is sent as
// an in-band vhl-approval-request frame to the human's address.
func (c *Client) VHLRequestApproval(humanAddr string, tier vhl.Tier, body string, presence vhl.PresenceStrength) (*vhl.ApprovalRequest, error) {
	if tier != vhl.Tier1 && tier != vhl.Tier2 {
		return nil, fmt.Errorf("approval requests need tier 1 or 2")
	}
	if !presence.Valid() {
		return nil, fmt.Errorf("unknown presence ceremony")
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("refusing to request approval for an empty draft")
	}
	reqID, err := vhl.NewRequestID()
	if err != nil {
		return nil, err
	}
	h := vhl.MsgHashOf([]byte(body))
	req := &vhl.ApprovalRequest{
		ID:           reqID,
		Tier:         int(tier),
		MsgHash:      b64.EncodeToString(h[:]),
		Draft:        body,
		WantPresence: presence.String(),
		ExpiresAt:    time.Now().Unix() + int64(vhl.RequestTTL/time.Second),
	}
	target := humanAddr
	if target == "" {
		target = c.cfg.Address
	}
	if target == c.cfg.Address {
		// Same-machine fast path: store locally, no relay round-trip.
		rec := &vhlRequestRecord{
			Request: req, From: c.cfg.Address,
			ReceivedAt: time.Now().Unix(), EnvelopeID: 0,
		}
		if err := updateVHL(func(ff *vhlFile) error {
			for len(ff.Requests) >= maxVHLPending {
				oldest, ot := "", int64(0)
				first := true
				for rid, r := range ff.Requests {
					if first || r.ReceivedAt < ot {
						oldest, ot, first = rid, r.ReceivedAt, false
					}
				}
				delete(ff.Requests, oldest)
			}
			ff.Requests[req.ID] = rec
			return nil
		}); err != nil {
			return nil, err
		}
		return req, nil
	}
	raw, err := vhl.EncodeApprovalRequest(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.sendVHLFrame(target, raw); err != nil {
		return nil, fmt.Errorf("send approval request: %w", err)
	}
	return req, nil
}

// VHLPendingRequests lists approval requests awaiting the human,
// oldest first. Expired requests are skipped.
func (c *Client) VHLPendingRequests() ([]*vhlRequestRecord, error) {
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	var out []*vhlRequestRecord
	for _, rec := range ff.Requests {
		if rec == nil || rec.Request.ExpiresAt <= now {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt < out[j].ReceivedAt })
	return out, nil
}

// VHLGetRequest finds a pending request by id or id prefix.
func (c *Client) VHLGetRequest(idOrPrefix string) (*vhlRequestRecord, error) {
	reqs, err := c.VHLPendingRequests()
	if err != nil {
		return nil, err
	}
	var hit *vhlRequestRecord
	for _, r := range reqs {
		if r.Request.ID == idOrPrefix || strings.HasPrefix(r.Request.ID, idOrPrefix) {
			if hit != nil {
				return nil, fmt.Errorf("ambiguous request id prefix %q", idOrPrefix)
			}
			hit = r
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("no pending approval request %q", idOrPrefix)
	}
	return hit, nil
}

// VHLApproveMint performs the human side of the approval ceremony
// for a pending request: it mints the Tier 2 attestation (signed
// with this identity's key over the exact approved bytes) and
// delivers it to the requester — stored locally for same-machine
// requests, sent as a vhl-attest frame otherwise.
//
// displayedHash and displayedFrom are what the human actually
// reviewed: the action hash the CLI printed and the sender it named.
// Inside ONE lock-protected critical section the request is reloaded,
// the action hash is recomputed from the STORED draft bytes, and it
// must equal the displayed hash AND the stored sender must equal the
// displayed sender — any mismatch refuses to mint and leaves the
// request untouched. The request is consumed atomically with the
// mint: approvals are single-shot, and a transport failure after the
// remote send needs a new request — retrying a consumed request is
// not allowed (issue #142 review).
//
// The ceremony actually performed must meet the strength the agent
// asked for: the performed presence (not the proof kind's ceiling)
// is checked against the request's wanted presence — no silent
// downgrades — and the proof kind must be able to deliver the claimed
// presence.
//
// For FIDO2 proofs, approvalNonce is the 32-byte fresh nonce the
// ceremony answered (the WebAuthn challenge binds it); it must be
// exactly 32 bytes and is embedded in the attestation so the receiver
// can consume it exactly once. PIN/challenge proofs pass nil.
func (c *Client) VHLApproveMint(requestID string, displayedHash [32]byte, displayedFrom string, proof vhl.Proof, presence vhl.PresenceStrength, approvalNonce []byte) (*vhl.Attestation, error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if proof.Kind == vhl.ProofFIDO2 {
		if len(approvalNonce) != 32 {
			return nil, fmt.Errorf("fido2 approval requires the 32-byte ceremony nonce")
		}
	} else if len(approvalNonce) != 0 {
		return nil, fmt.Errorf("approval nonce is only valid for fido2 proofs")
	}
	var att *vhl.Attestation
	var from string
	// Load, check, mint, consume, and persist inside one
	// lock-protected critical section: the display-to-sign gap
	// closes here, and signing inside the config lock is fine —
	// never network I/O (issue #142 review).
	if err := updateVHL(func(ff *vhlFile) error {
		rec := ff.Requests[requestID]
		if rec == nil || rec.Request == nil {
			return fmt.Errorf("no pending approval request %q", requestID)
		}
		req := rec.Request
		if req.Tier != 2 {
			return fmt.Errorf("tier 1 is session-scoped: mint a session token instead of approving per-message")
		}
		// The ceremony actually performed must meet the strength
		// the agent asked for — check the performed presence, not
		// the proof kind's ceiling.
		want, err := vhl.ParsePresence(req.WantPresence)
		if err != nil {
			return fmt.Errorf("request wants unknown presence: %w", err)
		}
		if !presence.AtLeast(want) {
			return fmt.Errorf("performed presence %q does not meet requested presence %q", presence, req.WantPresence)
		}
		if !presence.Valid() || !proof.Kind.Strength().AtLeast(presence) {
			return fmt.Errorf("proof %q does not meet ceremony presence %q", proof.Kind, presence)
		}
		// Defense in depth: recompute the action hash from the
		// STORED draft bytes and require it to equal what the human
		// reviewed — what-you-sign-is-what-you-saw, closed over the
		// display-to-sign gap. A mismatch does NOT mint and does
		// NOT consume the request.
		h := vhl.MsgHashOf([]byte(req.Draft))
		if subtle.ConstantTimeCompare(h[:], displayedHash[:]) != 1 {
			return fmt.Errorf("approval request changed since it was displayed; refusing to approve")
		}
		if rec.From != displayedFrom {
			return fmt.Errorf("approval request sender changed since it was displayed; refusing to approve")
		}
		wantHash, err := b64.DecodeString(req.MsgHash)
		if err != nil || subtle.ConstantTimeCompare(h[:], wantHash) != 1 {
			return fmt.Errorf("request draft does not match its recorded hash; refusing to approve")
		}
		a, err := vhl.NewTier2Attestation([]byte(req.Draft), c.cfg.Address, req.ID, proof.Kind, presence, proof, approvalNonce, id.EdPriv)
		if err != nil {
			return err
		}
		// The request is consumed: approvals are single-shot, and
		// the consumption is atomic with the mint.
		delete(ff.Requests, req.ID)
		if rec.From == c.cfg.Address || rec.From == "" {
			// Same-machine: hand the attestation to the local
			// agent directly.
			for len(ff.Attestations) >= maxVHLPending {
				oldest, ot := "", int64(0)
				first := true
				for aid, a := range ff.Attestations {
					if first || a.IssuedAt < ot {
						oldest, ot, first = aid, a.IssuedAt, false
					}
				}
				delete(ff.Attestations, oldest)
			}
			ff.Attestations[a.ID] = a
		}
		att, from = a, rec.From
		return nil
	}); err != nil {
		return nil, err
	}
	if from == c.cfg.Address || from == "" {
		return att, nil
	}
	raw, err := vhl.EncodeAttestation(att)
	if err != nil {
		return nil, err
	}
	if _, err := c.sendVHLFrame(from, raw); err != nil {
		// The request was already consumed above: a transport
		// failure needs a new request, never a retry of this one.
		return nil, fmt.Errorf("send attestation: %w", err)
	}
	return att, nil
}

// VHLAttestations lists received attestations not yet attached to an
// outgoing message, newest first.
func (c *Client) VHLAttestations() ([]*vhl.Attestation, error) {
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	var out []*vhl.Attestation
	for _, a := range ff.Attestations {
		if a.Validate() != nil || a.ExpiresAt <= now {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt > out[j].IssuedAt })
	return out, nil
}

// VHLGetAttestation finds a stored attestation by id or id prefix.
func (c *Client) VHLGetAttestation(idOrPrefix string) (*vhl.Attestation, error) {
	atts, err := c.VHLAttestations()
	if err != nil {
		return nil, err
	}
	var hit *vhl.Attestation
	for _, a := range atts {
		if a.ID == idOrPrefix || strings.HasPrefix(a.ID, idOrPrefix) {
			if hit != nil {
				return nil, fmt.Errorf("ambiguous attestation id prefix %q", idOrPrefix)
			}
			hit = a
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("no stored attestation %q", idOrPrefix)
	}
	return hit, nil
}

// ApproverInfo is the CLI-facing view of an enrolled approver.
type ApproverInfo struct {
	Address     string `json:"address"`
	Name        string `json:"name,omitempty"`
	Credentials int    `json:"credentials"`
	EnrolledAt  int64  `json:"enrolled_at"`
}

// vhlCredentialIDForAddress derives the ed25519 public key from an
// identity address. The credential id is the address itself: it is
// the base64url encoding of the key and therefore unique per key.
func vhlCredentialIDForAddress(address string) (string, []byte, error) {
	parsed, err := crypto.ParseAddressSuite(address)
	if err != nil {
		return "", nil, fmt.Errorf("bad address: %w", err)
	}
	if parsed.Suite != crypto.SuiteV1 {
		return "", nil, fmt.Errorf("address is not an ed25519 identity")
	}
	if len(parsed.PublicKey) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("address is not an ed25519 identity")
	}
	return address, parsed.PublicKey, nil
}

// VHLEnrollApprover enrolls address as an approver in the local
// registry, binding their ed25519 identity key. Enrollment is a
// human-controlled cryptographic ceremony (issue #142 review): the
// caller runs VHLEnrollApproverCeremony first and passes the resulting
// artifact here. The registry verifies the artifact — the challenge
// recomputes from the claimed addresses and timestamp, and the
// assertion verifies against the human's locally enrolled WebAuthn
// credential — before the identity is trusted.
func (c *Client) VHLEnrollApprover(address, name string, art *vhl.EnrollmentArtifact) error {
	if art == nil {
		return fmt.Errorf("enrollment requires an approver-enrollment ceremony artifact")
	}
	credID, pub, err := vhlCredentialIDForAddress(address)
	if err != nil {
		return err
	}
	return updateVHL(func(ff *vhlFile) error {
		return ff.Registry.EnrollWithArtifact(address, name, vhl.Credential{
			ID:         credID,
			Kind:       "ed25519",
			PublicKey:  b64.EncodeToString(pub),
			EnrolledAt: time.Now().Unix(),
			Device:     "courier-identity",
		}, c.cfg.Address, art, ff.RP, time.Now().Unix())
	})
}

// VHLUnenrollApprover revokes an approver, by address or by the local
// display name.
func (c *Client) VHLUnenrollApprover(addrOrName string) error {
	return updateVHL(func(ff *vhlFile) error {
		identity := addrOrName
		if ff.Registry.Approvers[identity] == nil {
			for id, a := range ff.Registry.Approvers {
				if a.Name == addrOrName {
					identity = id
					break
				}
			}
		}
		return ff.Registry.RevokeApprover(identity)
	})
}

// VHLApprovers lists enrolled approvers, oldest first.
func (c *Client) VHLApprovers() ([]ApproverInfo, error) {
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	var out []ApproverInfo
	for _, a := range ff.Registry.Approvers {
		out = append(out, ApproverInfo{
			Address: a.Identity, Name: a.Name,
			Credentials: len(a.Credentials), EnrolledAt: a.EnrolledAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt < out[j].EnrolledAt })
	return out, nil
}

// VHLBeginSessionMint starts minting a Tier 1 session token for
// this identity. It returns the pending mint — including the
// challenge the human's authenticator must sign in the WebAuthn
// mint ceremony. Complete it with VHLFinishSessionMint once the
// ceremony transport delivers the authenticator's assertion.
//
// There is deliberately no presence parameter: the ceremony
// strength is established by the assertion Finish verifies, never
// by a caller-supplied claim. A process holding this identity's
// key cannot complete a mint on its own — Finish fails closed
// without a real authenticator signature over the challenge.
func (c *Client) VHLBeginSessionMint(scope string, ttl time.Duration) (*vhl.PendingSessionMint, error) {
	if ttl <= 0 {
		ttl = vhl.DefaultSessionTTL
	}
	if ttl > 24*time.Hour {
		return nil, fmt.Errorf("session TTL over 24h is not allowed")
	}
	return vhl.BeginSessionMint(c.cfg.Address, scope, ttl, vhlBootIDNow())
}

// VHLFinishSessionMint completes a session-token mint started with
// VHLBeginSessionMint. credentialID names the enrolled WebAuthn
// credential the human used; assertionB64 is the authenticator's
// WebAuthn assertion over the pending's challenge. The assertion is
// verified against the enrolled credential and the configured
// relying party BEFORE the token is signed and sealed — no real
// authenticator signature, no token. The same-or-stronger re-mint
// guard applies as before: a live fido2_uv token is never renewable
// with a weaker ceremony.
func (c *Client) VHLFinishSessionMint(pending *vhl.PendingSessionMint, credentialID, assertionB64 string) (*vhl.SessionToken, error) {
	if pending == nil {
		return nil, fmt.Errorf("no pending session mint")
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	key, err := c.vhlSealKey()
	if err != nil {
		return nil, err
	}
	var tok *vhl.SessionToken
	// Load, guard, finish, and reseal inside one lock-protected
	// critical section: the credential lookup, RP check, re-mint
	// guard, and keystore append must see each other's writes, or
	// a concurrent mint slips past the ceremony-downgrade guard
	// (issue #142 review). Only local crypto and the seal key
	// derivation run here — never network I/O.
	if err := updateVHL(func(ff *vhlFile) error {
		if ff.RP.ID == "" || len(ff.RP.Origins) == 0 {
			return fmt.Errorf("session mint refused: no WebAuthn relying party configured — run `courier vhl rp set` first, then enroll a credential with `courier vhl enroll-webauthn`")
		}
		var cred *vhl.Credential
		for _, a := range ff.Registry.Approvers {
			if a.Identity != c.cfg.Address {
				continue
			}
			for i := range a.Credentials {
				if a.Credentials[i].ID == credentialID {
					cred = &a.Credentials[i]
					break
				}
			}
		}
		if cred == nil {
			return fmt.Errorf("session mint refused: credential %q is not enrolled for this identity", credentialID)
		}
		toks, err := openTokensLocked(ff.SealedTokens, key)
		if err != nil {
			return err
		}
		live := vhlLiveTokens(toks)
		// Same-or-stronger re-mint (issue #142): a token minted under a
		// stronger ceremony must never be renewable with a weaker one —
		// no downgrade path.
		for _, t := range live {
			if !t.MayRemint(vhl.PresenceFIDO2UV) {
				cur, _ := t.MintPresence()
				return fmt.Errorf("cannot re-mint with %q: live token %s was minted with stronger ceremony %q", vhl.PresenceFIDO2UV, t.ID, cur)
			}
		}
		tok, err = pending.Finish(cred, assertionB64, ff.RP, id.EdPriv)
		if err != nil {
			return err
		}
		live = append(live, tok)
		sealed, err := sealTokensLocked(live, key)
		if err != nil {
			return err
		}
		ff.SealedTokens = sealed
		return nil
	}); err != nil {
		return nil, err
	}
	return tok, nil
}

// VHLSessionStatus returns the live session tokens for this boot.
func (c *Client) VHLSessionStatus() ([]*vhl.SessionToken, error) {
	return c.vhlLoadTokens()
}

// VHLRevokeSessionToken revokes a session token by id (local
// revocation set) and drops it from the keystore so it is never
// served again. When broadcast is set, the revocation is also sent
// to every contact as a vhl-revoke frame.
func (c *Client) VHLRevokeSessionToken(idOrPrefix string, broadcast bool) error {
	id, err := c.cfg.Identity()
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	key, err := c.vhlSealKey()
	if err != nil {
		return err
	}
	var rv *vhl.Revocation
	// The revocation apply and the keystore drop happen in one
	// lock-protected critical section: the old load-then-store
	// split let a concurrent mint's token survive (or a concurrent
	// revoke's store restore the just-revoked token), because each
	// side overwrote the other's keystore write (issue #142
	// review).
	if err := updateVHL(func(ff *vhlFile) error {
		toks, err := openTokensLocked(ff.SealedTokens, key)
		if err != nil {
			return err
		}
		live := vhlLiveTokens(toks)
		var hit *vhl.SessionToken
		for _, t := range live {
			if t.ID == idOrPrefix || strings.HasPrefix(t.ID, idOrPrefix) {
				if hit != nil {
					return fmt.Errorf("ambiguous token id prefix %q", idOrPrefix)
				}
				hit = t
			}
		}
		if hit == nil {
			return fmt.Errorf("no live session token %q", idOrPrefix)
		}
		now := time.Now().Unix()
		rv = &vhl.Revocation{
			Version:  1,
			Issuer:   c.cfg.Address,
			IssuedAt: now,
			TokenIDs: []string{hit.ID},
		}
		if err := vhl.SignRevocation(rv, id.EdPriv); err != nil {
			return err
		}
		ff.Revoked.Apply(rv, now)
		var rest []*vhl.SessionToken
		for _, t := range live {
			if t.ID != hit.ID {
				rest = append(rest, t)
			}
		}
		sealed, err := sealTokensLocked(rest, key)
		if err != nil {
			return err
		}
		ff.SealedTokens = sealed
		return nil
	}); err != nil {
		return err
	}
	if broadcast {
		raw, err := vhl.EncodeRevocation(rv)
		if err != nil {
			return err
		}
		for name, addr := range c.cfg.Contacts {
			if _, err := c.sendVHLFrame(addr, raw); err != nil {
				fmt.Fprintf(os.Stderr, "warning: revoke broadcast to %s failed: %v\n", name, err)
			}
		}
	}
	return nil
}

// SendFullTiered is SendFull with a VHL tier tag and inline
// attestation (issue #142). Tier 1 wraps the live session token
// automatically when att is nil; Tier 2 requires att (from
// `courier vhl approve`). Tiered sends do not take attachments: the
// approval hash binds the body bytes, and an unattested attachment
// would bypass the human review.
func (c *Client) SendFullTiered(toOrName, body string, replyTo int64, ttl time.Duration, tier vhl.Tier, att *vhl.Attestation) (int64, error) {
	if replyTo < 0 {
		return 0, fmt.Errorf("invalid reply-to id %d: want a positive message id", replyTo)
	}
	if ttl < 0 {
		return 0, fmt.Errorf("ttl must not be negative")
	}
	var quote string
	if replyTo > 0 {
		quote, _ = LookupReplyParent(replyTo)
	}
	return c.send(toOrName, body, nil, replyTo, quote, true, ttl, tier, att)
}
