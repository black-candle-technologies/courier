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
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// vhlStoreChallenges seals the challenge list into the keystore
// (mirror of the token keystore: challenges are bearer-adjacent
// secrets until consumed).
func (c *Client) vhlStoreChallenges(chs []*vhl.Challenge) error {
	key, err := c.vhlSealKey()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(chs)
	if err != nil {
		return err
	}
	sealed, err := vhl.SealTokens(raw, key)
	if err != nil {
		return err
	}
	for i := range raw {
		raw[i] = 0
	}
	return updateVHL(func(ff *vhlFile) error {
		ff.SealedChall = b64.EncodeToString(sealed)
		return nil
	})
}

// vhlLoadChallenges opens the challenge store, dropping expired ones.
func (c *Client) vhlLoadChallenges() ([]*vhl.Challenge, error) {
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	if ff.SealedChall == "" {
		return nil, nil
	}
	key, err := c.vhlSealKey()
	if err != nil {
		return nil, err
	}
	sealed, err := b64.DecodeString(ff.SealedChall)
	if err != nil {
		return nil, fmt.Errorf("challenge store: %w", err)
	}
	raw, err := vhl.OpenTokens(sealed, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	var chs []*vhl.Challenge
	if err := json.Unmarshal(raw, &chs); err != nil {
		return nil, fmt.Errorf("challenge store: %w", err)
	}
	now := time.Now().Unix()
	var live []*vhl.Challenge
	for _, ch := range chs {
		if ch == nil || ch.Used || ch.ExpiresAt <= now {
			continue
		}
		live = append(live, ch)
	}
	return live, nil
}

// VHLMintChallenge mints an out-of-band challenge bound to the exact
// action bytes and returns the challenge plus its one-time code. The
// code is shown once: deliver it to the approver over an
// out-of-band channel; the response step is VHLVerifyChallenge.
func (c *Client) VHLMintChallenge(action []byte) (*vhl.Challenge, string, error) {
	if len(action) == 0 {
		return nil, "", fmt.Errorf("action bytes required")
	}
	ch, code, err := vhl.MintChallenge(action, 0)
	if err != nil {
		return nil, "", err
	}
	chs, err := c.vhlLoadChallenges()
	if err != nil {
		return nil, "", err
	}
	chs = append(chs, ch)
	if err := c.vhlStoreChallenges(chs); err != nil {
		return nil, "", err
	}
	return ch, code, nil
}

// VHLVerifyChallenge checks a challenge response code. Any attempt —
// success or failure — consumes the challenge (single-use, no
// brute-force retries against the code).
func (c *Client) VHLVerifyChallenge(challengeID, code string) error {
	chs, err := c.vhlLoadChallenges()
	if err != nil {
		return err
	}
	var found *vhl.Challenge
	for _, ch := range chs {
		if ch.ID == challengeID {
			found = ch
			break
		}
	}
	if found == nil {
		return fmt.Errorf("unknown or expired challenge")
	}
	verr := found.Verify(code, time.Now().Unix())
	var rest []*vhl.Challenge
	for _, ch := range chs {
		if ch.ID != challengeID {
			rest = append(rest, ch)
		}
	}
	if err := c.vhlStoreChallenges(rest); err != nil {
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
// requests, sent as a vhl-attest frame otherwise. The caller performs
// the interactive ceremony (PIN confirmation or challenge/response)
// and passes the resulting proof.
func (c *Client) VHLApproveMint(requestID string, proof vhl.Proof, presence vhl.PresenceStrength) (*vhl.Attestation, error) {
	rec, err := c.VHLGetRequest(requestID)
	if err != nil {
		return nil, err
	}
	req := rec.Request
	if req.Tier != 2 {
		return nil, fmt.Errorf("tier 1 is session-scoped: mint a session token instead of approving per-message")
	}
	// The ceremony actually performed must meet the strength the
	// agent asked for — no silent downgrades.
	want, err := vhl.ParsePresence(req.WantPresence)
	if err != nil {
		return nil, fmt.Errorf("request wants unknown presence: %w", err)
	}
	if !proof.Kind.Strength().AtLeast(want) {
		return nil, fmt.Errorf("proof %q does not meet requested presence %q", proof.Kind, req.WantPresence)
	}
	if !presence.Valid() || !proof.Kind.Strength().AtLeast(presence) {
		return nil, fmt.Errorf("proof %q does not meet ceremony presence %q", proof.Kind, presence)
	}
	// Defense in depth: recompute the action hash from the draft
	// bytes before signing — what-you-sign-is-what-you-saw.
	h := vhl.MsgHashOf([]byte(req.Draft))
	wantHash, err := b64.DecodeString(req.MsgHash)
	if err != nil || subtle.ConstantTimeCompare(h[:], wantHash) != 1 {
		return nil, fmt.Errorf("request draft does not match its recorded hash; refusing to approve")
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	att, err := vhl.NewTier2Attestation([]byte(req.Draft), c.cfg.Address, req.ID, proof.Kind, presence, proof, id.EdPriv)
	if err != nil {
		return nil, err
	}
	// The request is consumed: approvals are single-shot.
	if err := updateVHL(func(ff *vhlFile) error {
		delete(ff.Requests, req.ID)
		return nil
	}); err != nil {
		return nil, err
	}
	if rec.From == c.cfg.Address || rec.From == "" {
		// Same-machine: hand the attestation to the local agent
		// directly.
		if err := updateVHL(func(ff *vhlFile) error {
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
			ff.Attestations[att.ID] = att
			return nil
		}); err != nil {
			return nil, err
		}
		return att, nil
	}
	raw, err := vhl.EncodeAttestation(att)
	if err != nil {
		return nil, err
	}
	if _, err := c.sendVHLFrame(rec.From, raw); err != nil {
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
// registry, binding their ed25519 identity key. approvedEvent records
// the human ceremony that authorized the enrollment (the CLI passes
// an interactive-confirmation label); it must be non-empty.
func (c *Client) VHLEnrollApprover(address, name, approvedEvent string) error {
	if approvedEvent == "" {
		return fmt.Errorf("enrollment requires a recorded approval event")
	}
	credID, pub, err := vhlCredentialIDForAddress(address)
	if err != nil {
		return err
	}
	return updateVHL(func(ff *vhlFile) error {
		return ff.Registry.Enroll(address, name, vhl.Credential{
			ID:         credID,
			Kind:       "ed25519",
			PublicKey:  b64.EncodeToString(pub),
			EnrolledAt: time.Now().Unix(),
			Device:     "courier-identity",
		}, true)
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

// VHLMintSessionToken mints a Tier 1 session token signed with this
// identity's key and seals it into the keystore. scope limits which
// recipient the token attests for ("" = any). The caller performs
// the interactive presence ceremony and passes its strength.
func (c *Client) VHLMintSessionToken(scope string, ttl time.Duration, presence vhl.PresenceStrength) (*vhl.SessionToken, error) {
	if !presence.Valid() {
		return nil, fmt.Errorf("unknown presence ceremony")
	}
	if ttl <= 0 {
		ttl = vhl.DefaultSessionTTL
	}
	if ttl > 24*time.Hour {
		return nil, fmt.Errorf("session TTL over 24h is not allowed")
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	toks, err := c.vhlLoadTokens()
	if err != nil {
		return nil, err
	}
	// Same-or-stronger re-mint (issue #142): a token minted under a
	// stronger ceremony must never be renewable with a weaker one —
	// no downgrade path.
	for _, t := range toks {
		if !t.MayRemint(presence) {
			cur, _ := t.MintPresence()
			return nil, fmt.Errorf("cannot re-mint with %q: live token %s was minted with stronger ceremony %q", presence, t.ID, cur)
		}
	}
	tok, err := vhl.MintSessionToken(c.cfg.Address, scope, presence, ttl, vhlBootIDNow(), id.EdPriv)
	if err != nil {
		return nil, err
	}
	toks = append(toks, tok)
	if err := c.vhlStoreTokens(toks); err != nil {
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
	toks, err := c.vhlLoadTokens()
	if err != nil {
		return err
	}
	var hit *vhl.SessionToken
	for _, t := range toks {
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
	id, err := c.cfg.Identity()
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	now := time.Now().Unix()
	rv := &vhl.Revocation{
		Version:  1,
		Issuer:   c.cfg.Address,
		IssuedAt: now,
		TokenIDs: []string{hit.ID},
	}
	if err := vhl.SignRevocation(rv, id.EdPriv); err != nil {
		return err
	}
	if err := updateVHL(func(ff *vhlFile) error {
		ff.Revoked.Apply(rv, now)
		return nil
	}); err != nil {
		return err
	}
	var rest []*vhl.SessionToken
	for _, t := range toks {
		if t.ID != hit.ID {
			rest = append(rest, t)
		}
	}
	if err := c.vhlStoreTokens(rest); err != nil {
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
