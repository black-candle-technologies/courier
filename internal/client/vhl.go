package client

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// VHL (Verified Human in the Loop, issue #142): client-side state and
// protocol handling.
//
// Approval is an attestation, enforced by the receiver. The relay
// needs no changes: tier tags ride inside the E2E plaintext (so they
// are authenticated — no silent downgrades), and attestation artifacts
// travel in-band as native Courier message types (E2E DMs the relay
// sees only as ciphertext + metadata).

// vhlRequestRecord is a received approval request awaiting the human.
type vhlRequestRecord struct {
	Request    *vhl.ApprovalRequest `json:"request"`
	From       string               `json:"from"`
	ReceivedAt int64                `json:"received_at"`
	EnvelopeID int64                `json:"envelope_id"`
}

// vhlFile is the local VHL state: the enrollment registry (the trust
// root), the sealed session-token keystore, the sealed challenge
// store, the seen-artifact replay set, the revocation set, pending
// approval requests, and received attestations not yet attached to an
// outgoing message.
type vhlFile struct {
	Registry     *vhl.Registry                `json:"registry"`
	Seen         *vhl.SeenSet                 `json:"seen"`
	Revoked      *vhl.RevocationSet           `json:"revoked"`
	Nonces       *vhl.NonceSet                `json:"nonces,omitempty"`
	RP           vhl.WebAuthnRP               `json:"rp,omitempty"`
	SealedTokens string                       `json:"sealed_tokens,omitempty"`
	SealedChall  string                       `json:"sealed_challenges,omitempty"`
	Requests     map[string]*vhlRequestRecord `json:"requests,omitempty"`
	Attestations map[string]*vhl.Attestation  `json:"attestations,omitempty"`
	// RequiredTier is the receiver's required VHL tier floor
	// (issue #142 review): messages below this tier are held for
	// human review. 0 (the default) keeps the current behavior —
	// no requirement.
	RequiredTier int `json:"required_tier,omitempty"`
}

// maxVHLPending bounds the human-facing queues; the wire already
// bounds lifetimes, so this is just hygiene.
const maxVHLPending = 100

func vhlFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "vhl.json"), nil
}

func newVHLFile() *vhlFile {
	return &vhlFile{
		Registry:     vhl.NewRegistry(),
		Seen:         vhl.NewSeenSet(),
		Revoked:      vhl.NewRevocationSet(),
		Nonces:       vhl.NewNonceSet(),
		Requests:     map[string]*vhlRequestRecord{},
		Attestations: map[string]*vhl.Attestation{},
	}
}

func loadVHLLocked() (*vhlFile, error) {
	p, err := vhlFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return newVHLFile(), nil
		}
		return nil, err
	}
	ff := newVHLFile()
	if err := json.Unmarshal(data, &ff); err != nil {
		return nil, fmt.Errorf("vhl.json: %w", err)
	}
	if ff.Registry == nil {
		ff.Registry = vhl.NewRegistry()
	}
	if ff.Seen == nil {
		ff.Seen = vhl.NewSeenSet()
	}
	if ff.Revoked == nil {
		ff.Revoked = vhl.NewRevocationSet()
	}
	if ff.Nonces == nil {
		ff.Nonces = vhl.NewNonceSet()
	}
	if ff.Requests == nil {
		ff.Requests = map[string]*vhlRequestRecord{}
	}
	if ff.Attestations == nil {
		ff.Attestations = map[string]*vhl.Attestation{}
	}
	return ff, nil
}

func saveVHLLocked(ff *vhlFile) error {
	p, err := vhlFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "vhl-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	// Durability matches the main config: 0600, fsync, then rename.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, p)
}

// updateVHL performs an atomic read-modify-write of vhl.json under
// the cross-process config lock (same discipline as updateFS).
func updateVHL(fn func(*vhlFile) error) error {
	return withConfigLock(func() error {
		ff, err := loadVHLLocked()
		if err != nil {
			return err
		}
		if err := fn(ff); err != nil {
			return err
		}
		return saveVHLLocked(ff)
	})
}

func loadVHL() (*vhlFile, error) {
	var ff *vhlFile
	if err := withConfigLock(func() error {
		var err error
		ff, err = loadVHLLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return ff, nil
}

// removeVHLState deletes ~/.courier/vhl.json (best-effort). Used by
// `backup restore`: a restored identity is a new device and must not
// inherit the old device's enrollments, session tokens, or replay
// sets.
func removeVHLState() error {
	p, err := vhlFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// vhlBootIDOnce generates this process's VHL boot id. Session tokens
// are bound to the boot id of the process that minted them; a restart
// mints a new boot id, so pre-restart tokens are never served again
// (revoked on restart by construction, issue #142).
var (
	vhlBootID     string
	vhlBootIDOnce sync.Once
)

func vhlBootIDNow() string {
	vhlBootIDOnce.Do(func() {
		vhlBootID = machineBootID()
	})
	return vhlBootID
}

// VHLBootIDStable reports whether session tokens are bound to a
// boot id that survives process restart on this host. Without a
// stable machine boot id the id is process-local by construction,
// so a token minted by one process is never served by the next —
// tokens are single-process there. Callers that mint tokens (the
// CLI, the dashboard) should surface this so the human is not
// surprised when a minted token vanishes on the next invocation.
func (c *Client) VHLBootIDStable() bool {
	return strings.HasPrefix(vhlBootIDNow(), "boot-")
}

// machineBootID identifies the current machine boot. Session tokens
// bind to it so that a reboot revokes them by construction (issue
// #142). It must be stable across processes on the same boot — a
// process-local random value would silently drop every token minted
// by a previous CLI invocation, making `vhl session mint` useless.
// On Linux the kernel's boot_id is exactly this; elsewhere we fall
// back to a process-local value, which fails closed (tokens become
// single-process) rather than failing open.
func machineBootID() string {
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return "boot-" + id
		}
	}
	var rb [16]byte
	if _, err := rand.Read(rb[:]); err == nil {
		return "proc-" + b64.EncodeToString(rb[:])
	}
	return fmt.Sprintf("ts-%d", time.Now().UnixNano())
}

// vhlSealKey derives the token-keystore seal key from the identity
// seed (HKDF-SHA256, domain-separated). The seed never leaves the
// machine; the derived key unlocks the bearer tokens at rest.
func (c *Client) vhlSealKey() ([32]byte, error) {
	var zero [32]byte
	id, err := c.cfg.Identity()
	if err != nil {
		return zero, fmt.Errorf("identity: %w", err)
	}
	return vhl.DeriveSealKey(id.Seed), nil
}

// sealTokensLocked seals the token list into keystore bytes for
// ff.SealedTokens. The plaintext JSON is erased before returning.
// Callers hold the config lock via updateVHL: decrypt, modify, and
// reseal must be one atomic critical section, never split
// load/store steps (issue #142 review).
func sealTokensLocked(toks []*vhl.SessionToken, key [32]byte) (string, error) {
	raw, err := json.Marshal(toks)
	if err != nil {
		return "", err
	}
	sealed, err := vhl.SealTokens(raw, key)
	// Erase the plaintext copy.
	for i := range raw {
		raw[i] = 0
	}
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(sealed), nil
}

// openTokensLocked opens the keystore bytes from ff.SealedTokens.
// Empty input yields no tokens. The plaintext JSON is erased before
// returning.
func openTokensLocked(sealedB64 string, key [32]byte) ([]*vhl.SessionToken, error) {
	if sealedB64 == "" {
		return nil, nil
	}
	sealed, err := b64.DecodeString(sealedB64)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
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
	var toks []*vhl.SessionToken
	if err := json.Unmarshal(raw, &toks); err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	return toks, nil
}

// sealChallengesLocked / openChallengesLocked mirror the token
// keystore for the challenge store (challenges are bearer-adjacent
// secrets until consumed).
func sealChallengesLocked(chs []*vhl.Challenge, key [32]byte) (string, error) {
	raw, err := json.Marshal(chs)
	if err != nil {
		return "", err
	}
	sealed, err := vhl.SealTokens(raw, key)
	for i := range raw {
		raw[i] = 0
	}
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(sealed), nil
}

func openChallengesLocked(sealedB64 string, key [32]byte) ([]*vhl.Challenge, error) {
	if sealedB64 == "" {
		return nil, nil
	}
	sealed, err := b64.DecodeString(sealedB64)
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
	return chs, nil
}

// vhlLiveTokens filters a keystore token list down to the tokens
// usable now: structurally valid, minted on this boot, and
// unexpired. Previous-boot tokens are dropped — restart revokes by
// construction (issue #142).
func vhlLiveTokens(toks []*vhl.SessionToken) []*vhl.SessionToken {
	now := time.Now().Unix()
	boot := vhlBootIDNow()
	var live []*vhl.SessionToken
	for _, t := range toks {
		if t == nil || t.Validate() != nil {
			continue
		}
		if t.BootID != boot {
			continue // previous boot: revoked by construction
		}
		if !t.LiveAt(now) {
			continue
		}
		live = append(live, t)
	}
	return live
}

// vhlLiveChallenges drops used and expired challenges.
func vhlLiveChallenges(chs []*vhl.Challenge, now int64) []*vhl.Challenge {
	var live []*vhl.Challenge
	for _, ch := range chs {
		if ch == nil || ch.Used || ch.ExpiresAt <= now {
			continue
		}
		live = append(live, ch)
	}
	return live
}

// vhlLoadTokens opens the keystore and returns the live tokens for
// this boot. Expired tokens and tokens from a previous boot are
// dropped (restart revokes by construction).
func (c *Client) vhlLoadTokens() ([]*vhl.SessionToken, error) {
	key, err := c.vhlSealKey()
	if err != nil {
		return nil, err
	}
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	toks, err := openTokensLocked(ff.SealedTokens, key)
	if err != nil {
		return nil, err
	}
	return vhlLiveTokens(toks), nil
}

// vhlLiveToken returns the newest live session token usable for
// recipient: the newest token with an empty scope or an exact scope
// match. A token scoped to another counterparty must never attest a
// message to this one — the receiver would (correctly) hold it as
// token-scope (issue #142 review).
func (c *Client) vhlLiveToken(recipient string) (*vhl.SessionToken, error) {
	toks, err := c.vhlLoadTokens()
	if err != nil {
		return nil, err
	}
	// Newest first: the keystore appends.
	for i := len(toks) - 1; i >= 0; i-- {
		if toks[i].Scope == "" || toks[i].Scope == recipient {
			return toks[i], nil
		}
	}
	return nil, nil
}

// vhlVerifier builds the receiver-side verifier from local state.
func (c *Client) vhlVerifier() (*vhl.Verifier, error) {
	ff, err := loadVHL()
	if err != nil {
		return nil, err
	}
	// The WebAuthn relying party comes from operator configuration
	// (vhlFile.RP), set by the ceremony transport that defines it.
	// Until a ceremony flow exists and configures the RP, it stays
	// empty and fido2 proofs — including session-token mint
	// assertions — fail closed ("no relying party configured").
	// The schema alone never counts as verified presence.
	return &vhl.Verifier{Registry: ff.Registry, Seen: ff.Seen, Revoked: ff.Revoked, WebAuthn: ff.RP, Nonces: ff.Nonces}, nil
}

// vhlMergeSeen persists verifier mutations (consumed attestation ids,
// applied revocations, FIDO2 signature counters) after an inbox pass.
// The seen set only grows, so a union merge under the lock is safe.
// The registry merge is deliberately narrow — WebAuthn signature
// counters only, advanced monotonically per credential. A wholesale
// registry replace would clobber concurrent enrollments or
// revocations made through updateVHL during the fetch; the counters
// are the only registry field evaluation mutates (NoteSignCount),
// and they only ever move forward.
func vhlMergeSeen(vfr *vhl.Verifier) error {
	if vfr == nil {
		return nil
	}
	return updateVHL(func(ff *vhlFile) error {
		for id, env := range vfr.Seen.IDs {
			ff.Seen.Mark(id, env)
		}
		// The approval-nonce set merges the same way as the seen
		// set: union under the lock, earliest envelope id per key
		// (see NonceSet.Merge), so a consumed nonce is never
		// resurrected by a concurrent fetch (issue #142 review).
		ff.Nonces.Merge(vfr.Nonces)
		for id, ts := range vfr.Revoked.Tokens {
			ff.Revoked.Tokens[id] = ts
		}
		for id, ts := range vfr.Revoked.Artifacts {
			ff.Revoked.Artifacts[id] = ts
		}
		if vfr.Registry != nil && ff.Registry != nil {
			for identity, appr := range vfr.Registry.Approvers {
				pa := ff.Registry.Approvers[identity]
				if pa == nil {
					continue
				}
				for _, c := range appr.Credentials {
					for i := range pa.Credentials {
						if pa.Credentials[i].ID == c.ID && c.SignCount > pa.Credentials[i].SignCount {
							pa.Credentials[i].SignCount = c.SignCount
						}
					}
				}
			}
		}
		return nil
	})
}

// handleVHLFrame consumes an in-band VHL protocol frame. Frames are
// E2E DMs, so `from` is the authenticated sender. vfr is the caller's
// fetch-local verifier, if it has one: revocations applied to the
// persisted set are merged into it immediately, so a revocation frame
// and a later message using the revoked token in the same fetched
// page are evaluated against the fresh revocation set (issue #142
// review) — never the stale one the fetch started with.
func (c *Client) handleVHLFrame(from string, fr *vhl.Frame, envelopeID int64, vfr *vhl.Verifier) {
	now := time.Now().Unix()
	var applied *vhl.Revocation
	err := updateVHL(func(ff *vhlFile) error {
		switch fr.Type {
		case vhl.FrameApprovalRequest:
			r := fr.ApprovalRequest
			if r == nil || r.Validate(now) != nil {
				return nil // malformed: ignore, never fail the inbox
			}
			// Prune expired requests while we are here.
			for id, rec := range ff.Requests {
				if rec.Request.ExpiresAt <= now {
					delete(ff.Requests, id)
				}
			}
			// Keep the first request seen for an id: sender and body
			// are immutable once recorded, so a later frame carrying
			// the same id with different content is dropped rather
			// than overwriting the human's review queue (issue #142
			// review).
			if _, exists := ff.Requests[r.ID]; exists {
				return nil
			}
			for len(ff.Requests) >= maxVHLPending {
				// Drop the oldest.
				oldest, ot := "", int64(0)
				first := true
				for id, rec := range ff.Requests {
					if first || rec.ReceivedAt < ot {
						oldest, ot, first = id, rec.ReceivedAt, false
					}
				}
				delete(ff.Requests, oldest)
			}
			ff.Requests[r.ID] = &vhlRequestRecord{
				Request: r, From: from, ReceivedAt: now, EnvelopeID: envelopeID,
			}
		case vhl.FrameAttest:
			a := fr.Attestation
			if a == nil || a.Validate() != nil {
				return nil
			}
			for len(ff.Attestations) >= maxVHLPending {
				oldest, ot := "", int64(0)
				first := true
				for id, at := range ff.Attestations {
					if first || at.IssuedAt < ot {
						oldest, ot, first = id, at.IssuedAt, false
					}
				}
				delete(ff.Attestations, oldest)
			}
			ff.Attestations[a.ID] = a
		case vhl.FrameRevoke:
			rv := fr.Revocation
			if rv == nil || rv.Issuer == "" {
				return nil
			}
			// The revocation must verify under an enrolled key for
			// the claimed issuer — otherwise anyone could revoke
			// anyone's tokens.
			edKeys, _, err := ff.Registry.KeysFor(rv.Issuer)
			if err != nil {
				return nil
			}
			ok := false
			for _, k := range edKeys {
				if vhl.VerifyRevocationSignature(rv, k) == nil {
					ok = true
					break
				}
			}
			if !ok {
				return nil
			}
			ff.Revoked.Apply(rv, now)
			// Remember the applied revocation so the fetch-local
			// verifier can be brought up to date below.
			applied = rv
		}
		return nil
	})
	// A revocation that reached the persisted set must also reach
	// the live verifier before the fetch loop continues: without
	// this, a message later in the same page that uses the revoked
	// token would verify against the stale set and be delivered as
	// attested. Only merge on a clean persist so the two cannot
	// diverge.
	if err == nil && applied != nil && vfr != nil {
		if vfr.Revoked == nil {
			vfr.Revoked = vhl.NewRevocationSet()
		}
		vfr.Revoked.Apply(applied, now)
	}
}

// vhlEvaluateInbound runs the receiver-side VHL check for one
// decrypted chat message. tier/att come from inside the E2E
// plaintext (parseVHLPayload); envelopeID keys the replay guard so
// two consumers evaluating the same envelope do not false-positive.
func (c *Client) vhlEvaluateInbound(vfr *vhl.Verifier, tier vhl.Tier, body []byte, att *vhl.Attestation, envelopeID int64) vhl.EvalOutcome {
	if vfr == nil {
		// State unavailable: fail closed on any claimed tier.
		if tier == vhl.Tier0 && att == nil {
			return vhl.EvalOutcome{Verdict: vhl.VerdictUnattested, Tier: tier, Reason: "tier0"}
		}
		return vhl.EvalOutcome{Verdict: vhl.VerdictInvalid, Tier: tier, Reason: "vhl-unavailable"}
	}
	return vfr.Evaluate(vhl.EvalInput{
		Tier: tier, Body: body, Attestation: att,
		Receiver: c.cfg.Address, Now: time.Now().Unix(),
		EnvelopeID:   envelopeID,
		RequiredTier: vhl.Tier(vhlClampTier(vhlRequiredTier())),
	})
}

// vhlRequiredTier reads the receiver's persisted required-tier floor
// for inbound evaluation. A read failure yields 0 (no requirement,
// the current behavior); a persisted value outside 0..2 is clamped.
func vhlRequiredTier() int {
	ff, err := loadVHL()
	if err != nil {
		return 0
	}
	return vhlClampTier(ff.RequiredTier)
}

// vhlClampTier clamps a persisted tier floor to the valid 0..2 range.
func vhlClampTier(t int) int {
	if t < 0 {
		return 0
	}
	if t > int(vhl.Tier2) {
		return int(vhl.Tier2)
	}
	return t
}

// VHLGetRequiredTier returns the receiver's required VHL tier floor:
// messages below this tier are held for human review. 0 (the
// default) means no requirement.
func (c *Client) VHLGetRequiredTier() (int, error) {
	ff, err := loadVHL()
	if err != nil {
		return 0, err
	}
	return vhlClampTier(ff.RequiredTier), nil
}

// VHLSetRequiredTier sets the receiver's required VHL tier floor to
// 0, 1, or 2. The value persists in vhl.json and applies to inbound
// evaluation from the next fetch.
func (c *Client) VHLSetRequiredTier(tier int) error {
	if tier < 0 || tier > int(vhl.Tier2) {
		return fmt.Errorf("require-tier must be 0, 1, or 2")
	}
	return updateVHL(func(ff *vhlFile) error {
		ff.RequiredTier = tier
		return nil
	})
}

// vhlConsumeAttestation atomically checks and consumes an
// attestation id in the persisted replay set: under one
// read-modify-write it reports whether the id was already consumed in
// a different envelope, and marks it in the current one. The inbox
// loop's per-fetch verifier only sees its own page — two concurrent
// fetches (two processes: inbox CLI vs. dashboard push) could
// otherwise evaluate the same Tier 2 attestation against empty
// snapshots and both verdict attested. Check-and-consume must be one
// lock-protected operation (issue #142 review).
func vhlConsumeAttestation(attID string, envelopeID int64) (bool, error) {
	alreadySeen := false
	err := updateVHL(func(ff *vhlFile) error {
		if ff.Seen.Seen(attID, envelopeID) {
			alreadySeen = true
			return nil
		}
		ff.Seen.Mark(attID, envelopeID)
		return nil
	})
	return alreadySeen, err
}

// VHLStatus is the receiver-side VHL evaluation surfaced on a
// delivered message (issue #142).
type VHLStatus struct {
	// Tier is the message's VHL tier tag (0 when absent).
	Tier int `json:"tier"`
	// Verdict is unattested | attested | missing-attestation |
	// invalid-attestation.
	Verdict string `json:"verdict"`
	// Approver is the attesting human's address, when verified.
	Approver string `json:"approver,omitempty"`
	// Reason is the machine-readable detail for logs/audit.
	Reason string `json:"reason,omitempty"`
}

// Badge renders the VHL verdict as a one-line human-readable badge
// for inbox and thread output.
func (s *VHLStatus) Badge() string {
	switch s.Verdict {
	case "attested":
		return fmt.Sprintf("✔ human-verified (tier %d) by %s", s.Tier, s.Approver)
	case "missing-attestation":
		return fmt.Sprintf("⚠ UNVERIFIED — tier %d message with no attestation; HELD for human review", s.Tier)
	case "invalid-attestation":
		return fmt.Sprintf("⚠ UNVERIFIED — invalid attestation (%s); HELD for human review", s.Reason)
	default:
		return ""
	}
}

// vhlAttestForSend builds the Tier 1 attestation for an outgoing
// message from the live session token, or validates a caller-supplied
// Tier 2 attestation against the exact body bytes. recipient is the
// resolved recipient address: the token must be usable for them
// (empty scope or exact match) — a token scoped to another
// counterparty is never wrapped for this recipient. Tier 2 without an
// attestation fails closed: per-message human approval cannot be
// minted by the sending agent.
func (c *Client) vhlAttestForSend(tier vhl.Tier, body string, att *vhl.Attestation, recipient string) (*vhl.Attestation, error) {
	switch tier {
	case vhl.Tier0:
		if att != nil {
			return nil, fmt.Errorf("tier 0 messages carry no attestation")
		}
		return nil, nil
	case vhl.Tier1:
		if att != nil {
			if vhl.Tier(att.Tier) != vhl.Tier1 {
				return nil, fmt.Errorf("tier 1 message with tier %d attestation", att.Tier)
			}
			return att, nil
		}
		tok, err := c.vhlLiveToken(recipient)
		if err != nil {
			return nil, fmt.Errorf("session token: %w", err)
		}
		if tok == nil {
			return nil, fmt.Errorf("tier 1 requires a live VHL session token (run `courier vhl session mint`)")
		}
		id, err := c.cfg.Identity()
		if err != nil {
			return nil, fmt.Errorf("identity: %w", err)
		}
		return vhl.NewTier1Attestation(tok, id.EdPriv)
	case vhl.Tier2:
		if att == nil {
			return nil, fmt.Errorf("tier 2 requires a human approval attestation (see `courier vhl approve`)")
		}
		if vhl.Tier(att.Tier) != vhl.Tier2 {
			return nil, fmt.Errorf("tier 2 message with tier %d attestation", att.Tier)
		}
		// Fail fast: the attestation must bind these exact bytes,
		// or the recipient will (correctly) reject it.
		h := vhl.MsgHashOf([]byte(body))
		want, err := b64.DecodeString(att.MsgHash)
		if err != nil || subtle.ConstantTimeCompare(h[:], want) != 1 {
			return nil, fmt.Errorf("attestation message hash does not match these message bytes")
		}
		return att, nil
	default:
		return nil, fmt.Errorf("unknown VHL tier %d", int(tier))
	}
}

// parseVHLPayload extracts the VHL tier tag and inline attestation
// from a decrypted plaintext. Absent fields mean tier 0,
// unattested. Unknown payload versions yield nothing — never a
// higher tier.
func parseVHLPayload(plain []byte) (vhl.Tier, *vhl.Attestation) {
	var probe struct {
		V       int              `json:"v"`
		VHLTier *int             `json:"vhl_tier"`
		VHL     *vhl.Attestation `json:"vhl"`
	}
	if json.Unmarshal(plain, &probe) != nil {
		return vhl.Tier0, nil
	}
	if probe.V != 1 && probe.V != replyPayloadVersion {
		return vhl.Tier0, nil
	}
	tier := vhl.Tier0
	if probe.VHLTier != nil {
		tier = vhl.Tier(*probe.VHLTier)
	}
	return tier, probe.VHL
}

// encodeMessageBodyVHL is encodeMessageBody plus the VHL tier tag and
// optional inline attestation. Tier 0 without an attestation keeps
// the exact legacy wire.
func encodeMessageBodyVHL(body string, manifests []envelope.AttachmentManifest, replyTo int64, quote string, expiresAt int64, tier vhl.Tier, att *vhl.Attestation) ([]byte, error) {
	plain, err := encodeMessageBody(body, manifests, replyTo, quote, expiresAt)
	if err != nil {
		return nil, err
	}
	if tier == vhl.Tier0 && att == nil {
		return plain, nil
	}
	var rp replyPayload
	if json.Unmarshal(plain, &rp) == nil && rp.Version == replyPayloadVersion {
		rp.VHLTier = int(tier)
		rp.VHL = att
		return json.Marshal(rp)
	}
	var mp messagePayload
	if json.Unmarshal(plain, &mp) == nil && mp.Version == 1 {
		mp.VHLTier = int(tier)
		mp.VHL = att
		return json.Marshal(mp)
	}
	// Raw-text body: wrap in v1 with the VHL fields.
	return json.Marshal(messagePayload{Version: 1, Body: body, VHLTier: int(tier), VHL: att})
}
