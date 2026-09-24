package client

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/black-candle-technologies/courier/internal/vhl"
)

// Tests for the PR #144 review findings (client-side fixes, issue
// #142). Each test pins the fixed behavior against the exact failure
// mode the reviewer described.

// TestVHLRevocationAppliesWithinSamePage is the Codex P1 scenario: a
// revocation frame and a later message using the revoked token arrive
// in the same fetched page. The message must be evaluated against the
// fresh revocation set — never the stale one the fetch started with.
func TestVHLRevocationAppliesWithinSamePage(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	testEnrollApprover(t, env.senderCfg.Address, "sender")

	env.asSender()
	if err := env.sender.PublishKey(); err != nil {
		t.Fatalf("sender publish key: %v", err)
	}
	// Revocation broadcasts go to the sender's contacts.
	if err := env.senderCfg.AddContact("recipient", env.recipCfg.Address); err != nil {
		t.Fatalf("add contact: %v", err)
	}
	fix := setupMintFixture(t, env)
	tok := fix.mint(t, env, "")
	// Build the Tier 1 attestation while the token is live, then
	// revoke: the broadcast revocation frame lands in the
	// recipient's page BEFORE the message that uses the token.
	att, err := env.sender.vhlAttestForSend(vhl.Tier1, "post-revoke orders", nil, env.recipCfg.Address)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := env.sender.VHLRevokeSessionToken(tok.ID[:8], true); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	plain, err := encodeMessageBodyVHL("post-revoke orders", nil, 0, "", 0, vhl.Tier1, att)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := env.sender.sendSealed(env.recipCfg.Address, plain, "post-revoke orders", 0, "", true, 0); err != nil {
		t.Fatalf("sendSealed: %v", err)
	}

	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.VHL == nil || m.VHL.Verdict != "invalid-attestation" || !strings.Contains(m.VHL.Reason, "token-revoked") {
		t.Fatalf("VHL = %+v, want invalid-attestation/token-revoked: the same-page revocation was not applied to the live verifier", m.VHL)
	}
	if !m.Request || !containsFlag(m.Flags, "vhl_unverified") {
		t.Fatalf("revoked-token message not held: request=%v flags=%v", m.Request, m.Flags)
	}
}

// TestVHLTier1ScopedTokenSelection is the Codex P2 scenario: an
// unscoped token exists, then a token scoped to a third party is
// minted. A Tier 1 send to the recipient must wrap the unscoped
// token — never the newer third-party-scoped one — and the receiver
// must verify it attested, not hold it as token-scope.
func TestVHLTier1ScopedTokenSelection(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	testEnrollApprover(t, env.senderCfg.Address, "sender")

	env.asSender()
	fix := setupMintFixture(t, env)
	unscoped := fix.mint(t, env, "")
	fix.mint(t, env, env.snoopCfg.Address)
	tok, err := env.sender.vhlLiveToken(env.recipCfg.Address)
	if err != nil {
		t.Fatalf("live token: %v", err)
	}
	if tok == nil || tok.ID != unscoped.ID {
		t.Fatalf("selected token = %+v, want the unscoped token %s", tok, unscoped.ID)
	}
	// A token scoped to the recipient itself wins when it is the
	// newest usable one.
	scoped := fix.mint(t, env, env.recipCfg.Address)
	tok, err = env.sender.vhlLiveToken(env.recipCfg.Address)
	if err != nil {
		t.Fatalf("live token: %v", err)
	}
	if tok == nil || tok.ID != scoped.ID {
		t.Fatalf("selected token = %+v, want the recipient-scoped token %s", tok, scoped.ID)
	}

	// End to end: the Tier 1 send wraps a token usable for the
	// recipient and verifies attested — never held as token-scope.
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "scoped selection", vhl.Tier1, nil); err != nil {
		t.Fatalf("send tier 1: %v", err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	if msgs[0].VHL == nil || msgs[0].VHL.Verdict != "attested" {
		t.Fatalf("VHL = %+v, want attested", msgs[0].VHL)
	}
}

// TestVHLExplicitFetchDoesNotConsumeReplay pins the explicit fetch as
// strictly read-only for VHL: envelopes A (original) and B (replay)
// share one attestation id. Fetching B explicitly first must not
// persist the id, or the inbox would hold A as the replay and deliver
// B — exactly backwards.
func TestVHLExplicitFetchDoesNotConsumeReplay(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	testEnrollApprover(t, env.senderCfg.Address, "sender")

	env.asSender()
	fix := setupMintFixture(t, env)
	fix.mint(t, env, "")
	att, err := env.sender.vhlAttestForSend(vhl.Tier1, "rotate keys", nil, env.recipCfg.Address)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	idA, err := env.sender.SendTiered(env.recipCfg.Address, "rotate keys", vhl.Tier1, att)
	if err != nil {
		t.Fatalf("send A: %v", err)
	}
	idB, err := env.sender.SendTiered(env.recipCfg.Address, "rotate keys", vhl.Tier1, att)
	if err != nil {
		t.Fatalf("send B: %v", err)
	}

	env.asRecipient()
	fetched, err := env.recipient.FetchMessage(idB)
	if err != nil {
		t.Fatalf("explicit fetch of B: %v", err)
	}
	if fetched.VHL == nil || fetched.VHL.Verdict != "attested" {
		t.Fatalf("explicit fetch VHL = %+v, want attested", fetched.VHL)
	}
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("inbox: got %d messages, want 2", len(msgs))
	}
	if msgs[0].ID != idA || msgs[0].VHL == nil || msgs[0].VHL.Verdict != "attested" {
		t.Fatalf("envelope A VHL = %+v, want attested: the explicit fetch of B must not flip the original into a replay", msgs[0].VHL)
	}
	if msgs[1].ID != idB || msgs[1].VHL == nil || msgs[1].VHL.Verdict != "invalid-attestation" || !strings.Contains(msgs[1].VHL.Reason, "replay") {
		t.Fatalf("envelope B VHL = %+v, want invalid-attestation/replay", msgs[1].VHL)
	}
}

// TestVHLHeldSenderFramesGated verifies VHL frames from a held sender
// are not applied to protocol state — except revocation frames, which
// are self-verifying (enrolled-key signature) and always honored.
func TestVHLHeldSenderFramesGated(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	// Contacts-only policy with the sender not a contact: the sender
	// is held for review.
	if err := env.recipCfg.Update(func(fresh *Config) error {
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatalf("dm policy: %v", err)
	}
	// Enrollment is the VHL trust root — independent of contacts.
	testEnrollApprover(t, env.senderCfg.Address, "sender")

	env.asSender()
	if err := env.sender.PublishKey(); err != nil {
		t.Fatalf("sender publish key: %v", err)
	}
	if err := env.senderCfg.AddContact("recipient", env.recipCfg.Address); err != nil {
		t.Fatalf("add contact: %v", err)
	}
	fix := setupMintFixture(t, env)
	tok := fix.mint(t, env, "")

	// A held sender's approval-request frame must not land in the
	// recipient's review queue: it falls through to normal delivery
	// as a held message.
	if _, err := env.sender.VHLRequestApproval(env.recipCfg.Address, vhl.Tier2, "shut down the relay", vhl.PresencePIN); err != nil {
		t.Fatalf("request frame: %v", err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1 (the held frame)", len(msgs))
	}
	if !msgs[0].Request {
		t.Fatalf("held sender's frame was not delivered as a held message: %+v", msgs[0])
	}
	reqs, err := env.recipient.VHLPendingRequests()
	if err != nil {
		t.Fatalf("pending requests: %v", err)
	}
	if len(reqs) != 0 {
		t.Fatalf("pending requests = %d, want 0: a held sender's frame was applied to protocol state", len(reqs))
	}

	// A held sender's revocation frame is still honored.
	env.asSender()
	if err := env.sender.VHLRevokeSessionToken(tok.ID[:8], true); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	env.asRecipient()
	if _, _, _, _, err := env.recipient.Inbox(0, 50); err != nil {
		t.Fatalf("inbox: %v", err)
	}
	ff, err := loadVHL()
	if err != nil {
		t.Fatalf("load vhl state: %v", err)
	}
	if _, ok := ff.Revoked.Tokens[tok.ID]; !ok {
		t.Fatalf("held sender's revocation was not applied for %s", tok.ID)
	}
}

// TestVHLConsumeAttestationAtomic pins the check-and-consume
// primitive: first consume wins, the same envelope re-checked is not
// a replay, and a different envelope for the same id is.
func TestVHLConsumeAttestationAtomic(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	seen, err := vhlConsumeAttestation("att-atomic-1", "ed25519:approver", "", 100)
	if err != nil || seen {
		t.Fatalf("first consume: seen=%v err=%v, want false, nil", seen, err)
	}
	seen, err = vhlConsumeAttestation("att-atomic-1", "ed25519:approver", "", 100)
	if err != nil || seen {
		t.Fatalf("same envelope: seen=%v err=%v, want false, nil", seen, err)
	}
	seen, err = vhlConsumeAttestation("att-atomic-1", "ed25519:approver", "", 101)
	if err != nil || !seen {
		t.Fatalf("different envelope: seen=%v err=%v, want true, nil", seen, err)
	}
}

// testApprovalNonceB64 returns a fixed 32-byte approval nonce,
// base64url-encoded like Attestation.ApprovalNonce.
func testApprovalNonceB64() string {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return b64.EncodeToString(nonce[:])
}

// TestVHLConsumeAttestationNonceAtomic pins the nonce half of the
// check-and-consume primitive (issue #142 review): two attestations
// with different IDs but the same approval nonce are a rewrap
// replay — the second consume, in a different envelope, is flagged
// even though its attestation ID was never seen.
func TestVHLConsumeAttestationNonceAtomic(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	nonceB64 := testApprovalNonceB64()
	seen, err := vhlConsumeAttestation("att-nonce-1", "ed25519:approver", nonceB64, 100)
	if err != nil || seen {
		t.Fatalf("first consume: seen=%v err=%v, want false, nil", seen, err)
	}
	// Same nonce, different attestation ID, different envelope: the
	// rewrap replay the ID-only check would miss.
	seen, err = vhlConsumeAttestation("att-nonce-2", "ed25519:approver", nonceB64, 101)
	if err != nil || !seen {
		t.Fatalf("rewrapped nonce: seen=%v err=%v, want true, nil", seen, err)
	}
	// A different approver's identical nonce bytes are a different
	// key — approvers never collide.
	seen, err = vhlConsumeAttestation("att-nonce-3", "ed25519:other", nonceB64, 102)
	if err != nil || seen {
		t.Fatalf("other approver: seen=%v err=%v, want false, nil", seen, err)
	}
}

// TestVHLConsumeAttestationConcurrent pins the atomicity primitive
// under real concurrency: N goroutines racing to consume the same
// attestation id behind a shared start barrier must agree on exactly
// one winner (seen=false once). The sequential test above cannot
// detect two callers both passing the Seen check before either one
// saves — the race this primitive exists to prevent.
func TestVHLConsumeAttestationConcurrent(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	fresh := make(chan int64, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(envelope int64) {
			defer wg.Done()
			<-start
			seen, err := vhlConsumeAttestation("att-race", "ed25519:approver", "", envelope)
			if err != nil {
				errs <- err
				return
			}
			if !seen {
				fresh <- envelope
			}
		}(int64(100 + i))
	}
	close(start)
	wg.Wait()
	close(fresh)
	close(errs)
	for err := range errs {
		t.Fatalf("consume error: %v", err)
	}
	if got := len(fresh); got != 1 {
		t.Fatalf("fresh consumes = %d, want exactly 1", got)
	}
}

// TestVHLConsumeAttestationNonceConcurrent pins the nonce half of
// the primitive under real concurrency (issue #142 review): N
// goroutines racing to consume distinct attestation IDs that share
// one approval nonce — the concurrent-verifier rewrap replay — must
// agree on exactly one winner (seen=false once).
func TestVHLConsumeAttestationNonceConcurrent(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	nonceB64 := testApprovalNonceB64()
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	fresh := make(chan int64, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			seen, err := vhlConsumeAttestation(
				fmt.Sprintf("att-nonce-race-%d", i),
				"ed25519:approver", nonceB64, int64(200+i))
			if err != nil {
				errs <- err
				return
			}
			if !seen {
				fresh <- int64(i)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(fresh)
	close(errs)
	for err := range errs {
		t.Fatalf("consume error: %v", err)
	}
	if got := len(fresh); got != 1 {
		t.Fatalf("fresh consumes = %d, want exactly 1", got)
	}
}

// TestVHLMergeSeenPersistsSignCount covers the FIDO2 signature
// counter write-back: evaluation mutates the fetch-local registry
// (NoteSignCount); the end-of-fetch merge must persist the counter
// without clobbering concurrent registry changes, and must never
// rewind a newer persisted counter.
func TestVHLMergeSeenPersistsSignCount(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	const credID = "test-webauthn-credential"
	if err := updateVHL(func(ff *vhlFile) error {
		ff.Registry.Approvers[env.senderCfg.Address] = &vhl.Approver{
			Identity:   env.senderCfg.Address,
			Name:       "sender",
			EnrolledAt: 1,
			Credentials: []vhl.Credential{{
				ID: credID, Kind: "webauthn", PublicKey: "e30",
				EnrolledAt: 1, SignCount: 7,
			}},
		}
		return nil
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	// Simulate a fetch: evaluation observes a higher counter on the
	// fetch-local registry, and a concurrent enrollment lands before
	// the end-of-fetch merge.
	vfr, err := env.recipient.vhlVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	vfr.Registry.NoteSignCount(env.senderCfg.Address, credID, 12)
	other := env.snoopCfg.Address
	if err := updateVHL(func(ff *vhlFile) error {
		ff.Registry.Approvers[other] = &vhl.Approver{Identity: other, EnrolledAt: 2}
		return nil
	}); err != nil {
		t.Fatalf("concurrent enroll: %v", err)
	}
	if err := vhlMergeSeen(vfr); err != nil {
		t.Fatalf("merge: %v", err)
	}
	ff, err := loadVHL()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := ff.Registry.Approvers[env.senderCfg.Address]
	if got == nil || len(got.Credentials) != 1 || got.Credentials[0].SignCount != 12 {
		t.Fatalf("sign count not persisted: %+v", got)
	}
	if ff.Registry.Approvers[other] == nil {
		t.Fatalf("concurrent enrollment was clobbered by the merge")
	}
	// Monotonic: a stale fetch-local counter must not rewind the
	// persisted one.
	vfr2, err := env.recipient.vhlVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	vfr2.Registry.NoteSignCount(env.senderCfg.Address, credID, 5)
	if err := vhlMergeSeen(vfr2); err != nil {
		t.Fatalf("merge: %v", err)
	}
	ff, err = loadVHL()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ff.Registry.Approvers[env.senderCfg.Address]; got.Credentials[0].SignCount != 12 {
		t.Fatalf("sign count rewound to %d, want 12", got.Credentials[0].SignCount)
	}
}

// TestVHLRequiredTierHoldsUntagged is the regression test for the
// untagged-bypass finding (issue #142 review): with
// --require-tier 2, a plain Tier 0 DM (no tier tag, no attestation)
// must be held for review with below-required-tier — the sender
// cannot dodge the floor by omitting the tag. With the default
// floor 0 the same message is delivered normally.
func TestVHLRequiredTierHoldsUntagged(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLSetRequiredTier(2); err != nil {
		t.Fatalf("set required tier: %v", err)
	}

	env.asSender()
	if _, err := env.sender.Send(env.recipCfg.Address, "plain hello"); err != nil {
		t.Fatalf("send: %v", err)
	}

	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if !m.Request {
		t.Fatalf("untagged message with require-tier 2 was delivered, want held for review")
	}
	if m.VHL == nil || m.VHL.Verdict != "invalid-attestation" || m.VHL.Reason != "below-required-tier" {
		t.Fatalf("VHL = %+v, want invalid-attestation/below-required-tier", m.VHL)
	}

	// Floor back to 0: the same untagged message shape is delivered
	// normally again (no behavior change for the default policy).
	if err := env.recipient.VHLSetRequiredTier(0); err != nil {
		t.Fatalf("clear required tier: %v", err)
	}
	env.asSender()
	if _, err := env.sender.Send(env.recipCfg.Address, "plain hello again"); err != nil {
		t.Fatalf("send: %v", err)
	}
	env.asRecipient()
	msgs, _, _, _, err = env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	// The first message is still held (held messages are never
	// marked seen, so review re-derives them); the new one must
	// be delivered normally.
	if len(msgs) != 2 {
		t.Fatalf("inbox: got %d messages, want 2 (held + new)", len(msgs))
	}
	var fresh *Message
	for i := range msgs {
		if msgs[i].Body == "plain hello again" {
			fresh = &msgs[i]
		}
	}
	if fresh == nil {
		t.Fatalf("second message missing from inbox")
	}
	if fresh.Request {
		t.Fatalf("untagged message with require-tier 0 was held, want delivered")
	}
	if fresh.VHL != nil {
		t.Fatalf("VHL = %+v, want nil (untagged, floor 0: never evaluated)", fresh.VHL)
	}
}
