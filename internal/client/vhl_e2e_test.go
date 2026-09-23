package client

import (
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/vhl"
)

// TestVHLTier1EndToEnd exercises the full Tier 1 loop against a live
// relay: the recipient enrolls the sender, the sender mints a session
// token, sends tier 1, and the recipient's inbox shows a verified
// attested status bound to the sender's address.
func TestVHLTier1EndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	// The receiver enrolls the sender as an approver; that enrollment
	// is the trust root.
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	fix := setupMintFixture(t, env)
	fix.mint(t, env, "")
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "deploy staging", vhl.Tier1, nil); err != nil {
		t.Fatalf("send tier 1: %v", err)
	}

	env.asRecipient()
	msgs, _, skipped, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("inbox skipped %d messages", skipped)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.From != env.senderCfg.Address {
		t.Fatalf("From = %q, want sender %q", m.From, env.senderCfg.Address)
	}
	if m.Body != "deploy staging" {
		t.Fatalf("body = %q", m.Body)
	}
	if m.VHL == nil {
		t.Fatalf("VHL status missing")
	}
	if m.VHL.Verdict != "attested" {
		t.Fatalf("verdict = %q, want attested (reason %q)", m.VHL.Verdict, m.VHL.Reason)
	}
	if m.VHL.Tier != 1 {
		t.Fatalf("tier = %d, want 1", m.VHL.Tier)
	}
	if m.VHL.Approver != env.senderCfg.Address {
		t.Fatalf("approver = %q, want sender %q", m.VHL.Approver, env.senderCfg.Address)
	}
	if !containsFlag(m.Flags, "vhl_attested") {
		t.Fatalf("flags = %v, want vhl_attested", m.Flags)
	}
}

// TestVHLTier1MissingTokenFailsClosed verifies that a Tier 1 send
// without a live session token refuses to send — the sender never
// emits an unattested tier-tagged message.
func TestVHLTier1MissingTokenFailsClosed(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	env.asSender()
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "routine status", vhl.Tier1, nil); err == nil {
		t.Fatalf("tier 1 send without a session token succeeded, want failure")
	}
}

// TestVHLMissingAttestationHeld crafts a tier-tagged message with no
// attestation (as an adversarial or buggy sender might) and verifies
// the receiver holds it for human review instead of discarding it.
func TestVHLMissingAttestationHeld(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	plain, err := encodeMessageBodyVHL("wipe the database", nil, 0, "", 0, vhl.Tier2, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := env.sender.sendSealed(env.recipCfg.Address, plain, "wipe the database", 0, "", true, 0); err != nil {
		t.Fatalf("sendSealed: %v", err)
	}

	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1 (the held message must surface, not vanish)", len(msgs))
	}
	m := msgs[0]
	if m.VHL == nil || m.VHL.Verdict != "missing-attestation" {
		t.Fatalf("VHL = %+v, want missing-attestation verdict", m.VHL)
	}
	if !containsFlag(m.Flags, "vhl_unverified") {
		t.Fatalf("flags = %v, want vhl_unverified", m.Flags)
	}
	// The held draft surfaces as an inbox request for the human's
	// review — it is never silently discarded.
	if !m.Request {
		t.Fatalf("held message does not carry the request flag: %+v", m)
	}
}

// TestVHLTier2EndToEnd runs the whole Tier 2 loop: the sender's human
// approves exact bytes locally, the attestation ships with the
// message, and the recipient verifies it.
func TestVHLTier2EndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	req, err := env.sender.VHLRequestApproval("", vhl.Tier2, "merge PR #142", vhl.PresencePIN)
	if err != nil {
		t.Fatalf("request approval: %v", err)
	}
	att, err := env.sender.VHLApproveMint(req.ID, vhl.Proof{Kind: vhl.ProofPIN}, vhl.PresencePIN)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "merge PR #142", vhl.Tier2, att); err != nil {
		t.Fatalf("send tier 2: %v", err)
	}

	env.asRecipient()
	msgs, _, skipped, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("inbox skipped %d messages", skipped)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.VHL == nil || m.VHL.Verdict != "attested" || m.VHL.Tier != 2 {
		t.Fatalf("VHL = %+v, want tier-2 attested", m.VHL)
	}
	if m.VHL.Approver != env.senderCfg.Address {
		t.Fatalf("approver = %q, want sender", m.VHL.Approver)
	}
}

// TestVHLTier2BaitAndSwitch verifies that a Tier 2 attestation
// approves one set of bytes and cannot be reused on different bytes:
// the send fails closed on the sender side, and a hand-crafted
// mismatched message is held on the receiver side.
func TestVHLTier2BaitAndSwitch(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	req, err := env.sender.VHLRequestApproval("", vhl.Tier2, "review README", vhl.PresencePIN)
	if err != nil {
		t.Fatalf("request approval: %v", err)
	}
	att, err := env.sender.VHLApproveMint(req.ID, vhl.Proof{Kind: vhl.ProofPIN}, vhl.PresencePIN)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Sender-side fail-closed: attestation for "review README" must
	// not send with "merge PR #142".
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "merge PR #142", vhl.Tier2, att); err == nil {
		t.Fatalf("bait-and-switch send succeeded, want failure")
	}
	// Receiver-side: the same attestation arriving on different
	// bytes is held as invalid, not delivered as reviewed.
	plain, err := encodeMessageBodyVHL("merge PR #142", nil, 0, "", 0, vhl.Tier2, att)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := env.sender.sendSealed(env.recipCfg.Address, plain, "merge PR #142", 0, "", true, 0); err != nil {
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
	if m.VHL == nil || m.VHL.Verdict != "invalid-attestation" {
		t.Fatalf("VHL = %+v, want invalid-attestation", m.VHL)
	}
	if !containsFlag(m.Flags, "vhl_unverified") {
		t.Fatalf("flags = %v, want vhl_unverified", m.Flags)
	}
}

// TestVHLReplayHeldAcrossEnvelopes reuses one attestation in two
// distinct envelopes and verifies the recipient accepts the first
// and holds the second as a replay.
func TestVHLReplayHeldAcrossEnvelopes(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	fix := setupMintFixture(t, env)
	fix.mint(t, env, "")
	att, err := env.sender.vhlAttestForSend(vhl.Tier1, "rotate keys", nil, env.recipCfg.Address)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "rotate keys", vhl.Tier1, att); err != nil {
		t.Fatalf("send 1: %v", err)
	}
	// Same attestation ID, new envelope: a replay attack.
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "rotate keys", vhl.Tier1, att); err != nil {
		t.Fatalf("send 2: %v", err)
	}

	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("inbox: got %d messages, want 2", len(msgs))
	}
	if msgs[0].VHL == nil || msgs[0].VHL.Verdict != "attested" {
		t.Fatalf("first message VHL = %+v, want attested", msgs[0].VHL)
	}
	if msgs[1].VHL == nil || msgs[1].VHL.Verdict != "invalid-attestation" || !strings.Contains(msgs[1].VHL.Reason, "replay") {
		t.Fatalf("second message VHL = %+v, want invalid-attestation/replay", msgs[1].VHL)
	}
}

// TestVHLApprovalRequestFrame exercises the native approval-request
// frame: the agent asks a human over the wire, the human approves,
// and the attestation frame comes back as a stored attestation —
// without either side writing plaintext protocol messages.
func TestVHLApprovalRequestFrame(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	// Both sides publish their encryption keys: VHL frames are E2E
	// DMs and must be decryptable by the peer (the address-derived
	// fallback key is not the sender's real decryption key).
	env.asSender()
	if err := env.sender.PublishKey(); err != nil {
		t.Fatalf("sender publish key: %v", err)
	}

	// The agent sends an approval request frame to the human
	// (recipient). The human's inbox stores it in their review queue.
	if _, err := env.sender.VHLRequestApproval(env.recipCfg.Address, vhl.Tier2, "shut down the relay", vhl.PresencePIN); err != nil {
		t.Fatalf("send request frame: %v", err)
	}
	env.asRecipient()
	if _, _, _, _, err := env.recipient.Inbox(0, 50); err != nil {
		t.Fatalf("recipient inbox: %v", err)
	}
	reqs, err := env.recipient.VHLPendingRequests()
	if err != nil {
		t.Fatalf("pending requests: %v", err)
	}
	if len(reqs) != 1 || reqs[0].Request.Draft != "shut down the relay" {
		t.Fatalf("requests = %+v, want the drafted action", reqs)
	}

	// The human approves; VHLApproveMint returns the frame to the
	// agent over the native attestation frame, whose inbox stores
	// it for later use.
	if _, err := env.recipient.VHLApproveMint(reqs[0].Request.ID, vhl.Proof{Kind: vhl.ProofPIN}, vhl.PresencePIN); err != nil {
		t.Fatalf("approve: %v", err)
	}
	env.asSender()
	if _, _, _, _, err := env.sender.Inbox(0, 50); err != nil {
		t.Fatalf("sender inbox: %v", err)
	}
	atts, err := env.sender.VHLAttestations()
	if err != nil {
		t.Fatalf("attestations: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("attestations = %d, want 1", len(atts))
	}
	got, err := env.sender.VHLGetAttestation(atts[0].ID[:8])
	if err != nil {
		t.Fatalf("get attestation: %v", err)
	}
	if vhl.Tier(got.Tier) != vhl.Tier2 || !strings.EqualFold(got.Approver, env.recipCfg.Address) {
		t.Fatalf("attestation = %+v, want tier-2 from the human", got)
	}
}

// TestVHLSessionRevocationBroadcast verifies a revocation frame
// travels the native channel: after the sender revokes and
// broadcasts, the recipient's registry records the revoked token.
func TestVHLSessionRevocationBroadcast(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	if err := env.sender.PublishKey(); err != nil {
		t.Fatalf("sender publish key: %v", err)
	}
	// Revocation broadcasts go to the sender's contacts: the
	// recipient must be one for the frame to reach them.
	if err := env.senderCfg.AddContact("recipient", env.recipCfg.Address); err != nil {
		t.Fatalf("add contact: %v", err)
	}
	fix := setupMintFixture(t, env)
	tok := fix.mint(t, env, "")
	// Give the recipient something to verify against before
	// revocation: one attested message lands fine.
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "status ok", vhl.Tier1, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].VHL == nil || msgs[0].VHL.Verdict != "attested" {
		t.Fatalf("pre-revocation message = %+v, want attested", msgs)
	}

	env.asSender()
	if err := env.sender.VHLRevokeSessionToken(tok.ID[:8], true); err != nil {
		t.Fatalf("revoke broadcast: %v", err)
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
		t.Fatalf("recipient did not record the broadcast revocation for %s", tok.ID)
	}
}

// TestVHLTier0Compatibility verifies the old wire is untouched: a
// plain Tier 0 message arrives with no VHL status and no VHL flags.
func TestVHLTier0Compatibility(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	env.asSender()
	if _, err := env.sender.Send(env.recipCfg.Address, "just chatting"); err != nil {
		t.Fatalf("send: %v", err)
	}
	env.asRecipient()
	msgs, _, skipped, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("inbox skipped %d messages", skipped)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	// Pure Tier 0 keeps the legacy wire: no VHL status is attached
	// and no VHL flags are set — the message is exactly what the old
	// client would have delivered.
	if m.VHL != nil {
		t.Fatalf("VHL = %+v, want no VHL status on a plain tier-0 message", m.VHL)
	}
	if containsFlag(m.Flags, "vhl_attested") || containsFlag(m.Flags, "vhl_unverified") {
		t.Fatalf("flags = %v, want no VHL flags on tier 0", m.Flags)
	}
}

// TestVHLTier0WithAttestationRejected verifies a Tier 0 message that
// improperly carries an attestation is treated as invalid, not as
// harmless Tier 0.
func TestVHLTier0WithAttestationRejected(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}

	env.asSender()
	fix := setupMintFixture(t, env)
	fix.mint(t, env, "")
	att, err := env.sender.vhlAttestForSend(vhl.Tier1, "hello", nil, env.recipCfg.Address)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	// Tag tier 0 but smuggle an attestation in.
	plain, err := encodeMessageBodyVHL("hello", nil, 0, "", 0, vhl.Tier0, att)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := env.sender.sendSealed(env.recipCfg.Address, plain, "hello", 0, "", true, 0); err != nil {
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
	if m.VHL == nil || m.VHL.Verdict != "invalid-attestation" {
		t.Fatalf("VHL = %+v, want invalid-attestation for tier-0-with-attestation", m.VHL)
	}
	if !containsFlag(m.Flags, "vhl_unverified") {
		t.Fatalf("flags = %v, want vhl_unverified", m.Flags)
	}
}

// TestVHLPersistenceAcrossRestart verifies VHL state (registry,
// tokens, attestations) survives a client reload from disk: the
// receiver still attests with the pre-restart registry, and the
// sender's session token still works.
func TestVHLPersistenceAcrossRestart(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}
	if err := env.recipient.VHLEnrollApprover(env.senderCfg.Address, "sender", "test-enrollment"); err != nil {
		t.Fatalf("enroll approver: %v", err)
	}
	env.asSender()
	fix := setupMintFixture(t, env)
	fix.mint(t, env, "")

	// Reload both clients from disk — new Client instances with the
	// same HOME, as a process restart would.
	env.asRecipient()
	env.recipient = New(env.recipCfg)
	env.asSender()
	env.sender = New(env.senderCfg)

	env.asSender()
	if _, err := env.sender.SendTiered(env.recipCfg.Address, "after restart", vhl.Tier1, nil); err != nil {
		t.Fatalf("send tier 1 after restart: %v", err)
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
	if m.VHL == nil || m.VHL.Verdict != "attested" {
		t.Fatalf("VHL = %+v, want attested after restart", m.VHL)
	}
}

func containsFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
