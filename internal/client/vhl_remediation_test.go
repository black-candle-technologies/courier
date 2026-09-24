package client

import (
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/vhl"
)

// requestFixture records a same-machine Tier 2 approval request and
// returns it with its action hash. Same-machine requests never touch
// the relay: rec.From is the sender's own address.
func requestFixture(t *testing.T, c *Client, body string, want vhl.PresenceStrength) (*vhl.ApprovalRequest, [32]byte) {
	t.Helper()
	req, err := c.VHLRequestApproval("", vhl.Tier2, body, want)
	if err != nil {
		t.Fatalf("request approval: %v", err)
	}
	return req, vhl.MsgHashOf([]byte(body))
}

// TestVHLApproveMintPresenceDowngradeRejected is the regression test
// for the presence-downgrade finding (issue #142 review): the request
// wants fido2_uv, the ceremony performed is fido2, and the proof kind
// is FIDO2 (whose ceiling is fido2_uv). The old code checked the
// kind's ceiling and passed; the fixed code checks the performed
// presence and rejects. The matching-strength case must still mint.
func TestVHLApproveMintPresenceDowngradeRejected(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()

	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	proof := vhl.Proof{Kind: vhl.ProofFIDO2, CredentialID: "test-cred"}

	// want=fido2_uv, performed presence=fido2 -> must be rejected.
	req, h := requestFixture(t, env.sender, "downgrade me", vhl.PresenceFIDO2UV)
	_, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, proof, vhl.PresenceFIDO2, nonce[:])
	if err == nil || !strings.Contains(err.Error(), "does not meet requested presence") {
		t.Fatalf("downgrade approve = %v, want presence-downgrade rejection", err)
	}
	// The rejected request is NOT consumed: the human can still
	// approve it with the right ceremony.
	if _, err := env.sender.VHLGetRequest(req.ID); err != nil {
		t.Fatalf("rejected request should still be pending: %v", err)
	}

	// want=fido2, performed presence=fido2 -> accepted.
	req2, h2 := requestFixture(t, env.sender, "matching strength", vhl.PresenceFIDO2)
	att, err := env.sender.VHLApproveMint(req2.ID, h2, env.senderCfg.Address, proof, vhl.PresenceFIDO2, nonce[:])
	if err != nil {
		t.Fatalf("matching-strength approve: %v", err)
	}
	if att.ApprovalNonce != b64.EncodeToString(nonce[:]) {
		t.Fatalf("attestation nonce = %q, want the ceremony nonce", att.ApprovalNonce)
	}
	// Consumed on success.
	if _, err := env.sender.VHLGetRequest(req2.ID); err == nil {
		t.Fatal("approved request should be consumed")
	}
}

// TestVHLApproveMintTOCTOU exercises the display-to-sign binding
// (issue #142 review): the mint re-checks the displayed hash and
// sender against the STORED request inside one atomic critical
// section. Any mismatch refuses to mint AND leaves the request
// untouched.
func TestVHLApproveMintTOCTOU(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()
	pin := vhl.Proof{Kind: vhl.ProofPIN}

	t.Run("hash mismatch", func(t *testing.T) {
		req, _ := requestFixture(t, env.sender, "the real action", vhl.PresencePIN)
		var wrong [32]byte
		wrong[0] = 0xff
		if _, err := env.sender.VHLApproveMint(req.ID, wrong, env.senderCfg.Address, pin, vhl.PresencePIN, nil); err == nil {
			t.Fatal("mismatched displayed hash should fail")
		}
		if _, err := env.sender.VHLGetRequest(req.ID); err != nil {
			t.Fatalf("failed mint must not consume the request: %v", err)
		}
	})

	t.Run("sender mismatch", func(t *testing.T) {
		req, h := requestFixture(t, env.sender, "another action", vhl.PresencePIN)
		if _, err := env.sender.VHLApproveMint(req.ID, h, "ed25519:impostor", pin, vhl.PresencePIN, nil); err == nil {
			t.Fatal("mismatched displayed sender should fail")
		}
		if _, err := env.sender.VHLGetRequest(req.ID); err != nil {
			t.Fatalf("failed mint must not consume the request: %v", err)
		}
	})

	t.Run("unknown request", func(t *testing.T) {
		var h [32]byte
		if _, err := env.sender.VHLApproveMint("no-such-request", h, env.senderCfg.Address, pin, vhl.PresencePIN, nil); err == nil {
			t.Fatal("unknown request id should fail")
		}
	})

	t.Run("fido2 without 32-byte nonce", func(t *testing.T) {
		req, h := requestFixture(t, env.sender, "fido action", vhl.PresenceFIDO2)
		fido := vhl.Proof{Kind: vhl.ProofFIDO2, CredentialID: "test-cred"}
		for _, nonce := range [][]byte{nil, {1, 2, 3}, make([]byte, 31), make([]byte, 33)} {
			if _, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, fido, vhl.PresenceFIDO2, nonce); err == nil {
				t.Fatalf("fido2 with %d-byte nonce should fail", len(nonce))
			}
		}
		if _, err := env.sender.VHLGetRequest(req.ID); err != nil {
			t.Fatalf("failed mint must not consume the request: %v", err)
		}
	})

	t.Run("pin with stray nonce", func(t *testing.T) {
		req, h := requestFixture(t, env.sender, "pin action", vhl.PresencePIN)
		if _, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, pin, vhl.PresencePIN, make([]byte, 32)); err == nil {
			t.Fatal("pin proof with a nonce should fail closed")
		}
	})

	t.Run("happy path", func(t *testing.T) {
		req, h := requestFixture(t, env.sender, "final action", vhl.PresencePIN)
		att, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, pin, vhl.PresencePIN, nil)
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		if att.ApprovalNonce != "" {
			t.Fatalf("pin attestation should carry no approval nonce, got %q", att.ApprovalNonce)
		}
		if _, err := env.sender.VHLGetRequest(req.ID); err == nil {
			t.Fatal("approved request should be consumed")
		}
	})
}

// TestHandleVHLFrameDuplicateRequestID is the regression test for the
// duplicate pending-request-id finding (issue #142 review): after the
// expired-request prune and before capacity eviction, a second frame
// with an already-seen id is dropped — the first request (sender and
// body immutable) is kept.
func TestHandleVHLFrameDuplicateRequestID(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()

	id, err := vhl.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	mkreq := func(draft string) *vhl.ApprovalRequest {
		h := vhl.MsgHashOf([]byte(draft))
		return &vhl.ApprovalRequest{
			ID:           id,
			Tier:         int(vhl.Tier2),
			MsgHash:      b64.EncodeToString(h[:]),
			Draft:        draft,
			WantPresence: vhl.PresencePIN.String(),
			ExpiresAt:    9999999999,
		}
	}
	env.recipient.handleVHLFrame("ed25519:first-sender", &vhl.Frame{Type: vhl.FrameApprovalRequest, ApprovalRequest: mkreq("first draft")}, 1, nil)
	env.recipient.handleVHLFrame("ed25519:second-sender", &vhl.Frame{Type: vhl.FrameApprovalRequest, ApprovalRequest: mkreq("second draft")}, 2, nil)

	reqs, err := env.recipient.VHLPendingRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("pending requests = %d, want 1 (duplicate id dropped)", len(reqs))
	}
	if reqs[0].Request.Draft != "first draft" || reqs[0].From != "ed25519:first-sender" {
		t.Fatalf("kept request = %+v from %q, want the FIRST one", reqs[0].Request, reqs[0].From)
	}
}

// TestVHLRequiredTierRoundTrip covers the receiver tier-floor
// plumbing (issue #142 review): the default is 0 (no requirement,
// current behavior), set persists, out-of-range values fail, and the
// stored value clamps to 0..2.
func TestVHLRequiredTierRoundTrip(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()

	got, err := env.sender.VHLGetRequiredTier()
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("default required tier = %d, want 0", got)
	}
	if err := env.sender.VHLSetRequiredTier(2); err != nil {
		t.Fatal(err)
	}
	got, err = env.sender.VHLGetRequiredTier()
	if err != nil || got != 2 {
		t.Fatalf("required tier = %d, %v; want 2", got, err)
	}
	for _, bad := range []int{-1, 3, 99} {
		if err := env.sender.VHLSetRequiredTier(bad); err == nil {
			t.Fatalf("set required tier %d should fail", bad)
		}
	}
	// Persistence: a fresh load sees the stored value.
	got, err = env.sender.VHLGetRequiredTier()
	if err != nil || got != 2 {
		t.Fatalf("persisted required tier = %d, %v; want 2", got, err)
	}
	if err := env.sender.VHLSetRequiredTier(0); err != nil {
		t.Fatal(err)
	}
}

func TestVHLClampTier(t *testing.T) {
	for in, want := range map[int]int{-5: 0, -1: 0, 0: 0, 1: 1, 2: 2, 3: 2, 100: 2} {
		if got := vhlClampTier(in); got != want {
			t.Fatalf("vhlClampTier(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestVHLNonceSetMergeAndNilGuard covers the NonceSet persistence
// (issue #142 review): the merge across fetches unions the sets
// (earliest envelope id wins, so a consumed nonce is never
// resurrected), and an old vhl.json without the key loads with a
// non-nil set.
func TestVHLNonceSetMergeAndNilGuard(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()

	vfr := &vhl.Verifier{
		Registry: vhl.NewRegistry(),
		Seen:     vhl.NewSeenSet(),
		Revoked:  vhl.NewRevocationSet(),
		Nonces:   vhl.NewNonceSet(),
	}
	vfr.Nonces.Consume("approver\x00nonce-a", 7)
	vfr.Nonces.Consume("approver\x00nonce-b", 9)
	if err := vhlMergeSeen(vfr); err != nil {
		t.Fatalf("merge: %v", err)
	}
	ff, err := loadVHL()
	if err != nil {
		t.Fatal(err)
	}
	if !ff.Nonces.Consumed("approver\x00nonce-a", 42) {
		t.Fatal("merged nonce should be consumed in a different envelope")
	}
	if ff.Nonces.Consumed("approver\x00nonce-a", 7) {
		t.Fatal("same-envelope re-evaluation must not count as consumed")
	}

	// Old file without the key: nil-guard on load.
	if err := updateVHL(func(ff *vhlFile) error {
		ff.Nonces = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ff, err = loadVHL()
	if err != nil {
		t.Fatal(err)
	}
	if ff.Nonces == nil {
		t.Fatal("Nonces nil-guard: load of an old vhl.json must yield a non-nil set")
	}
}
