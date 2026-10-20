package client

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/vhl"
	"github.com/black-candle-technologies/courier/internal/vhltest"
)

// Exercise the existing relay/browser ceremony through mint, send and receiver
// verification. The test authenticator signs a genuine nonce-bound UV assertion.
func TestVHLApproveCeremonySendEndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	pki := vhltest.NewPKI(t)
	setupCeremonyRP(t, env, pki)
	enr := pki.Enroll(t, ceremonyTestRPID, ceremonyTestOrigin, vhltest.FreshChallenge(t))
	cred := vhl.Credential{
		ID: base64.RawURLEncoding.EncodeToString(enr.CredID), Kind: "webauthn",
		PublicKey:  base64.RawURLEncoding.EncodeToString(vhltest.COSEKeyP256(&enr.CredKey.PublicKey)),
		EnrolledAt: time.Now().Unix(), Device: "test-hardware",
	}
	for _, c := range []*Client{env.sender, env.recipient} {
		if err := c.cfg.local().updateVHL(func(ff *vhlFile) error {
			ff.RP.ID = ceremonyTestRPID
			ff.RP.Origins = []string{ceremonyTestOrigin}
			return ff.Registry.Enroll(env.senderCfg.Address, "sender", cred)
		}); err != nil {
			t.Fatal(err)
		}
	}
	env.asRecipient()
	testEnrollApprover(t, env.senderCfg.Address, "sender")
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	env.asSender()
	browser := newCeremonyBrowser(t, env, env.senderCfg.Address)
	body := "approve this exact action"
	req, h := requestFixture(t, env.sender, body, vhl.PresenceFIDO2UV)
	nonce := vhltest.FreshChallenge(t)
	sink := newCeremonyCodeSink()
	type result struct {
		proof vhl.Proof
		err   error
	}
	done := make(chan result, 1)
	go func() {
		p, err := env.sender.VHLApproveFIDO2Ceremony(nonce, h[:], req.ID, env.senderCfg.Address, body, sink.printf)
		done <- result{p, err}
	}()
	var code string
	select {
	case code = <-sink.ch:
	case out := <-done:
		t.Fatalf("ceremony failed before code: %v", out.err)
	case <-time.After(30 * time.Second):
		t.Fatal("no ceremony code")
	}
	challenge := browser.ceremonyChallenge(code)
	expected := vhl.ApprovalChallenge(h[:], nonce)
	if !bytes.Equal(challenge, expected[:]) {
		t.Fatal("ceremony lost action/nonce binding")
	}
	browser.submitAttestation(code, pki.Assert(t, enr.CredKey, enr.CredID, ceremonyTestRPID, ceremonyTestOrigin, challenge))
	var out result
	select {
	case out = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("approval did not finish")
	}
	if out.err != nil {
		t.Fatal(out.err)
	}
	att, err := env.sender.VHLApproveMint(req.ID, h, env.senderCfg.Address, out.proof, vhl.PresenceFIDO2UV, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.sender.VHLGetRequest(req.ID); err == nil {
		t.Fatal("approved request not consumed")
	}
	if _, err := env.sender.SendTiered(env.recipCfg.Address, body, vhl.Tier2, att); err != nil {
		t.Fatal(err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected one message: %+v", msgs)
	}
	if msgs[0].VHL == nil || msgs[0].VHL.Verdict != "attested" || msgs[0].VHL.Tier != 2 {
		t.Fatalf("expected verified Tier 2 message: %+v", msgs[0].VHL)
	}
}
