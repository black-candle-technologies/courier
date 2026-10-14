package main

import (
	"bytes"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

type approvalGateClient struct {
	t      *testing.T
	nonce  []byte
	called bool
}

func (f *approvalGateClient) VHLGetRequest(id string) (*client.VHLRequestRecord, error) {
	return &client.VHLRequestRecord{From: "requester", Request: &vhl.ApprovalRequest{ID: id, Tier: 2, Draft: "action", WantPresence: "fido2_uv"}}, nil
}
func (f *approvalGateClient) VHLApproveFIDO2Ceremony(nonce, hash []byte, id, approver, draft string, printf func(string, ...any)) (vhl.Proof, error) {
	f.called = true
	h := vhl.MsgHashOf([]byte("action"))
	if len(nonce) != 32 || !bytes.Equal(hash, h[:]) || id != "request-id" || approver != "approver" || draft != "action" {
		f.t.Fatal("wrong ceremony binding")
	}
	f.nonce = append([]byte(nil), nonce...)
	return vhl.Proof{Kind: vhl.ProofFIDO2, CredentialID: "test"}, nil
}
func (f *approvalGateClient) VHLApproveMint(id string, h [32]byte, from string, p vhl.Proof, strength vhl.PresenceStrength, nonce []byte) (*vhl.Attestation, error) {
	if !f.called || p.Kind != vhl.ProofFIDO2 || strength != vhl.PresenceFIDO2UV || !bytes.Equal(nonce, f.nonce) || from != "requester" {
		f.t.Fatal("mint bypassed FIDO2 UV ceremony")
	}
	return &vhl.Attestation{ID: "test-attestation"}, nil
}
func TestVHLApproveDefaultsToFIDO2UV(t *testing.T) {
	for _, args := range [][]string{{"request-id"}, {"request-id", "--presence", "fido2_uv"}} {
		f := &approvalGateClient{t: t}
		if err := cmdVHLApprove(&client.Config{Address: "approver"}, f, args); err != nil {
			t.Fatal(err)
		}
		if !f.called {
			t.Fatal("no hardware ceremony")
		}
	}
}
