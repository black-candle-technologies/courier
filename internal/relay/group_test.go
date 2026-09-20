// Group messaging tests (issue #32).
package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

func groupIdentities(t *testing.T) (alice, bob, carol *crypto.Identity) {
	t.Helper()
	var err error
	if alice, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if bob, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if carol, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	return alice, bob, carol
}

func addrOf(id *crypto.Identity) string { return crypto.FormatAddress(id.EdPub[:]) }

// postControl submits a signed membership-control message.
func postControl(t *testing.T, srv *Server, groupID, name, action, target, admin string, epoch int64, signer *crypto.Identity) *httptest.ResponseRecorder {
	t.Helper()
	sig := signer.Sign(envelope.GroupControl(groupID, action, target, admin, epoch))
	body, _ := json.Marshal(map[string]any{
		"group": groupID, "name": name, "action": action,
		"target": target, "admin": admin, "epoch": epoch, "sig": b64.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/groups/control", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

// makeGroupEnvelope builds a correctly signed group message envelope.
func makeGroupEnvelope(t *testing.T, sender *crypto.Identity, groupID string, keyEpoch int64, key [32]byte, body string) map[string]any {
	t.Helper()
	pt, _ := json.Marshal(map[string]string{"t": "m", "b": body})
	nonce, ct, err := crypto.SealSymmetric(&key, pt)
	if err != nil {
		t.Fatal(err)
	}
	var eph [32]byte
	if _, err := rand.Read(eph[:]); err != nil {
		t.Fatal(err)
	}
	sentAt := time.Now().Unix()
	sig := sender.Sign(envelope.GroupCanonical(groupID, sender.EdPub[:], keyEpoch, eph[:], nonce, sentAt, ct))
	return map[string]any{
		"to": groupID, "from": addrOf(sender),
		"eph": b64.EncodeToString(eph[:]), "nonce": b64.EncodeToString(nonce), "ct": b64.EncodeToString(ct),
		"sent_at": sentAt, "sig": b64.EncodeToString(sig),
		"kind": "group", "key_epoch": keyEpoch,
	}
}

// groupInbox fetches the group inbox as member, signed by signer.
func groupInbox(t *testing.T, srv *Server, groupID, member string, signer *crypto.Identity, after int64) *httptest.ResponseRecorder {
	t.Helper()
	memberEd, err := crypto.ParseAddress(member)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	sig := signer.Sign(envelope.GroupInboxRequest(groupID, memberEd[:], after, 50, ts))
	u := fmt.Sprintf("/v1/inbox?to=%s&member=%s&after=%d&limit=50&ts=%d&sig=%s",
		url.QueryEscape(groupID), url.QueryEscape(member), after, ts, b64.EncodeToString(sig))
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

func newGroupID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return envelope.FormatGroupID(raw)
}

// setupGroup creates a group with alice as admin and bob as member,
// returning the group ID.
func setupGroup(t *testing.T, srv *Server, alice, bob *crypto.Identity) string {
	t.Helper()
	groupID := newGroupID(t)
	if rr := postControl(t, srv, groupID, "test", envelope.GroupControlCreate, "", addrOf(alice), 1, alice); rr.Code != http.StatusCreated {
		t.Fatalf("create: code %d body %s", rr.Code, rr.Body.String())
	}
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlAdd, addrOf(bob), addrOf(alice), 2, alice); rr.Code != http.StatusCreated {
		t.Fatalf("add: code %d body %s", rr.Code, rr.Body.String())
	}
	return groupID
}

func TestGroupCreateAddSendRoundtrip(t *testing.T) {
	srv := testServer(t)
	alice, bob, _ := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	key, err := crypto.GenerateSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	env := makeGroupEnvelope(t, alice, groupID, 1, key, "hello group")
	if rr := postSend(t, srv, env); rr.Code != http.StatusCreated {
		t.Fatalf("send: code %d body %s", rr.Code, rr.Body.String())
	}

	rr := groupInbox(t, srv, groupID, addrOf(bob), bob, 0)
	if rr.Code != http.StatusOK {
		t.Fatalf("inbox: code %d body %s", rr.Code, rr.Body.String())
	}
	var in struct {
		Group    string `json:"group"`
		Messages []struct {
			ID       int64  `json:"id"`
			From     string `json:"from"`
			KeyEpoch int64  `json:"key_epoch"`
			Ct       string `json:"ct"`
			Nonce    string `json:"nonce"`
		} `json:"messages"`
		Controls []struct {
			Action string `json:"action"`
			Epoch  int64  `json:"epoch"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &in); err != nil {
		t.Fatal(err)
	}
	if in.Group != groupID {
		t.Fatalf("group = %q, want %q", in.Group, groupID)
	}
	if len(in.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(in.Messages))
	}
	if got := in.Messages[0].From; got != addrOf(alice) {
		t.Fatalf("from = %q, want alice", got)
	}
	if in.Messages[0].KeyEpoch != 1 {
		t.Fatalf("key_epoch = %d, want 1", in.Messages[0].KeyEpoch)
	}
	if len(in.Controls) != 2 || in.Controls[0].Action != "create" || in.Controls[1].Action != "add" {
		t.Fatalf("controls = %+v, want [create add]", in.Controls)
	}
	// The ciphertext must open under alice's sender key.
	nonce, _ := base64.RawURLEncoding.DecodeString(in.Messages[0].Nonce)
	ct, _ := base64.RawURLEncoding.DecodeString(in.Messages[0].Ct)
	plain, err := crypto.OpenSymmetric(key[:], nonce, ct)
	if err != nil {
		t.Fatalf("open group message: %v", err)
	}
	var body struct {
		T string `json:"t"`
		B string `json:"b"`
	}
	if err := json.Unmarshal(plain, &body); err != nil || body.B != "hello group" {
		t.Fatalf("body = %q, err %v", plain, err)
	}
}

func TestGroupNonMemberSendRejected(t *testing.T) {
	srv := testServer(t)
	alice, bob, carol := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	key, _ := crypto.GenerateSenderKey()
	env := makeGroupEnvelope(t, carol, groupID, 1, key, "intruder")
	if rr := postSend(t, srv, env); rr.Code != http.StatusForbidden {
		t.Fatalf("non-member send: code %d, want 403", rr.Code)
	}
}

func TestGroupRemovedMemberRejected(t *testing.T) {
	srv := testServer(t)
	alice, bob, _ := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	// Alice removes bob (epoch 3).
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlRemove, addrOf(bob), addrOf(alice), 3, alice); rr.Code != http.StatusCreated {
		t.Fatalf("remove: code %d body %s", rr.Code, rr.Body.String())
	}

	// Bob can no longer read the group.
	if rr := groupInbox(t, srv, groupID, addrOf(bob), bob, 0); rr.Code != http.StatusForbidden {
		t.Fatalf("removed member read: code %d, want 403", rr.Code)
	}
	// Bob can no longer post to the group.
	key, _ := crypto.GenerateSenderKey()
	env := makeGroupEnvelope(t, bob, groupID, 1, key, "after removal")
	if rr := postSend(t, srv, env); rr.Code != http.StatusForbidden {
		t.Fatalf("removed member send: code %d, want 403", rr.Code)
	}
	// Alice (still a member) can still read.
	if rr := groupInbox(t, srv, groupID, addrOf(alice), alice, 0); rr.Code != http.StatusOK {
		t.Fatalf("admin read after removal: code %d body %s", rr.Code, rr.Body.String())
	}
}

func TestGroupDuplicateEnvelope(t *testing.T) {
	srv := testServer(t)
	alice, bob, _ := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	key, _ := crypto.GenerateSenderKey()
	env := makeGroupEnvelope(t, alice, groupID, 1, key, "once")
	rr1 := postSend(t, srv, env)
	rr2 := postSend(t, srv, env) // exact replay
	if rr1.Code != http.StatusCreated || rr2.Code != http.StatusCreated {
		t.Fatalf("codes %d/%d, want 201/201", rr1.Code, rr2.Code)
	}
	var r1, r2 struct {
		ID        int64 `json:"id"`
		Duplicate bool  `json:"duplicate"`
	}
	if err := json.Unmarshal(rr1.Body.Bytes(), &r1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Duplicate != true || r2.ID != r1.ID {
		t.Fatalf("replay: id %d dup %v, want id %d dup true", r2.ID, r2.Duplicate, r1.ID)
	}
	rr := groupInbox(t, srv, groupID, addrOf(bob), bob, 0)
	var in struct {
		Messages []any `json:"messages"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &in); err != nil {
		t.Fatal(err)
	}
	if len(in.Messages) != 1 {
		t.Fatalf("messages = %d, want 1 (no duplicate delivery)", len(in.Messages))
	}
}

func TestGroupControlReplayRejected(t *testing.T) {
	srv := testServer(t)
	alice, bob, _ := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	// Replay the add control (epoch 2): must be rejected.
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlAdd, addrOf(bob), addrOf(alice), 2, alice); rr.Code != http.StatusBadRequest {
		t.Fatalf("replayed control: code %d, want 400", rr.Code)
	}
	// Skipped epoch (4 instead of 3): must be rejected.
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlRemove, addrOf(bob), addrOf(alice), 4, alice); rr.Code != http.StatusBadRequest {
		t.Fatalf("skipped-epoch control: code %d, want 400", rr.Code)
	}
}

func TestGroupNonAdminControlRejected(t *testing.T) {
	srv := testServer(t)
	alice, bob, carol := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	// Bob is not the admin: his correctly signed add must be rejected.
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlAdd, addrOf(carol), addrOf(bob), 3, bob); rr.Code != http.StatusBadRequest {
		t.Fatalf("non-admin control: code %d, want 400", rr.Code)
	}
}

func TestGroupControlBadSignatureRejected(t *testing.T) {
	srv := testServer(t)
	alice, bob, _ := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	// Signed by bob but claiming alice as admin: signature mismatch.
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlRemove, addrOf(bob), addrOf(alice), 3, bob); rr.Code != http.StatusBadRequest {
		t.Fatalf("forged control: code %d, want 400", rr.Code)
	}
}

func TestGroupAdminTransfer(t *testing.T) {
	srv := testServer(t)
	alice, bob, carol := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)

	// Alice transfers adminship to bob (epoch 3).
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlTransferAdmin, addrOf(bob), addrOf(alice), 3, alice); rr.Code != http.StatusCreated {
		t.Fatalf("transfer: code %d body %s", rr.Code, rr.Body.String())
	}
	// Bob (new admin) can now add carol (epoch 4).
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlAdd, addrOf(carol), addrOf(bob), 4, bob); rr.Code != http.StatusCreated {
		t.Fatalf("new admin add: code %d body %s", rr.Code, rr.Body.String())
	}
	// Alice (old admin) can no longer control the group.
	if rr := postControl(t, srv, groupID, "", envelope.GroupControlRemove, addrOf(carol), addrOf(alice), 5, alice); rr.Code != http.StatusBadRequest {
		t.Fatalf("old admin control: code %d, want 400", rr.Code)
	}
}

func TestGroupSendKindValidation(t *testing.T) {
	srv := testServer(t)
	alice, bob, _ := groupIdentities(t)
	groupID := setupGroup(t, srv, alice, bob)
	key, _ := crypto.GenerateSenderKey()

	// kind "group" addressed to a personal address: rejected.
	env := makeGroupEnvelope(t, alice, groupID, 1, key, "x")
	env["to"] = addrOf(bob)
	if rr := postSend(t, srv, env); rr.Code != http.StatusBadRequest {
		t.Fatalf("group kind to address: code %d, want 400", rr.Code)
	}
	// Unknown kind to a personal address: rejected.
	dm := makeEnvelope(t, alice, bob, "hi")
	dm["kind"] = "future-kind"
	if rr := postSend(t, srv, dm); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind: code %d, want 400", rr.Code)
	}
	// Wrong kind for a group recipient: rejected.
	env2 := makeGroupEnvelope(t, alice, groupID, 1, key, "x")
	env2["kind"] = "dm"
	if rr := postSend(t, srv, env2); rr.Code != http.StatusBadRequest {
		t.Fatalf("dm kind to group: code %d, want 400", rr.Code)
	}
}
