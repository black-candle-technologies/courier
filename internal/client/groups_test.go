// Group messaging tests (issue #32).
package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

func TestGroupSenderKeyRoundTrip(t *testing.T) {
	k, err := crypto.GenerateSenderKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := crypto.SealSymmetric(&k, []byte("hello group"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.OpenSymmetric(k[:], nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "hello group" {
		t.Fatalf("plain = %q", plain)
	}
	// Wrong key must not open it.
	k2, _ := crypto.GenerateSenderKey()
	if _, err := crypto.OpenSymmetric(k2[:], nonce, ct); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
	// Tampered ciphertext must not open.
	ct[0] ^= 1
	if _, err := crypto.OpenSymmetric(k[:], nonce, ct); err == nil {
		t.Fatal("expected decryption failure with tampered ciphertext")
	}
}

func TestGroupIDFormat(t *testing.T) {
	var raw [16]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	id := envelope.FormatGroupID(raw)
	if !strings.HasPrefix(id, "group:") {
		t.Fatalf("id = %q, want group: prefix", id)
	}
	got, err := envelope.ParseGroupID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got != raw {
		t.Fatalf("round trip = %x, want %x", got, raw)
	}
	// 128 bits of entropy: 22 base64url chars.
	if len(strings.TrimPrefix(id, "group:")) != 22 {
		t.Fatalf("id = %q, want 22 base64url chars", id)
	}
	for _, bad := range []string{"", "group:", "group:!!!", "ed25519:abcd", "group:" + base64.RawURLEncoding.EncodeToString(make([]byte, 15))} {
		if _, err := envelope.ParseGroupID(bad); err == nil {
			t.Fatalf("bad id %q accepted", bad)
		}
	}
}

func TestGroupCanonicalSignVerify(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var raw [16]byte
	copy(raw[:], []byte("0123456789abcdef"))
	groupID := envelope.FormatGroupID(raw)
	var eph [32]byte
	nonce := make([]byte, 24)
	ct := []byte("ciphertext")
	sentAt := int64(1700000000)
	canon := envelope.GroupCanonical(groupID, id.EdPub[:], 7, eph[:], nonce, sentAt, ct)
	sig := id.Sign(canon)
	if !crypto.Verify(id.EdPub[:], canon, sig) {
		t.Fatal("signature did not verify")
	}
	// A different key epoch changes the canonical bytes.
	canon2 := envelope.GroupCanonical(groupID, id.EdPub[:], 8, eph[:], nonce, sentAt, ct)
	if crypto.Verify(id.EdPub[:], canon2, sig) {
		t.Fatal("signature verified under a different key epoch")
	}
}

func TestGroupControlSignVerify(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	other, _ := crypto.GenerateIdentity()
	groupID := "group:AAAAAAAAAAAAAAAAAAAAAA"
	admin := crypto.FormatAddress(id.EdPub[:])
	target := crypto.FormatAddress(other.EdPub[:])
	canon := envelope.GroupControl(groupID, envelope.GroupControlAdd, target, admin, 2)
	sig := id.Sign(canon)
	if !crypto.Verify(id.EdPub[:], canon, sig) {
		t.Fatal("control signature did not verify")
	}
	// Different action: must not verify.
	canon2 := envelope.GroupControl(groupID, envelope.GroupControlRemove, target, admin, 2)
	if crypto.Verify(id.EdPub[:], canon2, sig) {
		t.Fatal("control signature verified for a different action")
	}
}

func TestGroupDMPayloadRouting(t *testing.T) {
	keyPayload, _ := json.Marshal(groupDMPayload{Magic: 1, Type: "key", Group: "group:AAAAAAAAAAAAAAAAAAAAAA", Key: "x", Epoch: 1})
	if p, ok := parseGroupDMPayload(keyPayload); !ok || p.Type != "key" {
		t.Fatal("key payload not recognized")
	}
	invitePayload, _ := json.Marshal(groupDMPayload{Magic: 1, Type: "invite", Group: "group:AAAAAAAAAAAAAAAAAAAAAA"})
	if _, ok := parseGroupDMPayload(invitePayload); !ok {
		t.Fatal("invite payload not recognized")
	}
	// Ordinary chat JSON must not be intercepted.
	chat, _ := json.Marshal(map[string]string{"hello": "world"})
	if _, ok := parseGroupDMPayload(chat); ok {
		t.Fatal("chat message misclassified as group protocol")
	}
	// Right magic, unknown type: not intercepted (fail-open for display).
	unknown, _ := json.Marshal(groupDMPayload{Magic: 1, Type: "mystery", Group: "group:AAAAAAAAAAAAAAAAAAAAAA"})
	if _, ok := parseGroupDMPayload(unknown); ok {
		t.Fatal("unknown group DM type intercepted")
	}
	// Wrong magic: not intercepted.
	wrong, _ := json.Marshal(map[string]any{"cg": 2, "t": "key", "g": "group:AAAAAAAAAAAAAAAAAAAAAA"})
	if _, ok := parseGroupDMPayload(wrong); ok {
		t.Fatal("wrong magic intercepted")
	}
}

// TestInboxSkipsUnknownKind: envelopes with kinds this client does not
// understand (e.g. from a newer client) are skipped without stalling the
// cursor — the v0.6.12 forward-compatibility requirement (issue #32).
func TestInboxSkipsUnknownKind(t *testing.T) {
	cfg := testConfig(t)
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	toEd, _ := crypto.ParseAddress(cfg.Address)
	toX, _ := crypto.Ed25519PubToX25519(toEd[:])
	eph, nonce, ct, err := crypto.Seal(&toX, []byte("from the future"))
	if err != nil {
		t.Fatal(err)
	}
	sig := sender.Sign(envelope.Canonical(toEd[:], sender.EdPub[:], eph, nonce, 1700000000, ct))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"messages":[{"id":41,"from":%q,"eph":%q,"nonce":%q,"ct":%q,"sent_at":1700000000,"received_at":1700000001,"sig":%q,"kind":"future-kind"}]}`,
			crypto.FormatAddress(sender.EdPub[:]),
			base64.RawURLEncoding.EncodeToString(eph),
			base64.RawURLEncoding.EncodeToString(nonce),
			base64.RawURLEncoding.EncodeToString(ct),
			base64.RawURLEncoding.EncodeToString(sig))
	}))
	defer ts.Close()
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	msgs, lastID, skipped, _, err := cl.Inbox(40, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("msgs = %d, want 0", len(msgs))
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if lastID != 41 {
		t.Fatalf("lastID = %d, want 41 (cursor must advance past unknown kinds)", lastID)
	}
}

// ---- end-to-end group flow against a real relay ----

type groupTestEnv struct {
	t     *testing.T
	srv   *httptest.Server
	alice *Client
	bob   *Client
	aHome string
	bHome string
	aCfg  *Config
	bCfg  *Config
}

func newGroupTestEnv(t *testing.T) *groupTestEnv {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	t.Cleanup(srv.Close)

	aHome := t.TempDir()
	bHome := t.TempDir()
	t.Setenv("HOME", aHome)
	aCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := aCfg.Save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", bHome)
	bCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := bCfg.Save(); err != nil {
		t.Fatal(err)
	}
	env := &groupTestEnv{
		t: t, srv: srv,
		alice: New(aCfg), bob: New(bCfg),
		aHome: aHome, bHome: bHome, aCfg: aCfg, bCfg: bCfg,
	}
	// Real clients publish their (rotated) encryption keys; without the
	// announcements, DMs would fall back to address-derived keys the
	// test configs cannot decrypt.
	env.asAlice()
	if err := env.alice.PublishKey(); err != nil {
		t.Fatal(err)
	}
	env.asBob()
	if err := env.bob.PublishKey(); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *groupTestEnv) asAlice() { e.t.Setenv("HOME", e.aHome) }
func (e *groupTestEnv) asBob()   { e.t.Setenv("HOME", e.bHome) }

// syncPersonal runs a personal inbox sync like `courier inbox` does,
// returning chat messages.
func (e *groupTestEnv) syncPersonal(c *Client, cfg *Config, cursor *int64) []Message {
	e.t.Helper()
	msgs, lastID, _, _, err := c.Inbox(*cursor, 50)
	if err != nil {
		e.t.Fatal(err)
	}
	*cursor = lastID
	if err := cfg.Update(func(fresh *Config) error {
		fresh.Cursor = *cursor
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return msgs
}

func (e *groupTestEnv) groupState(home, groupID string) *groupState {
	e.t.Helper()
	e.t.Setenv("HOME", home)
	gs, err := loadGroups()
	if err != nil {
		e.t.Fatal(err)
	}
	g, ok := gs[groupID]
	if !ok {
		e.t.Fatalf("no local state for group %s", groupID)
	}
	return g
}

// TestGroupEndToEnd exercises the full issue #32 flow: create, join via
// invite, send/receive round trip in both directions, removal, rekey, and
// the removed member's inability to read or post.
func TestGroupEndToEnd(t *testing.T) {
	e := newGroupTestEnv(t)
	var aCursor, bCursor int64

	// Alice creates the group and adds bob.
	e.asAlice()
	g, err := e.alice.GroupCreate("test-group", []string{e.bCfg.Address})
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}
	if !strings.HasPrefix(g.ID, "group:") {
		t.Fatalf("group id = %q", g.ID)
	}

	// Bob syncs his personal inbox: the invite is consumed and his
	// group state is created (no chat message surfaces).
	e.asBob()
	if msgs := e.syncPersonal(e.bob, e.bCfg, &bCursor); len(msgs) != 0 {
		t.Fatalf("invite surfaced as chat: %+v", msgs)
	}
	bg := e.groupState(e.bHome, g.ID)
	if bg.Admin != e.aCfg.Address {
		t.Fatalf("bob's admin = %q, want alice", bg.Admin)
	}
	if len(bg.Roster) != 2 {
		t.Fatalf("bob's roster = %v", bg.Roster)
	}

	// Alice syncs: she receives bob's sender-key DM.
	e.asAlice()
	e.syncPersonal(e.alice, e.aCfg, &aCursor)
	ag := e.groupState(e.aHome, g.ID)
	if _, ok := ag.Keys[e.bCfg.Address]; !ok {
		t.Fatal("alice did not receive bob's sender key")
	}

	// Round trip: alice -> bob.
	e.asAlice()
	if _, err := e.alice.GroupSend(g.ID, "hello group"); err != nil {
		t.Fatalf("GroupSend: %v", err)
	}
	e.asBob()
	msgs, err := e.bob.GroupInbox(g.ID)
	if err != nil {
		t.Fatalf("GroupInbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Body != "hello group" || msgs[0].From != e.aCfg.Address {
		t.Fatalf("msgs = %+v", msgs)
	}

	// Round trip: bob -> alice (exercises bob's sender key).
	e.asBob()
	if _, err := e.bob.GroupSend(g.ID, "hi alice"); err != nil {
		t.Fatalf("bob GroupSend: %v", err)
	}
	e.asAlice()
	msgs, err = e.alice.GroupInbox(g.ID)
	if err != nil {
		t.Fatalf("alice GroupInbox: %v", err)
	}
	// Alice sees her own earlier message too (her cursor was 0); the
	// new one is bob's.
	if len(msgs) != 2 || msgs[1].Body != "hi alice" || msgs[1].From != e.bCfg.Address {
		t.Fatalf("msgs = %+v", msgs)
	}

	// Alice removes bob: her sender key must rotate and bob's key must
	// be dropped locally.
	e.asAlice()
	epochBefore := e.groupState(e.aHome, g.ID).MyEpoch
	if err := e.alice.GroupRemove(g.ID, e.bCfg.Address); err != nil {
		t.Fatalf("GroupRemove: %v", err)
	}
	ag = e.groupState(e.aHome, g.ID)
	if ag.MyEpoch != epochBefore+1 {
		t.Fatalf("MyEpoch = %d, want %d (rekey on removal)", ag.MyEpoch, epochBefore+1)
	}
	if _, ok := ag.Keys[e.bCfg.Address]; ok {
		t.Fatal("bob's sender key was not dropped after removal")
	}
	if len(ag.Roster) != 1 {
		t.Fatalf("roster = %v, want only alice", ag.Roster)
	}

	// Alice sends after the removal.
	if _, err := e.alice.GroupSend(g.ID, "after removal"); err != nil {
		t.Fatalf("GroupSend after removal: %v", err)
	}

	// Bob can no longer read the group (relay 403, recorded locally).
	e.asBob()
	if _, err := e.bob.GroupInbox(g.ID); err == nil {
		t.Fatal("expected error reading as removed member")
	} else if !strings.Contains(err.Error(), "removed") {
		t.Fatalf("err = %q, want mention of removal", err)
	}
	if bg := e.groupState(e.bHome, g.ID); !bg.Removed {
		t.Fatal("bob's local state was not marked removed")
	}

	// Bob can no longer post to the group either.
	if _, err := e.bob.GroupSend(g.ID, "sneaky"); err == nil {
		t.Fatal("expected error sending as removed member")
	}

	// Alice's own reads still work and see the post-removal message.
	e.asAlice()
	msgs, err = e.alice.GroupInbox(g.ID)
	if err != nil {
		t.Fatalf("alice GroupInbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Body != "after removal" {
		t.Fatalf("msgs = %+v", msgs)
	}
}

// TestGroupDuplicateInviteIsIdempotent: a replayed invite DM must not
// duplicate group state or clobber the existing sender key.
func TestGroupDuplicateInviteIsIdempotent(t *testing.T) {
	e := newGroupTestEnv(t)
	var bCursor int64

	e.asAlice()
	g, err := e.alice.GroupCreate("dup-test", []string{e.bCfg.Address})
	if err != nil {
		t.Fatal(err)
	}
	e.asBob()
	e.syncPersonal(e.bob, e.bCfg, &bCursor)
	before := e.groupState(e.bHome, g.ID)

	// Replay the invite by re-sending the same DM payload through the
	// normal path: craft it manually and feed it via handleGroupDM.
	payload, _ := json.Marshal(groupDMPayload{
		Magic: 1, Type: "invite", Group: g.ID,
		Name: "dup-test", Admin: e.aCfg.Address,
		Roster: []string{e.aCfg.Address, e.bCfg.Address},
		Keys:   map[string]groupSenderKey{e.aCfg.Address: {Key: before.Keys[e.aCfg.Address].Key, Epoch: 1}},
		Cursor: 0,
	})
	e.asBob()
	if p, ok := parseGroupDMPayload(payload); !ok {
		t.Fatal("payload not recognized")
	} else {
		e.bob.handleGroupDM(e.aCfg.Address, p)
	}
	after := e.groupState(e.bHome, g.ID)
	if after.MyKey != before.MyKey || after.InboxCursor != before.InboxCursor {
		t.Fatal("replayed invite clobbered group state")
	}
}

// TestGroupNonAdminAddRejected: only the admin can add members.
func TestGroupNonAdminAddRejected(t *testing.T) {
	e := newGroupTestEnv(t)
	var bCursor int64

	e.asAlice()
	g, err := e.alice.GroupCreate("admin-test", []string{e.bCfg.Address})
	if err != nil {
		t.Fatal(err)
	}
	e.asBob()
	e.syncPersonal(e.bob, e.bCfg, &bCursor)

	// Bob is not the admin: his add must fail.
	e.asBob()
	carol, err := NewIdentity(e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.bob.GroupAdd(g.ID, carol.Address); err == nil {
		t.Fatal("expected error adding as non-admin")
	} else if !strings.Contains(err.Error(), "admin") {
		t.Fatalf("err = %q, want admin complaint", err)
	}
}
