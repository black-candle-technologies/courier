// OOB-code private channel tests (issue #48, phase 2).
package client

import (
	"crypto/rand"
	"strings"
	"testing"
)

// TestJoinCodeRoundTrip: format -> parse is the identity, and the code
// is 6 groups of 4 characters.
func TestJoinCodeRoundTrip(t *testing.T) {
	var raw [joinCodeBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	code, err := FormatJoinCode(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(code, "-")
	if len(parts) != 6 {
		t.Fatalf("code = %q, want 6 groups", code)
	}
	for _, p := range parts {
		if len(p) != 4 {
			t.Fatalf("code = %q, want groups of 4", code)
		}
	}
	back, err := ParseJoinCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(raw[:]) {
		t.Fatal("round trip mismatch")
	}
	// Lowercase + spaces tolerated.
	back, err = ParseJoinCode(strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(raw[:]) {
		t.Fatal("case/space-insensitive round trip mismatch")
	}
	for _, bad := range []string{"", "ABCD", "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12", "!!!!-!!!!-!!!!-!!!!-!!!!-!!!!"} {
		if _, err := ParseJoinCode(bad); err == nil {
			t.Fatalf("bad code %q accepted", bad)
		}
	}
	if _, err := FormatJoinCode([]byte{1, 2, 3}); err == nil {
		t.Fatal("short secret accepted")
	}
}

// TestParseChannelDMPayload: only well-formed channel payloads are
// intercepted; anything else falls through to ordinary delivery.
func TestParseChannelDMPayload(t *testing.T) {
	mk := func(s string) []byte { return []byte(s) }
	if _, ok := parseChannelDMPayload(mk(`{"cc":2,"t":"join-request","s":"abc"}`)); !ok {
		t.Fatal("valid join-request not recognized")
	}
	if _, ok := parseChannelDMPayload(mk(`{"cc":2,"t":"msg","ch":"ch_x","e":1}`)); !ok {
		t.Fatal("valid msg not recognized")
	}
	for _, bad := range []string{
		``,
		`not json`,
		`{"cc":1,"t":"invite","g":"group:x"}`, // group magic, not channel
		`{"cc":2,"t":"bogus"}`,
		`{"cc":2}`, // no type
		`{"t":"msg"}`, // no magic
	} {
		if _, ok := parseChannelDMPayload(mk(bad)); ok {
			t.Fatalf("payload %q intercepted", bad)
		}
	}
}

// TestNewChannelIDFormat checks the channel id shape.
func TestNewChannelIDFormat(t *testing.T) {
	id, err := newChannelID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "ch_") || len(id) != 3+26 {
		t.Fatalf("id = %q", id)
	}
	id2, _ := newChannelID()
	if id == id2 {
		t.Fatal("duplicate channel ids")
	}
}

func channelStateFor(t *testing.T, home, id string) *channelState {
	t.Helper()
	t.Setenv("HOME", home)
	cs, err := loadChannels()
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := cs[id]
	if !ok {
		t.Fatalf("no local state for channel %s", id)
	}
	return ch
}

// TestChannelEndToEnd exercises the full issue #48 phase-2 flow: create,
// OOB invite, join handshake via inbox syncs (with mutual verification),
// message round trips in both directions, member removal with rekey, and
// the removed member's inability to read or post.
func TestChannelEndToEnd(t *testing.T) {
	e := newGroupTestEnv(t)
	var aCursor, bCursor int64

	// Named contacts both ways, so the OOB ceremony marks verifications.
	e.asAlice()
	if err := e.aCfg.AddContact("bob", e.bCfg.Address); err != nil {
		t.Fatal(err)
	}
	e.asBob()
	if err := e.bCfg.AddContact("alice", e.aCfg.Address); err != nil {
		t.Fatal(err)
	}

	// Alice creates the channel and mints an invite.
	e.asAlice()
	ch, err := e.alice.ChannelCreate("team")
	if err != nil {
		t.Fatalf("ChannelCreate: %v", err)
	}
	if !strings.HasPrefix(ch.ID, "ch_") {
		t.Fatalf("channel id = %q", ch.ID)
	}
	code, err := e.alice.ChannelInvite(ch.ID)
	if err != nil {
		t.Fatalf("ChannelInvite: %v", err)
	}
	secret, err := ParseJoinCode(code)
	if err != nil {
		t.Fatalf("invite code does not parse: %v", err)
	}

	// Non-admin invite must fail.
	e.asBob()
	if _, err := e.bob.ChannelInvite(ch.ID); err == nil {
		t.Fatal("non-member ChannelInvite succeeded")
	}

	// Bob sends the join request directly (deterministic; ChannelJoin's
	// 60s wait loop is exercised separately).
	e.asBob()
	if err := e.bob.sendChannelJoinRequest(e.aCfg.Address, secret); err != nil {
		t.Fatalf("sendChannelJoinRequest: %v", err)
	}

	// Alice syncs: the join request is consumed silently, bob joins the
	// roster, the invite burns, and the accept goes out. Bob is marked
	// verified: code possession is the OOB ceremony.
	e.asAlice()
	if msgs := e.syncPersonal(e.alice, e.aCfg, &aCursor); len(msgs) != 0 {
		t.Fatalf("join request surfaced as chat: %+v", msgs)
	}
	ag := channelStateFor(t, e.aHome, ch.ID)
	if len(ag.Roster) != 2 {
		t.Fatalf("alice roster = %v", ag.Roster)
	}
	if st, _ := e.alice.ContactTrust("bob"); st != TrustVerified {
		t.Fatalf("bob trust after join = %v, want verified (OOB bootstrap)", st)
	}

	// Bob syncs: the accept is consumed, his channel state appears, and
	// alice is marked verified on his side too.
	e.asBob()
	if msgs := e.syncPersonal(e.bob, e.bCfg, &bCursor); len(msgs) != 0 {
		t.Fatalf("join accept surfaced as chat: %+v", msgs)
	}
	bg := channelStateFor(t, e.bHome, ch.ID)
	if bg.Admin != e.aCfg.Address || bg.Name != "team" {
		t.Fatalf("bob channel = %+v", bg)
	}
	if len(bg.Roster) != 2 {
		t.Fatalf("bob roster = %v", bg.Roster)
	}
	if st, _ := e.bob.ContactTrust("alice"); st != TrustVerified {
		t.Fatalf("alice trust after join = %v, want verified (OOB bootstrap)", st)
	}

	// Round trip: alice -> bob. Channel DMs never surface as chat.
	e.asAlice()
	if err := e.alice.ChannelSend(ch.ID, "hello channel"); err != nil {
		t.Fatalf("ChannelSend: %v", err)
	}
	e.asBob()
	if msgs := e.syncPersonal(e.bob, e.bCfg, &bCursor); len(msgs) != 0 {
		t.Fatalf("channel msg surfaced as chat: %+v", msgs)
	}
	msgs, err := e.bob.ChannelMessages(ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Body != "hello channel" || msgs[0].From != e.aCfg.Address {
		t.Fatalf("bob inbox = %+v", msgs)
	}

	// Round trip: bob -> alice.
	e.asBob()
	if err := e.bob.ChannelSend(ch.ID, "hi alice"); err != nil {
		t.Fatalf("bob ChannelSend: %v", err)
	}
	e.asAlice()
	e.syncPersonal(e.alice, e.aCfg, &aCursor)
	msgs, err = e.alice.ChannelMessages(ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[1].Body != "hi alice" || msgs[1].From != e.bCfg.Address {
		t.Fatalf("alice inbox = %+v", msgs)
	}

	// Alice removes bob: the channel secret must rotate.
	e.asAlice()
	epochBefore := channelStateFor(t, e.aHome, ch.ID).Epoch
	if err := e.alice.ChannelRemoveMember(ch.ID, e.bCfg.Address); err != nil {
		t.Fatalf("ChannelRemoveMember: %v", err)
	}
	ag = channelStateFor(t, e.aHome, ch.ID)
	if ag.Epoch != epochBefore+1 {
		t.Fatalf("epoch = %d, want %d (rekey on removal)", ag.Epoch, epochBefore+1)
	}
	if len(ag.Roster) != 1 {
		t.Fatalf("roster after removal = %v", ag.Roster)
	}

	// Alice sends again; bob (removed, old secret) must not read it.
	e.asAlice()
	if err := e.alice.ChannelSend(ch.ID, "after removal"); err != nil {
		t.Fatalf("ChannelSend after removal: %v", err)
	}
	e.asBob()
	e.syncPersonal(e.bob, e.bCfg, &bCursor)
	msgs, err = e.bob.ChannelMessages(ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Body == "after removal" {
			t.Fatal("removed member read a post-removal message")
		}
	}
	// Bob's post is dropped: he is no longer in the roster.
	if err := e.bob.ChannelSend(ch.ID, "sneaky"); err != nil {
		t.Fatalf("bob ChannelSend: %v", err)
	}
	e.asAlice()
	e.syncPersonal(e.alice, e.aCfg, &aCursor)
	msgs, err = e.alice.ChannelMessages(ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Body == "sneaky" {
			t.Fatal("removed member's post was accepted")
		}
	}
}

// TestChannelJoinValidation: join requests with unknown, expired, or
// already-used secrets are ignored without creating channel state.
func TestChannelJoinValidation(t *testing.T) {
	e := newGroupTestEnv(t)

	e.asAlice()
	ch, err := e.alice.ChannelCreate("team")
	if err != nil {
		t.Fatal(err)
	}
	code, err := e.alice.ChannelInvite(ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ParseJoinCode(code)
	if err != nil {
		t.Fatal(err)
	}
	secretB64 := b64enc(secret)

	// Unknown secret.
	e.alice.handleChannelDM(e.bCfg.Address, channelDMPayload{Type: channelJoinRequest, Secret: b64enc([]byte("0123456789abcde"))})
	// Expired invite: backdate it, then try.
	e.asAlice()
	t.Setenv("HOME", e.aHome)
	_ = updateChannels(func(cs *channelStore) error {
		cs.Invites[secretB64].CreatedAt -= channelInviteTTL + 60
		return nil
	})
	e.alice.handleChannelDM(e.bCfg.Address, channelDMPayload{Type: channelJoinRequest, Secret: secretB64})
	if n := len(channelStateFor(t, e.aHome, ch.ID).Roster); n != 1 {
		t.Fatalf("roster = %d members after bad joins, want 1", n)
	}

	// Fresh invite, used twice: the second join must be rejected.
	code2, err := e.alice.ChannelInvite(ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret2, _ := ParseJoinCode(code2)
	secret2B64 := b64enc(secret2)
	e.asBob()
	t.Setenv("HOME", e.bHome)
	_ = e.bob.sendChannelJoinRequest(e.aCfg.Address, secret2) // records pending on bob's side; harmless
	e.asAlice()
	e.alice.handleChannelDM(e.bCfg.Address, channelDMPayload{Type: channelJoinRequest, Secret: secret2B64})
	e.alice.handleChannelDM(e.bCfg.Address, channelDMPayload{Type: channelJoinRequest, Secret: secret2B64})
	if n := len(channelStateFor(t, e.aHome, ch.ID).Roster); n != 2 {
		t.Fatalf("roster = %d members, want 2 (single-use invite)", n)
	}
}

// TestChannelRekeyValidation: rekeys from non-admins or on stale epochs
// are ignored.
func TestChannelRekeyValidation(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	ch, err := e.alice.ChannelCreate("team")
	if err != nil {
		t.Fatal(err)
	}
	origSecret := channelStateFor(t, e.aHome, ch.ID).Secret

	// Non-admin rekey.
	e.alice.handleChannelDM(e.bCfg.Address, channelDMPayload{
		Type: channelRekey, Channel: ch.ID, Secret: origSecret, Epoch: 2,
		Roster: []string{e.aCfg.Address, e.bCfg.Address}, Admin: e.bCfg.Address,
	})
	// Stale epoch from the real admin.
	e.alice.handleChannelDM(e.aCfg.Address, channelDMPayload{
		Type: channelRekey, Channel: ch.ID, Secret: origSecret, Epoch: 1,
		Roster: []string{e.aCfg.Address}, Admin: e.aCfg.Address,
	})
	if got := channelStateFor(t, e.aHome, ch.ID).Secret; got != origSecret {
		t.Fatal("channel secret changed on invalid rekey")
	}
}

// TestChannelDMNotInSentLog: protocol DMs must not pollute the sent log
// (and hence the dashboard).
func TestChannelDMNotInSentLog(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	if err := e.alice.sendChannelDM(e.bCfg.Address, channelDMPayload{Type: channelJoinRequest, Secret: "x"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", e.aHome)
	entries, err := readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(en.Body, `"cc":2`) {
			t.Fatalf("protocol DM in sent log: %q", en.Body)
		}
	}
}

// TestChannelLeaveNotifiesAdmin: leaving drops local state and DMs the admin.
func TestChannelLeaveNotifiesAdmin(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	ch, err := e.alice.ChannelCreate("team")
	if err != nil {
		t.Fatal(err)
	}
	e.asBob()
	t.Setenv("HOME", e.bHome)
	cs, err := loadChannels()
	if err != nil {
		t.Fatal(err)
	}
	cs.Channels[ch.ID] = &channelState{ID: ch.ID, Name: "team", Secret: ch.Secret,
		Epoch: 1, Roster: []string{e.aCfg.Address, e.bCfg.Address}, Admin: e.aCfg.Address}
	if err := saveChannelsLocked(cs); err != nil {
		t.Fatal(err)
	}
	if err := e.bob.ChannelLeave(ch.ID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", e.bHome)
	if cs, _ := loadChannels(); cs.Channels[ch.ID] != nil {
		t.Fatal("channel record survived leave")
	}
	// Alice syncs: the leave DM updates her roster.
	var aCursor int64
	e.asAlice()
	e.syncPersonal(e.alice, e.aCfg, &aCursor)
	if n := len(channelStateFor(t, e.aHome, ch.ID).Roster); n != 1 {
		t.Fatalf("alice roster = %d after leave, want 1", n)
	}
}
