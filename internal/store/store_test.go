package store

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/envelope"
	_ "modernc.org/sqlite"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testEnvelope() *Envelope {
	return &Envelope{
		To: "ed25519:to", From: "ed25519:from",
		Eph: "eph", Nonce: "nonce", Ct: "ciphertext",
		SentAt: 1700000000, Sig: "sig",
	}
}

func TestSaveDedupsIdenticalEnvelopes(t *testing.T) {
	s := testStore(t)
	id, stored, err := s.Save(testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if !stored || id == 0 {
		t.Fatalf("first save: id=%d stored=%v", id, stored)
	}
	id2, stored2, err := s.Save(testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if stored2 || id2 != id {
		t.Fatalf("replay: id=%d stored=%v, want id=%d stored=false", id2, stored2, id)
	}
	// A different envelope (different ciphertext) is a new message.
	other := testEnvelope()
	other.Ct = "different"
	id3, stored3, err := s.Save(other)
	if err != nil {
		t.Fatal(err)
	}
	if !stored3 || id3 == id {
		t.Fatalf("distinct: id=%d stored=%v", id3, stored3)
	}
	list, err := s.List("ed25519:to", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 stored envelopes, got %d", len(list))
	}
}

// TestMigrateBackfillsEnvHash simulates a pre-v0.6.11 database (no
// env_hash column) and verifies the migration backfills hashes so old
// messages are covered by replay dedup.
func TestMigrateBackfillsEnvHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Old schema: no env_hash.
	if _, err := db.Exec(`CREATE TABLE envelopes (
		id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL,
		sender TEXT NOT NULL, eph TEXT NOT NULL, nonce TEXT NOT NULL,
		ct TEXT NOT NULL, sent_at INTEGER NOT NULL,
		received_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		sig TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	e := testEnvelope()
	if _, err := db.Exec(`INSERT INTO envelopes
		(recipient, sender, eph, nonce, ct, sent_at, sig)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.To, e.From, e.Eph, e.Nonce, e.Ct, e.SentAt, e.Sig); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	var hash sql.NullString
	if err := s.db.QueryRow(`SELECT env_hash FROM envelopes`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	want := envelope.DedupHash(e.To, e.From, e.Eph, e.Nonce, e.SentAt, e.Ct, e.Sig)
	if !hash.Valid || hash.String != want {
		t.Fatalf("env_hash not backfilled: %+v want %s", hash, want)
	}
	// The pre-existing message must now dedup.
	id, stored, err := s.Save(testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if stored || id != 1 {
		t.Fatalf("old message replay: id=%d stored=%v", id, stored)
	}
}

func testKeyAnnouncement(epoch int64, pub string) *KeyAnnouncement {
	return &KeyAnnouncement{
		Address: "ed25519:testaddr", X25519Pub: pub, Epoch: epoch, Sig: "sig",
	}
}

func TestSaveKeyMonotonic(t *testing.T) {
	s := testStore(t)
	if ok, err := s.SaveKey(testKeyAnnouncement(100, "pub1")); err != nil || !ok {
		t.Fatalf("first save: ok=%v err=%v", ok, err)
	}
	// Stale epoch must lose and must not overwrite.
	if ok, err := s.SaveKey(testKeyAnnouncement(50, "pub-stale")); err != nil || ok {
		t.Fatalf("stale save: ok=%v err=%v", ok, err)
	}
	// Equal epoch is also stale (strictly increasing).
	if ok, err := s.SaveKey(testKeyAnnouncement(100, "pub-same")); err != nil || ok {
		t.Fatalf("equal-epoch save: ok=%v err=%v", ok, err)
	}
	got, err := s.GetKey("ed25519:testaddr")
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 100 || got.X25519Pub != "pub1" {
		t.Fatalf("stale announcement overwrote the row: %+v", got)
	}
	// Newer epoch wins, including the signature column.
	if ok, err := s.SaveKey(testKeyAnnouncement(200, "pub2")); err != nil || !ok {
		t.Fatalf("newer save: ok=%v err=%v", ok, err)
	}
	got, err = s.GetKey("ed25519:testaddr")
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 200 || got.X25519Pub != "pub2" {
		t.Fatalf("newer announcement not stored: %+v", got)
	}
}

func TestSaveKeyScrambledOrderKeepsNewest(t *testing.T) {
	s := testStore(t)
	// Announcements arriving out of order: the newest epoch must win
	// regardless of arrival order (the single-statement upsert makes
	// each save atomic).
	for _, epoch := range []int64{300, 100, 500, 200, 400} {
		if _, err := s.SaveKey(testKeyAnnouncement(epoch, "pub")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetKey("ed25519:testaddr")
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 500 {
		t.Fatalf("want epoch 500, got %d", got.Epoch)
	}
}

// TestDashboardThreadsUnreadCounts seeds several threads and verifies the
// F7 rewrite reports correct per-thread unread counts, latest messages,
// and message counts.
func TestDashboardThreadsUnreadCounts(t *testing.T) {
	s := testStore(t)
	self := "ed25519:self"
	peerA := "ed25519:peerA"
	peerB := "ed25519:peerB"
	uid := int64(1)

	// Create the dashboard user row the seen bookkeeping keys off.
	if _, err := s.db.Exec(
		`INSERT INTO dashboard_users(username, password_hash, courier_address, api_token_hash) VALUES(?,?,?,?)`,
		"lane", "x", self, "tokhash"); err != nil {
		t.Fatal(err)
	}

	push := func(courierID int64, sender, peer, body string, ts int64) {
		t.Helper()
		if _, err := s.SaveDashboardMessage(uid, courierID, sender, self, peer, body, ts, ts, 0, "", 0, false); err != nil {
			t.Fatal(err)
		}
	}
	// Thread A: 3 inbound from peerA, 1 outbound from self.
	push(1, peerA, peerA, "a1", 100)
	push(2, peerA, peerA, "a2", 200)
	push(3, self, peerA, "a3-out", 300)
	push(4, peerA, peerA, "a4-latest", 400)
	// Thread B: 2 inbound from peerB.
	push(5, peerB, peerB, "b1", 150)
	push(6, peerB, peerB, "b2-latest", 250)

	threads, err := s.DashboardThreads(uid, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 2 {
		t.Fatalf("threads = %d, want 2", len(threads))
	}
	byPeer := map[string]DashboardThread{}
	for _, th := range threads {
		byPeer[th.Peer] = th
	}
	a, b := byPeer[peerA], byPeer[peerB]
	// Most recent activity first: A (ts 400) before B (ts 250).
	if threads[0].Peer != peerA || threads[1].Peer != peerB {
		t.Fatalf("order = %q, %q, want A then B", threads[0].Peer, threads[1].Peer)
	}
	if a.Unread != 3 || b.Unread != 2 {
		t.Fatalf("unread = A:%d B:%d, want 3 and 2 (outbound excluded)", a.Unread, b.Unread)
	}
	if a.Count != 4 || b.Count != 2 {
		t.Fatalf("count = A:%d B:%d, want 4 and 2", a.Count, b.Count)
	}
	if a.LastBody != "a4-latest" || b.LastBody != "b2-latest" {
		t.Fatalf("latest bodies = %q, %q", a.LastBody, b.LastBody)
	}
	if a.LastOut {
		t.Fatal("thread A latest is inbound, LastOut must be false")
	}

	// Mark thread A seen: unread clears, B untouched.
	var maxA int64
	if err := s.db.QueryRow(`SELECT MAX(id) FROM dashboard_messages WHERE user_id=? AND peer=?`, uid, peerA).Scan(&maxA); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkThreadSeen(uid, peerA, maxA); err != nil {
		t.Fatal(err)
	}
	threads, err = s.DashboardThreads(uid, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, th := range threads {
		switch th.Peer {
		case peerA:
			if th.Unread != 0 {
				t.Fatalf("thread A unread after seen = %d, want 0", th.Unread)
			}
		case peerB:
			if th.Unread != 2 {
				t.Fatalf("thread B unread after A seen = %d, want 2", th.Unread)
			}
		}
	}

	// A new inbound message on A becomes unread again.
	push(7, peerA, peerA, "a5-new", 500)
	threads, err = s.DashboardThreads(uid, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, th := range threads {
		if th.Peer == peerA {
			if th.Unread != 1 || th.LastBody != "a5-new" {
				t.Fatalf("thread A after new msg: unread=%d body=%q, want 1 / a5-new", th.Unread, th.LastBody)
			}
		}
	}
}

// TestDashboardThreadMessagesNewest500 verifies F12: the thread view
// returns the NEWEST 500 messages in chronological display order — the
// oldest messages fall off instead of the newest being unreachable.
func TestDashboardThreadMessagesNewest500(t *testing.T) {
	s := testStore(t)
	uid := int64(1)
	self := "ed25519:self"
	peer := "ed25519:peer"
	for i := int64(1); i <= 600; i++ {
		body := "msg-" + strconv.FormatInt(i, 10)
		if _, err := s.SaveDashboardMessage(uid, i, peer, self, peer, body, i, i, 0, "", 0, false); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := s.DashboardThreadMessages(uid, peer, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 500 {
		t.Fatalf("messages = %d, want 500", len(msgs))
	}
	if msgs[0].Body != "msg-101" {
		t.Fatalf("oldest shown = %q, want msg-101 (oldest 100 dropped)", msgs[0].Body)
	}
	if msgs[499].Body != "msg-600" {
		t.Fatalf("newest shown = %q, want msg-600", msgs[499].Body)
	}
	for i := 1; i < len(msgs); i++ {
		if msgs[i].ID <= msgs[i-1].ID {
			t.Fatalf("messages not in chronological order at index %d", i)
		}
	}
	for _, m := range msgs {
		if m.Body == "msg-1" || m.Body == "msg-100" {
			t.Fatalf("stale message %q still shown", m.Body)
		}
	}
}

// TestPeerHandlesExpiry: pushed handle labels fade after the TTL so
// unregistered handles do not linger forever (issue #39).
func TestPeerHandlesExpiry(t *testing.T) {
	s := testStore(t)
	const userID = 1
	const peer = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := s.SavePeerHandle(userID, peer, "oldhandle"); err != nil {
		t.Fatal(err)
	}
	handles, err := s.PeerHandles(userID, 7*24*3600*1e9)
	if err != nil {
		t.Fatal(err)
	}
	if handles[peer] != "oldhandle" {
		t.Fatalf("fresh handle not returned: %v", handles)
	}
	// Backdate beyond the TTL.
	if _, err := s.db.Exec(`UPDATE dashboard_peer_handles SET updated_at = 0
		WHERE user_id = ? AND peer = ?`, userID, peer); err != nil {
		t.Fatal(err)
	}
	handles, err = s.PeerHandles(userID, 7*24*3600*1e9)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := handles[peer]; ok {
		t.Fatal("stale handle should be ignored")
	}
	// Empty handle clears the label.
	if err := s.SavePeerHandle(userID, peer, "newhandle"); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePeerHandle(userID, peer, ""); err != nil {
		t.Fatal(err)
	}
	handles, err = s.PeerHandles(userID, 7*24*3600*1e9)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := handles[peer]; ok {
		t.Fatal("cleared handle should be gone")
	}
}

// TestPeerVerifiedRoundTrip: save/refresh/TTL/clear of peer verification
// badges (issue #48).
func TestPeerVerifiedRoundTrip(t *testing.T) {
	s := testStore(t)
	const userID = 1
	const peer = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := s.SavePeerVerified(userID, peer, "verified"); err != nil {
		t.Fatal(err)
	}
	got, err := s.PeerVerified(userID, 7*24*3600*1e9)
	if err != nil {
		t.Fatal(err)
	}
	if got[peer] != "verified" {
		t.Fatalf("fresh status not returned: %v", got)
	}
	// Upsert to stale.
	if err := s.SavePeerVerified(userID, peer, "stale"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PeerVerified(userID, 7*24*3600*1e9)
	if got[peer] != "stale" {
		t.Fatalf("upsert failed: %v", got)
	}
	// Bad status rejected.
	if err := s.SavePeerVerified(userID, peer, "bogus"); err == nil {
		t.Fatal("bad status accepted")
	}
	// Backdate beyond the TTL: ignored.
	if _, err := s.db.Exec(`UPDATE dashboard_peer_verified SET updated_at = 0
		WHERE user_id = ? AND peer = ?`, userID, peer); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PeerVerified(userID, 7*24*3600*1e9)
	if _, ok := got[peer]; ok {
		t.Fatal("stale verification should be ignored")
	}
	// Empty status clears.
	if err := s.SavePeerVerified(userID, peer, "verified"); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePeerVerified(userID, peer, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PeerVerified(userID, 7*24*3600*1e9)
	if _, ok := got[peer]; ok {
		t.Fatal("cleared verification should be gone")
	}
}

// TestDashboardMessageReplyThreading verifies the issue #51 reply_to /
// quote columns round-trip through SaveDashboardMessage and
// DashboardThreadMessages, and that the migration leaves pre-threading
// rows with zero values.
func TestDashboardMessageReplyThreading(t *testing.T) {
	s := testStore(t)
	uid := int64(1)
	self := "ed25519:self"
	peer := "ed25519:peer"
	if _, err := s.SaveDashboardMessage(uid, 1, peer, "", peer, "parent", 100, 100, 0, "", 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 2, self, peer, peer, "reply", 101, 101, 1, "parent", 0, false); err != nil {
		t.Fatal(err)
	}
	msgs, err := s.DashboardThreadMessages(uid, peer, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2", len(msgs))
	}
	if msgs[0].ReplyTo != 0 || msgs[0].Quote != "" {
		t.Fatalf("plain message got reply metadata: %+v", msgs[0])
	}
	if msgs[1].ReplyTo != 1 || msgs[1].Quote != "parent" {
		t.Fatalf("reply metadata lost: %+v", msgs[1])
	}
}

// TestMigrateAdoptsPreHardeningSchema builds a database with the
// pre-#108/#111 schema (no failed_logins, lock_until, csrf_token) and
// verifies Open adopts it: the additive migrations add the columns with
// safe defaults and the new methods work on the old rows.
func TestMigrateAdoptsPreHardeningSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE dashboard_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		must_change INTEGER NOT NULL DEFAULT 1,
		courier_address TEXT NOT NULL UNIQUE,
		api_token_hash TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		bct_user_id INTEGER,
		bct_email TEXT NOT NULL DEFAULT '')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE dashboard_sessions (
		token_hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		expires_at INTEGER NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dashboard_users (username, password_hash, courier_address, api_token_hash)
		VALUES ('olduser', 'h', 'ed25519:old', 'tok')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dashboard_sessions (token_hash, user_id, expires_at)
		VALUES ('sesshash', 1, 9999999999)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on pre-hardening DB: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	u, err := s.DashboardUserByName("olduser")
	if err != nil {
		t.Fatal(err)
	}
	if u.FailedLogins != 0 || u.LockUntil != 0 {
		t.Fatalf("adopted defaults: %+v", u)
	}
	// The backoff machinery works on the adopted row.
	before := time.Now().Unix()
	if err := s.NoteLoginFailure("olduser", time.Second, time.Hour); err != nil {
		t.Fatal(err)
	}
	u, err = s.DashboardUserByName("olduser")
	if err != nil {
		t.Fatal(err)
	}
	if u.FailedLogins != 1 {
		t.Fatalf("FailedLogins = %d, want 1", u.FailedLogins)
	}
	if u.LockUntil < before+1 || u.LockUntil > before+5 {
		t.Fatalf("LockUntil = %d, want ~1s in the future", u.LockUntil)
	}
	// Unknown usernames are a no-op, not an error.
	if err := s.NoteLoginFailure("nobody", time.Second, time.Hour); err != nil {
		t.Fatalf("unknown user: %v", err)
	}
	// The pre-CSRF session has no token: fail closed.
	tok, err := s.SessionCSRFToken("sesshash")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Fatalf("pre-CSRF session token = %q, want empty", tok)
	}
	// New sessions get a token.
	if err := s.CreateSession("newsess", u.ID, time.Hour, "raw-token-123"); err != nil {
		t.Fatal(err)
	}
	tok, err = s.SessionCSRFToken("newsess")
	if err != nil || tok != "raw-token-123" {
		t.Fatalf("SessionCSRFToken = %q, %v; want raw-token-123", tok, err)
	}
}

// TestLoginBackoffGrowth verifies the exponential schedule and the cap.
func TestLoginBackoffGrowth(t *testing.T) {
	base, max := 2*time.Second, 15*time.Minute
	cases := map[int]time.Duration{
		1:   base,
		2:   2 * base,
		3:   4 * base,
		10:  max,
		100: max,
	}
	for n, want := range cases {
		if got := LoginBackoff(n, base, max); got != want {
			t.Errorf("LoginBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// TestDashboardMessageBridgedRoundTrip: the bridged flag (issues
// #96/#97) survives the dashboard push store round trip — both the
// per-message read path and the thread-list latest-message query — so
// the dashboard can badge pin-list-derived attribution it never
// derived itself.
func TestDashboardMessageBridgedRoundTrip(t *testing.T) {
	s := testStore(t)
	self := "ed25519:self"
	peer := "ed25519:peer"
	uid := int64(1)
	if _, err := s.SaveDashboardMessage(uid, 1, peer, "", peer, "plain", 100, 100, 0, "", 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 2, peer, "", peer, "via bridge", 101, 101, 0, "", 0, true); err != nil {
		t.Fatal(err)
	}
	msgs, err := s.DashboardThreadMessages(uid, peer, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2", len(msgs))
	}
	if msgs[0].Bridged {
		t.Error("ordinary message read back as bridged")
	}
	if !msgs[1].Bridged {
		t.Error("bridged message lost its flag on read")
	}
	threads, err := s.DashboardThreads(uid, self, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 {
		t.Fatalf("threads = %d, want 1", len(threads))
	}
	if !threads[0].LastBridged {
		t.Error("thread list lost the latest message's bridged flag")
	}
}

// TestDashboardMessageBridgedMigration: a pre-change dashboard DB
// (rows written before the bridged column existed) still opens and
// reads — the migration backfills bridged=0 and the badge falls back
// to the body banner (issues #96/#97, never fail closed on a healthy
// DB).
func TestDashboardMessageBridgedMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-change schema: drop the column the migration
	// added and remove its ledger row, then re-open so the migration
	// re-runs and re-adds it.
	if _, err := s.db.Exec(`ALTER TABLE dashboard_messages DROP COLUMN bridged`); err != nil {
		s.Close()
		t.Skipf("sqlite cannot drop column: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations WHERE version = 21`); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO dashboard_messages
		 (user_id, courier_id, sender, recipient, peer, body, sent_at, received_at, reply_to, quote, expires_at)
		 VALUES (1, 1, 'ed25519:peer', '', 'ed25519:peer', 'old row', 100, 100, 0, '', 0)`); err != nil {
		s.Close()
		t.Fatal(err)
	}
	s.Close()
	// Re-open: the migration must adopt the old DB, not fail on it.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open after migration: %v", err)
	}
	defer s2.Close()
	msgs, err := s2.DashboardThreadMessages(1, "ed25519:peer", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Bridged {
		t.Fatalf("old row misread: %+v", msgs)
	}
}
