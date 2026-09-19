package store

import (
	"database/sql"
	"path/filepath"
	"testing"

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
