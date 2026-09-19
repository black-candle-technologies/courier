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
