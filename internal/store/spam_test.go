package store

import (
	"database/sql"
	"testing"
)

// TestSpamReportsDistinctCountAndDecay covers the metadata-only
// throttle's counting rules: only distinct reporters count, duplicate
// reports are idempotent, and reports age out of the window (decay).
func TestSpamReportsDistinctCountAndDecay(t *testing.T) {
	s := testStore(t)

	if err := s.RecordSpamReport("alice", "bob", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSpamReport("alice", "carol", 2); err != nil {
		t.Fatal(err)
	}
	// Same reporter flags another of alice's messages: still one
	// reporter — one angry recipient cannot throttle a sender alone.
	if err := s.RecordSpamReport("alice", "bob", 3); err != nil {
		t.Fatal(err)
	}
	n, err := s.DistinctReporterCount("alice", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("want 2 distinct reporters, got %d", n)
	}

	// Age every report beyond the window: the count decays to zero.
	if _, err := s.db.Exec(`UPDATE spam_reports SET reported_at = strftime('%s','now') - 7200`); err != nil {
		t.Fatal(err)
	}
	n, err = s.DistinctReporterCount("alice", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("want 0 after reports decay out of the window, got %d", n)
	}

	// A fresh report counts again: decay is not a pardon, it is a
	// sliding window.
	if err := s.RecordSpamReport("alice", "dave", 4); err != nil {
		t.Fatal(err)
	}
	n, err = s.DistinctReporterCount("alice", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 fresh reporter, got %d", n)
	}

	// Other senders are unaffected.
	n, err = s.DistinctReporterCount("mallory", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("want 0 for unreported sender, got %d", n)
	}
}

// TestEnvelopeByID covers the lookup the relay uses to authorize spam
// reports: only the envelope's recipient may report it.
func TestEnvelopeByID(t *testing.T) {
	s := testStore(t)
	id, stored, err := s.Save(&Envelope{
		To: "ed25519:recipient", From: "ed25519:sender",
		Eph: "e", Nonce: "n", Ct: "c", SentAt: 123, Sig: "s",
	})
	if err != nil || !stored {
		t.Fatalf("save: %v, stored=%v", err, stored)
	}
	e, err := s.EnvelopeByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.To != "ed25519:recipient" || e.From != "ed25519:sender" {
		t.Fatalf("wrong envelope: %+v", e)
	}
	if _, err := s.EnvelopeByID(id + 999); err != sql.ErrNoRows {
		t.Fatalf("unknown id: want sql.ErrNoRows, got %v", err)
	}
}
