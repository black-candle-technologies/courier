// Tests for disappearing dashboard messages (issue #53).
package store

import (
	"testing"
	"time"
)

func testDashboardUser(t *testing.T, s *Store) int64 {
	t.Helper()
	res, err := s.db.Exec(
		`INSERT INTO dashboard_users(username, password_hash, courier_address, api_token_hash) VALUES(?,?,?,?)`,
		"ttluser", "x", "ed25519:self", "tokhash")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

func TestDashboardMessageExpiryReadFilter(t *testing.T) {
	s := testStore(t)
	uid := testDashboardUser(t, s)
	self, peer := "ed25519:self", "ed25519:peer"
	now := time.Now().Unix()

	// One immortal, one expiring in the future, one already expired.
	if _, err := s.SaveDashboardMessage(uid, 1, peer, self, peer, "immortal", now, now, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 2, peer, self, peer, "fading", now, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 3, peer, self, peer, "gone", now, now, now-10); err != nil {
		t.Fatal(err)
	}

	threads, err := s.DashboardThreads(uid, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 {
		t.Fatalf("threads = %d, want 1", len(threads))
	}
	if threads[0].Count != 2 {
		t.Errorf("thread count = %d, want 2 (expired excluded)", threads[0].Count)
	}
	if threads[0].LastBody != "fading" {
		t.Errorf("last body = %q, want %q", threads[0].LastBody, "fading")
	}

	msgs, err := s.DashboardThreadMessages(uid, peer, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("thread messages = %d, want 2", len(msgs))
	}
	if msgs[1].ExpiresAt != now+3600 {
		t.Errorf("ExpiresAt = %d, want %d", msgs[1].ExpiresAt, now+3600)
	}
	if msgs[0].ExpiresAt != 0 {
		t.Errorf("immortal ExpiresAt = %d, want 0", msgs[0].ExpiresAt)
	}

	peers, err := s.SearchThreadPeers(uid, "gone")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Errorf("expired message still searchable: %v", peers)
	}
	peers, err = s.SearchThreadPeers(uid, "fading")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Errorf("live expiring message not searchable: %v", peers)
	}
}

func TestPruneExpiredDashboardMessages(t *testing.T) {
	s := testStore(t)
	uid := testDashboardUser(t, s)
	self, peer := "ed25519:self", "ed25519:peer"
	now := time.Now().Unix()

	if _, err := s.SaveDashboardMessage(uid, 1, peer, self, peer, "gone1", now, now, now-10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 2, peer, self, peer, "gone2", now, now, now-1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 3, peer, self, peer, "live", now, now, now+3600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDashboardMessage(uid, 4, peer, self, peer, "immortal", now, now, 0); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneExpiredDashboardMessages()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("pruned = %d, want 2", n)
	}
	msgs, err := s.DashboardThreadMessages(uid, peer, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("remaining = %d, want 2", len(msgs))
	}
	// Second sweep is a no-op.
	n, err = s.PruneExpiredDashboardMessages()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second prune = %d, want 0", n)
	}
}
