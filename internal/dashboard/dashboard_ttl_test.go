// Tests for disappearing-message dashboard push handling (issue #53).
package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// TestPushDisappearingMessages: pushes with expires_at are stored with
// the expiry, already-expired and negative-expiry pushes are skipped,
// and the push-time sweep deletes rows that expired since.
func TestPushDisappearingMessages(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	addr := crypto.FormatAddress(id.EdPub[:])
	testPW := "correct horse battery staple"
	token := register(t, srv, "ttluser", testPW, id)
	now := time.Now().Unix()

	payload, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"courier_id": 1, "from": addr, "body": "immortal", "sent_at": now, "received_at": now},
		{"courier_id": 2, "from": addr, "body": "fading", "sent_at": now, "received_at": now, "expires_at": now + 3600},
		{"courier_id": 3, "from": addr, "body": "already gone", "sent_at": now - 100, "received_at": now - 100, "expires_at": now - 10},
		{"courier_id": 4, "from": addr, "body": "negative", "sent_at": now, "received_at": now, "expires_at": -5},
	}})
	req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Stored int `json:"stored"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Stored != 2 {
		t.Fatalf("push stored = %d, want 2 (expired + negative skipped)", out.Stored)
	}

	u, err := srv.store.DashboardUserByName("ttluser")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := srv.store.DashboardThreadMessages(u.ID, addr, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("thread messages = %d, want 2", len(msgs))
	}
	if msgs[1].Body != "fading" || msgs[1].ExpiresAt != now+3600 {
		t.Errorf("expiring message wrong: %+v", msgs[1])
	}

	// A row that is already expired at rest (e.g. expired between
	// pushes) is filtered from reads, then deleted by the next push's
	// sweep. SaveDashboardMessage itself does not filter — only the
	// push handler and read paths do.
	if _, err := srv.store.SaveDashboardMessage(u.ID, 9, addr, "", addr, "doomed", now-100, now-100, 0, "", now-10, false); err != nil {
		t.Fatal(err)
	}
	msgs, err = srv.store.DashboardThreadMessages(u.ID, addr, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Body == "doomed" {
			t.Error("expired row still visible in thread")
		}
	}
	// Next push sweeps it away: a follow-up manual prune must find
	// nothing left to delete.
	payload2, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"courier_id": 10, "from": addr, "body": "after", "sent_at": now, "received_at": now},
	}})
	req2 := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload2))
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("push2: got %d", rec2.Code)
	}
	n, err := srv.store.PruneExpiredDashboardMessages()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("sweep left %d expired rows; push should have deleted them", n)
	}
}

// TestUntilRendersCountdown checks the template countdown helper.
// The +2s padding defeats unix-second truncation (the helper floors).
func TestUntilRendersCountdown(t *testing.T) {
	now := time.Now()
	if got := until(now.Add(5*time.Minute + 2*time.Second).Unix()); got != "in 5m" {
		t.Errorf("until(+5m) = %q", got)
	}
	if got := until(now.Add(2*time.Hour + 2*time.Second).Unix()); got != "in 2h" {
		t.Errorf("until(+2h) = %q", got)
	}
	if got := until(now.Add(-time.Minute).Unix()); got != "expired" {
		t.Errorf("until(-1m) = %q", got)
	}
	if got := until(now.Add(30 * time.Second).Unix()); got != "in under a minute" {
		t.Errorf("until(+30s) = %q", got)
	}
}
