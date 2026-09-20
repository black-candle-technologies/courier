package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// TestPushReplyThreading pushes messages carrying reply metadata and
// verifies it is stored and rendered as a quote block in the thread
// view. The dashboard never decrypts: the agent reports, the dashboard
// displays.
func TestPushReplyThreading(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	addr := crypto.FormatAddress(id.EdPub[:])
	token := register(t, srv, "lane", "temporary-password-123", id)

	peer := crypto.FormatAddress(testIdentity(t).EdPub[:])
	payload, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"courier_id": 1, "from": peer, "body": "want to sync at 3?", "sent_at": 100, "received_at": 101},
		{"courier_id": 2, "from": addr, "to": peer, "body": "yes, 3 works",
			"sent_at": 102, "received_at": 102, "reply_to": 1, "quote": "want to sync at 3?"},
		// Malformed threading metadata must not lose the message:
		// negative ids clamp to 0, overlong quotes truncate.
		{"courier_id": 3, "from": peer, "body": "great", "sent_at": 103, "received_at": 104,
			"reply_to": -5, "quote": strings.Repeat("q", 5000)},
	}})
	req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d: %s", rec.Code, rec.Body.String())
	}

	u, err := srv.store.DashboardUserByName("lane")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := srv.store.DashboardThreadMessages(u.ID, peer, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("thread messages = %d, want 3", len(msgs))
	}
	for _, m := range msgs {
		switch m.CourierID {
		case 1:
			if m.ReplyTo != 0 || m.Quote != "" {
				t.Fatalf("plain message got reply metadata: %+v", m)
			}
		case 2:
			if m.ReplyTo != 1 || m.Quote != "want to sync at 3?" {
				t.Fatalf("reply metadata not stored: %+v", m)
			}
		case 3:
			if m.ReplyTo != 0 {
				t.Fatalf("negative reply_to not clamped: %+v", m)
			}
			if len(m.Quote) != 4096 {
				t.Fatalf("quote not truncated: len %d", len(m.Quote))
			}
		}
	}

	// The thread view renders the quote block (HTML-escaped).
	cookie := login(t, srv, "lane", "temporary-password-123")
	// Password must be changed first; do it, then re-login.
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
	req = httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change-password: <redacted>: %s", rec.Body.String())
	}
	cookie = login(t, srv, "lane", "a-new-password-123")
	trec := get(t, srv, "/app/thread?with="+url.QueryEscape(peer), cookie)
	if trec.Code != http.StatusOK {
		t.Fatalf("thread view: got %d", trec.Code)
	}
	html := trec.Body.String()
	if !strings.Contains(html, "in reply to #1") {
		t.Fatalf("thread view missing reply reference:\n%s", html)
	}
	if !strings.Contains(html, "want to sync at 3?") {
		t.Fatalf("thread view missing quote:\n%s", html)
	}
}
