// Contact-discovery dashboard tests (issue #39): peer handle labels
// and identicons.
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

// pushWithToken pushes messages+handles for a fresh user and returns the
// user id and a logged-in session cookie.
func pushWithToken(t *testing.T, srv *Server, username string, payload map[string]any) *http.Cookie {
	t.Helper()
	id := testIdentity(t)
	token := register(t, srv, username, "temporary-password-123", id)
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("push: got %d: %s", rec.Code, rec.Body.String())
	}
	// Log in (forced password change first).
	creds := login(t, srv, username, "temporary-password-123")
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
	rec2 := postChangePassword(t, srv, creds, form)
	if rec2.Code != 303 {
		t.Fatalf("change-password: got %d: %s", rec2.Code, rec2.Body.String())
	}
	for _, c := range rec2.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no fresh session cookie after password change")
	return nil
}

func TestPushPeerHandles(t *testing.T) {
	srv := testServer(t)
	peerAddr := crypto.FormatAddress(testIdentity(t).EdPub[:])
	cookie := pushWithToken(t, srv, "handleuser", map[string]any{
		"messages": []map[string]any{
			{"courier_id": 1, "from": peerAddr, "body": "hello", "sent_at": 100, "received_at": 101},
		},
		"handles": map[string]string{
			peerAddr: "peerhandle",
		},
	})

	u, err := srv.store.DashboardUserByName("handleuser")
	if err != nil {
		t.Fatal(err)
	}
	threads, err := srv.store.DashboardThreads(u.ID, u.CourierAddress, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 {
		t.Fatalf("want 1 thread, got %+v", threads)
	}
	if threads[0].Handle != "peerhandle" {
		t.Fatalf("thread handle = %q, want %q", threads[0].Handle, "peerhandle")
	}

	// The /app thread list shows the handle and an identicon.
	rec := get(t, srv, "/app", cookie)
	if rec.Code != 200 {
		t.Fatalf("/app: got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "@peerhandle") {
		t.Fatalf("thread list does not show @handle:\n%.600s", body)
	}
	if !strings.Contains(body, `class="identicon"`) {
		t.Fatal("thread list does not render identicons")
	}

	// The thread view header shows the handle too.
	rec = get(t, srv, "/app/thread?with="+url.QueryEscape(peerAddr), cookie)
	if rec.Code != 200 {
		t.Fatalf("/app/thread: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "@peerhandle") {
		t.Fatal("thread view does not show @handle")
	}
}

func TestPushPeerHandlesRejectsBadInput(t *testing.T) {
	srv := testServer(t)
	peerAddr := crypto.FormatAddress(testIdentity(t).EdPub[:])
	otherAddr := crypto.FormatAddress(testIdentity(t).EdPub[:])
	pushWithToken(t, srv, "badhandleuser", map[string]any{
		"messages": []map[string]any{
			{"courier_id": 1, "from": peerAddr, "body": "hello", "sent_at": 100, "received_at": 101},
		},
		"handles": map[string]string{
			"not-an-address": "somehandle", // invalid peer: skipped
			peerAddr:         "UPPERCASE",  // normalized to lowercase
			otherAddr:        "has space",  // invalid handle: skipped
		},
	})
	u, _ := srv.store.DashboardUserByName("badhandleuser")
	handles, err := srv.store.PeerHandles(u.ID, 7*24*3600*1e9)
	if err != nil {
		t.Fatal(err)
	}
	if len(handles) != 1 || handles[peerAddr] != "uppercase" {
		t.Fatalf("handles = %v, want only the normalized entry", handles)
	}
}

func TestIdenticonDeterministic(t *testing.T) {
	a := "ed25519:hsJUdqOA-Mv6TsJJ3-PMxs2_zrF4ibULuTcrAVXHqSQ"
	b := "ed25519:lFiSei_xNaaXcWxl5bmHIxTjRENFo9K_0LpfzeZ1TAc"
	ia1, ia2 := string(identicon(a)), string(identicon(a))
	ib := string(identicon(b))
	if ia1 != ia2 {
		t.Fatal("identicon not deterministic")
	}
	if ia1 == ib {
		t.Fatal("different addresses produced identical identicons")
	}
	for _, s := range []string{ia1, ib} {
		if !strings.HasPrefix(s, "<svg") || !strings.HasSuffix(s, "</svg>") {
			t.Fatalf("not an svg: %.60s", s)
		}
		if !strings.Contains(s, "<rect") {
			t.Fatal("identicon has no cells")
		}
	}
	// The center cell (x=2,y=2) is always filled.
	if !strings.Contains(ia1, `<rect x="2" y="2"`) {
		t.Fatal("center cell missing")
	}
	// Degenerate inputs still render.
	for _, addr := range []string{"ed25519:AAAA", "x", ""} {
		if s := string(identicon(addr)); !strings.HasPrefix(s, "<svg") {
			t.Fatalf("bad identicon for %q", addr)
		}
	}
}
