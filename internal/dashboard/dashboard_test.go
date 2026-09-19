package dashboard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

var b64 = base64.RawURLEncoding

func testServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{store: st}
}

func testIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// register creates a dashboard user via the API and returns the API token.
func register(t *testing.T, srv *Server, username, password string, id *crypto.Identity) string {
	t.Helper()
	addr := crypto.FormatAddress(id.EdPub[:])
	sig := id.Sign(envelope.DashboardRegister(username, id.EdPub[:]))
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
		"address":  addr,
		"sig":      b64.EncodeToString(sig),
	})
	req := httptest.NewRequest("POST", "/v1/dashboard/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.APIToken == "" {
		t.Fatalf("register: bad response: %s", rec.Body.String())
	}
	return out.APIToken
}

func TestRegisterAndPush(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	token := register(t, srv, "lane", "temporary-password-123", id)

	// Push two messages with the token.
	payload, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"courier_id": 1, "from": crypto.FormatAddress(id.EdPub[:]), "body": "hello", "sent_at": 100, "received_at": 101},
		{"courier_id": 2, "from": crypto.FormatAddress(id.EdPub[:]), "body": "world", "sent_at": 102, "received_at": 103},
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
		t.Fatalf("push stored = %d, want 2", out.Stored)
	}

	// Re-push is idempotent (dedupe by courier_id).
	req2 := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("re-push: got %d", rec2.Code)
	}

	u, err := srv.store.DashboardUserByName("lane")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := srv.store.DashboardMessages(u.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Body != "world" {
		t.Fatalf("messages = %+v", msgs)
	}
}

func TestRegisterBadSignature(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	other := testIdentity(t)
	addr := crypto.FormatAddress(id.EdPub[:])
	// Signed by a different identity than the claimed address.
	sig := other.Sign(envelope.DashboardRegister("lane", id.EdPub[:]))
	body, _ := json.Marshal(map[string]string{
		"username": "lane", "password": "temporary-password-123",
		"address": addr, "sig": b64.EncodeToString(sig),
	})
	req := httptest.NewRequest("POST", "/v1/dashboard/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged registration: got %d, want 400", rec.Code)
	}
}

func TestRegisterDuplicateUsername(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	id2 := testIdentity(t)
	addr := crypto.FormatAddress(id2.EdPub[:])
	sig := id2.Sign(envelope.DashboardRegister("lane", id2.EdPub[:]))
	body, _ := json.Marshal(map[string]string{
		"username": "lane", "password": "another-temporary-pw",
		"address": addr, "sig": b64.EncodeToString(sig),
	})
	req := httptest.NewRequest("POST", "/v1/dashboard/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate username: got %d, want 409", rec.Code)
	}
}

func TestPushBadToken(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/v1/dashboard/push", strings.NewReader(`{"messages":[]}`))
	req.Header.Set("Authorization", "Bearer bogus")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", rec.Code)
	}
}

// login performs a form login and returns the session cookie value.
func login(t *testing.T, srv *Server, username, password string) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: got %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("login: no session cookie")
	return nil
}

func get(t *testing.T, srv *Server, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestLoginForcesPasswordChange(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	token := register(t, srv, "lane", "temporary-password-123", id)

	// Push a message so /app has something to show.
	payload, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"courier_id": 7, "from": crypto.FormatAddress(id.EdPub[:]), "body": "hi lane", "sent_at": 1, "received_at": 2},
	}})
	req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("push: %d", rec.Code)
	}

	cookie := login(t, srv, "lane", "temporary-password-123")

	// First login must force a password change: /app redirects.
	if r := get(t, srv, "/app", cookie); r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/change-password" {
		t.Fatalf("/app: got %d -> %q, want redirect to /change-password", r.Code, r.Header().Get("Location"))
	}

	// Change the password.
	form := url.Values{"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"}}
	req = httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/app" {
		t.Fatalf("change-password: got %d -> %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}

	// Now /app renders the pushed message.
	r := get(t, srv, "/app", cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("/app after change: got %d", r.Code)
	}
	if !strings.Contains(r.Body.String(), "hi lane") {
		t.Fatalf("/app does not show the pushed message")
	}

	// Old temp password no longer works.
	form = url.Values{"username": {"lane"}, "password": {"temporary-password-123"}}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK { // re-rendered login page with error
		t.Fatalf("old password login: got %d, want 200 (rejected)", rec.Code)
	}
}

func TestLoginBadPassword(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	form := url.Values{"username": {"lane"}, "password": {"wrong"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bad login: got %d, want 200 with error", rec.Code)
	}
	if c := rec.Result().Cookies(); len(c) != 0 {
		t.Fatalf("bad login set a session cookie")
	}
}
