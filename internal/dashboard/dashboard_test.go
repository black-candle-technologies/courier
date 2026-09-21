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

	"github.com/black-candle-technologies/courier/internal/bridge"
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
	addr := crypto.FormatAddress(id.EdPub[:])
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
	threads, err := srv.store.DashboardThreads(u.ID, addr, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Both pushed messages have no "to", so each thread's peer is the sender
	// (here the user's own address — a self-thread in this synthetic test).
	if len(threads) != 1 || threads[0].Count != 2 || threads[0].LastBody != "world" {
		t.Fatalf("threads = %+v", threads)
	}
}

// TestThreads groups inbound and outbound messages into per-counterparty
// threads and renders the conversation oldest-first.
func TestThreads(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	other := testIdentity(t)
	me := crypto.FormatAddress(id.EdPub[:])
	them := crypto.FormatAddress(other.EdPub[:])
	token := register(t, srv, "lane", "temporary-password-123", id)

	push := func(msgs ...map[string]any) {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"messages": msgs})
		req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("push: got %d: %s", rec.Code, rec.Body.String())
		}
	}
	// Inbound from them, outbound to them, inbound from a third party.
	push(
		map[string]any{"courier_id": 1, "from": them, "body": "hey", "sent_at": 100, "received_at": 101},
		map[string]any{"courier_id": 2, "from": me, "to": them, "body": "hi back", "sent_at": 102, "received_at": 102},
	)
	third := testIdentity(t)
	push(map[string]any{"courier_id": 3, "from": crypto.FormatAddress(third.EdPub[:]), "body": "other person", "sent_at": 103, "received_at": 104})

	// An outbound message forged from someone else's address is skipped.
	push(map[string]any{"courier_id": 4, "from": them, "to": me, "body": "forged", "sent_at": 105, "received_at": 105})

	u, err := srv.store.DashboardUserByName("lane")
	if err != nil {
		t.Fatal(err)
	}
	threads, err := srv.store.DashboardThreads(u.ID, me, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 2 {
		t.Fatalf("threads = %+v, want 2", threads)
	}
	// Most recent thread first: the third party (ts 104) before them (ts 102).
	if threads[0].Peer != crypto.FormatAddress(third.EdPub[:]) || threads[1].Peer != them {
		t.Fatalf("thread order/peers = %+v", threads)
	}
	if threads[1].Count != 2 || !threads[1].LastOut || threads[1].LastBody != "hi back" {
		t.Fatalf("thread with them = %+v", threads[1])
	}

	msgs, err := srv.store.DashboardThreadMessages(u.ID, them, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Body != "hey" || msgs[1].Body != "hi back" {
		t.Fatalf("thread messages = %+v", msgs)
	}
	if msgs[0].Sender != them || msgs[1].Recipient != them {
		t.Fatalf("directions wrong: %+v", msgs)
	}

	// The /app thread list and /app/thread pages render.
	cookie := login(t, srv, "lane", "temporary-password-123")
	// Password must be changed first; do it, then re-login.
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change-password: got %d", rec.Code)
	}
	cookie = login(t, srv, "lane", "a-new-password-123")
	rec = get(t, srv, "/app", cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hi back") {
		t.Fatalf("/app: got %d, body missing thread preview", rec.Code)
	}
	rec = get(t, srv, "/app/thread?with="+url.QueryEscape(them), cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hey") {
		t.Fatalf("/app/thread: got %d", rec.Code)
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

	// Change the password. F6: the change revokes all sessions and issues
	// a fresh one, so pick up the new cookie.
	rec = postChangePassword(t, srv, cookie, url.Values{"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/app" {
		t.Fatalf("change-password: got %d -> %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	cookie = sessionCookieFromRec(t, rec)

	// Now /app renders the pushed message.
	r := get(t, srv, "/app", cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("/app after change: got %d", r.Code)
	}
	if !strings.Contains(r.Body.String(), "hi lane") {
		t.Fatalf("/app does not show the pushed message")
	}

	// Old temp password no longer works.
	form := url.Values{"username": {"lane"}, "password": {"temporary-password-123"}}
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

func TestUnreadBadges(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	peerID := testIdentity(t)
	peer := crypto.FormatAddress(peerID.EdPub[:])
	self := crypto.FormatAddress(id.EdPub[:])
	token := register(t, srv, "lane", "temporary-password-123", id)

	push := func(msgs []map[string]any) {
		payload, _ := json.Marshal(map[string]any{"messages": msgs})
		req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("push: got %d", rec.Code)
		}
	}
	// Two inbound from the peer, one outbound from the user.
	push([]map[string]any{
		{"courier_id": 1, "from": peer, "body": "one", "sent_at": 100, "received_at": 101},
		{"courier_id": 2, "from": peer, "body": "two", "sent_at": 102, "received_at": 103},
		{"courier_id": 3, "from": self, "to": peer, "body": "three", "sent_at": 104, "received_at": 105},
	})

	u, err := srv.store.DashboardUserByName("lane")
	if err != nil {
		t.Fatal(err)
	}
	threads, err := srv.store.DashboardThreads(u.ID, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 || threads[0].Unread != 2 {
		t.Fatalf("unread before open = %+v, want 2 inbound unread", threads)
	}

	// Open the thread (login first: forced password change). F6: the
	// password change revokes the login session, so use the fresh cookie.
	cookie := sessionCookieFromRec(t, postChangePassword(t, srv,
		login(t, srv, "lane", "temporary-password-123"),
		url.Values{"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"}}))

	if r := get(t, srv, "/app/thread?with="+url.QueryEscape(peer), cookie); r.Code != http.StatusOK {
		t.Fatalf("open thread: got %d", r.Code)
	}
	threads, _ = srv.store.DashboardThreads(u.ID, self, 100)
	if threads[0].Unread != 0 {
		t.Fatalf("unread after open = %d, want 0", threads[0].Unread)
	}
	// The /app HTML should show the unread badge before opening...
	// (verified via store above; HTML check on a fresh thread below)
}

func TestSearch(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	a := crypto.FormatAddress(testIdentity(t).EdPub[:])
	b := crypto.FormatAddress(testIdentity(t).EdPub[:])
	token := register(t, srv, "lane", "temporary-password-123", id)

	payload, _ := json.Marshal(map[string]any{"messages": []map[string]any{
		{"courier_id": 1, "from": a, "body": "hello world", "sent_at": 100, "received_at": 101},
		{"courier_id": 2, "from": b, "body": "goodbye moon", "sent_at": 102, "received_at": 103},
	}})
	req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("push: got %d", rec.Code)
	}

	cookie := login(t, srv, "lane", "temporary-password-123")
	// F6: the password change revokes the login session; use the fresh cookie.
	cookie = sessionCookieFromRec(t, postChangePassword(t, srv, cookie,
		url.Values{"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"}}))

	r := get(t, srv, "/app?q=hello", cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("search: got %d", r.Code)
	}
	body := r.Body.String()
	if !strings.Contains(body, "hello world") {
		t.Fatalf("search result missing the matching thread")
	}
	if strings.Contains(body, "goodbye moon") {
		t.Fatalf("search result contains a non-matching thread")
	}
	// A LIKE metacharacter must not break the query.
	if r := get(t, srv, "/app?q=%25", cookie); r.Code != http.StatusOK {
		t.Fatalf("search with %%: got %d", r.Code)
	}
}

func TestPWAAssets(t *testing.T) {
	srv := testServer(t)
	h := srv.Routes()

	// Manifest: installable, correct content type, valid JSON.
	req := httptest.NewRequest("GET", "/manifest.webmanifest", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest: got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/manifest+json" {
		t.Fatalf("manifest content type = %q", ct)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	for _, k := range []string{"name", "start_url", "display", "icons"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("manifest missing %q", k)
		}
	}

	// Service worker: must contain a fetch handler for installability.
	req = httptest.NewRequest("GET", "/sw.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sw: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "addEventListener('fetch'") {
		t.Fatalf("service worker has no fetch handler")
	}

	// Icons: PNG magic bytes, non-trivial size.
	for _, p := range []string{"/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"} {
		req = httptest.NewRequest("GET", p, nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
			t.Fatalf("%s content type = %q", p, ct)
		}
		b := rec.Body.Bytes()
		if len(b) < 500 || string(b[:8]) != "\x89PNG\r\n\x1a\n" {
			t.Fatalf("%s: not a plausible PNG (%d bytes)", p, len(b))
		}
	}

	// The app shell links the manifest and carries the install button.
	id := testIdentity(t)
	register(t, srv, "lane", "temporary-password-123", id)
	// F6: the password change revokes the login session; use the fresh cookie.
	cookie := sessionCookieFromRec(t, postChangePassword(t, srv,
		login(t, srv, "lane", "temporary-password-123"),
		url.Values{"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"}}))

	r := get(t, srv, "/app", cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("/app: got %d", r.Code)
	}
	html := r.Body.String()
	if !strings.Contains(html, `rel="manifest"`) {
		t.Fatalf("/app missing manifest link")
	}
	if !strings.Contains(html, `id="installBtn"`) {
		t.Fatalf("/app missing install button")
	}
}

func registerRaw(t *testing.T, srv *Server, username, password string, id *crypto.Identity) *httptest.ResponseRecorder {
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
	return rec
}

// TestRegisterPasswordByteLimit enforces the 72-byte bcrypt limit at
// registration (F15). bcrypt errors past 72 bytes, so the server must
// reject with a clear message instead of failing at hash time.
func TestRegisterPasswordByteLimit(t *testing.T) {
	srv := testServer(t)

	// 73 bytes: rejected.
	if rec := registerRaw(t, srv, "lane", strings.Repeat("x", 73), testIdentity(t)); rec.Code != http.StatusBadRequest {
		t.Fatalf("73-byte password: got %d, want 400", rec.Code)
	} else if !strings.Contains(rec.Body.String(), "72") {
		t.Fatalf("no byte-limit message: %s", rec.Body.String())
	}
	// Exactly 72 bytes: accepted (proves the boundary via the helper's
	// 201 assertion). Multibyte rune that pushes past 72 bytes: rejected
	// (the limit is bytes, not runes).
	register(t, srv, "lane72", strings.Repeat("x", 72), testIdentity(t))
	if rec := registerRaw(t, srv, "laneuni", strings.Repeat("é", 37), testIdentity(t)); rec.Code != http.StatusBadRequest {
		t.Fatalf("37 multibyte runes (74 bytes): got %d, want 400", rec.Code)
	}
	register(t, srv, "laneuniok", strings.Repeat("é", 36), testIdentity(t)) // 72 bytes
}

// TestChangePasswordByteLimit enforces the 72-byte bcrypt limit on the
// change-password form (F15).
func TestChangePasswordByteLimit(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	cookie := login(t, srv, "lane", "temporary-password-123")

	long := strings.Repeat("y", 73)
	form := url.Values{"password": {long}, "confirm": {long}}
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("73-byte password: got %d, want 200 (form re-rendered with error)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "72 bytes") {
		t.Fatalf("no byte-limit error in response")
	}
	// The password must be unchanged: the old temp password still logs in.
	login(t, srv, "lane", "temporary-password-123")
}

// postChangePassword submits the change-password form with an optional
// session cookie, returning the recorder.
func postChangePassword(t *testing.T, srv *Server, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// sessionCookieFromRec extracts the session cookie a response set.
func sessionCookieFromRec(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie in response")
	return nil
}

// TestChangePasswordRevokesSessions verifies F6: any successful password
// change revokes ALL existing sessions atomically and issues a fresh one
// for the requester.
func TestChangePasswordRevokesSessions(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	cookieA := login(t, srv, "lane", "temporary-password-123")
	cookieB := login(t, srv, "lane", "temporary-password-123") // second session

	// Forced change (the temp password is the credential here): no
	// current-password check, but sessions must still be revoked.
	rec := postChangePassword(t, srv, cookieA, url.Values{
		"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change-password: got %d: %s", rec.Code, rec.Body.String())
	}
	fresh := sessionCookieFromRec(t, rec)

	// Both pre-existing sessions are dead.
	for i, c := range []*http.Cookie{cookieA, cookieB} {
		r := get(t, srv, "/app", c)
		if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/" {
			t.Fatalf("old session %d still valid: got %d -> %q", i, r.Code, r.Header().Get("Location"))
		}
	}
	// The fresh session keeps the requester logged in.
	if r := get(t, srv, "/app", fresh); r.Code != http.StatusOK {
		t.Fatalf("fresh session: got %d, want 200", r.Code)
	}
	// The old temp password no longer logs in.
	form := url.Values{"username": {"lane"}, "password": {"temporary-password-123"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	lrec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(lrec, req)
	if lrec.Code != http.StatusOK {
		t.Fatalf("old password login: got %d, want 200 (rejected)", lrec.Code)
	}
}

// TestChangePasswordRequiresCurrent verifies F6: non-forced changes
// (must_change=0) require the current password.
func TestChangePasswordRequiresCurrent(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	cookie := login(t, srv, "lane", "temporary-password-123")
	// Forced change first, so must_change=0 afterwards.
	rec := postChangePassword(t, srv, cookie, url.Values{
		"password": {"second-password-1"}, "confirm": {"second-password-1"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("forced change: got %d", rec.Code)
	}
	cookie = sessionCookieFromRec(t, rec)

	// Missing current password: rejected.
	rec = postChangePassword(t, srv, cookie, url.Values{
		"password": {"third-password-1"}, "confirm": {"third-password-1"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Current password is incorrect") {
		t.Fatalf("missing current: got %d, want 200 with error", rec.Code)
	}
	// Wrong current password: rejected.
	rec = postChangePassword(t, srv, cookie, url.Values{
		"current": {"not-the-password"}, "password": {"third-password-1"}, "confirm": {"third-password-1"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Current password is incorrect") {
		t.Fatalf("wrong current: got %d, want 200 with error", rec.Code)
	}
	// Password unchanged: the second password still logs in.
	login(t, srv, "lane", "second-password-1")

	// Correct current password: accepted, old sessions revoked, fresh
	// session issued.
	rec = postChangePassword(t, srv, cookie, url.Values{
		"current": {"second-password-1"}, "password": {"third-password-1"}, "confirm": {"third-password-1"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("valid change: got %d: %s", rec.Code, rec.Body.String())
	}
	fresh := sessionCookieFromRec(t, rec)
	if r := get(t, srv, "/app", cookie); r.Code != http.StatusSeeOther {
		t.Fatalf("old session still valid after change: got %d", r.Code)
	}
	if r := get(t, srv, "/app", fresh); r.Code != http.StatusOK {
		t.Fatalf("fresh session: got %d, want 200", r.Code)
	}
	login(t, srv, "lane", "third-password-1")
}

// TestThreadSeenWatermark verifies F14: opening a thread marks
// last_seen_id to the maximum DISPLAYED message ID and clears the
// unread badge. With >500 messages, the watermark is the newest
// displayed message, not the oldest in the thread.
func TestThreadSeenWatermark(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	peerID := testIdentity(t)
	peer := crypto.FormatAddress(peerID.EdPub[:])
	self := crypto.FormatAddress(id.EdPub[:])
	token := register(t, srv, "lane", "temporary-password-123", id)

	// 600 inbound messages; only the newest 500 are displayed (F12).
	// The push endpoint caps at 200 messages per request.
	for start := 1; start <= 600; start += 200 {
		msgs := make([]map[string]any, 0, 200)
		for i := start; i < start+200 && i <= 600; i++ {
			msgs = append(msgs, map[string]any{
				"courier_id": i, "from": peer, "body": "m",
				"sent_at": i, "received_at": i,
			})
		}
		payload, _ := json.Marshal(map[string]any{"messages": msgs})
		req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("push: got %d", rec.Code)
		}
	}

	// Log in (forced password change), using the fresh F6 session.
	cookie := sessionCookieFromRec(t, postChangePassword(t, srv,
		login(t, srv, "lane", "temporary-password-123"),
		url.Values{"password": {"a-brand-new-password"}, "confirm": {"a-brand-new-password"}}))

	// Badge shows unread before opening.
	u, err := srv.store.DashboardUserByName("lane")
	if err != nil {
		t.Fatal(err)
	}
	threads, err := srv.store.DashboardThreads(u.ID, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 || threads[0].Unread != 600 {
		t.Fatalf("unread before open = %+v, want 600", threads)
	}

	// Open the thread.
	if r := get(t, srv, "/app/thread?with="+url.QueryEscape(peer), cookie); r.Code != http.StatusOK {
		t.Fatalf("open thread: got %d", r.Code)
	}

	// Watermark = the maximum displayed message ID (the 600th message),
	// and the unread badge is cleared.
	lastSeen, err := srv.store.ThreadSeenID(u.ID, peer)
	if err != nil {
		t.Fatal(err)
	}
	displayed, err := srv.store.DashboardThreadMessages(u.ID, peer, 500)
	if err != nil {
		t.Fatal(err)
	}
	var maxShown int64
	for _, m := range displayed {
		if m.ID > maxShown {
			maxShown = m.ID
		}
	}
	if lastSeen != maxShown {
		t.Fatalf("last_seen_id = %d, want max displayed %d", lastSeen, maxShown)
	}
	threads, err = srv.store.DashboardThreads(u.ID, self, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 || threads[0].Unread != 0 {
		t.Fatalf("unread after open = %+v, want 0", threads)
	}
}

// TestBridgeBadge verifies that messages which arrived via a non-E2E
// bridge (issue #61) are explicitly marked in the dashboard: a badge in
// the thread view and a marker in the thread list. Ordinary E2E
// messages get no badge.
func TestBridgeBadge(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	other := testIdentity(t)
	me := crypto.FormatAddress(id.EdPub[:])
	them := crypto.FormatAddress(other.EdPub[:])
	_ = me
	token := register(t, srv, "lane", "temporary-password-123", id)

	push := func(msgs ...map[string]any) {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"messages": msgs})
		req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("push: got %d: %s", rec.Code, rec.Body.String())
		}
	}
	// One ordinary E2E message and one bridged (non-E2E) message.
	push(
		map[string]any{"courier_id": 1, "from": them, "body": "hey", "sent_at": 100, "received_at": 101},
		map[string]any{"courier_id": 2, "from": them, "body": bridge.WrapBody("hello from chatgpt"), "sent_at": 102, "received_at": 103},
	)

	// Login dance: the temp password must be changed first.
	cookie := login(t, srv, "lane", "temporary-password-123")
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change-password: got %d", rec.Code)
	}
	cookie = login(t, srv, "lane", "a-new-password-123")

	// Thread view: exactly one badge — on the bridged message only.
	rec = get(t, srv, "/app/thread?with="+url.QueryEscape(them), cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("/app/thread: got %d", rec.Code)
	}
	if n := strings.Count(body, "Not end-to-end encrypted"); n != 1 {
		t.Fatalf("/app/thread: want exactly 1 non-E2E badge, got %d", n)
	}
	if !strings.Contains(body, bridge.BridgeBannerHeader) {
		t.Fatal("/app/thread: bridge banner text missing from body")
	}

	// Thread list: the thread whose latest message is bridged is flagged.
	rec = get(t, srv, "/app", cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `class="nbadge small"`) {
		t.Fatalf("/app: got %d, missing bridged-thread marker", rec.Code)
	}
}

// TestBridgeBadgeFromPinList: the dashboard badges a message the agent
// reported as bridged even when the body carries no banner (issue
// #96). This is the pinned bridge-address list rendering path: the
// agent derived bridged-ness from its pin list (no payload metadata,
// no banner) and the dashboard displays the reported flag.
func TestBridgeBadgeFromPinList(t *testing.T) {
	srv := testServer(t)
	id := testIdentity(t)
	other := testIdentity(t)
	_ = crypto.FormatAddress(id.EdPub[:])
	them := crypto.FormatAddress(other.EdPub[:])
	token := register(t, srv, "lane", "temporary-password-123", id)

	push := func(msgs ...map[string]any) {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"messages": msgs})
		req := httptest.NewRequest("POST", "/v1/dashboard/push", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("push: got %d: %s", rec.Code, rec.Body.String())
		}
	}
	// No banner in the body — bridged-ness comes only from the
	// agent-reported flag (the pin-list path).
	push(
		map[string]any{"courier_id": 1, "from": them, "body": "hello via bridge", "sent_at": 100, "received_at": 101, "bridged": true},
	)

	// Login dance: the temp password must be changed first.
	cookie := sessionCookieFromRec(t, postChangePassword(t, srv,
		login(t, srv, "lane", "temporary-password-123"),
		url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}))

	// Thread view: the badge renders from the reported flag alone.
	rec := get(t, srv, "/app/thread?with="+url.QueryEscape(them), cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("/app/thread: got %d", rec.Code)
	}
	if n := strings.Count(body, "Not end-to-end encrypted"); n != 1 {
		t.Fatalf("/app/thread: want exactly 1 non-E2E badge from pin-list flag, got %d", n)
	}

	// Thread list: the marker renders from the reported flag alone.
	rec = get(t, srv, "/app", cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `class="nbadge small"`) {
		t.Fatalf("/app: got %d, missing bridged-thread marker from pin-list flag", rec.Code)
	}
}
