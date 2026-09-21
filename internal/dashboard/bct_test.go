package dashboard

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/black-candle-technologies/courier/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// mockAccount is one fake authd account.
type mockAccount struct {
	password string
	id       int64
	verified bool
}

// mockAuthd fakes the Black Candle auth service (/v1/login, /v1/logout)
// for BCT linking tests.
type mockAuthd struct {
	t       *testing.T
	apiKey  string
	mu      sync.Mutex
	accts   map[string]mockAccount
	logouts []string
}

func newMockAuthd(t *testing.T) *mockAuthd {
	t.Helper()
	return &mockAuthd{t: t, apiKey: "test-api-key", accts: map[string]mockAccount{}}
}

func (m *mockAuthd) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != m.apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		acct, ok := m.accts[strings.ToLower(req.Email)]
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok || acct.password != req.Password {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"Invalid email or password."}`))
			return
		}
		if !acct.verified {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"confirm first","needs_verification":true}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user":          map[string]any{"id": acct.id, "email": strings.ToLower(req.Email), "email_verified": true, "created_at": 1},
			"session_token": "sess-for-test",
			"expires_at":    9999999999,
		})
	})
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != m.apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			SessionToken string `json:"session_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		m.logouts = append(m.logouts, req.SessionToken)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return mux
}

func (m *mockAuthd) logoutCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.logouts)
}

// testServerWithBCT builds a dashboard server with linking enabled
// against the mock auth service.
func testServerWithBCT(t *testing.T, m *mockAuthd) (*Server, *httptest.Server) {
	t.Helper()
	auth := httptest.NewServer(m.handler())
	t.Cleanup(auth.Close)
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewWithBCT(st, BCTConfig{URL: auth.URL, APIKey: m.apiKey}), auth
}

// bctTestUser creates a dashboard user whose temp password is already
// changed (so no forced redirect), and returns it with a session cookie.
func bctTestUser(t *testing.T, srv *Server, username string) (*store.DashboardUser, string) {
	t.Helper()
	pwHash, err := bcrypt.GenerateFromPassword([]byte("dashboard-password-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u, err := srv.store.CreateDashboardUser(username, string(pwHash), "ed25519:bcttest"+username, "tokenhash-"+username)
	if err != nil {
		t.Fatal(err)
	}
	// Clear must_change so the user can reach /settings.
	if err := srv.store.ChangeDashboardPassword(u.ID, string(pwHash)); err != nil {
		t.Fatal(err)
	}
	u, err = srv.store.DashboardUserByName(username)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"username": {username}, "password": {"dashboard-password-1"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: got %d: %s", rec.Code, rec.Body.String())
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("login: no session cookie")
	}
	return u, cookie
}

func bctGet(t *testing.T, srv *Server, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func bctPostForm(t *testing.T, srv *Server, path, cookie string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestBCTDisabledByDefault(t *testing.T) {
	srv := testServer(t) // no BCT config
	// Linking routes don't exist: POSTs are rejected (404, or 405 from
	// the GET / catch-all's method mismatch — either way, not handled).
	for _, path := range []string{"/login-bct", "/settings/link-bct", "/settings/unlink-bct"} {
		if r := bctPostForm(t, srv, path, "", url.Values{}); r.Code != http.StatusNotFound && r.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s: got %d, want 404/405", path, r.Code)
		}
	}
	// Login page shows no Black Candle affordance.
	r := bctGet(t, srv, "/", "")
	if strings.Contains(r.Body.String(), "Black Candle") {
		t.Fatal("login page mentions Black Candle while the feature is disabled")
	}
	// Unknown GET paths fall through to the login page (pre-existing mux
	// behavior); it must not offer linking either.
	r = bctGet(t, srv, "/settings", "")
	if strings.Contains(r.Body.String(), "Link your Black Candle account") {
		t.Fatal("/settings offers linking while the feature is disabled")
	}
}

func TestBCTVerifyCredentials(t *testing.T) {
	m := newMockAuthd(t)
	m.accts["ada@blackcandle.test"] = mockAccount{password: "correct-horse", id: 42, verified: true}
	m.accts["new@blackcandle.test"] = mockAccount{password: "correct-horse", id: 43, verified: false}
	auth := httptest.NewServer(m.handler())
	defer auth.Close()
	c := newBCTClient(auth.URL, m.apiKey)
	ctx := t.Context()

	bu, err := c.verifyCredentials(ctx, "ada@blackcandle.test", "correct-horse", "1.2.3.4")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if bu.ID != 42 || bu.Email != "ada@blackcandle.test" {
		t.Fatalf("verify: got %+v", bu)
	}
	// The throwaway authd session is destroyed.
	if m.logoutCount() != 1 {
		t.Fatalf("logouts = %d, want 1", m.logoutCount())
	}

	if _, err := c.verifyCredentials(ctx, "ada@blackcandle.test", "wrong", "1.2.3.4"); err != errBCTBadCredentials {
		t.Fatalf("bad password: got %v, want errBCTBadCredentials", err)
	}
	if _, err := c.verifyCredentials(ctx, "nobody@blackcandle.test", "x", "1.2.3.4"); err != errBCTBadCredentials {
		t.Fatalf("unknown email: got %v, want errBCTBadCredentials", err)
	}
	if _, err := c.verifyCredentials(ctx, "new@blackcandle.test", "correct-horse", "1.2.3.4"); err != errBCTNeedsVerification {
		t.Fatalf("unverified: got %v, want errBCTNeedsVerification", err)
	}

	// Unreachable auth service.
	c2 := newBCTClient("http://127.0.0.1:1", m.apiKey)
	if _, err := c2.verifyCredentials(ctx, "ada@blackcandle.test", "correct-horse", "1.2.3.4"); err != errBCTUnavailable {
		t.Fatalf("unreachable: got %v, want errBCTUnavailable", err)
	}
}

func TestBCTLinkUnlinkFlow(t *testing.T) {
	m := newMockAuthd(t)
	m.accts["ada@blackcandle.test"] = mockAccount{password: "correct-horse", id: 42, verified: true}
	srv, _ := testServerWithBCT(t, m)
	u, cookie := bctTestUser(t, srv, "bctlinker")

	// Settings page shows the link form.
	r := bctGet(t, srv, "/settings", cookie)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "Link your Black Candle account") {
		t.Fatalf("GET /settings: got %d", r.Code)
	}

	// Wrong password: not linked, error shown.
	r = bctPostForm(t, srv, "/settings/link-bct", cookie,
		url.Values{"email": {"ada@blackcandle.test"}, "password": {"nope"}})
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "Invalid Black Candle email or password") {
		t.Fatalf("link bad password: got %d", r.Code)
	}
	if got, _ := srv.store.DashboardUserByName("bctlinker"); got.BCTUserID != 0 {
		t.Fatal("linked despite bad password")
	}

	// Good credentials: linked, redirected.
	r = bctPostForm(t, srv, "/settings/link-bct", cookie,
		url.Values{"email": {"ada@blackcandle.test"}, "password": {"correct-horse"}})
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/settings" {
		t.Fatalf("link: got %d -> %q: %s", r.Code, r.Header().Get("Location"), r.Body.String())
	}
	got, err := srv.store.DashboardUserByName("bctlinker")
	if err != nil || got.BCTUserID != 42 || got.BCTEmail != "ada@blackcandle.test" {
		t.Fatalf("after link: %+v, err=%v", got, err)
	}
	_ = u

	// Settings now shows the linked state.
	r = bctGet(t, srv, "/settings", cookie)
	if !strings.Contains(r.Body.String(), "ada@blackcandle.test") || !strings.Contains(r.Body.String(), "Unlink") {
		t.Fatal("settings does not show linked state")
	}

	// Unlink.
	r = bctPostForm(t, srv, "/settings/unlink-bct", cookie, url.Values{})
	if r.Code != http.StatusSeeOther {
		t.Fatalf("unlink: got %d", r.Code)
	}
	got, _ = srv.store.DashboardUserByName("bctlinker")
	if got.BCTUserID != 0 || got.BCTEmail != "" {
		t.Fatalf("after unlink: %+v", got)
	}
	// Dashboard password still works after unlink.
	form := url.Values{"username": {"bctlinker"}, "password": {"dashboard-password-1"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("password login after unlink: got %d", rec.Code)
	}
}

func TestBCTLoginFlow(t *testing.T) {
	m := newMockAuthd(t)
	m.accts["ada@blackcandle.test"] = mockAccount{password: "correct-horse", id: 42, verified: true}
	m.accts["solo@blackcandle.test"] = mockAccount{password: "correct-horse", id: 43, verified: true}
	srv, _ := testServerWithBCT(t, m)
	_, cookie := bctTestUser(t, srv, "bctloginer")

	// Link first.
	r := bctPostForm(t, srv, "/settings/link-bct", cookie,
		url.Values{"email": {"ada@blackcandle.test"}, "password": {"correct-horse"}})
	if r.Code != http.StatusSeeOther {
		t.Fatalf("link: got %d", r.Code)
	}

	// Log in with the Black Candle account: session + redirect to /app.
	r = bctPostForm(t, srv, "/login-bct", "",
		url.Values{"email": {"ada@blackcandle.test"}, "password": {"correct-horse"}})
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/app" {
		t.Fatalf("login-bct: got %d -> %q: %s", r.Code, r.Header().Get("Location"), r.Body.String())
	}
	bctCookie := ""
	for _, c := range r.Result().Cookies() {
		if c.Name == sessionCookie {
			bctCookie = c.Name + "=" + c.Value
		}
	}
	if bctCookie == "" {
		t.Fatal("login-bct: no session cookie")
	}
	if r := bctGet(t, srv, "/app", bctCookie); r.Code != http.StatusOK {
		t.Fatalf("GET /app with BCT session: got %d", r.Code)
	}

	// BCT account with no linked dashboard user: helpful error, no session.
	r = bctPostForm(t, srv, "/login-bct", "",
		url.Values{"email": {"solo@blackcandle.test"}, "password": {"correct-horse"}})
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "No dashboard account is linked") {
		t.Fatalf("login-bct unlinked: got %d", r.Code)
	}

	// Wrong BCT password: rejected.
	r = bctPostForm(t, srv, "/login-bct", "",
		url.Values{"email": {"ada@blackcandle.test"}, "password": {"wrong"}})
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "Invalid Black Candle email or password") {
		t.Fatalf("login-bct bad password: got %d", r.Code)
	}
}

func TestBCTDoubleLinkRejected(t *testing.T) {
	m := newMockAuthd(t)
	m.accts["ada@blackcandle.test"] = mockAccount{password: "correct-horse", id: 42, verified: true}
	srv, _ := testServerWithBCT(t, m)
	_, cookie1 := bctTestUser(t, srv, "bctfirst")
	_, cookie2 := bctTestUser(t, srv, "bctsecond")

	form := url.Values{"email": {"ada@blackcandle.test"}, "password": {"correct-horse"}}
	if r := bctPostForm(t, srv, "/settings/link-bct", cookie1, form); r.Code != http.StatusSeeOther {
		t.Fatalf("first link: got %d", r.Code)
	}
	r := bctPostForm(t, srv, "/settings/link-bct", cookie2, form)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "already linked to another dashboard user") {
		t.Fatalf("second link: got %d: %s", r.Code, r.Body.String())
	}
	got, _ := srv.store.DashboardUserByName("bctsecond")
	if got.BCTUserID != 0 {
		t.Fatal("second user linked despite conflict")
	}

	// Re-linking the same account to the same user is idempotent.
	if r := bctPostForm(t, srv, "/settings/link-bct", cookie1, form); r.Code != http.StatusSeeOther {
		t.Fatalf("re-link same user: got %d", r.Code)
	}
}

func TestBCTUnverifiedCannotLink(t *testing.T) {
	m := newMockAuthd(t)
	m.accts["new@blackcandle.test"] = mockAccount{password: "correct-horse", id: 43, verified: false}
	srv, _ := testServerWithBCT(t, m)
	_, cookie := bctTestUser(t, srv, "bctunver")

	r := bctPostForm(t, srv, "/settings/link-bct", cookie,
		url.Values{"email": {"new@blackcandle.test"}, "password": {"correct-horse"}})
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "isn&#39;t confirmed yet") {
		t.Fatalf("link unverified: got %d: %s", r.Code, r.Body.String())
	}
	got, _ := srv.store.DashboardUserByName("bctunver")
	if got.BCTUserID != 0 {
		t.Fatal("linked an unverified BCT account")
	}
}

func TestBCTSettingsRequiresLogin(t *testing.T) {
	m := newMockAuthd(t)
	srv, _ := testServerWithBCT(t, m)
	if r := bctGet(t, srv, "/settings", ""); r.Code != http.StatusSeeOther {
		t.Fatalf("GET /settings without login: got %d, want redirect", r.Code)
	}
	if r := bctPostForm(t, srv, "/settings/link-bct", "", url.Values{}); r.Code != http.StatusSeeOther {
		t.Fatalf("POST /settings/link-bct without login: got %d, want redirect", r.Code)
	}
}

func TestBCTStoreRoundTrip(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, err := st.CreateDashboardUser("s1", "h", "ed25519:s1", "tok1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateDashboardUser("s2", "h", "ed25519:s2", "tok2")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkBCTAccount(a.ID, 42, "ada@blackcandle.test"); err != nil {
		t.Fatal(err)
	}
	// Second user cannot take the same BCT account (unique index).
	if err := st.LinkBCTAccount(b.ID, 42, "ada@blackcandle.test"); err == nil {
		t.Fatal("unique index allowed a double link")
	}
	u, err := st.DashboardUserByBCTUserID(42)
	if err != nil || u.ID != a.ID || u.BCTEmail != "ada@blackcandle.test" {
		t.Fatalf("lookup: %+v, err=%v", u, err)
	}
	if err := st.UnlinkBCTAccount(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DashboardUserByBCTUserID(42); err != sql.ErrNoRows {
		t.Fatalf("after unlink: err=%v", err)
	}
}
