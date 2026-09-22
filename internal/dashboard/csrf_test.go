package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// postAuthed submits a session-authenticated form POST, attaching the
// session cookie and optionally the synchronizer CSRF token. mode picks
// how the token is sent:
//
//	"valid"   — the real token from the login CSRF cookie
//	"missing" — no token at all (and no CSRF cookie)
//	"wrong"   — a token from a different session
func postAuthed(t *testing.T, srv *Server, path string, creds testLogin, form url.Values, mode string) *httptest.ResponseRecorder {
	t.Helper()
	form = cloneValues(form)
	switch mode {
	case "valid":
		form.Set(csrfField, sessionCSRFToken(t, srv, creds.session))
	case "wrong":
		// A token that was never minted for this session must not validate.
		form.Set(csrfField, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	case "missing":
		// leave the token out entirely
	default:
		t.Fatalf("unknown csrf mode %q", mode)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(creds.session)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestCSRFLoginMissingToken(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	form := url.Values{"username": {"lane"}, "password": {"temporary-password-123"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login without token: got %d, want 403", rec.Code)
	}
}

func TestCSRFLoginWrongToken(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	// Fetch the cookie but submit a different token value.
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	var csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == loginCSRFCookie {
			csrf = c
		}
	}
	if csrf == nil {
		t.Fatal("no pre-login CSRF cookie")
	}
	form := url.Values{
		"username": {"lane"},
		"password": {"temporary-password-123"},
		csrfField:  {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login with wrong token: got %d, want 403", rec.Code)
	}
}

func TestCSRFChangePassword(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	creds := login(t, srv, "lane", "temporary-password-123")
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}

	if rec := postAuthed(t, srv, "/change-password", creds, form, "missing"); rec.Code != http.StatusForbidden {
		t.Fatalf("change-password without token: got %d, want 403", rec.Code)
	}
	if rec := postAuthed(t, srv, "/change-password", creds, form, "wrong"); rec.Code != http.StatusForbidden {
		t.Fatalf("change-password with wrong token: got %d, want 403", rec.Code)
	}
	if rec := postAuthed(t, srv, "/change-password", creds, form, "valid"); rec.Code != http.StatusSeeOther {
		t.Fatalf("change-password with valid token: got %d, want 303", rec.Code)
	}
}

func TestCSRFLogout(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	creds := login(t, srv, "lane", "temporary-password-123")

	if rec := postAuthed(t, srv, "/logout", creds, url.Values{}, "missing"); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without token: got %d, want 403", rec.Code)
	}
	// The rejected logout must not destroy the session.
	if r := get(t, srv, "/change-password", creds.session); r.Code != http.StatusOK {
		t.Fatalf("session destroyed by rejected logout: got %d", r.Code)
	}
	if rec := postAuthed(t, srv, "/logout", creds, url.Values{}, "wrong"); rec.Code != http.StatusForbidden {
		t.Fatalf("logout with wrong token: got %d, want 403", rec.Code)
	}
	if rec := postAuthed(t, srv, "/logout", creds, url.Values{}, "valid"); rec.Code != http.StatusSeeOther {
		t.Fatalf("logout with valid token: got %d, want 303", rec.Code)
	}
	// The session is really gone now.
	if r := get(t, srv, "/app", creds.session); r.Code != http.StatusSeeOther {
		t.Fatalf("post-logout /app: got %d, want 303", r.Code)
	}
}

func TestCSRFTokenIsSessionBound(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	a := login(t, srv, "lane", "temporary-password-123")
	// Lane's token submitted with a's own session — but the token value
	// is b's: must fail.
	register(t, srv, "grace", "temporary-password-123", testIdentity(t))
	b := login(t, srv, "grace", "temporary-password-123")

	form := url.Values{"password": {"x-x-x-x-x-x-x-x-x"}, "confirm": {"x-x-x-x-x-x-x-x-x"}}
	form.Set(csrfField, sessionCSRFToken(t, srv, b.session))
	req := httptest.NewRequest("POST", "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(a.session)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-session token: got %d, want 403", rec.Code)
	}
}

func TestCSRFOriginRefererEnforcement(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	form := url.Values{"username": {"lane"}, "password": {"temporary-password-123"}}

	getCSRF := func() *http.Cookie {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		for _, c := range rec.Result().Cookies() {
			if c.Name == loginCSRFCookie {
				return c
			}
		}
		t.Fatal("no pre-login CSRF cookie")
		return nil
	}

	// Mismatched Origin is rejected even with a valid token.
	csrf := getCSRF()
	good := cloneValues(form)
	good.Set(csrfField, csrf.Value)
	req := httptest.NewRequest("POST", "/login", strings.NewReader(good.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.test")
	req.AddCookie(csrf)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login with evil Origin: got %d, want 403", rec.Code)
	}

	// Mismatched Referer is rejected too.
	req = httptest.NewRequest("POST", "/login", strings.NewReader(good.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://evil.test/phish")
	req.AddCookie(csrf)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login with evil Referer: got %d, want 403", rec.Code)
	}

	// A matching Origin passes (defense in depth alongside the token).
	req = httptest.NewRequest("POST", "/login", strings.NewReader(good.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host)
	req.AddCookie(csrf)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login with matching Origin: got %d, want 303", rec.Code)
	}
}

func TestCSRFGETsNeedNoToken(t *testing.T) {
	srv := testServer(t)
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	creds := login(t, srv, "lane", "temporary-password-123")
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
	if rec := postChangePassword(t, srv, creds, form); rec.Code != http.StatusSeeOther {
		t.Fatalf("change-password: got %d", rec.Code)
	}
	creds = login(t, srv, "lane", "a-new-password-123")

	// Pre-login and authenticated GET routes render fine without any
	// CSRF token submission.
	for _, path := range []string{"/", "/login"} {
		req := httptest.NewRequest("GET", path, nil)
		r := httptest.NewRecorder()
		srv.Routes().ServeHTTP(r, req)
		if r.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d, want 200", path, r.Code)
		}
	}
	for _, path := range []string{"/app", "/change-password"} {
		if r := get(t, srv, path, creds.session); r.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d, want 200", path, r.Code)
		}
	}
}

func TestCSRFUnlinkMissingToken(t *testing.T) {
	rg := newOAuthTestRig(t)
	u, cookie := oauthTestUser(t, rg, "ada")
	if err := rg.srv.store.LinkBCTAccount(u.ID, rg.provider.account.id, rg.provider.account.email); err != nil {
		t.Fatal(err)
	}
	// POST without the synchronizer token must be rejected and must not
	// unlink the account.
	req, _ := http.NewRequest("POST", rg.dash.URL+"/settings/unlink-bct", nil)
	req.Header.Set("Cookie", cookie)
	resp, err := rg.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlink without token: got %d, want 403", resp.StatusCode)
	}
	got, err := rg.srv.store.DashboardUserByName("ada")
	if err != nil {
		t.Fatal(err)
	}
	if got.BCTUserID == 0 {
		t.Fatal("unlink without token still unlinked the account")
	}
	// With the token it works (covered by TestOAuthUnlinkStillWorks).
}
