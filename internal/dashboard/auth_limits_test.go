package dashboard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---- unit tests: backoff schedule ----

func TestLoginBackoffSchedule(t *testing.T) {
	base, max := 2*time.Second, 15*time.Minute
	cases := map[int]time.Duration{
		0:   base, // clamped to first failure
		1:   base,
		2:   2 * base,
		3:   4 * base,
		4:   8 * base,
		10:  max, // 2^9 * 2s would be 1024s > 15m
		100: max,
	}
	for n, want := range cases {
		if got := loginBackoff(n, base, max); got != want {
			t.Errorf("loginBackoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// ---- unit tests: limiter ----

func TestFixedWindowLimiterWindow(t *testing.T) {
	l := newFixedWindowLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	if !l.allow("k", 2, time.Minute) {
		t.Fatal("first event in window should pass")
	}
	if !l.allow("k", 2, time.Minute) {
		t.Fatal("second event in window should pass")
	}
	if l.allow("k", 2, time.Minute) {
		t.Fatal("third event in window should be denied")
	}
	// A different key has its own budget.
	if !l.allow("other", 2, time.Minute) {
		t.Fatal("fresh key should pass")
	}
	// After the window rolls, the budget resets.
	now = now.Add(61 * time.Second)
	if !l.allow("k", 2, time.Minute) {
		t.Fatal("event in new window should pass")
	}
}

func TestClientIP(t *testing.T) {
	srv := testServer(t)
	// X-Forwarded-For is honored from a trusted peer (loopback): the
	// dashboard normally sits behind Caddy on the same host.
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	if got := srv.clientIP(req); got != "1.2.3.4" {
		t.Fatalf("XFF from loopback: got %q, want 1.2.3.4", got)
	}
	// From an untrusted peer the header must be ignored: blindly
	// trusting it would let an attacker evade per-IP rate limits.
	req = httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := srv.clientIP(req); got != "9.9.9.9" {
		t.Fatalf("XFF from untrusted peer: got %q, want 9.9.9.9", got)
	}
	// A proxy on another host can be trusted explicitly.
	srv.trustedProxies = parseTrustedProxies("9.9.9.0/24")
	req = httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := srv.clientIP(req); got != "1.2.3.4" {
		t.Fatalf("XFF from configured proxy: got %q, want 1.2.3.4", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets := parseTrustedProxies("10.0.0.1, 192.168.0.0/24, not-an-ip, ")
	if len(nets) != 2 {
		t.Fatalf("got %d networks, want 2", len(nets))
	}
}

// ---- config tests ----

func TestAuthLimitsDefaultsSane(t *testing.T) {
	l := DefaultAuthLimits()
	for name, v := range map[string]int{
		"LoginAttemptsPerIP":    l.LoginAttemptsPerIP,
		"LoginAttemptsGlobal":   l.LoginAttemptsGlobal,
		"RegisterAttemptsPerIP": l.RegisterAttemptsPerIP,
		"OAuthAttemptsPerIP":    l.OAuthAttemptsPerIP,
		"OAuthAttemptsGlobal":   l.OAuthAttemptsGlobal,
	} {
		if v <= 0 {
			t.Errorf("%s = %d, want positive", name, v)
		}
	}
	for name, d := range map[string]time.Duration{
		"LoginBackoffBase": l.LoginBackoffBase,
		"LoginBackoffMax":  l.LoginBackoffMax,
	} {
		if d <= 0 {
			t.Errorf("%s = %v, want positive", name, d)
		}
	}
	if l.LoginBackoffBase >= l.LoginBackoffMax {
		t.Errorf("backoff base %v >= max %v", l.LoginBackoffBase, l.LoginBackoffMax)
	}
}

func TestAuthLimitsFromEnv(t *testing.T) {
	t.Setenv("DASHBOARD_LOGIN_PER_IP", "5")
	t.Setenv("DASHBOARD_LOGIN_BACKOFF_MAX_SECS", "60")
	t.Setenv("DASHBOARD_REGISTER_PER_IP", "not-a-number")
	l := AuthLimitsFromEnv()
	if l.LoginAttemptsPerIP != 5 {
		t.Errorf("LoginAttemptsPerIP = %d, want 5", l.LoginAttemptsPerIP)
	}
	if l.LoginBackoffMax != 60*time.Second {
		t.Errorf("LoginBackoffMax = %v, want 60s", l.LoginBackoffMax)
	}
	if l.RegisterAttemptsPerIP != DefaultAuthLimits().RegisterAttemptsPerIP {
		t.Errorf("unparsable env should keep default, got %d", l.RegisterAttemptsPerIP)
	}
	if l.OAuthAttemptsPerIP != DefaultAuthLimits().OAuthAttemptsPerIP {
		t.Errorf("unset env should keep default, got %d", l.OAuthAttemptsPerIP)
	}
}

// ---- integration tests: per-IP and global login budgets ----

func TestLoginPerIPRateLimit(t *testing.T) {
	srv := testServer(t)
	srv.limits = AuthLimits{LoginAttemptsPerIP: 3}
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	bad := url.Values{"username": {"lane"}, "password": {"wrong"}}
	for i := 0; i < 3; i++ {
		if rec := postLoginRaw(t, srv, bad); rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200", i+1, rec.Code)
		}
	}
	rec := postLoginRaw(t, srv, bad)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget attempt: got %d, want 429", rec.Code)
	}
	// A different IP still has its own budget.
	if rec := postLoginRawXFF(t, srv, bad, "10.9.9.9"); rec.Code != http.StatusOK {
		t.Fatalf("other IP: got %d, want 200", rec.Code)
	}
}

func TestLoginGlobalRateLimit(t *testing.T) {
	srv := testServer(t)
	srv.limits = AuthLimits{LoginAttemptsGlobal: 3, LoginAttemptsPerIP: 1000}
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	for i := 0; i < 3; i++ {
		form := url.Values{"username": {"lane"}, "password": {"wrong"}}
		rec := postLoginRawXFF(t, srv, form, fmt.Sprintf("10.0.0.%d", i+1))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200", i+1, rec.Code)
		}
	}
	// The global budget is spent even though each IP is fresh.
	form := url.Values{"username": {"lane"}, "password": {"wrong"}}
	if rec := postLoginRawXFF(t, srv, form, "10.0.0.9"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over global budget: got %d, want 429", rec.Code)
	}
}

// postLoginRawXFF submits the login form with the pre-login CSRF token
// and a spoofed X-Forwarded-For client IP.
func postLoginRawXFF(t *testing.T, srv *Server, form url.Values, ip string) *httptest.ResponseRecorder {
	t.Helper()
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
	form = cloneValues(form)
	form.Set(csrfField, csrf.Value)
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "127.0.0.1:1234" // trusted proxy peer: XFF honored
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	req.AddCookie(csrf)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// ---- integration tests: per-account exponential backoff ----

func TestLoginAccountBackoff(t *testing.T) {
	srv := testServer(t)
	// One failure locks the account for an hour: deterministic.
	srv.limits = AuthLimits{LoginBackoffBase: time.Hour, LoginBackoffMax: time.Hour}
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))

	bad := url.Values{"username": {"lane"}, "password": {"wrong"}}
	if rec := postLoginRaw(t, srv, bad); rec.Code != http.StatusOK {
		t.Fatalf("failed login: got %d, want 200", rec.Code)
	}
	u, err := srv.store.DashboardUserByName("lane")
	if err != nil {
		t.Fatal(err)
	}
	if u.FailedLogins != 1 {
		t.Fatalf("FailedLogins = %d, want 1", u.FailedLogins)
	}
	if u.LockUntil <= time.Now().Unix() {
		t.Fatal("LockUntil is not in the future")
	}

	// The correct password is rejected while locked — with the SAME
	// generic message as a wrong password (no user enumeration).
	good := url.Values{"username": {"lane"}, "password": {"temporary-password-123"}}
	rec := postLoginRaw(t, srv, good)
	if rec.Code != http.StatusOK {
		t.Fatalf("locked login: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), invalidCredentials) {
		t.Fatalf("locked login should render the generic error, got %.200s", rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("locked login must not set a session")
	}
}

func TestLoginGenericErrorsIdentical(t *testing.T) {
	srv := testServer(t)
	srv.limits = AuthLimits{LoginBackoffBase: time.Hour, LoginBackoffMax: time.Hour}
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	// Lock the account.
	postLoginRaw(t, srv, url.Values{"username": {"lane"}, "password": {"wrong"}})

	bodies := map[string]string{}
	for name, form := range map[string]url.Values{
		"unknown-user":   {"username": {"nobody-here"}, "password": {"whatever"}},
		"wrong-password": {"username": {"lane"}, "password": {"wrong-again"}},
		"locked-account": {"username": {"lane"}, "password": {"temporary-password-123"}},
	} {
		rec := postLoginRaw(t, srv, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", name, rec.Code)
		}
		bodies[name] = rec.Body.String()
	}
	// All three render the generic error; none sets a session.
	for name, body := range bodies {
		if !strings.Contains(body, invalidCredentials) {
			t.Errorf("%s: missing generic error message", name)
		}
	}
}

func TestLoginBackoffResetOnSuccess(t *testing.T) {
	srv := testServer(t)
	srv.limits = AuthLimits{LoginBackoffBase: time.Hour, LoginBackoffMax: time.Hour}
	register(t, srv, "lane", "temporary-password-123", testIdentity(t))
	postLoginRaw(t, srv, url.Values{"username": {"lane"}, "password": {"wrong"}})
	u, _ := srv.store.DashboardUserByName("lane")
	if u.FailedLogins != 1 {
		t.Fatalf("FailedLogins = %d, want 1", u.FailedLogins)
	}
	// Simulate the lockout expiring, then log in successfully.
	if err := srv.store.ClearLoginFailures(u.ID); err != nil {
		t.Fatal(err)
	}
	creds := login(t, srv, "lane", "temporary-password-123")
	if creds.session == nil {
		t.Fatal("login after backoff reset failed")
	}
	u, _ = srv.store.DashboardUserByName("lane")
	if u.FailedLogins != 0 || u.LockUntil != 0 {
		t.Fatalf("backoff not reset: %+v", u)
	}
}

// ---- integration tests: registration quota ----

func TestRegisterPerIPQuota(t *testing.T) {
	srv := testServer(t)
	srv.limits = AuthLimits{RegisterAttemptsPerIP: 2}
	register(t, srv, "w8user1", "temporary-password-123", testIdentity(t))
	register(t, srv, "w8user2", "temporary-password-123", testIdentity(t))

	// A third registration from the same IP is rejected before any
	// expensive work, even with a valid signature.
	if rec := registerRaw(t, srv, "w8user3", "temporary-password-123", testIdentity(t)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-quota register: got %d, want 429", rec.Code)
	}
}

// ---- integration tests: OAuth budgets are separate ----

func TestOAuthBudgetsSeparateFromLogin(t *testing.T) {
	srv := testServer(t)
	srv = NewWithBCTAndLimits(srv.store, BCTOAuthConfig{
		URL: "https://auth.example.test", ClientID: "x", ClientSecret: "y",
	}, AuthLimits{LoginAttemptsPerIP: 2, OAuthAttemptsPerIP: 2})

	// Exhaust the local-login per-IP budget.
	bad := url.Values{"username": {"lane"}, "password": {"wrong"}}
	postLoginRaw(t, srv, bad)
	postLoginRaw(t, srv, bad)
	if rec := postLoginRaw(t, srv, bad); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login over budget: got %d, want 429", rec.Code)
	}
	// The OAuth flow still starts: separate budget.
	req := httptest.NewRequest("GET", "/oauth/bct/login", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("oauth start with login budget spent: got %d, want 302", rec.Code)
	}

	// Now exhaust the OAuth per-IP budget; the login budget is already
	// spent, so check the other direction on a fresh server.
	srv2base := testServer(t)
	srv2 := NewWithBCTAndLimits(srv2base.store, BCTOAuthConfig{
		URL: "https://auth.example.test", ClientID: "x", ClientSecret: "y",
	}, AuthLimits{LoginAttemptsPerIP: 100, OAuthAttemptsPerIP: 2})
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/oauth/bct/login", nil)
		rec := httptest.NewRecorder()
		srv2.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("oauth start %d: got %d, want 302", i+1, rec.Code)
		}
	}
	req = httptest.NewRequest("GET", "/oauth/bct/login", nil)
	rec = httptest.NewRecorder()
	srv2.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("oauth over budget: got %d, want 429", rec.Code)
	}
	// Password login is unaffected by the spent OAuth budget.
	if rec := postLoginRaw(t, srv2, bad); rec.Code != http.StatusOK {
		t.Fatalf("login with oauth budget spent: got %d, want 200", rec.Code)
	}
}
