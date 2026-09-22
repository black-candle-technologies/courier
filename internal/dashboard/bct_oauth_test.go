package dashboard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// ---- mock OAuth 2.0 provider ----

// mockOAuthAccount is the single fake Black Candle account the mock
// provider authenticates.
type mockOAuthAccount struct {
	id       int64
	email    string
	verified bool
}

type mockOAuthCode struct {
	redirectURI string
	challenge   string
	accountID   int64
}

// mockOAuthProvider fakes authd's /oauth/* endpoints: authorize
// auto-approves (as if the user were already logged in and consented),
// token exchanges single-use codes with PKCE verification, and userinfo
// returns the account identity.
type mockOAuthProvider struct {
	t            *testing.T
	clientID     string
	clientSecret string

	mu            sync.Mutex
	account       mockOAuthAccount
	codes         map[string]mockOAuthCode
	tokens        map[string]int64
	lastAuthorize url.Values
	failToken     bool
}

func newMockOAuthProvider(t *testing.T) *mockOAuthProvider {
	t.Helper()
	return &mockOAuthProvider{
		t:            t,
		clientID:     "courier-dashboard",
		clientSecret: "test-oauth-secret",
		account:      mockOAuthAccount{id: 4242, email: "user@blackcandle.test", verified: true},
		codes:        map[string]mockOAuthCode{},
		tokens:       map[string]int64{},
	}
}

func (m *mockOAuthProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/authorize", m.handleAuthorize)
	mux.HandleFunc("POST /oauth/token", m.handleToken)
	mux.HandleFunc("GET /oauth/userinfo", m.handleUserinfo)
	return mux
}

func (m *mockOAuthProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != m.clientID {
		http.Error(w, "bad client", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || q.Get("response_type") != "code" || q.Get("state") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE required", http.StatusBadRequest)
		return
	}
	code, err := randomB64(16)
	if err != nil {
		http.Error(w, "nope", http.StatusInternalServerError)
		return
	}
	m.mu.Lock()
	m.lastAuthorize = q
	m.codes[code] = mockOAuthCode{
		redirectURI: redirectURI,
		challenge:   q.Get("code_challenge"),
		accountID:   m.account.id,
	}
	m.mu.Unlock()
	u, _ := url.Parse(redirectURI)
	pq := u.Query()
	pq.Set("code", code)
	pq.Set("state", q.Get("state"))
	u.RawQuery = pq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (m *mockOAuthProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != m.clientID || pass != m.clientSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}
	_ = r.ParseForm()
	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "bad grant", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failToken {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	code := r.FormValue("code")
	mc, ok := m.codes[code]
	delete(m.codes, code) // single-use
	if !ok || r.FormValue("redirect_uri") != mc.redirectURI {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != mc.challenge {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	token, _ := randomB64(16)
	m.tokens[token] = mc.accountID
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token, "token_type": "bearer", "expires_in": 3600,
	})
}

func (m *mockOAuthProvider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	m.mu.Lock()
	accountID, ok := m.tokens[token]
	acct := m.account
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok || accountID != acct.id {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": acct.id, "email": acct.email, "email_verified": acct.verified,
	})
}

// ---- test scaffolding ----

type oauthTestRig struct {
	srv      *Server
	dash     *httptest.Server
	provider *mockOAuthProvider
	client   *http.Client // does not follow redirects
}

func newOAuthTestRig(t *testing.T) *oauthTestRig {
	t.Helper()
	provider := newMockOAuthProvider(t)
	provSrv := httptest.NewServer(provider.handler())
	t.Cleanup(provSrv.Close)

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewWithBCT(st, BCTOAuthConfig{
		URL:          provSrv.URL,
		ClientID:     provider.clientID,
		ClientSecret: provider.clientSecret,
	})
	dash := httptest.NewServer(srv.Routes())
	t.Cleanup(dash.Close)
	// Explicit redirect URI so the derived-request path is also covered
	// by TestOAuthRedirectURIDerived.
	srv.bct.cfg.RedirectURI = dash.URL + bctOAuthCallbackPath

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &oauthTestRig{srv: srv, dash: dash, provider: provider, client: client}
}

func (rg *oauthTestRig) get(t *testing.T, url, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	// Caller owns the body: readBody closes it, or close it directly.
	resp, err := rg.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// driveFlow runs one full browser flow: dashboard start → provider
// authorize (auto-approve) → dashboard callback. Returns the callback
// response and its parsed authorize params.
func (rg *oauthTestRig) driveFlow(t *testing.T, startPath, cookie string) (*http.Response, url.Values) {
	t.Helper()
	resp := rg.get(t, rg.dash.URL+startPath, cookie)
	if resp.StatusCode != http.StatusFound {
		resp.Body.Close()
		t.Fatalf("start %s: got %d, want 302", startPath, resp.StatusCode)
	}
	authURL := resp.Header.Get("Location")
	resp.Body.Close()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(parsed.Path, "/oauth/authorize") {
		t.Fatalf("start did not redirect to provider authorize: %s", authURL)
	}
	params := parsed.Query()

	resp2 := rg.get(t, authURL, "")
	if resp2.StatusCode != http.StatusFound {
		resp2.Body.Close()
		t.Fatalf("provider authorize: got %d, want 302", resp2.StatusCode)
	}
	callbackURL := resp2.Header.Get("Location")
	resp2.Body.Close()
	if !strings.HasPrefix(callbackURL, rg.dash.URL+bctOAuthCallbackPath) {
		t.Fatalf("provider did not redirect to dashboard callback: %s", callbackURL)
	}
	resp3 := rg.get(t, callbackURL, cookie)
	return resp3, params
}

func oauthTestUser(t *testing.T, rg *oauthTestRig, username string) (*store.DashboardUser, string) {
	t.Helper()
	pwHash, err := bcrypt.GenerateFromPassword([]byte("dashboard-password-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u, err := rg.srv.store.CreateDashboardUser(username, string(pwHash), "ed25519:oauth"+username, "tokenhash-"+username)
	if err != nil {
		t.Fatal(err)
	}
	// Clear must_change so the user can reach /settings.
	if err := rg.srv.store.ChangeDashboardPassword(u.ID, string(pwHash)); err != nil {
		t.Fatal(err)
	}
	u, err = rg.srv.store.DashboardUserByName(username)
	if err != nil {
		t.Fatal(err)
	}
	// Issue #111: the login form requires the pre-login double-submit
	// CSRF token. Fetch it from the login page first.
	getResp := rg.get(t, rg.dash.URL+"/", "")
	var loginCSRF string
	for _, c := range getResp.Cookies() {
		if c.Name == loginCSRFCookie {
			loginCSRF = c.Value
		}
	}
	_ = getResp.Body.Close()
	if loginCSRF == "" {
		t.Fatal("login: no pre-login CSRF cookie")
	}
	form := url.Values{"username": {username}, "password": {"dashboard-password-1"}, csrfField: {loginCSRF}}
	req, _ := http.NewRequest("POST", rg.dash.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: loginCSRFCookie, Value: loginCSRF})
	resp, err := rg.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: got %d", resp.StatusCode)
	}
	// The login sets the session cookie; the session's CSRF token
	// (issue #111) lives in the session DB row, not a second cookie.
	var cookie string
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatalf("login: no session cookie, got %v", resp.Cookies())
	}
	return u, cookie
}

// settingsCSRFToken fetches /settings and extracts the hidden CSRF
// token, like a browser rendering the unlink form.
var csrfHiddenRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func settingsCSRFToken(t *testing.T, rg *oauthTestRig, cookie string) string {
	t.Helper()
	resp := rg.get(t, rg.dash.URL+"/settings", cookie)
	body := readBody(t, resp)
	m := csrfHiddenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token in /settings page")
	}
	return m[1]
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	buf := new(strings.Builder)
	_, _ = io.Copy(buf, resp.Body)
	return buf.String()
}

// ---- tests ----

func TestOAuthStartRedirectShape(t *testing.T) {
	rg := newOAuthTestRig(t)
	_, cookie := oauthTestUser(t, rg, "ada")

	resp := rg.get(t, rg.dash.URL+"/oauth/bct/link", cookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("link start: got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasSuffix(loc.Path, "/oauth/authorize") {
		t.Fatalf("link start: not the provider: %s", loc)
	}
	q := loc.Query()
	want := map[string]string{
		"client_id":             rg.provider.clientID,
		"redirect_uri":          rg.dash.URL + bctOAuthCallbackPath,
		"response_type":         "code",
		"scope":                 "identity",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("authorize param %s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Get("state") == "" || q.Get("code_challenge") == "" {
		t.Errorf("authorize missing state/challenge: %v", q)
	}
}

func TestOAuthLoginSuccess(t *testing.T) {
	rg := newOAuthTestRig(t)
	u, _ := oauthTestUser(t, rg, "ada")
	// Link the BCT account first (as the link flow would).
	if err := rg.srv.store.LinkBCTAccount(u.ID, rg.provider.account.id, rg.provider.account.email); err != nil {
		t.Fatal(err)
	}

	resp, _ := rg.driveFlow(t, "/oauth/bct/login", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: got %d: %s", resp.StatusCode, readBody(t, resp))
	}
	if loc := resp.Header.Get("Location"); loc != "/app" {
		t.Errorf("callback: redirect = %q, want /app", loc)
	}
	cookie := ""
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("callback: no dashboard session cookie")
	}
	// The session works.
	appResp := rg.get(t, rg.dash.URL+"/app", cookie)
	defer appResp.Body.Close()
	if appResp.StatusCode != http.StatusOK {
		t.Errorf("GET /app with OAuth session: got %d", appResp.StatusCode)
	}
}

func TestOAuthLoginUnlinked(t *testing.T) {
	rg := newOAuthTestRig(t)
	oauthTestUser(t, rg, "ada") // not linked

	resp, _ := rg.driveFlow(t, "/oauth/bct/login", "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d", resp.StatusCode)
	}
	want := "No Courier account is linked to that Black Candle account yet — log in with your Courier credentials and link it in Settings."
	if !strings.Contains(body, want) {
		t.Errorf("unlinked login: missing message, got %.300s", body)
	}
	// No session was created.
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Errorf("unlinked login: session cookie was set")
		}
	}
}

func TestOAuthLinkSuccess(t *testing.T) {
	rg := newOAuthTestRig(t)
	_, cookie := oauthTestUser(t, rg, "ada")

	resp, _ := rg.driveFlow(t, "/oauth/bct/link", cookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("link callback: got %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	got, err := rg.srv.store.DashboardUserByName("ada")
	if err != nil {
		t.Fatal(err)
	}
	if got.BCTUserID != rg.provider.account.id || got.BCTEmail != rg.provider.account.email {
		t.Errorf("link: BCTUserID=%d BCTEmail=%q", got.BCTUserID, got.BCTEmail)
	}
	// Settings page shows the linked state.
	settingsResp := rg.get(t, rg.dash.URL+"/settings", cookie)
	body := readBody(t, settingsResp)
	if !strings.Contains(body, "Linked to") || !strings.Contains(body, rg.provider.account.email) {
		t.Errorf("settings: missing linked state, got %.300s", body)
	}
}

func TestOAuthLinkDuplicate(t *testing.T) {
	rg := newOAuthTestRig(t)
	u1, _ := oauthTestUser(t, rg, "ada")
	u2, cookie2 := oauthTestUser(t, rg, "grace")
	if err := rg.srv.store.LinkBCTAccount(u1.ID, rg.provider.account.id, rg.provider.account.email); err != nil {
		t.Fatal(err)
	}

	resp, _ := rg.driveFlow(t, "/oauth/bct/link", cookie2)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("duplicate link: got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "already linked to another dashboard user") {
		t.Errorf("duplicate link: missing error, got %.300s", body)
	}
	got, _ := rg.srv.store.DashboardUserByName("grace")
	if got.BCTUserID != 0 {
		t.Errorf("duplicate link: grace got BCTUserID=%d", got.BCTUserID)
	}
	_ = u2
}

func TestOAuthUnlinkStillWorks(t *testing.T) {
	rg := newOAuthTestRig(t)
	u, cookie := oauthTestUser(t, rg, "ada")
	if err := rg.srv.store.LinkBCTAccount(u.ID, rg.provider.account.id, rg.provider.account.email); err != nil {
		t.Fatal(err)
	}
	// Issue #111: unlink requires the session's synchronizer CSRF token;
	// pull it from the settings page like a browser would.
	csrf := settingsCSRFToken(t, rg, cookie)
	form := url.Values{csrfField: {csrf}}
	req, _ := http.NewRequest("POST", rg.dash.URL+"/settings/unlink-bct", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	resp, err := rg.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("unlink: got %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	got, err := rg.srv.store.DashboardUserByName("ada")
	if err != nil {
		t.Fatal(err)
	}
	if got.BCTUserID != 0 {
		t.Errorf("unlink: BCTUserID=%d, want 0", got.BCTUserID)
	}
}

func TestOAuthLinkIdempotent(t *testing.T) {
	rg := newOAuthTestRig(t)
	u, cookie := oauthTestUser(t, rg, "ada")
	if err := rg.srv.store.LinkBCTAccount(u.ID, rg.provider.account.id, rg.provider.account.email); err != nil {
		t.Fatal(err)
	}
	// Re-linking the same BCT account to the same user succeeds.
	resp, _ := rg.driveFlow(t, "/oauth/bct/link", cookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("re-link: got %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestOAuthLinkRequiresLogin(t *testing.T) {
	rg := newOAuthTestRig(t)
	resp := rg.get(t, rg.dash.URL+"/oauth/bct/link", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Errorf("link without session: got %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestOAuthCallbackBadState(t *testing.T) {
	rg := newOAuthTestRig(t)
	resp := rg.get(t, rg.dash.URL+"/oauth/bct/callback?code=x&state=bogus", "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("bad state: got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Black Candle sign-in failed") {
		t.Errorf("bad state: missing error, got %.200s", body)
	}
}

func TestOAuthCallbackExpiredState(t *testing.T) {
	rg := newOAuthTestRig(t)
	state, _, err := rg.srv.bct.newState(oauthIntentLogin, 0, rg.dash.URL+bctOAuthCallbackPath)
	if err != nil {
		t.Fatal(err)
	}
	rg.srv.bct.mu.Lock()
	rg.srv.bct.states[state].expiresAt = time.Now().Add(-time.Minute)
	rg.srv.bct.mu.Unlock()

	resp := rg.get(t, rg.dash.URL+"/oauth/bct/callback?code=x&state="+url.QueryEscape(state), "")
	body := readBody(t, resp)
	if !strings.Contains(body, "Black Candle sign-in failed") {
		t.Errorf("expired state: missing error, got %.200s", body)
	}
}

func TestOAuthCallbackReplayedState(t *testing.T) {
	rg := newOAuthTestRig(t)
	u, _ := oauthTestUser(t, rg, "ada")
	if err := rg.srv.store.LinkBCTAccount(u.ID, rg.provider.account.id, rg.provider.account.email); err != nil {
		t.Fatal(err)
	}

	// Drive the flow manually to capture the callback URL.
	resp := rg.get(t, rg.dash.URL+"/oauth/bct/login", "")
	authURL := resp.Header.Get("Location")
	resp.Body.Close()
	resp2 := rg.get(t, authURL, "")
	callbackURL := resp2.Header.Get("Location")
	resp2.Body.Close()

	resp3 := rg.get(t, callbackURL, "")
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusSeeOther {
		t.Fatalf("first callback: got %d", resp3.StatusCode)
	}
	// Replay the same callback: the state is consumed.
	resp4 := rg.get(t, callbackURL, "")
	body := readBody(t, resp4)
	if !strings.Contains(body, "Black Candle sign-in failed") {
		t.Errorf("replayed state: missing error, got %.200s", body)
	}
}

func TestOAuthCallbackProviderError(t *testing.T) {
	rg := newOAuthTestRig(t)
	resp := rg.get(t, rg.dash.URL+"/oauth/bct/callback?error=access_denied&state=x", "")
	body := readBody(t, resp)
	if !strings.Contains(body, "cancelled or failed") {
		t.Errorf("provider error: missing message, got %.200s", body)
	}
}

func TestOAuthTokenExchangeFailure(t *testing.T) {
	rg := newOAuthTestRig(t)
	rg.provider.mu.Lock()
	rg.provider.failToken = true
	rg.provider.mu.Unlock()

	resp, _ := rg.driveFlow(t, "/oauth/bct/login", "")
	body := readBody(t, resp)
	if !strings.Contains(body, "Black Candle sign-in failed") {
		t.Errorf("exchange failure: missing error, got %.200s", body)
	}
}

func TestOAuthUnverifiedUserinfo(t *testing.T) {
	rg := newOAuthTestRig(t)
	rg.provider.mu.Lock()
	rg.provider.account.verified = false
	rg.provider.mu.Unlock()

	resp, _ := rg.driveFlow(t, "/oauth/bct/login", "")
	body := readBody(t, resp)
	if !strings.Contains(body, "isn&#39;t confirmed yet") && !strings.Contains(body, "isn't confirmed yet") {
		t.Errorf("unverified: missing confirm-email message, got %.300s", body)
	}
}

func TestOAuthNoPasswordForm(t *testing.T) {
	rg := newOAuthTestRig(t)

	// Login page: one Courier form + the OAuth button, no BCT password fields.
	resp := rg.get(t, rg.dash.URL+"/", "")
	body := readBody(t, resp)
	if !strings.Contains(body, "/oauth/bct/login") {
		t.Errorf("login page: missing OAuth button")
	}
	for _, bad := range []string{`action="/login-bct"`, `name="password" id="bp"`, "/settings/link-bct"} {
		if strings.Contains(body, bad) {
			t.Errorf("login page: still contains BCT password form fragment %q", bad)
		}
	}
	if got := strings.Count(body, "<form"); got != 1 {
		t.Errorf("login page: got %d forms, want 1 (Courier only)", got)
	}

	// Settings page: link button, no password form.
	_, cookie := oauthTestUser(t, rg, "ada")
	resp = rg.get(t, rg.dash.URL+"/settings", cookie)
	body = readBody(t, resp)
	if !strings.Contains(body, "/oauth/bct/link") {
		t.Errorf("settings: missing link button")
	}
	if strings.Contains(body, `action="/settings/link-bct"`) {
		t.Errorf("settings: still contains password link form")
	}
}

func TestOAuthDisabled(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st) // no OAuth config
	dash := httptest.NewServer(srv.Routes())
	t.Cleanup(dash.Close)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	// Unknown GET paths fall through to the login page (pre-existing mux
	// behavior); it must not offer OAuth.
	for _, path := range []string{"/", "/oauth/bct/login", "/oauth/bct/link", "/oauth/bct/callback?code=x&state=y"} {
		resp, err := client.Get(dash.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body := readBody(t, resp)
		if strings.Contains(body, "Black Candle") {
			t.Errorf("GET %s: mentions Black Candle while disabled", path)
		}
		if strings.Contains(body, "/oauth/bct/") {
			t.Errorf("GET %s: contains OAuth route while disabled", path)
		}
	}
}

func TestOAuthRedirectURIDerived(t *testing.T) {
	// Without an explicit RedirectURI the dashboard derives it from the
	// incoming request (https when X-Forwarded-Proto says so).
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	provider := newMockOAuthProvider(t)
	provSrv := httptest.NewServer(provider.handler())
	t.Cleanup(provSrv.Close)
	srv := NewWithBCT(st, BCTOAuthConfig{
		URL: provSrv.URL, ClientID: provider.clientID, ClientSecret: provider.clientSecret,
		// no RedirectURI
	})
	req := httptest.NewRequest("GET", "/oauth/bct/login", nil)
	req.Host = "courier.blackcandletech.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: got %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("redirect_uri"); got != "https://courier.blackcandletech.com"+bctOAuthCallbackPath {
		t.Errorf("derived redirect_uri = %q", got)
	}
}

func TestOAuthStateSingleUseAndExpiry(t *testing.T) {
	rg := newOAuthTestRig(t)
	c := rg.srv.bct

	s1, v1, err := c.newState(oauthIntentLogin, 0, "https://x/cb")
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := c.newState(oauthIntentLink, 7, "https://x/cb")
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Errorf("states not unique")
	}
	// PKCE challenge must be S256 of the verifier.
	sum := sha256.Sum256([]byte(v1))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); pkceChallenge(v1) != want {
		t.Errorf("pkceChallenge mismatch")
	}
	st, ok := c.consumeState(s1)
	if !ok || st.intent != oauthIntentLogin || st.userID != 0 || st.verifier != v1 {
		t.Errorf("consumeState(s1) = %+v, %v", st, ok)
	}
	if _, ok := c.consumeState(s1); ok {
		t.Errorf("state replay succeeded")
	}
	st2, ok := c.consumeState(s2)
	if !ok || st2.intent != oauthIntentLink || st2.userID != 7 {
		t.Errorf("consumeState(s2) = %+v, %v", st2, ok)
	}
	// Expired states are purged on next creation.
	s3, _, _ := c.newState(oauthIntentLogin, 0, "https://x/cb")
	c.mu.Lock()
	c.states[s3].expiresAt = time.Now().Add(-time.Minute)
	c.mu.Unlock()
	_, _, _ = c.newState(oauthIntentLogin, 0, "https://x/cb")
	c.mu.Lock()
	_, stillThere := c.states[s3]
	c.mu.Unlock()
	if stillThere {
		t.Errorf("expired state not purged")
	}
}
