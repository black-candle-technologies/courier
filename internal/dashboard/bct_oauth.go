package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Optional Black Candle login via OAuth 2.0.
//
// The dashboard ships the OAuth code in every build, but the feature is
// dormant unless the operator configures the identity provider
// (BCTOAuthConfig). That keeps one codebase and one release: the hosted
// dashboard sets the provider URL, client ID, and secret, self-hosted
// installs simply don't, and the UI affordances never render for them.
// No build flags, no version split.
//
// OAuth is per-user and opt-in: a logged-in user binds their dashboard
// account to a Black Candle account in Settings (link intent), and may
// unlink at any time. Anyone can also log in directly with a Black
// Candle account that is already linked (login intent). The dashboard
// username/password keeps working either way.
//
// Trust model: the dashboard is an OAuth 2.0 confidential client. The
// client secret lives in server config and is never rendered to the
// browser. Black Candle passwords are never collected, transmitted, or
// stored by the dashboard — the user authenticates on
// auth.blackcandletech.com itself. The provider redirects back with a
// single-use authorization code, which the dashboard exchanges for a
// bearer token and uses to read the user's identity (id, email,
// email_verified). CSRF is bound by a single-use state parameter and
// authorization-code interception by PKCE S256.

// BCTOAuthConfig configures the optional Black Candle OAuth provider.
// Zero value disables the feature entirely. RedirectURI is the exact
// registered callback URI; when empty it is derived from the incoming
// request (scheme + host + /oauth/bct/callback).
type BCTOAuthConfig struct {
	// URL is the auth service base URL, e.g. https://auth.blackcandletech.com.
	URL string
	// ClientID is the OAuth client_id registered with the provider.
	ClientID string
	// ClientSecret is the OAuth client secret. Server-side only.
	ClientSecret string
	// RedirectURI overrides the derived callback URI. Set it explicitly
	// in production (e.g. https://courier.blackcandletech.com/oauth/bct/callback).
	RedirectURI string
}

// bctOAuthClient is the dashboard's OAuth 2.0 client for the Black
// Candle identity provider, plus the in-flight authorization state.
type bctOAuthClient struct {
	cfg  BCTOAuthConfig
	http *http.Client
	mu   sync.Mutex
	// states holds unredeemed authorization states: single-use,
	// ten-minute expiry, purged lazily on creation.
	states map[string]*oauthState
}

func newBCTOAuthClient(cfg BCTOAuthConfig) *bctOAuthClient {
	return &bctOAuthClient{
		cfg:    cfg,
		http:   &http.Client{Timeout: 10 * time.Second},
		states: make(map[string]*oauthState),
	}
}

const (
	oauthIntentLogin = "login"
	oauthIntentLink  = "link"
	// oauthStateTTL bounds an in-flight authorization to 10 minutes.
	oauthStateTTL = 10 * time.Minute
	// bctOAuthCallbackPath is the dashboard's registered callback path.
	bctOAuthCallbackPath = "/oauth/bct/callback"
)

// oauthState is one in-flight authorization request.
type oauthState struct {
	intent      string // oauthIntentLogin | oauthIntentLink
	userID      int64  // dashboard user for link intents; 0 for login
	verifier    string // PKCE verifier
	expiresAt   time.Time
	redirectURI string // exact redirect_uri sent to the provider
}

// randomB64 returns n crypto-random bytes as unpadded base64url.
func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge derives the S256 code_challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newState creates, stores, and returns a fresh single-use state value.
func (c *bctOAuthClient) newState(intent string, userID int64, redirectURI string) (string, string, error) {
	state, err := randomB64(32)
	if err != nil {
		return "", "", err
	}
	verifier, err := randomB64(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	// Lazy purge of expired states.
	for k, st := range c.states {
		if now.After(st.expiresAt) {
			delete(c.states, k)
		}
	}
	c.states[state] = &oauthState{
		intent:      intent,
		userID:      userID,
		verifier:    verifier,
		redirectURI: redirectURI,
		expiresAt:   now.Add(oauthStateTTL),
	}
	return state, verifier, nil
}

// consumeState atomically takes and deletes a state: single-use, so a
// replayed or expired state fails closed.
func (c *bctOAuthClient) consumeState(state string) (*oauthState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.states[state]
	if ok {
		delete(c.states, state)
	}
	if !ok || time.Now().After(st.expiresAt) {
		return nil, false
	}
	return st, true
}

// redirectURIFor returns the exact callback URI: explicit config wins,
// otherwise derived from the incoming request.
func (c *bctOAuthClient) redirectURIFor(r *http.Request) string {
	if c.cfg.RedirectURI != "" {
		return c.cfg.RedirectURI
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + bctOAuthCallbackPath
}

// authorizeURL builds the provider's /oauth/authorize URL.
func (c *bctOAuthClient) authorizeURL(state, verifier, redirectURI string) string {
	q := url.Values{
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"identity"},
		"state":                 {state},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	return strings.TrimSuffix(c.cfg.URL, "/") + "/oauth/authorize?" + q.Encode()
}

var (
	// errOAuthExchange means the code/token exchange with the provider failed.
	errOAuthExchange = errors.New("sign-in with Black Candle failed — try again")
	// errOAuthUnverified means the Black Candle email is not confirmed.
	errOAuthUnverified = errors.New("confirm your Black Candle email first, then try again")
	// errOAuthUnavailable means the provider could not be reached.
	errOAuthUnavailable = errors.New("the Black Candle sign-in service is temporarily unavailable")
)

// exchangeCode trades an authorization code for an access token.
func (c *bctOAuthClient) exchangeCode(r *http.Request, code, verifier, redirectURI string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST",
		strings.TrimSuffix(c.cfg.URL, "/")+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errOAuthUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	res, err := c.http.Do(req)
	if err != nil {
		return "", errOAuthUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", errOAuthExchange
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", errOAuthExchange
	}
	return out.AccessToken, nil
}

// bctIdentity is the verified Black Candle account behind an access token.
type bctIdentity struct {
	ID    int64
	Email string
}

// fetchIdentity reads /oauth/userinfo for the access token.
func (c *bctOAuthClient) fetchIdentity(r *http.Request, token string) (*bctIdentity, error) {
	req, err := http.NewRequestWithContext(r.Context(), "GET",
		strings.TrimSuffix(c.cfg.URL, "/")+"/oauth/userinfo", nil)
	if err != nil {
		return nil, errOAuthUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errOAuthUnavailable
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		var out struct {
			ID            int64  `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.ID == 0 {
			return nil, errOAuthExchange
		}
		if !out.EmailVerified {
			return nil, errOAuthUnverified
		}
		return &bctIdentity{ID: out.ID, Email: out.Email}, nil
	case http.StatusForbidden:
		return nil, errOAuthUnverified
	default:
		return nil, errOAuthExchange
	}
}

// oauthErrMessage maps an OAuth failure to a user-facing message.
func oauthErrMessage(err error) string {
	switch {
	case errors.Is(err, errOAuthUnverified):
		return "That Black Candle account's email isn't confirmed yet — check your inbox for the confirmation link, then try again."
	case errors.Is(err, errOAuthUnavailable):
		return "Black Candle sign-in is temporarily unavailable. Try again in a moment."
	default:
		return "Black Candle sign-in failed. Try again."
	}
}

// ---- dashboard handlers ----

// startOAuthFlow creates the state and redirects the browser to the
// provider's authorization endpoint.
func (s *Server) startOAuthFlow(w http.ResponseWriter, r *http.Request, intent string, userID int64) {
	if !s.bctEnabled() {
		http.NotFound(w, r)
		return
	}
	redirectURI := s.bct.redirectURIFor(r)
	state, verifier, err := s.bct.newState(intent, userID, redirectURI)
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.bct.authorizeURL(state, verifier, redirectURI), http.StatusFound)
}

// handleOAuthBCTLogin starts the login flow: no dashboard session needed.
func (s *Server) handleOAuthBCTLogin(w http.ResponseWriter, r *http.Request) {
	s.startOAuthFlow(w, r, oauthIntentLogin, 0)
}

// handleOAuthBCTLink starts the link flow: the user must already be
// logged into the dashboard, and the state is bound to their user ID.
func (s *Server) handleOAuthBCTLink(w http.ResponseWriter, r *http.Request) {
	u := s.requireBCTUser(w, r)
	if u == nil {
		return
	}
	s.startOAuthFlow(w, r, oauthIntentLink, u.ID)
}

// handleOAuthBCTCallback handles the provider's redirect: validate and
// consume the state, exchange the code, fetch the identity, then either
// log in or link depending on the intent.
func (s *Server) handleOAuthBCTCallback(w http.ResponseWriter, r *http.Request) {
	if !s.bctEnabled() {
		http.NotFound(w, r)
		return
	}
	fail := func(msg string) {
		render(w, loginTmpl, map[string]any{"Error": msg, "BCTEnabled": true})
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		fail("Black Candle sign-in was cancelled or failed. Try again.")
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		fail("Black Candle sign-in failed. Try again.")
		return
	}
	st, ok := s.bct.consumeState(state)
	if !ok {
		fail("Black Candle sign-in failed. Try again.")
		return
	}
	token, err := s.bct.exchangeCode(r, code, st.verifier, st.redirectURI)
	if err != nil {
		fail(oauthErrMessage(err))
		return
	}
	id, err := s.bct.fetchIdentity(r, token)
	if err != nil {
		fail(oauthErrMessage(err))
		return
	}
	switch st.intent {
	case oauthIntentLink:
		s.finishOAuthLink(w, r, st, id)
	case oauthIntentLogin:
		s.finishOAuthLogin(w, r, id)
	default:
		fail("Black Candle sign-in failed. Try again.")
	}
}

// finishOAuthLink binds the verified Black Candle account to the
// dashboard user the state was issued for. The session must still belong
// to that same user.
func (s *Server) finishOAuthLink(w http.ResponseWriter, r *http.Request, st *oauthState, id *bctIdentity) {
	u := s.requireBCTUser(w, r)
	if u == nil {
		return
	}
	if u.ID != st.userID {
		http.Error(w, "session changed during sign-in — try again", http.StatusBadRequest)
		return
	}
	// One BCT account links to at most one dashboard user. Re-linking
	// the same account to the same user is a no-op success (idempotent).
	if other, err := s.store.DashboardUserByBCTUserID(id.ID); err == nil && other.ID != u.ID {
		render(w, settingsTmpl, map[string]any{
			"User": u.Username, "BCTEmail": u.BCTEmail, "Linked": u.BCTUserID != 0,
			"Error": "That Black Candle account is already linked to another dashboard user.",
		})
		return
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	if err := s.store.LinkBCTAccount(u.ID, id.ID, id.Email); err != nil {
		// A unique-index race surfaces here if two users link the same
		// BCT account concurrently.
		render(w, settingsTmpl, map[string]any{
			"User": u.Username, "BCTEmail": u.BCTEmail, "Linked": u.BCTUserID != 0,
			"Error": "That Black Candle account is already linked to another dashboard user.",
		})
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// finishOAuthLogin maps the verified Black Candle account to the linked
// dashboard user and issues a dashboard session.
func (s *Server) finishOAuthLogin(w http.ResponseWriter, r *http.Request, id *bctIdentity) {
	user, err := s.store.DashboardUserByBCTUserID(id.ID)
	if err != nil {
		render(w, loginTmpl, map[string]any{
			"BCTEnabled": true,
			"Error":      "No Courier account is linked to that Black Candle account yet — log in with your Courier credentials and link it in Settings.",
		})
		return
	}
	if err := s.setSession(w, user.ID); err != nil {
		http.Error(w, "session failed", http.StatusInternalServerError)
		return
	}
	if user.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}
