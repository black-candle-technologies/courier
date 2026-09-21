package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Optional Black Candle account linking.
//
// The dashboard ships the linking code in every build, but the feature is
// dormant unless the operator configures an auth service (BCTConfig). That
// keeps one codebase and one release: the hosted dashboard sets the URL
// and API key, self-hosted installs simply don't, and the UI affordances
// never render for them. No build flags, no version split.
//
// Linking is per-user and opt-in: a logged-in user binds their dashboard
// account to a Black Candle account in Settings, and may unlink at any
// time. The dashboard username/password keeps working either way.
//
// Trust model: the dashboard acts as an authd API client (service API key
// in server config, never rendered to the browser). BCT passwords are
// passed through transiently to verify credentials and are never stored
// or logged. Verification goes through authd's own /v1/login, so its
// account lockout and rate limits apply unchanged.

// BCTConfig configures the optional Black Candle auth service. Zero value
// disables account linking.
type BCTConfig struct {
	// URL is the auth service base URL, e.g. https://auth.blackcandletech.com.
	URL string
	// APIKey is the authd service API key (X-Api-Key). Server-side only.
	APIKey string
}

// bctClient is a minimal authd API client used only for verifying Black
// Candle credentials during link and login.
type bctClient struct {
	url    string
	apiKey string
	http   *http.Client
}

func newBCTClient(url, apiKey string) *bctClient {
	return &bctClient{
		url:    strings.TrimSuffix(url, "/"),
		apiKey: apiKey,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// bctUser is the verified Black Candle account.
type bctUser struct {
	ID    int64
	Email string
}

var (
	// errBCTBadCredentials means authd rejected the email/password.
	errBCTBadCredentials = errors.New("invalid Black Candle email or password")
	// errBCTNeedsVerification means the credentials were right but the
	// BCT email address is not confirmed yet.
	errBCTNeedsVerification = errors.New("confirm your Black Candle email first, then link it here")
	// errBCTLocked means authd rate-limited or locked the account.
	errBCTLocked = errors.New("too many attempts — try again later")
	// errBCTUnavailable means the auth service could not be reached.
	errBCTUnavailable = errors.New("Black Candle sign-in is temporarily unavailable")
)

type bctLoginResponse struct {
	User struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	SessionToken string `json:"session_token"`
}

type bctErrorResponse struct {
	Error             string `json:"error"`
	NeedsVerification bool   `json:"needs_verification"`
}

// verifyCredentials checks a Black Candle email+password against authd.
// On success it destroys the throwaway authd session (linking and
// dashboard login need no authd session of their own) and returns the BCT
// user. A successful authd login sends the account holder a sign-in
// notification email — that is correct: this was a real sign-in.
func (c *bctClient) verifyCredentials(ctx context.Context, email, password, ip string) (*bctUser, error) {
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"ip":       ip,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/v1/login", bytes.NewReader(body))
	if err != nil {
		return nil, errBCTUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errBCTUnavailable
	}
	defer res.Body.Close()

	var out bctLoginResponse
	var errOut bctErrorResponse
	dec := json.NewDecoder(res.Body)
	switch res.StatusCode {
	case http.StatusOK:
		if err := dec.Decode(&out); err != nil || out.User.ID == 0 {
			return nil, errBCTUnavailable
		}
		// Destroy the throwaway session: best-effort, never fail the
		// verification on it.
		c.destroySession(ctx, out.SessionToken)
		return &bctUser{ID: out.User.ID, Email: out.User.Email}, nil
	case http.StatusForbidden:
		_ = dec.Decode(&errOut)
		if errOut.NeedsVerification {
			return nil, errBCTNeedsVerification
		}
		return nil, errBCTBadCredentials
	case http.StatusTooManyRequests:
		return nil, errBCTLocked
	default:
		return nil, errBCTBadCredentials
	}
}

// destroySession logs out a throwaway authd session. Best-effort.
func (c *bctClient) destroySession(ctx context.Context, token string) {
	if token == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"session_token": token})
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/v1/logout", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)
	res, err := c.http.Do(req)
	if err != nil {
		return
	}
	res.Body.Close()
}

// bctErrMessage maps a verification error to a user-facing message.
func bctErrMessage(err error) string {
	switch {
	case errors.Is(err, errBCTNeedsVerification):
		return "That Black Candle account's email isn't confirmed yet — check your inbox for the confirmation link, then try again."
	case errors.Is(err, errBCTLocked):
		return "Too many attempts. Try again in a few minutes."
	case errors.Is(err, errBCTUnavailable):
		return "Black Candle sign-in is temporarily unavailable. Try again in a moment."
	default:
		return "Invalid Black Candle email or password."
	}
}

// clientIP returns the remote host without the port, for the authd login
// record (it powers the "new sign-in" notification email).
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
