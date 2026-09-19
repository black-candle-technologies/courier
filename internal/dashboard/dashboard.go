// Package dashboard implements the Courier web dashboard (v0.6.0): a
// human-facing web app where a user logs in and reads the decrypted
// messages their agent's Courier identity received.
//
// Trust model: the dashboard never holds Courier private keys and cannot
// decrypt anything itself. The agent — which legitimately holds its keys —
// decrypts its inbox and pushes plaintext to the dashboard over a
// per-user API token (`courier dashboard push`). Users authenticate with
// username + password (bcrypt). The first password is temporary, generated
// by the agent at registration, and must be changed on first login.
package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Version of the dashboard server.
const Version = "0.6.0"

// sessionTTL is how long a login session lasts.
const sessionTTL = 30 * 24 * time.Hour

// sessionCookie is the login session cookie name.
const sessionCookie = "courier_session"

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// Server is the dashboard HTTP server.
type Server struct {
	store *store.Store
}

// New returns a Server backed by st.
func New(st *store.Store) *Server { return &Server{store: st} }

// Routes returns the HTTP handler with all endpoints registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	// Agent APIs (JSON).
	mux.HandleFunc("POST /v1/dashboard/register", s.handleRegister)
	mux.HandleFunc("POST /v1/dashboard/push", s.handlePush)
	// Human web UI.
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /app", s.handleApp)
	mux.HandleFunc("GET /change-password", s.handleChangePasswordForm)
	mux.HandleFunc("POST /change-password", s.handleChangePassword)
	mux.HandleFunc("POST /logout", s.handleLogout)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": Version})
}

// ---- agent API: registration ----

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"` // temporary; must be changed on first login
	Address  string `json:"address"`  // ed25519:<base64url> Courier identity
	Sig      string `json:"sig"`      // Ed25519 signature over the registration
}

// handleRegister creates a dashboard user. The Ed25519 signature proves the
// caller holds the Courier identity's private key, binding the username to
// that address. Returns the API token (shown once) the agent uses to push
// messages.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !usernameRe.MatchString(req.Username) {
		writeErr(w, http.StatusBadRequest, "username must be 3-32 chars: lowercase letters, digits, - and _")
		return
	}
	if len(req.Password) < 16 || len(req.Password) > 128 {
		writeErr(w, http.StatusBadRequest, "password must be 16-128 characters")
		return
	}
	addr, err := crypto.ParseAddress(req.Address)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("address: %v", err))
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Sig)
	if err != nil || len(sig) != 64 {
		writeErr(w, http.StatusBadRequest, `"sig" must be a base64url Ed25519 signature`)
		return
	}
	canon := envelope.DashboardRegister(req.Username, addr[:])
	if !crypto.Verify(addr[:], canon, sig) {
		writeErr(w, http.StatusBadRequest, "signature verification failed")
		return
	}
	if _, err := s.store.DashboardUserByName(req.Username); err == nil {
		writeErr(w, http.StatusConflict, "username is taken")
		return
	} else if err != sql.ErrNoRows {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	pwHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash failed")
		return
	}
	token, tokenHash, err := newAPIToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token failed")
		return
	}
	if _, err := s.store.CreateDashboardUser(req.Username, string(pwHash), req.Address, tokenHash); err != nil {
		writeErr(w, http.StatusConflict, "username or address is already registered")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"username":  req.Username,
		"api_token": token, // shown once: the agent stores it, it is never stored raw
	})
}

// newAPIToken generates a random API token and its SHA256 hex hash.
func newAPIToken() (token, hash string, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// ---- agent API: message push ----

type pushMessage struct {
	CourierID  int64  `json:"courier_id"`
	From       string `json:"from"`
	Body       string `json:"body"`
	SentAt     int64  `json:"sent_at"`
	ReceivedAt int64  `json:"received_at"`
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return ""
	}
	return h[len(prefix):]
}

// handlePush accepts decrypted messages from the agent that owns the API
// token. The dashboard cannot decrypt Courier envelopes itself; the agent
// pushes what it decrypted from its own inbox.
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeErr(w, http.StatusUnauthorized, "bearer API token required")
		return
	}
	sum := sha256.Sum256([]byte(token))
	user, err := s.store.DashboardUserByTokenHash(hex.EncodeToString(sum[:]))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid API token")
		return
	}
	var req struct {
		Messages []pushMessage `json:"messages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Messages) > 200 {
		writeErr(w, http.StatusBadRequest, "at most 200 messages per push")
		return
	}
	stored := 0
	for _, m := range req.Messages {
		if len(m.Body) == 0 || len(m.Body) > 256*1024 || m.CourierID <= 0 {
			continue
		}
		if _, err := crypto.ParseAddress(m.From); err != nil {
			continue
		}
		if err := s.store.SaveDashboardMessage(user.ID, m.CourierID, m.From, m.Body, m.SentAt, m.ReceivedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "store failed")
			return
		}
		stored++
	}
	writeJSON(w, http.StatusOK, map[string]any{"stored": stored})
}

// ---- human web UI ----

func (s *Server) sessionUser(r *http.Request) *store.DashboardUser {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(c.Value))
	u, err := s.store.SessionUser(hex.EncodeToString(sum[:]))
	if err != nil {
		return nil
	}
	return u
}

func (s *Server) setSession(w http.ResponseWriter, userID int64) error {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	if err := s.store.CreateSession(hex.EncodeToString(sum[:]), userID, sessionTTL); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true, // dashboard is TLS-only
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		sum := sha256.Sum256([]byte(c.Value))
		_ = s.store.DeleteSession(hex.EncodeToString(sum[:]))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if u := s.sessionUser(r); u != nil {
		if u.MustChange {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	render(w, loginTmpl, nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username, password := r.FormValue("username"), r.FormValue("password")
	user, err := s.store.DashboardUserByName(username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		render(w, loginTmpl, map[string]any{"Error": "Invalid username or password."})
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

func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(r)
	if u == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if u.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}
	msgs, err := s.store.DashboardMessages(u.ID, 200)
	if err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	render(w, appTmpl, map[string]any{"User": u.Username, "Messages": msgs})
}

func (s *Server) handleChangePasswordForm(w http.ResponseWriter, r *http.Request) {
	if s.sessionUser(r) == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	render(w, changeTmpl, map[string]any{"Forced": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(r)
	if u == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pw := r.FormValue("password")
	if len(pw) < 12 || len(pw) > 128 {
		render(w, changeTmpl, map[string]any{"Forced": u.MustChange, "Error": "Password must be 12-128 characters."})
		return
	}
	if pw != r.FormValue("confirm") {
		render(w, changeTmpl, map[string]any{"Forced": u.MustChange, "Error": "Passwords do not match."})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "hash failed", http.StatusInternalServerError)
		return
	}
	if err := s.store.SetDashboardPassword(u.ID, string(hash)); err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func render(w http.ResponseWriter, tmpl string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("p").Funcs(template.FuncMap{
		"time": func(unix int64) string {
			return time.Unix(unix, 0).Format("2006-01-02 15:04:05 MST")
		},
	}).Parse(tmpl))
	_ = t.Execute(w, data)
}

const pageHead = `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Courier dashboard</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:720px;margin:2em auto;padding:0 1em;color:#1a1a1a;background:#fafafa}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:1.5em;margin:1em 0}
input,button{font-size:1em;padding:.5em;margin:.25em 0}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{background:#111;color:#fff;border:0;border-radius:4px;padding:.6em 1.2em;cursor:pointer}
.error{color:#a00;margin:.5em 0}
.msg{border-bottom:1px solid #eee;padding:.75em 0}
.meta{color:#666;font-size:.85em}
pre{white-space:pre-wrap;word-wrap:break-word;margin:.4em 0}
.top{display:flex;justify-content:space-between;align-items:center}
</style></head><body>`

const loginTmpl = pageHead + `
<h1>Courier dashboard</h1>
<div class="card">
<form method="post" action="/login">
<label>Username<br><input type="text" name="username" autocomplete="username" required></label><br>
<label>Password<br><input type="password" name="password" autocomplete="current-password" required></label><br>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<button type="submit">Log in</button>
</form>
<p class="meta">Your agent created this account with a temporary password. You'll be asked to change it on first login.</p>
</div></body></html>`

const changeTmpl = pageHead + `
<h1>{{if .Forced}}Choose a new password{{else}}Change password{{end}}</h1>
<div class="card">
{{if .Forced}}<p>Your temporary password has expired. Pick a new one to continue.</p>{{end}}
<form method="post" action="/change-password">
<label>New password (12+ characters)<br><input type="password" name="password" autocomplete="new-password" required></label><br>
<label>Confirm<br><input type="password" name="confirm" autocomplete="new-password" required></label><br>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<button type="submit">Set password</button>
</form>
</div></body></html>`

const appTmpl = pageHead + `
<div class="top"><h1>Messages</h1>
<form method="post" action="/logout"><button type="submit">Log out ({{.User}})</button></form>
</div>
{{if .Messages}}
{{range .Messages}}<div class="card msg">
<div class="meta">From <code>{{.Sender}}</code> · courier #{{.CourierID}} · {{.ReceivedAt | time}}</div>
<pre>{{.Body}}</pre>
</div>{{end}}
{{else}}
<div class="card"><p>No messages yet. Your agent pushes new Courier messages here with <code>courier dashboard push</code>.</p></div>
{{end}}
</body></html>`
