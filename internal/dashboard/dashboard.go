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
	"hash/fnv"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Version of the dashboard server.
const Version = "0.6.7"

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
	mux.HandleFunc("GET /app/thread", s.handleThread)
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
	To         string `json:"to,omitempty"` // set for outbound messages the agent sent
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
		// peer is the counterparty: the sender for inbound messages, the
		// recipient for outbound ones the agent sent itself.
		peer := m.From
		recipient := ""
		if m.To != "" {
			if _, err := crypto.ParseAddress(m.To); err != nil {
				continue
			}
			if m.From != user.CourierAddress {
				continue // agents only push their own sent mail
			}
			recipient = m.To
			peer = m.To
		}
		inserted, err := s.store.SaveDashboardMessage(user.ID, m.CourierID, m.From, recipient, peer, m.Body, m.SentAt, m.ReceivedAt)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store failed")
			return
		}
		if inserted {
			stored++
		}
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
	threads, err := s.store.DashboardThreads(u.ID, u.CourierAddress, 100)
	if err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	type threadView struct {
		store.DashboardThread
		PeerArg string // url-escaped peer for the thread link
		Preview string // truncated last-message preview
	}
	views := make([]threadView, 0, len(threads))
	for _, th := range threads {
		preview := th.LastBody
		if th.LastOut {
			preview = "You: " + preview
		}
		if len([]rune(preview)) > 120 {
			preview = string([]rune(preview)[:120]) + "…"
		}
		views = append(views, threadView{
			DashboardThread: th,
			PeerArg:         url.QueryEscape(th.Peer),
			Preview:         preview,
		})
	}
	render(w, appTmpl, map[string]any{"User": u.Username, "Threads": views})
}

// handleThread shows one conversation: every message exchanged with a
// single counterparty address, oldest first, with the user's own messages
// on the right.
func (s *Server) handleThread(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(r)
	if u == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if u.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}
	peer := r.URL.Query().Get("with")
	if _, err := crypto.ParseAddress(peer); err != nil {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	msgs, err := s.store.DashboardThreadMessages(u.ID, peer, 500)
	if err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	if len(msgs) == 0 {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	type msgView struct {
		store.DashboardMessage
		Out bool
		TS  int64
	}
	views := make([]msgView, 0, len(msgs))
	for _, m := range msgs {
		ts := m.SentAt
		if m.ReceivedAt > ts {
			ts = m.ReceivedAt
		}
		views = append(views, msgView{DashboardMessage: m, Out: m.Sender == u.CourierAddress, TS: ts})
	}
	render(w, threadTmpl, map[string]any{"User": u.Username, "Peer": peer, "Messages": views})
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
		"ago":            ago,
		"senderShort":    senderShort,
		"senderInitials": senderInitials,
		"senderHue":      senderHue,
	}).Parse(tmpl))
	_ = t.Execute(w, data)
}

// ago renders a unix timestamp as a human relative time ("3h ago").
func ago(unix int64) string {
	d := time.Since(time.Unix(unix, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return time.Unix(unix, 0).Format("Jan 2, 2006")
	}
}

// senderShort truncates a Courier address for display while keeping it
// identifiable: ed25519:hsJUdq…AVXHqSQ.
func senderShort(addr string) string {
	const prefix = "ed25519:"
	key := strings.TrimPrefix(addr, prefix)
	if len(key) <= 14 {
		return addr
	}
	return prefix + key[:6] + "…" + key[len(key)-6:]
}

// senderInitials returns up to two uppercase alphanumeric characters from
// the address, used for the sender avatar.
func senderInitials(addr string) string {
	key := strings.TrimPrefix(addr, "ed25519:")
	out := make([]byte, 0, 2)
	for i := 0; i < len(key) && len(out) < 2; i++ {
		c := key[i]
		switch {
		case 'a' <= c && c <= 'z':
			out = append(out, c-('a'-'A'))
		case 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

// senderHue derives a stable avatar hue (0-359) from the sender address.
func senderHue(addr string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(addr))
	return int(h.Sum32() % 360)
}

// pageHead holds the shared document head and the responsive stylesheet.
// Mobile-first: the base layout targets phones, with breakpoints widening
// the content column for tablets/laptops and desktops. Dark mode follows
// the OS preference.
const pageHead = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Courier dashboard</title>
<style>
:root{
  --bg:#f4f5f7; --card:#ffffff; --ink:#14171c; --muted:#606875;
  --line:#e2e6ec; --accent:#174ea6; --accent-ink:#ffffff;
  --error:#b3261e; --error-bg:#fbeae8;
  --radius:14px; --maxw:44rem;
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d1015; --card:#151a22; --ink:#e9ecf1; --muted:#9aa3b2;
    --line:#242c38; --accent:#8ab4f8; --accent-ink:#0d1015;
    --error:#ff8a80; --error-bg:#3a1e1b;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  font-size:16px;line-height:1.55}
h1{font-size:1.35rem;margin:0}
h2{font-size:1.1rem;margin:0 0 .4rem}
p{margin:.4em 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em}
.wrap{max-width:var(--maxw);margin:0 auto;padding:1rem .875rem 3rem}
@media(min-width:700px){
  :root{--maxw:48rem}
  .wrap{padding:2rem 1.25rem 4rem}
  h1{font-size:1.6rem}
}
@media(min-width:1100px){:root{--maxw:56rem}}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:1.1rem;box-shadow:0 1px 2px rgba(0,0,0,.05)}
@media(min-width:700px){.card{padding:1.5rem}}
/* auth pages */
.auth{max-width:26rem;margin:6vh auto 0}
@media(min-width:700px){.auth{margin-top:10vh}}
.brand{display:flex;align-items:center;gap:.8rem;margin-bottom:1.25rem}
.mark{flex:none;width:2.75rem;height:2.75rem;border-radius:12px;background:var(--ink);color:var(--bg);
  display:flex;align-items:center;justify-content:center;font-size:1.4rem}
.brand p{margin:.1em 0 0;color:var(--muted);font-size:.92rem}
.hint{color:var(--muted);font-size:.85rem;margin-top:1rem;text-align:center}
/* forms */
.field{margin:0 0 1rem}
label{display:block;font-weight:600;font-size:.9rem;margin-bottom:.35rem}
input[type=text],input[type=password]{width:100%;font-size:16px;padding:.7rem .8rem;
  border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink)}
input:focus{border-color:var(--accent);outline:none}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;
  font-size:1rem;font-weight:600;border:0;border-radius:10px;padding:.7rem 1.25rem;
  background:var(--accent);color:var(--accent-ink);cursor:pointer;text-decoration:none}
.btn-block{width:100%}
.btn-ghost{background:transparent;color:var(--ink);border:1px solid var(--line);
  min-height:40px;padding:.45rem .9rem;font-size:.9rem}
.error{background:var(--error-bg);color:var(--error);border:1px solid var(--error);
  border-radius:10px;padding:.6rem .8rem;margin:.75rem 0;font-size:.9rem}
/* app header */
.appbar{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--line)}
@supports ((-webkit-backdrop-filter:blur(8px)) or (backdrop-filter:blur(8px))){
  .appbar{background:color-mix(in srgb, var(--bg) 82%, transparent);
    -webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}
}
.appbar-inner{max-width:var(--maxw);margin:0 auto;padding:.55rem .875rem;
  display:flex;align-items:center;gap:.6rem .75rem;flex-wrap:wrap}
.appbar h1{flex:1;min-width:6rem}
.user{font-size:.85rem;color:var(--muted);max-width:11rem;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
/* threads */
.avatar{flex:none;width:2.3rem;height:2.3rem;border-radius:50%;color:#fff;
  display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.78rem}
.sender{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.84rem;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.when{font-size:.78rem;color:var(--muted)}
.msg-body{margin:.3rem 0 0;white-space:pre-wrap;word-break:break-word;font-size:.95rem}
.thread{display:flex;align-items:center;gap:.75rem;background:var(--card);
  border:1px solid var(--line);border-radius:var(--radius);padding:.85rem 1rem;
  margin:0 0 .6rem;color:inherit;text-decoration:none;min-height:44px}
@media(min-width:700px){.thread{padding:.95rem 1.15rem}}
.thread:active{background:var(--line)}
.thread-main{flex:1;min-width:0}
.thread-top{display:flex;align-items:baseline;gap:.6rem;justify-content:space-between}
.thread-top .sender{flex:1;min-width:0}
.preview{margin:.25rem 0 0;font-size:.9rem;color:var(--muted);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.count{flex:none;min-width:1.6rem;height:1.6rem;border-radius:999px;background:var(--line);
  color:var(--muted);font-size:.78rem;font-weight:700;display:flex;align-items:center;
  justify-content:center;padding:0 .45rem}
/* conversation */
.back{flex:none;display:inline-flex;align-items:center;justify-content:center;
  width:44px;height:44px;font-size:1.6rem;color:var(--ink);text-decoration:none;
  border-radius:10px}
.thread-title{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.thread-wrap{display:flex;flex-direction:column;gap:.5rem}
.row{display:flex;justify-content:flex-start}
.row.out{justify-content:flex-end}
.bubble{max-width:78%;background:var(--card);border:1px solid var(--line);
  border-radius:var(--radius);padding:.6rem .85rem}
@media(min-width:700px){.bubble{max-width:68%}}
.row.out .bubble{background:var(--accent);border-color:transparent}
.row.out .bubble .msg-body{color:var(--accent-ink)}
.row.out .bubble .when{color:var(--accent-ink);opacity:.75}
.bubble .when{display:block;margin-top:.3rem;font-size:.75rem;text-align:right}
/* empty state */
.empty{text-align:center;padding:3rem 1.5rem;color:var(--muted)}
.empty-mark{font-size:2.5rem;margin-bottom:.5rem}
.empty h2{color:var(--ink)}
.foot{margin-top:2.5rem;color:var(--muted);font-size:.78rem;text-align:center}
</style></head><body>`

const loginTmpl = pageHead + `
<div class="wrap"><div class="auth">
<header class="brand">
  <div class="mark" aria-hidden="true">◈</div>
  <div><h1>Courier</h1><p>Messages from your agent, decrypted for your eyes only.</p></div>
</header>
<div class="card">
<form method="post" action="/login">
<div class="field">
<label for="u">Username</label>
<input id="u" type="text" name="username" autocomplete="username" autocapitalize="none" autocorrect="off" required>
</div>
<div class="field">
<label for="p">Password</label>
<input id="p" type="password" name="password" autocomplete="current-password" required>
</div>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<button class="btn btn-block" type="submit">Log in</button>
</form>
</div>
<p class="hint">Your agent created this account with a temporary password — you'll set your own on first login.</p>
</div></div></body></html>`

const changeTmpl = pageHead + `
<div class="wrap"><div class="auth">
<header class="brand">
  <div class="mark" aria-hidden="true">◈</div>
  <div><h1>{{if .Forced}}Set your password{{else}}Change password{{end}}</h1>
  {{if .Forced}}<p>Your temporary password has expired. Pick a new one to continue.</p>{{end}}</div>
</header>
<div class="card">
<form method="post" action="/change-password">
<div class="field">
<label for="pw">New password (12+ characters)</label>
<input id="pw" type="password" name="password" autocomplete="new-password" required>
</div>
<div class="field">
<label for="cf">Confirm new password</label>
<input id="cf" type="password" name="confirm" autocomplete="new-password" required>
</div>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<button class="btn btn-block" type="submit">Set password</button>
</form>
</div>
</div></div></body></html>`

const appTmpl = pageHead + `
<header class="appbar"><div class="appbar-inner">
<h1>Messages</h1>
<span class="user" title="{{.User}}">{{.User}}</span>
<form method="post" action="/logout"><button class="btn-ghost btn" type="submit">Log out</button></form>
</div></header>
<div class="wrap">
{{if .Threads}}
{{range .Threads}}<a class="thread" href="/app/thread?with={{.PeerArg}}">
<span class="avatar" style="background:hsl({{senderHue .Peer}} 55% 38%)" aria-hidden="true">{{senderInitials .Peer}}</span>
<div class="thread-main">
<div class="thread-top">
<span class="sender" title="{{.Peer}}">{{senderShort .Peer}}</span>
<span class="when">{{ago .LastTS}}</span>
</div>
<p class="preview">{{.Preview}}</p>
</div>
{{if gt .Count 1}}<span class="count" aria-label="{{.Count}} messages">{{.Count}}</span>{{end}}
</a>{{end}}
{{else}}
<div class="card empty">
<div class="empty-mark" aria-hidden="true">✉</div>
<h2>No messages yet</h2>
<p>Your agent pushes new Courier messages here with <code>courier dashboard push</code>.</p>
</div>
{{end}}
<footer class="foot">Courier dashboard · messages are decrypted by your agent, never on this server</footer>
</div></body></html>`

const threadTmpl = pageHead + `
<header class="appbar"><div class="appbar-inner">
<a class="back" href="/app" aria-label="Back to threads">‹</a>
<h1 class="thread-title" title="{{.Peer}}">{{senderShort .Peer}}</h1>
<span class="user" title="{{.User}}">{{.User}}</span>
</div></header>
<div class="wrap thread-wrap">
{{range .Messages}}<div class="row{{if .Out}} out{{end}}">
<div class="bubble">
<p class="msg-body">{{.Body}}</p>
<span class="when">{{ago .TS}}</span>
</div>
</div>{{end}}
<footer class="foot">Courier dashboard · messages are decrypted by your agent, never on this server</footer>
</div></body></html>`
