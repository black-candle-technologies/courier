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
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Version of the dashboard server.
const Version = "0.13.0"

//go:embed static/icon-192.png static/icon-512.png static/apple-touch-icon.png
var staticFiles embed.FS

// appManifest is the PWA manifest: it lets the dashboard be installed
// as an app (e.g. "Add to Home screen" on Android Chrome).
const appManifest = `{
  "name": "Courier dashboard",
  "short_name": "Courier",
  "description": "Read your Courier agent's messages",
  "id": "/app",
  "start_url": "/app",
  "scope": "/",
  "display": "standalone",
  "orientation": "portrait",
  "background_color": "#f4f5f7",
  "theme_color": "#174ea6",
  "icons": [
    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}
  ]
}`

// serviceWorker is a minimal worker: Chrome requires a fetch handler
// before it offers "install app". Dynamic pages stay network-first.
const serviceWorker = `self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function(e){
  e.respondWith(fetch(e.request).catch(function(){ return caches.match(e.request); }));
});`

// sessionTTL is how long a login session lasts.
const sessionTTL = 30 * 24 * time.Hour

// sessionCookie is the login session cookie name.
const sessionCookie = "courier_session"

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// Server is the dashboard HTTP server.
type Server struct {
	store *store.Store
	// bct is the optional Black Candle OAuth client. Nil unless the
	// operator configured the identity provider: the OAuth feature is
	// dormant in self-hosted installs.
	bct *bctOAuthClient
}

// New returns a Server backed by st.
func New(st *store.Store) *Server { return &Server{store: st} }

// NewWithBCT returns a Server backed by st with optional Black Candle
// login via OAuth. A zero BCTOAuthConfig disables the feature entirely:
// the OAuth routes are not registered and the UI affordances never
// render.
func NewWithBCT(st *store.Store, cfg BCTOAuthConfig) *Server {
	s := &Server{store: st}
	if cfg.URL != "" && cfg.ClientID != "" && cfg.ClientSecret != "" {
		s.bct = newBCTOAuthClient(cfg)
	}
	return s
}

// bctEnabled reports whether Black Candle OAuth login is configured.
func (s *Server) bctEnabled() bool { return s.bct != nil }

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
	// Optional Black Candle login via OAuth: only registered when the
	// identity provider is configured. Self-hosted installs never see
	// these routes or the UI that points at them.
	if s.bctEnabled() {
		mux.HandleFunc("GET /oauth/bct/login", s.handleOAuthBCTLogin)
		mux.HandleFunc("GET /oauth/bct/link", s.handleOAuthBCTLink)
		mux.HandleFunc("GET /oauth/bct/callback", s.handleOAuthBCTCallback)
		mux.HandleFunc("GET /settings", s.handleSettings)
		mux.HandleFunc("POST /settings/unlink-bct", s.handleUnlinkBCT)
	}
	// PWA install assets (no login required).
	mux.HandleFunc("GET /manifest.webmanifest", handleManifest)
	mux.HandleFunc("GET /sw.js", handleServiceWorker)
	mux.HandleFunc("GET /icon-192.png", handleStaticIcon("icon-192.png"))
	mux.HandleFunc("GET /icon-512.png", handleStaticIcon("icon-512.png"))
	mux.HandleFunc("GET /apple-touch-icon.png", handleStaticIcon("apple-touch-icon.png"))
	return mux
}

// handleManifest serves the PWA manifest for "install app" on Android.
func handleManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.WriteString(w, appManifest)
}

// handleServiceWorker serves the minimal worker Chrome requires before
// offering app installation.
func handleServiceWorker(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.WriteString(w, serviceWorker)
}

// handleStaticIcon serves an embedded PNG app icon.
func handleStaticIcon(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := staticFiles.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=604800")
		_, _ = w.Write(b)
	}
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
	// bcrypt errors past 72 bytes, so enforce the byte limit here with a
	// clear message instead of failing at hash time (F15).
	if len(req.Password) < 16 || len(req.Password) > 72 {
		writeErr(w, http.StatusBadRequest, "password must be 16-72 bytes")
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
	// issue #51: reply threading, reported by the agent (which
	// decrypted the envelope); the dashboard never decrypts.
	ReplyTo int64  `json:"reply_to,omitempty"`
	Quote   string `json:"quote,omitempty"`
	// ExpiresAt is the issue #53 disappearing-message expiry (0 =
	// never). Expired rows are filtered from reads and deleted by the
	// push-time sweep.
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// Bridged marks messages the agent derived as bridged (issues
	// #96/#97). Reported by the agent (which decrypted the envelope
	// and holds the pin list); the dashboard only displays it.
	Bridged bool `json:"bridged,omitempty"`
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
		Messages []pushMessage     `json:"messages"`
		Handles  map[string]string `json:"handles,omitempty"`
		Verified map[string]string `json:"verified,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Messages) > 200 {
		writeErr(w, http.StatusBadRequest, "at most 200 messages per push")
		return
	}
	// issue #39: peer handle labels. The agent resolves listed handles
	// via the signed directory reverse endpoint and pushes them; the
	// dashboard only displays what the agent reports — it never queries
	// the directory itself (it holds no identity key). Handles are
	// validated like any other directory input; an empty value clears
	// a stale label.
	for peer, handle := range req.Handles {
		if _, err := crypto.ParseAddress(peer); err != nil {
			continue
		}
		if handle != "" {
			h, err := envelope.NormalizeHandle(handle)
			if err != nil {
				continue
			}
			handle = h
		}
		if err := s.store.SavePeerHandle(user.ID, peer, handle); err != nil {
			writeErr(w, http.StatusInternalServerError, "store failed")
			return
		}
	}
	// issue #48: peer verification badges. Same trust model as handles:
	// the agent reports its out-of-band verification state and the
	// dashboard only displays it. Unknown peers get no badge.
	for peer, status := range req.Verified {
		if _, err := crypto.ParseAddress(peer); err != nil {
			continue
		}
		if status != "verified" && status != "stale" {
			continue
		}
		if err := s.store.SavePeerVerified(user.ID, peer, status); err != nil {
			writeErr(w, http.StatusInternalServerError, "store failed")
			return
		}
	}
	stored := 0
	now := time.Now().Unix()
	for _, m := range req.Messages {
		if len(m.Body) == 0 || len(m.Body) > 256*1024 || m.CourierID <= 0 {
			continue
		}
		if _, err := crypto.ParseAddress(m.From); err != nil {
			continue
		}
		// issue #51: the agent reports reply threading; the dashboard
		// only displays it. Sanitize defensively: a negative id is not
		// a reply, and the quote is length-bounded for storage.
		replyTo := m.ReplyTo
		if replyTo < 0 {
			replyTo = 0
		}
		quote := m.Quote
		if len(quote) > 4096 {
			quote = quote[:4096]
		}
		// issue #53: a negative expiry is a malformed push; an already
		// expired message is gone before it arrives — don't store it.
		if m.ExpiresAt < 0 {
			continue
		}
		if m.ExpiresAt != 0 && m.ExpiresAt <= now {
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
		inserted, err := s.store.SaveDashboardMessage(user.ID, m.CourierID, m.From, recipient, peer, m.Body, m.SentAt, m.ReceivedAt, replyTo, quote, m.ExpiresAt, m.Bridged)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store failed")
			return
		}
		if inserted {
			stored++
		}
	}
	// issue #53: disappearing-message sweep. Read paths already filter
	// expired rows; the sweep reclaims the space. Best-effort: a sweep
	// failure must not fail the push.
	_, _ = s.store.PruneExpiredDashboardMessages()
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
	render(w, loginTmpl, map[string]any{"BCTEnabled": s.bctEnabled()})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username, password := r.FormValue("username"), r.FormValue("password")
	user, err := s.store.DashboardUserByName(username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		render(w, loginTmpl, map[string]any{"Error": "Invalid username or password.", "BCTEnabled": s.bctEnabled()})
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
	// Optional search: keep only threads with a message matching q.
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q != "" {
		peers, err := s.store.SearchThreadPeers(u.ID, q)
		if err != nil {
			http.Error(w, "store failed", http.StatusInternalServerError)
			return
		}
		keep := make(map[string]bool, len(peers))
		for _, p := range peers {
			keep[p] = true
		}
		filtered := threads[:0]
		for _, th := range threads {
			if keep[th.Peer] {
				filtered = append(filtered, th)
			}
		}
		threads = filtered
	}
	type threadView struct {
		store.DashboardThread
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
		// issues #61/#96: flag the thread from the agent-reported
		// bridged flag OR the body banner, so threads badge even for
		// pushes that predate the stored flag.
		th.LastBridged = th.LastBridged || bridge.HasBanner(th.LastBody)
		views = append(views, threadView{
			DashboardThread: th,
			Preview:         preview,
		})
	}
	render(w, appTmpl, map[string]any{"User": u.Username, "Threads": views, "Q": q, "BCTEnabled": s.bctEnabled()})
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
	// Opening a thread marks it read up to the newest message actually
	// displayed. The maximum ID is computed explicitly (F14) rather than
	// taken from an assumed array position, so the watermark always
	// reflects what the user saw even if the display order changes.
	var maxID int64
	for _, m := range msgs {
		if m.ID > maxID {
			maxID = m.ID
		}
	}
	if err := s.store.MarkThreadSeen(u.ID, peer, maxID); err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
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
		// issues #61/#96: badge from the agent-reported bridged flag
		// OR the body banner, so messages badge even for pushes that
		// predate the stored flag.
		m.Bridged = m.Bridged || bridge.HasBanner(m.Body)
		views = append(views, msgView{DashboardMessage: m, Out: m.Sender == u.CourierAddress, TS: ts})
	}
	// issue #39: show the peer's listed handle when the agent resolved
	// one; the dashboard never queries the directory itself.
	// issue #48: same for the verification badge.
	var peerHandle, peerVerified string
	if handles, err := s.store.PeerHandles(u.ID, 7*24*time.Hour); err == nil {
		peerHandle = handles[peer]
	}
	if verified, err := s.store.PeerVerified(u.ID, 7*24*time.Hour); err == nil {
		peerVerified = verified[peer]
	}
	render(w, threadTmpl, map[string]any{
		"User": u.Username, "Peer": peer, "PeerHandle": peerHandle,
		"PeerVerified": peerVerified, "Messages": views,
	})
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
	// F6: a non-forced change must prove the current password, so anyone
	// holding only a stale session (or a leaked temp password after the
	// owner already changed it) cannot lock the owner out. The forced
	// first-login flow is authenticated by the temporary password
	// itself, so it is exempt — but its sessions are still revoked below.
	if !u.MustChange {
		cur := r.FormValue("current")
		if cur == "" || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(cur)) != nil {
			render(w, changeTmpl, map[string]any{"Forced": false, "Error": "Current password is incorrect."})
			return
		}
	}
	pw := r.FormValue("password")
	// bcrypt errors past 72 bytes: enforce the byte limit up front (F15).
	// len() on a string counts bytes, which is what bcrypt cares about.
	if len(pw) < 12 || len(pw) > 72 {
		render(w, changeTmpl, map[string]any{"Forced": u.MustChange, "Error": "Password must be 12-72 characters (max 72 bytes)."})
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
	if err := s.store.ChangeDashboardPassword(u.ID, string(hash)); err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	// F6: every session was revoked above (including the requester's), so
	// issue a fresh one to keep the requester logged in.
	if err := s.setSession(w, u.ID); err != nil {
		http.Error(w, "session failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- optional Black Candle login via OAuth ----

// requireBCTUser returns the session user when OAuth is enabled and the
// account is in good standing, redirecting otherwise.
func (s *Server) requireBCTUser(w http.ResponseWriter, r *http.Request) *store.DashboardUser {
	if !s.bctEnabled() {
		http.NotFound(w, r)
		return nil
	}
	u := s.sessionUser(r)
	if u == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}
	if u.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return nil
	}
	return u
}

// handleSettings shows the account settings page: Black Candle link
// status with a link button, or the unlink button when already linked.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	u := s.requireBCTUser(w, r)
	if u == nil {
		return
	}
	render(w, settingsTmpl, map[string]any{
		"User":     u.Username,
		"BCTEmail": u.BCTEmail,
		"Linked":   u.BCTUserID != 0,
	})
}

// handleUnlinkBCT removes the Black Candle binding. The dashboard
// username/password keeps working unchanged.
func (s *Server) handleUnlinkBCT(w http.ResponseWriter, r *http.Request) {
	u := s.requireBCTUser(w, r)
	if u == nil {
		return
	}
	if err := s.store.UnlinkBCTAccount(u.ID); err != nil {
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func render(w http.ResponseWriter, tmpl string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("p").Funcs(template.FuncMap{
		"ago":            ago,
		"until":          until,
		"senderShort":    senderShort,
		"senderInitials": senderInitials,
		"senderHue":      senderHue,
		"identicon":      identicon,
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

// until renders a future unix timestamp as a relative countdown
// ("in 5m", "in 2h") for issue #53 disappearing messages. Past
// timestamps render as "expired" (the row should already be gone;
// the sweep is best-effort).
func until(unix int64) string {
	d := time.Until(time.Unix(unix, 0))
	switch {
	case d <= 0:
		return "expired"
	case d < time.Hour:
		m := int(d.Minutes())
		if m < 1 {
			return "in under a minute"
		}
		return fmt.Sprintf("in %dm", m)
	case d < 24*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()))
	default:
		return fmt.Sprintf("in %dd", int(d.Hours()/24))
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

// identicon renders a deterministic, address-derived identicon as inline
// SVG: a 5x5 horizontally-symmetric block pattern in a stable hue
// (issue #39). It is generated at display time from the address alone —
// nothing is uploaded, nothing is stored, and no PII beyond the address
// the dashboard already holds is involved. The center cell is always
// filled so no address renders blank.
func identicon(addr string) template.HTML {
	sum := sha256.Sum256([]byte("courier-identicon/v1:" + addr))
	hue := (int(sum[0])<<8 | int(sum[1])) % 360
	bits := uint16(sum[2])<<8 | uint16(sum[3]) | 1<<8 // center cell (r=2,c=2) always on
	var sb strings.Builder
	sb.WriteString(`<svg class="identicon" viewBox="0 0 5 5" role="img" aria-label="sender identicon">`)
	fmt.Fprintf(&sb, `<rect width="5" height="5" rx="1" fill="hsl(%d 30%% 90%%)"/>`, hue)
	fmt.Fprintf(&sb, `<g fill="hsl(%d 55%% 42%%)">`, hue)
	for r := 0; r < 5; r++ {
		for c := 0; c < 3; c++ {
			if bits&(1<<(r*3+c)) == 0 {
				continue
			}
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="1" height="1"/>`, c, r)
			if c < 2 {
				fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="1" height="1"/>`, 4-c, r)
			}
		}
	}
	sb.WriteString(`</g></svg>`)
	return template.HTML(sb.String())
}

// pageHead holds the shared document head and the responsive stylesheet.
// Mobile-first: the base layout targets phones, with breakpoints widening
// the content column for tablets/laptops and desktops. Dark mode follows
// the OS preference.
// pageHead holds the shared document head and the responsive stylesheet.
// Mobile-first: the base layout targets phones, with breakpoints widening
// the content column for tablets/laptops and desktops. Dark mode follows
// the OS preference.
//
// The visual language mirrors blackcandletech.com ("quiet confidence"): a
// light editorial canvas with crisp ink typography, hairline borders, soft
// neutral shadows and one warm candlelight accent; dark mode reuses the
// site's deep-ink Courier band palette.
const pageHead = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#fbfbfc">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0a0a0d">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<title>Courier dashboard</title>
<style>
:root{
  /* blackcandletech.com light canvas */
  --bg:#fbfbfc; --bg-alt:#f4f4f6; --surface:#ffffff;
  --ink:#1d1d1f; --ink-2:#515154; --ink-3:#86868b;
  --line:rgba(0,0,0,.08); --line-strong:rgba(0,0,0,.16);
  /* candlelight accent */
  --accent:#b45309; --accent-strong:#92400e;
  --accent-soft:rgba(180,83,9,.07); --accent-line:rgba(180,83,9,.32);
  --error:#b3261e; --error-bg:rgba(200,40,40,.06); --error-line:rgba(200,40,40,.3);
  --out-bg:#1d1d1f; --out-ink:#ffffff;
  --badge-bg:#b45309; --badge-ink:#ffffff;
  --radius:20px; --radius-sm:12px; --maxw:44rem;
  --shadow-sm:0 1px 2px rgba(0,0,0,.05);
  --shadow-card:0 1px 2px rgba(0,0,0,.04),0 24px 48px -24px rgba(0,0,0,.16);
  --ease-enter:cubic-bezier(.22,1,.36,1);
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){
  :root{
    /* site's deep-ink Courier band */
    --bg:#0a0a0d; --bg-alt:#141419; --surface:#141419;
    --ink:#f5f5f7; --ink-2:#a1a1a6; --ink-3:#6e6e73;
    --line:rgba(255,255,255,.1); --line-strong:rgba(255,255,255,.2);
    --accent:#f0b35c; --accent-strong:#f8cf8a;
    --accent-soft:rgba(240,179,92,.1); --accent-line:rgba(240,179,92,.35);
    --error:#ff9e99; --error-bg:rgba(255,120,110,.08); --error-line:rgba(255,120,110,.35);
    --out-bg:#f5f5f7; --out-ink:#0a0a0d;
    --badge-bg:#f0b35c; --badge-ink:#0a0a0d;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased;
  text-rendering:optimizeLegibility}
::selection{background:rgba(180,83,9,.18)}
@media (prefers-color-scheme:dark){::selection{background:rgba(240,179,92,.25)}}
h1,h2{line-height:1.08;letter-spacing:-.03em;font-weight:700;margin:0}
h1{font-size:1.35rem}
h2{font-size:1.1rem}
p{margin:.4em 0}
code{font-family:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:.86em;background:rgba(0,0,0,.05);border:1px solid var(--line);
  border-radius:6px;padding:.12em .42em;white-space:nowrap}
@media (prefers-color-scheme:dark){code{background:rgba(255,255,255,.06)}}
a{color:inherit}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:4px}
.wrap{max-width:var(--maxw);margin:0 auto;
  padding:1rem max(.875rem,env(safe-area-inset-left)) 3rem}
@media(min-width:700px){
  :root{--maxw:48rem}
  .wrap{padding:2rem 1.25rem 4rem}
  h1{font-size:1.6rem}
}
@media(min-width:1100px){:root{--maxw:56rem}}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  padding:1.25rem;box-shadow:var(--shadow-sm)}
@media(min-width:700px){.card{padding:1.75rem}}
.card h2{font-size:1.2rem;letter-spacing:-.02em;margin:0 0 .4rem}
.eyebrow{color:var(--accent);text-transform:uppercase;font-size:12.5px;font-weight:700;
  letter-spacing:.18em;margin:0 0 .55rem}
/* auth pages */
.auth{max-width:26rem;margin:6vh auto 0}
@media(min-width:700px){.auth{margin-top:9vh}}
.auth .card{box-shadow:var(--shadow-card)}
.brand{display:flex;align-items:center;gap:.9rem;margin-bottom:1.5rem}
.mark{flex:none;width:3rem;height:3rem;border-radius:14px;background:var(--accent-soft);
  border:1px solid var(--accent-line);color:var(--accent);
  display:flex;align-items:center;justify-content:center;font-size:1.5rem}
.brand p{margin:.15em 0 0;color:var(--ink-2);font-size:.92rem}
.hint{color:var(--ink-2);font-size:.85rem;margin-top:1rem;text-align:center}
/* forms */
.field{margin:0 0 1.1rem}
label{display:block;font-weight:600;font-size:13.5px;color:var(--ink-2);margin-bottom:.45rem}
input[type=text],input[type=password]{width:100%;font-family:inherit;font-size:16px;
  color:var(--ink);background:var(--surface);border:1px solid var(--line-strong);
  border-radius:var(--radius-sm);padding:.75rem 1rem;
  transition:border-color .2s ease,box-shadow .2s ease}
input[type=text]:focus,input[type=password]:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-soft)}
input::placeholder{color:var(--ink-3)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  min-height:48px;font-family:inherit;font-size:15px;font-weight:600;line-height:1;
  padding:.85rem 1.75rem;border-radius:999px;border:1px solid transparent;
  background:var(--ink);color:#fff;cursor:pointer;text-decoration:none;white-space:nowrap;
  transition:background-color .2s ease,border-color .2s ease,color .2s ease,
    transform .2s var(--ease-enter),box-shadow .2s ease}
.btn:hover{background:#000}
.btn:active{transform:scale(.98)}
@media (prefers-color-scheme:dark){.btn{background:#fff;color:#1d1d1f}
  .btn:hover{background:#e8e8ed}}
.btn-block{width:100%}
.btn-ghost{background:transparent;color:var(--ink);border-color:var(--line-strong)}
.btn-ghost:hover{background:rgba(0,0,0,.04);border-color:var(--ink)}
@media (prefers-color-scheme:dark){.btn-ghost:hover{background:rgba(255,255,255,.06)}}
.btn-sm{font-size:13.5px;padding:.55rem 1.1rem;min-height:38px}
.error{background:var(--error-bg);color:var(--error);border:1px solid var(--error-line);
  border-radius:var(--radius-sm);padding:.75rem 1rem;margin:.75rem 0;font-size:.9rem}
/* app header */
.appbar{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--line)}
@supports ((-webkit-backdrop-filter:blur(20px)) or (backdrop-filter:blur(20px))){
  .appbar{background:color-mix(in srgb,var(--bg) 72%,transparent);
    -webkit-backdrop-filter:blur(20px) saturate(1.5);backdrop-filter:blur(20px) saturate(1.5)}
}
.appbar-inner{max-width:var(--maxw);margin:0 auto;
  padding:.6rem max(.875rem,env(safe-area-inset-left));
  display:flex;align-items:center;gap:.6rem .75rem;flex-wrap:wrap}
.appbar h1{flex:1;min-width:6rem}
.user{font-size:.85rem;color:var(--ink-2);max-width:11rem;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
/* threads */
.avatar{flex:none;width:2.3rem;height:2.3rem;border-radius:50%;color:#fff;
  display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.78rem}
.identicon{flex:none;width:2.3rem;height:2.3rem;border-radius:28%;
  box-shadow:inset 0 0 0 1px var(--line)}
.sender{display:block;font-family:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:.84rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.when{font-size:.78rem;color:var(--ink-3)}
.msg-body{margin:.3rem 0 0;white-space:pre-wrap;word-break:break-word;font-size:.95rem}
.thread{display:flex;align-items:center;gap:.85rem;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--radius);padding:.9rem 1.05rem;
  margin:0 0 .6rem;color:inherit;text-decoration:none;min-height:44px;
  transition:transform .25s var(--ease-enter),box-shadow .25s ease,border-color .25s ease}
.thread:hover{border-color:var(--line-strong);box-shadow:var(--shadow-sm)}
.thread:active{transform:scale(.99)}
.thread-main{flex:1;min-width:0}
.thread-top{display:flex;align-items:baseline;gap:.6rem;justify-content:space-between}
.thread-top .sender{flex:1;min-width:0}
/* issue #48: contact-verification badges */
.vbadge{display:inline-block;margin-left:.35rem;color:#2f9e44;font-weight:700}
.vbadge.stale{color:#d99413}
/* nbadge marks messages that arrived via a non-E2E bridge (issue #61):
   the body banner is the disclosure, this is the unmissable flag. */
.nbadge{display:inline-block;margin:.35rem 0 0;padding:.12rem .5rem;border-radius:999px;
  background:rgba(217,148,19,.14);border:1px solid rgba(217,148,19,.45);
  color:#8a5a0b;font-size:.72rem;font-weight:700;line-height:1.4;white-space:nowrap}
.nbadge.small{margin:0 0 0 .35rem;padding:.05rem .4rem;font-size:.68rem;vertical-align:baseline}
.preview{margin:.25rem 0 0;font-size:.9rem;color:var(--ink-2);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.count{flex:none;min-width:1.6rem;height:1.6rem;border-radius:999px;background:var(--line);
  color:var(--ink-2);font-size:.78rem;font-weight:700;display:flex;align-items:center;
  justify-content:center;padding:0 .45rem}
.unread{flex:none;min-width:1.6rem;height:1.6rem;border-radius:999px;background:var(--badge-bg);
  color:var(--badge-ink);font-size:.78rem;font-weight:700;display:flex;align-items:center;
  justify-content:center;padding:0 .45rem}
.search{display:flex;gap:.5rem;margin:0 0 .9rem}
.search input{flex:1;min-width:0;min-height:48px;border:1px solid var(--line-strong);
  border-radius:999px;background:var(--surface);color:var(--ink);font-family:inherit;
  padding:.6rem 1.1rem;font-size:1rem;transition:border-color .2s ease,box-shadow .2s ease}
.search input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.search .clear{flex:none;display:inline-flex;align-items:center;justify-content:center;
  width:48px;min-height:48px;border-radius:50%;background:var(--surface);color:var(--ink-2);
  text-decoration:none;font-size:1.4rem;line-height:1;border:1px solid var(--line-strong)}
.installbtn{flex:none;border:1px solid var(--line-strong);background:var(--surface);
  color:var(--accent);border-radius:999px;padding:.45rem 1rem;font-size:.85rem;
  font-weight:600;font-family:inherit;min-height:38px;cursor:pointer}
.installbtn[hidden]{display:none}
/* conversation */
.back{flex:none;display:inline-flex;align-items:center;justify-content:center;
  width:44px;height:44px;font-size:1.6rem;color:var(--ink);text-decoration:none;
  border-radius:12px}
.back:hover{background:rgba(0,0,0,.05)}
@media (prefers-color-scheme:dark){.back:hover{background:rgba(255,255,255,.06)}}
.thread-title{flex:1;min-width:0;font-family:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.thread-wrap{display:flex;flex-direction:column;gap:.55rem}
.row{display:flex;justify-content:flex-start}
.row.out{justify-content:flex-end}
.bubble{max-width:78%;background:var(--surface);border:1px solid var(--line);
  border-radius:var(--radius);padding:.65rem .95rem;box-shadow:var(--shadow-sm)}
@media(min-width:700px){.bubble{max-width:68%}}
.row.out .bubble{background:var(--out-bg);border-color:transparent}
.row.out .bubble .msg-body{color:var(--out-ink)}
.row.out .bubble .when{color:var(--out-ink);opacity:.7}
.bubble .when{display:block;margin-top:.35rem;font-size:.75rem;text-align:right}
/* issue #51: reply quote block inside a bubble */
.reply{margin:0 0 .4rem;padding:.35rem .65rem;border-left:3px solid var(--line);
  font-size:.8rem;color:var(--ink-2)}
.row.out .reply{border-left-color:var(--out-ink);color:var(--out-ink);opacity:.85}
.reply .reply-quote{display:block;margin-top:.15rem;font-style:italic;
  white-space:pre-wrap;word-break:break-word}
/* empty state */
.empty{text-align:center;padding:3rem 1.5rem;color:var(--ink-2)}
.empty-mark{font-size:2.5rem;margin-bottom:.5rem}
.empty h2{color:var(--ink);margin-bottom:.4rem}
.foot{margin-top:2.5rem;color:var(--ink-3);font-size:.78rem;text-align:center}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{transition:none!important;animation:none!important}
}
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
{{if .BCTEnabled}}
<div class="card" style="margin-top:1rem">
<p class="eyebrow">Black Candle</p>
<h2>Sign in with your account</h2>
<a class="btn btn-block" href="/oauth/bct/login" style="text-decoration:none;display:block;text-align:center">Log in with Black Candle</a>
<p class="hint" style="text-align:left;margin-bottom:0">You'll sign in on blackcandletech.com — your password never comes here. Works once you've linked your Black Candle account in Settings.</p>
</div>
{{end}}
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
{{if not .Forced}}
<div class="field">
<label for="cur">Current password</label>
<input id="cur" type="password" name="current" autocomplete="current-password" required>
</div>
{{end}}
<div class="field">
<label for="pw">New password (12+ characters, max 72 bytes)</label>
<input id="pw" type="password" name="password" autocomplete="new-password" minlength="12" maxlength="72" required>
</div>
<div class="field">
<label for="cf">Confirm new password</label>
<input id="cf" type="password" name="confirm" autocomplete="new-password" minlength="12" maxlength="72" required>
</div>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<button class="btn btn-block" type="submit">Set password</button>
</form>
</div>
</div></div></body></html>`

const settingsTmpl = pageHead + `
<header class="appbar"><div class="appbar-inner">
<a class="back" href="/app" aria-label="Back to messages">‹</a>
<h1>Settings</h1>
<span class="user" title="{{.User}}">{{.User}}</span>
</div></header>
<div class="wrap"><div class="auth" style="margin-top:2rem">
<div class="card">
<p class="eyebrow">Black Candle</p>
<h2>Account linking</h2>
{{if .Linked}}
<p>Linked to <strong>{{.BCTEmail}}</strong>. You can log in with either your dashboard password or your Black Candle account.</p>
<form method="post" action="/settings/unlink-bct">
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<button class="btn-ghost btn btn-block" type="submit">Unlink Black Candle account</button>
</form>
{{else}}
<p>Link your Black Candle account to log in with it. Optional — your dashboard username and password keep working either way.</p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<a class="btn btn-block" href="/oauth/bct/link" style="text-decoration:none;display:block;text-align:center">Link Black Candle account</a>
<p class="hint" style="text-align:left;margin-bottom:0">You'll sign in on blackcandletech.com and approve the link — your password never comes here.</p>
{{end}}
</div>
<div class="card" style="margin-top:1rem">
<p class="eyebrow">Security</p>
<h2>Password</h2>
<p><a href="/change-password">Change your dashboard password</a></p>
</div>
</div></div></body></html>`

const appTmpl = pageHead + `
<header class="appbar"><div class="appbar-inner">
<h1>Messages</h1>
<button class="installbtn" id="installBtn" hidden>Install app</button>
<span class="user" title="{{.User}}">{{.User}}</span>
{{if .BCTEnabled}}<a class="btn btn-ghost btn-sm" href="/settings">Settings</a>{{end}}
<form method="post" action="/logout"><button class="btn btn-ghost btn-sm" type="submit">Log out</button></form>
</div></header>
<div class="wrap">
<form class="search" method="get" action="/app" role="search">
<input type="search" name="q" value="{{.Q}}" placeholder="Search messages" aria-label="Search messages" autocomplete="off">
{{if .Q}}<a class="clear" href="/app" aria-label="Clear search">×</a>{{end}}
</form>
{{if .Threads}}
{{range .Threads}}<a class="thread" href="/app/thread?with={{.Peer}}">
{{identicon .Peer}}
<div class="thread-main">
<div class="thread-top">
{{if .Handle}}<span class="sender" title="{{.Peer}}">@{{.Handle}}</span>{{else}}<span class="sender" title="{{.Peer}}">{{senderShort .Peer}}</span>{{end}}{{if eq .Verified "verified"}}<span class="vbadge" title="Identity verified out of band">✓</span>{{else if eq .Verified "stale"}}<span class="vbadge stale" title="Their encryption key changed — re-verify out of band">⚠</span>{{end}}{{if .LastBridged}}<span class="nbadge small" title="Latest message arrived via the ChatGPT web bridge — not end-to-end encrypted">⚠</span>{{end}}
<span class="when" data-ts="{{.LastTS}}">{{ago .LastTS}}</span>
</div>
<p class="preview">{{.Preview}}</p>
</div>
{{if gt .Unread 0}}<span class="unread" aria-label="{{.Unread}} unread">{{.Unread}}</span>{{else if gt .Count 1}}<span class="count" aria-label="{{.Count}} messages">{{.Count}}</span>{{end}}
</a>{{end}}
{{else}}
{{if .Q}}
<div class="card empty">
<div class="empty-mark" aria-hidden="true">🔍</div>
<h2>No matches</h2>
<p>No messages contain “{{.Q}}”.</p>
</div>
{{else}}
<div class="card empty">
<div class="empty-mark" aria-hidden="true">✉</div>
<h2>No messages yet</h2>
<p>Your agent pushes new Courier messages here with <code>courier dashboard push</code>.</p>
</div>
{{end}}
{{end}}
<footer class="foot">Courier dashboard · messages are decrypted by your agent, never on this server</footer>
</div>` + pageFoot

// pageFoot closes the page and converts server-rendered relative times
// (data-ts = unix seconds) to the viewer's local time. Without JS the
// relative times remain.
const pageFoot = `<script>
(function(){try{
var els=document.querySelectorAll('[data-ts]');
if(!els.length)return;
function fmt(ms){
  var d=new Date(ms),t=d.toLocaleTimeString([], {hour:'numeric',minute:'2-digit'});
  var day=new Date(d.getFullYear(),d.getMonth(),d.getDate()).getTime();
  var now=new Date();now=new Date(now.getFullYear(),now.getMonth(),now.getDate()).getTime();
  var diff=Math.round((now-day)/864e5);
  if(diff<=0)return t;
  if(diff===1)return 'Yesterday '+t;
  if(diff<7)return d.toLocaleDateString([], {weekday:'short'})+' '+t;
  return d.toLocaleDateString([], {month:'short',day:'numeric'})+' '+t;
}
for(var i=0;i<els.length;i++){var e=els[i];e.textContent=fmt(1e3*+e.getAttribute('data-ts'));}
}catch(e){}})();
</script>
<script>
/* PWA install: register the worker, then show the Install button when
   Android Chrome fires beforeinstallprompt. */
(function(){try{
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(function(){});}
var btn=document.getElementById('installBtn');
if(!btn)return;
function inApp(){return window.matchMedia('(display-mode: standalone)').matches||window.navigator.standalone===true;}
if(inApp())return;
var deferred=null;
window.addEventListener('beforeinstallprompt',function(e){
  e.preventDefault();deferred=e;btn.hidden=false;
});
btn.addEventListener('click',function(){
  if(!deferred)return;
  deferred.prompt();
  deferred.userChoice.then(function(c){if(c&&c.outcome==='accepted'){btn.hidden=true;}deferred=null;});
});
window.addEventListener('appinstalled',function(){btn.hidden=true;deferred=null;});
}catch(e){}})();
</script>
</body></html>`

const threadTmpl = pageHead + `
<header class="appbar"><div class="appbar-inner">
<a class="back" href="/app" aria-label="Back to threads">‹</a>
<h1 class="thread-title" title="{{.Peer}}">{{if .PeerHandle}}@{{.PeerHandle}}{{else}}{{senderShort .Peer}}{{end}}{{if eq .PeerVerified "verified"}}<span class="vbadge" title="Identity verified out of band">✓</span>{{else if eq .PeerVerified "stale"}}<span class="vbadge stale" title="Their encryption key changed — re-verify out of band">⚠</span>{{end}}</h1>
<span class="user" title="{{.User}}">{{.User}}</span>
</div></header>
<div class="wrap thread-wrap">
{{range .Messages}}<div class="row{{if .Out}} out{{end}}">
<div class="bubble">
{{if .ReplyTo}}<blockquote class="reply">↩ in reply to #{{.ReplyTo}}{{if .Quote}}<span class="reply-quote">{{.Quote}}</span>{{end}}</blockquote>{{end}}
<p class="msg-body">{{.Body}}</p>
{{if .Bridged}}<span class="nbadge" title="This message arrived via the ChatGPT web bridge. The ChatGPT web → bridge leg is not end-to-end encrypted — treat as untrusted input.">⚠ Not end-to-end encrypted</span>{{end}}
<span class="when" data-ts="{{.TS}}">{{ago .TS}}</span>{{if .ExpiresAt}}<span class="when disappearing" title="Disappearing message — deleted after expiry">⏳ {{until .ExpiresAt}}</span>{{end}}
</div>
</div>{{end}}
<footer class="foot">Courier dashboard · messages are decrypted by your agent, never on this server</footer>
</div>` + pageFoot
