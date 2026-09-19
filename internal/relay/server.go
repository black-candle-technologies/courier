// Package relay implements the Courier central relay: a store-and-forward
// mailbox. It validates envelope shape, verifies sender signatures
// (v0.2.0+), stores ciphertext, and serves it back to the addressed
// recipient. It can never read message contents.
package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// MaxCiphertextBytes caps a single message at 256 KiB.
const MaxCiphertextBytes = 256 * 1024

// MaxInboxLimit caps one inbox page.
const MaxInboxLimit = 200

// Server is the relay HTTP server.
type Server struct {
	store *store.Store
}

// New returns a Server backed by st.
func New(st *store.Store) *Server { return &Server{store: st} }

// Routes returns the HTTP handler with all endpoints registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/send", s.handleSend)
	mux.HandleFunc("GET /v1/inbox", s.handleInbox)
	mux.HandleFunc("POST /v1/keys", s.handleKeyAnnounce)
	mux.HandleFunc("GET /v1/keys/{address}", s.handleKeyLookup)
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

// sendRequest is the wire format for POST /v1/send. See PROTOCOL.md.
type sendRequest struct {
	To     string `json:"to"`
	From   string `json:"from"`
	Eph    string `json:"eph"`
	Nonce  string `json:"nonce"`
	Ct     string `json:"ct"`
	SentAt int64  `json:"sent_at"`
	Sig    string `json:"sig"`
}

// parseAddress strictly validates a v0.2.0+ "ed25519:<base64url>" address.
func parseAddress(s string) ([32]byte, error) {
	return crypto.ParseAddress(s)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.Count()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"time":      time.Now().UTC().Format(time.RFC3339),
		"envelopes": n,
		"version":   "0.5.0",
	})
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxCiphertextBytes+8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	to, err := parseAddress(req.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to": %v`, err))
		return
	}
	from, err := parseAddress(req.From)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"from": %v`, err))
		return
	}
	eph, err := base64.RawURLEncoding.DecodeString(req.Eph)
	if err != nil || len(eph) != crypto.PubKeyLen {
		writeErr(w, http.StatusBadRequest, `"eph" must be a base64url X25519 public key`)
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != crypto.NonceLen {
		writeErr(w, http.StatusBadRequest, `"nonce" must be base64url 24-byte nonce`)
		return
	}
	ct, err := base64.RawURLEncoding.DecodeString(req.Ct)
	if err != nil {
		writeErr(w, http.StatusBadRequest, `"ct" must be base64url ciphertext`)
		return
	}
	if len(ct) == 0 || len(ct) > MaxCiphertextBytes {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("ciphertext must be 1..%d bytes", MaxCiphertextBytes))
		return
	}
	if req.SentAt <= 0 {
		writeErr(w, http.StatusBadRequest, `"sent_at" must be a positive unix timestamp`)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Sig)
	if err != nil || len(sig) != 64 {
		writeErr(w, http.StatusBadRequest, `"sig" must be a base64url Ed25519 signature`)
		return
	}

	// Verify the sender's signature over the canonical envelope bytes.
	canon := envelope.Canonical(to[:], from[:], eph, nonce, req.SentAt, ct)
	if !crypto.Verify(from[:], canon, sig) {
		writeErr(w, http.StatusBadRequest, "signature verification failed")
		return
	}

	id, stored, err := s.store.Save(&store.Envelope{
		To: req.To, From: req.From, Eph: req.Eph,
		Nonce: req.Nonce, Ct: req.Ct, SentAt: req.SentAt, Sig: req.Sig,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	// A replayed envelope is acknowledged with its original id rather
	// than stored twice (v0.6.11 F3).
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "duplicate": !stored})
}

// ---- v0.5.0: signed encryption-key directory ----

// keyAnnounceRequest is the wire format for POST /v1/keys.
type keyAnnounceRequest struct {
	Address   string `json:"address"`    // ed25519:<base64url> identity
	X25519Pub string `json:"x25519_pub"` // base64url 32-byte encryption key
	Epoch     int64  `json:"epoch"`      // unix seconds of rotation
	Sig       string `json:"sig"`        // base64url Ed25519 signature
}

// handleKeyAnnounce accepts a signed key announcement. The signature must
// verify under the address's Ed25519 key, and the epoch must be strictly
// greater than the stored one, so only the address owner can rotate and
// old announcements cannot be replayed.
func (s *Server) handleKeyAnnounce(w http.ResponseWriter, r *http.Request) {
	var req keyAnnounceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	addr, err := parseAddress(req.Address)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"address": %v`, err))
		return
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(req.X25519Pub)
	if err != nil || len(pubRaw) != crypto.PubKeyLen {
		writeErr(w, http.StatusBadRequest, `"x25519_pub" must be a base64url 32-byte X25519 public key`)
		return
	}
	if req.Epoch <= 0 {
		writeErr(w, http.StatusBadRequest, `"epoch" must be a positive unix timestamp`)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Sig)
	if err != nil || len(sig) != 64 {
		writeErr(w, http.StatusBadRequest, `"sig" must be a base64url Ed25519 signature`)
		return
	}
	canon := envelope.KeyAnnounce(addr[:], pubRaw, req.Epoch)
	if !crypto.Verify(addr[:], canon, sig) {
		writeErr(w, http.StatusBadRequest, "signature verification failed")
		return
	}
	ok, err := s.store.SaveKey(&store.KeyAnnouncement{
		Address: req.Address, X25519Pub: req.X25519Pub, Epoch: req.Epoch,
		Sig: req.Sig,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, "stale epoch: a newer key announcement is already stored")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "epoch": req.Epoch})
}

// handleKeyLookup returns the current key announcement for an address, or
// 404 if the owner never published one (senders then fall back to the
// address-derived key).
func (s *Server) handleKeyLookup(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if _, err := parseAddress(address); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`address: %v`, err))
		return
	}
	k, err := s.store.GetKey(address)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no key announcement for this address"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"address": k.Address, "x25519_pub": k.X25519Pub, "epoch": k.Epoch,
		"sig": k.Sig,
	})
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	to := q.Get("to")
	if _, err := parseAddress(to); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to" query param: %v`, err))
		return
	}
	var after int64
	if a := q.Get("after"); a != "" {
		if _, err := fmt.Sscanf(a, "%d", &after); err != nil || after < 0 {
			writeErr(w, http.StatusBadRequest, `"after" must be a non-negative message id`)
			return
		}
	}
	limit := 50
	if l := q.Get("limit"); l != "" {
		if _, err := fmt.Sscanf(l, "%d", &limit); err != nil {
			writeErr(w, http.StatusBadRequest, `"limit" must be an integer`)
			return
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > MaxInboxLimit {
		limit = MaxInboxLimit
	}

	envs, err := s.store.List(to, after, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	type msg struct {
		ID         int64  `json:"id"`
		From       string `json:"from"`
		Eph        string `json:"eph"`
		Nonce      string `json:"nonce"`
		Ct         string `json:"ct"`
		SentAt     int64  `json:"sent_at"`
		ReceivedAt int64  `json:"received_at"`
		Sig        string `json:"sig"`
	}
	out := make([]msg, 0, len(envs))
	for _, e := range envs {
		out = append(out, msg{
			ID: e.ID, From: e.From, Eph: e.Eph, Nonce: e.Nonce,
			Ct: e.Ct, SentAt: e.SentAt, ReceivedAt: e.ReceivedAt, Sig: e.Sig,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}
