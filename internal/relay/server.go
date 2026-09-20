// Package relay implements the Courier central relay: a store-and-forward
// mailbox. It validates envelope shape, verifies sender signatures
// (v0.2.0+), stores ciphertext, and serves it back to the addressed
// recipient. It can never read message contents.
package relay

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// MaxCiphertextBytes caps a single message at 256 KiB.
const MaxCiphertextBytes = 256 * 1024

// MaxInboxLimit caps one inbox page.
const MaxInboxLimit = 200

// MaxInboxPageBytes caps one inbox page by encoded size (v0.6.11 F8).
// Pages were bounded by message count only, so large ciphertexts could
// exceed the client's 8 MiB read limit. 1 MiB leaves ample headroom.
const MaxInboxPageBytes = 1 << 20

// maxSignedRequestAge bounds signed request timestamps: the relay
// rejects requests older or newer than 300 seconds (v0.6.11 F10), so a
// captured signed request cannot be replayed indefinitely.
const maxSignedRequestAge = 300

// MaxBlobUploadBytes caps a blob upload body: the largest attachment
// plus framing overhead, with slack for the HTTP framing.
const MaxBlobUploadBytes = envelope.MaxBlobBytes + 8192

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
	mux.HandleFunc("POST /v1/blobs", s.handleBlobUpload)
	mux.HandleFunc("GET /v1/blobs/{blob_id}", s.handleBlobDownload)
	mux.HandleFunc("POST /v1/keys", s.handleKeyAnnounce)
	mux.HandleFunc("GET /v1/keys/{address}", s.handleKeyLookup)
	// issue #32: group messaging.
	mux.HandleFunc("POST /v1/groups/control", s.handleGroupControl)
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
// Kind/KeyEpoch carry issue #32 group messages: kind is "" (or "dm")
// for direct messages and "group" for group messages; key_epoch is the
// sender's group sender-key epoch covered by the group signature.
type sendRequest struct {
	To       string `json:"to"`
	From     string `json:"from"`
	Eph      string `json:"eph"`
	Nonce    string `json:"nonce"`
	Ct       string `json:"ct"`
	SentAt   int64  `json:"sent_at"`
	Sig      string `json:"sig"`
	Kind     string `json:"kind,omitempty"`
	KeyEpoch int64  `json:"key_epoch,omitempty"`
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
		"version":   "0.6.12",
	})
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxCiphertextBytes+8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// issue #32: envelopes addressed to a group ID take the group path.
	if strings.HasPrefix(req.To, envelope.GroupIDPrefix) {
		s.handleGroupSend(w, req)
		return
	}
	if req.Kind != "" && req.Kind != "dm" {
		writeErr(w, http.StatusBadRequest, `"kind" must be "" or "dm" for direct messages`)
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
	// issue #32: reads addressed to a group ID take the group path, with
	// a signed membership authorization instead of an address-key one.
	if strings.HasPrefix(q.Get("to"), envelope.GroupIDPrefix) {
		s.handleGroupInbox(w, r)
		return
	}
	to := q.Get("to")
	toEd, err := parseAddress(to)
	if err != nil {
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

	// v0.6.11 (F10): inbox reads require a recipient-signed request, so
	// only the address owner can read their ciphertext and metadata.
	// The signature covers the requested address, cursor, limit, and a
	// timestamp, and is verified against the "to" address key — which
	// also binds the requester to the address they are reading.
	var ts int64
	if t := q.Get("ts"); t == "" {
		writeErr(w, http.StatusBadRequest, `"ts" query param is required`)
		return
	} else if _, err := fmt.Sscanf(t, "%d", &ts); err != nil {
		writeErr(w, http.StatusBadRequest, `"ts" must be a unix timestamp`)
		return
	}
	if now := time.Now().Unix(); ts < now-maxSignedRequestAge || ts > now+maxSignedRequestAge {
		writeErr(w, http.StatusBadRequest, `"ts" is outside the freshness window`)
		return
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	if err != nil || len(sigRaw) != 64 {
		writeErr(w, http.StatusUnauthorized, `"sig" must be a base64url Ed25519 signature`)
		return
	}
	canon := envelope.InboxRequest(toEd[:], after, int64(limit), ts)
	if !crypto.Verify(toEd[:], canon, sigRaw) {
		writeErr(w, http.StatusUnauthorized, "inbox request signature verification failed")
		return
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
	var size int
	for _, e := range envs {
		// Bound the page by encoded bytes (v0.6.11 F8): the base64url
		// fields plus JSON overhead per message. Always return at
		// least one message; pagination continues via after=lastID.
		size += len(e.From) + len(e.Eph) + len(e.Nonce) + len(e.Ct) + len(e.Sig) + 128
		if size > MaxInboxPageBytes && len(out) > 0 {
			break
		}
		out = append(out, msg{
			ID: e.ID, From: e.From, Eph: e.Eph, Nonce: e.Nonce,
			Ct: e.Ct, SentAt: e.SentAt, ReceivedAt: e.ReceivedAt, Sig: e.Sig,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

// ---- Attachments: encrypted blob store ----

// parseBlobAuth parses and freshness-checks the common signed-request
// query params used by the blob endpoints (ts, sig), mirroring the
// inbox-request authorization style.
func parseBlobAuth(get func(string) string) (ts int64, sig []byte, err error) {
	t := get("ts")
	if t == "" {
		return 0, nil, fmt.Errorf(`"ts" query param is required`)
	}
	if _, err := fmt.Sscanf(t, "%d", &ts); err != nil {
		return 0, nil, fmt.Errorf(`"ts" must be a unix timestamp`)
	}
	if now := time.Now().Unix(); ts < now-maxSignedRequestAge || ts > now+maxSignedRequestAge {
		return 0, nil, fmt.Errorf(`"ts" is outside the freshness window`)
	}
	sig, err = base64.RawURLEncoding.DecodeString(get("sig"))
	if err != nil || len(sig) != 64 {
		return 0, nil, fmt.Errorf(`"sig" must be a base64url Ed25519 signature`)
	}
	return ts, sig, nil
}

// handleBlobUpload stores one encrypted attachment blob.
//
//	POST /v1/blobs?from=<addr>&to=<addr>&blob_id=<b64url32>&size=<bytes>&ts=<unix>&sig=<b64url>
//
// The body is the opaque framed ciphertext. Authorization is a
// sender-signed statement binding the uploader, the intended recipient,
// the random blob id, the exact byte size, and a timestamp — so blob
// storage is attributable, and the recipient's signed inbox messages
// later tell them exactly which blob ids to fetch. The relay enforces
// the size cap and replays are idempotent: re-uploading the same blob id
// returns the stored record (duplicate=true) instead of a second row.
func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, err := parseAddress(q.Get("from"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"from": %v`, err))
		return
	}
	to, err := parseAddress(q.Get("to"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to": %v`, err))
		return
	}
	blobIDRaw, err := base64.RawURLEncoding.DecodeString(q.Get("blob_id"))
	if err != nil || len(blobIDRaw) != 32 {
		writeErr(w, http.StatusBadRequest, `"blob_id" must be base64url 32 random bytes`)
		return
	}
	var size int64
	if _, err := fmt.Sscanf(q.Get("size"), "%d", &size); err != nil || size <= 0 || size > envelope.MaxBlobBytes {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"size" must be a positive integer <= %d`, envelope.MaxBlobBytes))
		return
	}
	ts, sig, err := parseBlobAuth(q.Get)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !crypto.Verify(from[:], envelope.BlobUpload(from[:], to[:], blobIDRaw, size, ts), sig) {
		writeErr(w, http.StatusUnauthorized, "blob upload signature verification failed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBlobUploadBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "failed to read blob body")
		return
	}
	if int64(len(body)) != size {
		writeErr(w, http.StatusBadRequest, "body size does not match the declared size")
		return
	}
	stored, err := s.store.SaveBlob(&store.Blob{
		BlobID:    q.Get("blob_id"),
		Recipient: q.Get("to"),
		Uploader:  q.Get("from"),
		Size:      size,
		Data:      body,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"blob_id": q.Get("blob_id"), "duplicate": !stored})
}

// handleBlobDownload returns one stored blob's ciphertext.
//
//	GET /v1/blobs/<blob_id>?ts=<unix>&sig=<b64url>
//
// Authorization is a recipient-signed, freshness-checked request over
// the blob id — mirroring inbox reads — verified against the address
// the blob was uploaded for. Anyone else, the relay included, gets
// ciphertext they cannot use; the blob is returned only to its
// recipient. Unknown blob ids 404 without leaking whether an id was
// ever valid for a different recipient.
func (s *Server) handleBlobDownload(w http.ResponseWriter, r *http.Request) {
	blobID := r.PathValue("blob_id")
	blobIDRaw, err := base64.RawURLEncoding.DecodeString(blobID)
	if err != nil || len(blobIDRaw) != 32 {
		writeErr(w, http.StatusBadRequest, `"blob_id" must be base64url 32 random bytes`)
		return
	}
	blob, err := s.store.GetBlob(blobID)
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusNotFound, "unknown blob")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	recipient, err := parseAddress(blob.Recipient)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stored recipient is corrupt")
		return
	}
	q := r.URL.Query()
	ts, sig, err := parseBlobAuth(q.Get)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !crypto.Verify(recipient[:], envelope.BlobRequest(recipient[:], blobIDRaw, ts), sig) {
		writeErr(w, http.StatusUnauthorized, "blob request signature verification failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(blob.Data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob.Data)
}
