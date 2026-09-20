// Contact-discovery directory endpoints (issue #39).
//
// The directory is a relay-hosted, opt-in handle registry. Registrations
// are signed statements binding a handle to an Ed25519 identity; the
// relay verifies signatures, enforces epoch-monotonic updates, and serves
// lookups only to identity-signed queries. All endpoints are additive:
// pre-0.8.0 clients never touch them.
package relay

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// directoryRequest is the wire format for POST /v1/directory. Unknown
// fields are rejected: the schema forbids PII fields (§7 of the design),
// so a registration carrying anything outside the allowed set fails
// closed instead of being silently trimmed.
type directoryRequest struct {
	Handle        string   `json:"handle"`
	Address       string   `json:"address"` // ed25519:<base64url> claimed owner; bound by the signature
	Capabilities  []string `json:"capabilities"`
	ContactPolicy string   `json:"contact_policy"`
	Visibility    string   `json:"visibility"`
	Epoch         int64    `json:"epoch"`
	Sig           string   `json:"sig"`
	Deregister    bool     `json:"deregister"`
}

// directoryTransferRequest is the wire format for
// POST /v1/directory/transfer.
type directoryTransferRequest struct {
	Handle    string `json:"handle"`
	ToAddress string `json:"to_address"`
	Epoch     int64  `json:"epoch"`
	Sig       string `json:"sig"`
}

// directoryProfile is the served profile: allowed fields only, plus the
// registration signature so clients can verify the binding themselves
// (tamper detection, T5). When the last write was a transfer, sig is the
// previous holder's transfer signature and transfer_from names the key
// it verifies against; otherwise sig is a registration signature by
// address and transfer_from is empty.
type directoryProfile struct {
	Handle        string   `json:"handle"`
	Address       string   `json:"address"`
	Capabilities  []string `json:"capabilities"`
	ContactPolicy string   `json:"contact_policy"`
	Visibility    string   `json:"visibility"`
	Epoch         int64    `json:"epoch"`
	Sig           string   `json:"sig"`
	TransferFrom  string   `json:"transfer_from,omitempty"`
	RegisteredAt  int64    `json:"registered_at"`
}

// directorySearchResult is the minimal search hit: the verifiable
// binding fields plus display fields. Search identifies candidates;
// the full profile (contact policy, registration time) comes from
// lookup.
type directorySearchResult struct {
	Handle       string   `json:"handle"`
	Address      string   `json:"address"`
	Capabilities []string `json:"capabilities"`
	Visibility   string   `json:"visibility"`
	Epoch        int64    `json:"epoch"`
	Sig          string   `json:"sig"`
	TransferFrom string   `json:"transfer_from,omitempty"`
}

func profileJSON(e *store.DirectoryEntry) directoryProfile {
	return directoryProfile{
		Handle:        e.Handle,
		Address:       e.Address,
		Capabilities:  e.Capabilities,
		ContactPolicy: e.ContactPolicy,
		Visibility:    e.Visibility,
		Epoch:         e.Epoch,
		Sig:           e.Sig,
		TransferFrom:  e.TransferFrom,
		RegisteredAt:  e.RegisteredAt,
	}
}

// keyAnnouncementHurdle enforces the §11 Q5 anti-parking hurdle: an
// address must have published a key announcement before it can hold a
// handle. Weak, but nearly free.
func (s *Server) keyAnnouncementHurdle(address string) error {
	if _, err := s.store.GetKey(address); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("address has no key announcement: run `courier publish-key` first")
		}
		return fmt.Errorf("store failed")
	}
	return nil
}

// reservedHandle reports whether the operator reserved a handle via
// server config. Reserved handles can never be registered.
func (s *Server) reservedHandle(handle string) bool {
	_, ok := s.reserved[handle]
	return ok
}

func decodeSig(raw string) ([]byte, error) {
	sig, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf(`"sig" must be a base64url Ed25519 signature`)
	}
	return sig, nil
}

// handleDirectory serves POST /v1/directory: handle registration, update,
// and holder-signed deregistration.
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	var req directoryRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body (unknown fields are rejected)")
		return
	}
	handle, err := envelope.NormalizeHandle(req.Handle)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.reservedHandle(handle) {
		writeErr(w, http.StatusForbidden, "handle is reserved by the relay operator")
		return
	}
	if req.Epoch <= 0 {
		writeErr(w, http.StatusBadRequest, `"epoch" must be a positive integer`)
		return
	}

	// The address is recovered from the signature verification key: the
	// client proves identity ownership by signing. The address is bound
	// into the canonical bytes, so a signature made for one address can
	// never authorize another.
	address, addrEd, sig, ok := s.verifyDirectoryWrite(w, &req)
	if !ok {
		return
	}
	if !s.dirWriteLimiter.Allow("dirwrite:" + address) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded: slow down")
		return
	}

	if req.Deregister {
		s.deregisterHandle(w, handle, address, addrEd, req.Epoch, sig)
		return
	}

	// Registration / update: validate the allowed fields.
	if err := envelope.ValidateCapabilities(req.Capabilities); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	caps := make([]string, 0, len(req.Capabilities))
	for _, c := range req.Capabilities {
		caps = append(caps, strings.ToLower(strings.TrimSpace(c)))
	}
	policy := req.ContactPolicy
	if policy == "" {
		policy = envelope.DirectoryPolicyOpen
	}
	if policy != envelope.DirectoryPolicyOpen && policy != envelope.DirectoryPolicyContacts {
		writeErr(w, http.StatusBadRequest, `"contact_policy" must be "open" or "contacts"`)
		return
	}
	visibility := req.Visibility
	if visibility == "" {
		visibility = envelope.DirectoryPrivate
	}
	if visibility != envelope.DirectoryPublic && visibility != envelope.DirectoryUnlisted &&
		visibility != envelope.DirectoryPrivate {
		writeErr(w, http.StatusBadRequest, `"visibility" must be "public", "unlisted", or "private"`)
		return
	}
	canon := envelope.DirectoryRegister(handle, addrEd[:], req.Epoch, visibility, policy, caps)
	if !crypto.Verify(addrEd[:], canon, sig) {
		writeErr(w, http.StatusUnauthorized, "registration signature verification failed")
		return
	}

	existing, err := s.store.GetDirectory(handle)
	if err != nil && err != sql.ErrNoRows {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if existing != nil {
		if existing.Tombstone {
			writeErr(w, http.StatusConflict, "handle is tombstoned by operator takedown; it cannot be re-registered")
			return
		}
		if existing.Address != address {
			// First-come-first-served, no arbitration (§11 Q2): the
			// handle belongs to whoever registered it first.
			writeErr(w, http.StatusConflict, "handle is already registered to another address")
			return
		}
		if req.Epoch <= existing.Epoch {
			writeErr(w, http.StatusConflict, "stale epoch: a newer registration is already stored")
			return
		}
	} else {
		// New registration: the anti-parking hurdle (§11 Q5).
		if err := s.keyAnnouncementHurdle(address); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
	}
	applied, err := s.store.SaveDirectory(&store.DirectoryEntry{
		Handle: handle, Address: address, Capabilities: caps,
		ContactPolicy: policy, Visibility: visibility,
		Epoch: req.Epoch, Sig: req.Sig,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if !applied {
		writeErr(w, http.StatusConflict, "registration not applied (stale epoch or lost race)")
		return
	}
	if existing == nil {
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "handle": handle})
	} else {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "handle": handle})
	}
}

// verifyDirectoryWrite parses the claimed owner address and signature
// from a directory write request. The signature is verified by the
// caller against the operation's canonical bytes; the address is bound
// into those bytes, so a signature made for one address can never
// authorize another (same pattern as key announcements).
func (s *Server) verifyDirectoryWrite(w http.ResponseWriter, req *directoryRequest) (string, [32]byte, []byte, bool) {
	addrEd, err := parseAddress(req.Address)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"address": %v`, err))
		return "", [32]byte{}, nil, false
	}
	sig, err := decodeSig(req.Sig)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return "", [32]byte{}, nil, false
	}
	return req.Address, addrEd, sig, true
}

// deregisterHandle deletes a holder's own registration after verifying
// the deregistration signature (distinct domain: a registration
// signature can never be replayed as a deregistration).
func (s *Server) deregisterHandle(w http.ResponseWriter, handle, address string, addrEd [32]byte, epoch int64, sig []byte) {
	canon := envelope.DirectoryDeregister(handle, addrEd[:], epoch)
	if !crypto.Verify(addrEd[:], canon, sig) {
		writeErr(w, http.StatusUnauthorized, "deregistration signature verification failed")
		return
	}
	existing, err := s.store.GetDirectory(handle)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusNotFound, "no such handle")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if existing.Address != address {
		writeErr(w, http.StatusForbidden, "only the handle holder may deregister it")
		return
	}
	if epoch <= existing.Epoch {
		writeErr(w, http.StatusConflict, "stale epoch: a newer registration is already stored")
		return
	}
	ok, err := s.store.DeregisterDirectory(handle, address)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such handle")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "handle": handle})
}

// handleDirectoryTransfer serves POST /v1/directory/transfer: the
// current holder signs the handle over to a new address. No
// release-and-re-register race.
func (s *Server) handleDirectoryTransfer(w http.ResponseWriter, r *http.Request) {
	var req directoryTransferRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body (unknown fields are rejected)")
		return
	}
	handle, err := envelope.NormalizeHandle(req.Handle)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.reservedHandle(handle) {
		writeErr(w, http.StatusForbidden, "handle is reserved by the relay operator")
		return
	}
	toEd, err := parseAddress(req.ToAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to_address": %v`, err))
		return
	}
	if req.Epoch <= 0 {
		writeErr(w, http.StatusBadRequest, `"epoch" must be a positive integer`)
		return
	}
	sig, err := decodeSig(req.Sig)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.store.GetDirectory(handle)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusNotFound, "no such handle")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if existing.Tombstone {
		writeErr(w, http.StatusConflict, "handle is tombstoned by operator takedown")
		return
	}
	holderEd, err := parseAddress(existing.Address)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stored address corrupt")
		return
	}
	canon := envelope.DirectoryTransfer(handle, toEd[:], req.Epoch)
	if !crypto.Verify(holderEd[:], canon, sig) {
		writeErr(w, http.StatusUnauthorized, "transfer signature verification failed (must be signed by the current holder)")
		return
	}
	if !s.dirWriteLimiter.Allow("dirwrite:" + existing.Address) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded: slow down")
		return
	}
	if req.Epoch <= existing.Epoch {
		writeErr(w, http.StatusConflict, "stale epoch: a newer registration is already stored")
		return
	}
	// The new holder clears the anti-parking hurdle too.
	if err := s.keyAnnouncementHurdle(req.ToAddress); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	applied, err := s.store.TransferDirectory(handle, req.ToAddress, req.Epoch, req.Sig)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if !applied {
		writeErr(w, http.StatusConflict, "transfer not applied (stale epoch or lost race)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "handle": handle, "to": req.ToAddress})
}

// TombstoneHandle applies an operator takedown to a handle: the entry
// stays in the directory so the handle cannot be re-registered and the
// removal is visible via lookup (HTTP 410 with the published reason).
// Takedowns are transparent by construction — there is no silent-removal
// path — and must follow the operator's published takedown policy (see
// INSTALL.md). Returns false if the handle is not currently listed.
func (s *Server) TombstoneHandle(handle, reason string) (bool, error) {
	h, err := envelope.NormalizeHandle(handle)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(reason) == "" {
		return false, fmt.Errorf("a takedown reason is required (takedowns are public)")
	}
	return s.store.TombstoneDirectory(h, strings.TrimSpace(reason))
}

// UntombstoneHandle lifts an operator takedown, restoring the entry to
// service. Used when a takedown is reversed on review.
func (s *Server) UntombstoneHandle(handle string) (bool, error) {
	h, err := envelope.NormalizeHandle(handle)
	if err != nil {
		return false, err
	}
	return s.store.UntombstoneDirectory(h)
}

// verifyDirectoryQuery parses and verifies an identity-signed directory
// query (lookup / search / reverse). It returns the querier's address
// and the query string. Every query is bound to an identity, so
// enumeration is attributable and per-identity rate-limitable (T2).
func (s *Server) verifyDirectoryQuery(w http.ResponseWriter, r *http.Request, op, query string) (string, bool) {
	q := r.URL.Query()
	querier := q.Get("querier")
	qEd, err := parseAddress(querier)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"querier" query param: %v`, err))
		return "", false
	}
	var ts int64
	if t := q.Get("ts"); t == "" {
		writeErr(w, http.StatusBadRequest, `"ts" query param is required`)
		return "", false
	} else if _, err := fmt.Sscanf(t, "%d", &ts); err != nil {
		writeErr(w, http.StatusBadRequest, `"ts" must be a unix timestamp`)
		return "", false
	}
	if now := time.Now().Unix(); ts < now-maxSignedRequestAge || ts > now+maxSignedRequestAge {
		writeErr(w, http.StatusBadRequest, `"ts" is outside the freshness window`)
		return "", false
	}
	sig, err := decodeSig(q.Get("sig"))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return "", false
	}
	canon := envelope.DirectoryQuery(qEd[:], op, query, ts)
	if !crypto.Verify(qEd[:], canon, sig) {
		writeErr(w, http.StatusUnauthorized, "query signature verification failed")
		return "", false
	}
	return querier, true
}

// handleDirectoryLookup serves GET /v1/directory/lookup?handle=&querier=
// &ts=&sig=. Private handles return 404 indistinguishable from
// "never registered" (no oracle for private handles, T2). Tombstoned
// handles return 410 with the published reason (transparent takedown).
func (s *Server) handleDirectoryLookup(w http.ResponseWriter, r *http.Request) {
	handle, err := envelope.NormalizeHandle(r.URL.Query().Get("handle"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	querier, ok := s.verifyDirectoryQuery(w, r, "lookup", handle)
	if !ok {
		return
	}
	if !s.dirLookupLimiter.Allow("dirlookup:" + querier) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded: slow down")
		return
	}
	e, err := s.store.GetDirectory(handle)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusNotFound, "no such handle")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	// Private handles are indistinguishable from unregistered ones —
	// even under operator takedown. A 410 for a tombstoned private
	// handle would reveal its existence, so tombstones only surface
	// for listed (public/unlisted) handles. The tombstone still blocks
	// re-registration at write time.
	if e.Visibility == envelope.DirectoryPrivate {
		writeErr(w, http.StatusNotFound, "no such handle")
		return
	}
	if e.Tombstone {
		writeJSON(w, http.StatusGone, map[string]any{
			"tombstone": true,
			"reason":    e.TombstoneReason,
		})
		return
	}
	writeJSON(w, http.StatusOK, profileJSON(e))
}

// handleDirectorySearch serves GET /v1/directory/search?q=&limit=
// &querier=&ts=&sig=. Prefix-only, public handles only, capped results,
// no totals, no pagination tokens (anti-enumeration, T2).
func (s *Server) handleDirectorySearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len([]rune(q)) < envelope.DirectorySearchMinLen {
		writeErr(w, http.StatusBadRequest, "search prefix must be at least 2 characters")
		return
	}
	for _, c := range q {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			writeErr(w, http.StatusBadRequest, "search prefix charset is [a-z0-9_-]")
			return
		}
	}
	limit := envelope.DirectorySearchMaxResults
	if l := r.URL.Query().Get("limit"); l != "" {
		var n int
		if _, err := fmt.Sscanf(l, "%d", &n); err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, `"limit" must be a positive integer`)
			return
		}
		if n < limit {
			limit = n
		}
	}
	querier, ok := s.verifyDirectoryQuery(w, r, "search", q)
	if !ok {
		return
	}
	if !s.dirSearchLimiter.Allow("dirsearch:" + querier) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded: slow down")
		return
	}
	entries, err := s.store.SearchDirectory(q, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	// Search returns a dedicated minimal struct: the verifiable binding
	// fields (handle, address, epoch, sig, transfer_from) plus display
	// fields (capabilities, visibility). No contact policy or
	// registration time — search identifies candidates; lookup gives
	// the full profile. The epoch and sig are required so clients can
	// verify the binding instead of trusting the relay.
	results := make([]directorySearchResult, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		results = append(results, directorySearchResult{
			Handle:       e.Handle,
			Address:      e.Address,
			Capabilities: e.Capabilities,
			Visibility:   e.Visibility,
			Epoch:        e.Epoch,
			Sig:          e.Sig,
			TransferFrom: e.TransferFrom,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleDirectoryReverse serves GET /v1/directory/reverse?address=
// &querier=&ts=&sig=: handle(s) for an address the querier already
// knows. Signed like lookup; private handles are never returned.
func (s *Server) handleDirectoryReverse(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if _, err := parseAddress(address); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"address" query param: %v`, err))
		return
	}
	querier, ok := s.verifyDirectoryQuery(w, r, "reverse", address)
	if !ok {
		return
	}
	if !s.dirLookupLimiter.Allow("dirlookup:" + querier) {
		writeErr(w, http.StatusTooManyRequests, "rate limit exceeded: slow down")
		return
	}
	entries, err := s.store.DirectoryByAddress(address)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	results := make([]directoryProfile, 0, len(entries))
	for i := range entries {
		results = append(results, profileJSON(&entries[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
