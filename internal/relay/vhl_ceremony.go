package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// VHL WebAuthn ceremony transport (issue #142).
//
// The agent cannot touch a YubiKey, so the human performs the
// WebAuthn ceremony in their browser on the dashboard host while the
// agent orchestrates over an authenticated API:
//
//  1. The agent creates a ceremony: POST /v1/vhl/ceremonies with a
//     request signed by its identity key over the ceremony type, the
//     challenge the authenticator must answer, and a fresh timestamp.
//  2. The relay answers with a short random single-use code and a
//     ceremony path. The code is short-lived (vhlCeremonyTTL) and
//     the agent prints the full ceremony URL for the human.
//  3. The human opens the URL in their browser (logged into the
//     dashboard), and the page runs navigator.credentials.create()
//     (enrollment) or .get() (session mint, action approval,
//     approver enrollment) with the agent's challenge. For mint,
//     approve, and enroll-approver the page first displays the
//     human-reviewed ceremony context (what authority is being
//     granted) and recomputes the challenge from the displayed
//     context, refusing to proceed on mismatch. The browser POSTs
//     the attestation/assertion back through the relay. Browser
//     endpoints are gated on the shared dashboard session cookie,
//     and the session's Courier address must match the address
//     that created the ceremony.
//  4. The agent polls GET /v1/vhl/ceremonies/{code}/result (signed
//     request, same identity) until the attestation arrives, then
//     independently verifies it against its own RP config: exact
//     challenge equality/freshness, expected RP ID and origin, user
//     verification, and the authenticator signature/attestation.
//
// Trust boundary: the relay is an authenticated pipe. It sees the
// challenge and the ceremony responses, but it never sees private
// key material; it cannot mint a session token (minting needs the
// agent's identity key) and it cannot forge an attestation
// (enrollment requires attestation chaining to operator-configured
// roots; minting needs the authenticator's private key). A malicious
// relay could substitute its own challenge — but the agent verifies
// exact challenge equality against the one it generated, so the
// ceremony simply fails closed. Codes are 40-bit random and expire
// in minutes; ceremony records live in memory and never touch the
// database (unlike enrollment publications, they are transient).

// vhlCeremonyTTL bounds how long a ceremony code stays usable: the
// human must complete the browser ceremony within this window after
// the agent creates it.
const vhlCeremonyTTL = 5 * time.Minute

// vhlCompletedGrace keeps a completed ceremony's result available for
// polling briefly after completion before the record is purged.
const vhlCompletedGrace = 10 * time.Minute

// vhlCeremonyCodeLen is the random code length: 8 chars from a
// 32-symbol alphabet = 40 bits. Online guessing is infeasible inside
// the 5-minute TTL.
const vhlCeremonyCodeLen = 8

// vhlCodeAlphabet avoids ambiguous characters (no 0/O, 1/l/I).
const vhlCodeAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// vhlMaxAttestationBytes caps the browser-submitted ceremony
// response: real attestation objects with x5c chains are a few
// kilobytes; this leaves wide headroom while bounding relay memory.
const vhlMaxAttestationBytes = 16 * 1024

// vhlMaxCeremonies caps the transient ceremony registry (issue #142
// review): the per-address creation limiter is Sybil-able (an
// attacker mints identities), so the registry itself needs a global
// bound. When full, creation purges expired records once more and
// then fails closed with 503 instead of growing without bound.
const vhlMaxCeremonies = 1024

// vhlMaxCeremonyAttestationBytes caps the total stored
// ceremony-response bytes across the whole registry (issue #142
// review): 8 MiB is 512 max-size attestations, far above any
// legitimate burst of human-paced ceremonies, and it bounds relay
// memory independently of the record-count cap.
const vhlMaxCeremonyAttestationBytes = 8 * 1024 * 1024

// vhlCeremonyGlobalBurst / vhlCeremonyGlobalRatePerSec tune the
// registry-global (non-identity) ceremony-creation limiter (issue
// #142 review): ceremony creation is human-paced — one per
// enrollment, mint, or approval — so a burst of 32 with 4/sec
// sustained is invisible to legitimate use and blunts a Sybil flood
// that the per-address limiter cannot see. It is defense in depth
// behind the registry caps, not a replacement for them.
const vhlCeremonyGlobalBurst = 32
const vhlCeremonyGlobalRatePerSec = 4.0

// vhlMaxContextJSONBytes caps the agent-supplied ceremony context
// JSON: the context is displayed verbatim to the human (a draft
// summary can be a paragraph), but it must stay small enough to
// render and to sign cheaply.
const vhlMaxContextJSONBytes = 16 * 1024

// vhlCeremonyTypeEnroll, vhlCeremonyTypeMint,
// vhlCeremonyTypeApprove, and vhlCeremonyTypeEnrollApprover are the
// ceremony kinds, enforced end to end (the page, the agent, and the
// verifier all agree on which WebAuthn call to make). "enroll" is a
// registration ceremony (navigator.credentials.create); "mint",
// "approve", and "enroll-approver" are assertion ceremonies
// (navigator.credentials.get) over a human-reviewed context the
// page displays before the key is touched.
const (
	vhlCeremonyTypeEnroll         = "enroll"
	vhlCeremonyTypeMint           = "mint"
	vhlCeremonyTypeApprove        = "approve"
	vhlCeremonyTypeEnrollApprover = "enroll-approver"
)

// vhlCeremony is one in-flight WebAuthn ceremony record.
type vhlCeremony struct {
	Code          string
	Type          string // enroll | mint | approve | enroll-approver
	Address       string // creator identity address
	ChallengeB64  string // base64url challenge the authenticator answers
	ContextJSON   string // human-reviewed ceremony context (mint/approve/enroll-approver)
	RPID          string // RP id echoed to the browser page
	CredentialIDs []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	// CompletedAt is set once the browser submits the attestation;
	// AttestationB64 holds the raw base64url ceremony response for
	// the agent to poll.
	CompletedAt    time.Time
	AttestationB64 string
}

// errVHLCeremoniesFull reports a registry at its global record cap.
var errVHLCeremoniesFull = fmt.Errorf("ceremony registry full")

// errVHLCeremonyBytesFull reports a registry at its global
// attestation-byte cap.
var errVHLCeremonyBytesFull = fmt.Errorf("ceremony attestation storage full")

// vhlCeremonies is the relay's transient ceremony registry.
type vhlCeremonies struct {
	mu     sync.Mutex
	byCode map[string]*vhlCeremony
	// attBytes tracks the total stored attestation-response bytes
	// across all records, against vhlMaxCeremonyAttestationBytes.
	attBytes int64
	// globalLimiter is the non-identity ceremony-creation rate
	// limiter, keyed on the single shared key
	// "vhl-ceremony-global" so every identity draws from one
	// bucket. Kept alongside the per-address limiter as defense in
	// depth: the per-address limiter cannot see a Sybil flood.
	globalLimiter *Limiter
}

// newVHLCeremonies returns an empty ceremony registry.
func newVHLCeremonies() *vhlCeremonies {
	return &vhlCeremonies{
		byCode:        make(map[string]*vhlCeremony),
		globalLimiter: NewLimiter(vhlCeremonyGlobalBurst, vhlCeremonyGlobalRatePerSec),
	}
}

// deleteLocked removes one record, releasing its attestation bytes.
// Callers must hold c.mu.
func (c *vhlCeremonies) deleteLocked(code string) {
	if cer, ok := c.byCode[code]; ok {
		c.attBytes -= int64(len(cer.AttestationB64))
		if c.attBytes < 0 {
			c.attBytes = 0
		}
		delete(c.byCode, code)
	}
}

// create draws a fresh code and inserts the ceremony atomically.
// The code draw and the insert share one lock hold so two
// concurrent creates can never land on the same code. The registry
// is globally capped at vhlMaxCeremonies: when full, expired
// records are purged once more and creation then fails closed with
// errVHLCeremoniesFull rather than growing without bound.
func (c *vhlCeremonies) create(cer *vhlCeremony) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	if len(c.byCode) >= vhlMaxCeremonies {
		c.purgeLocked()
		if len(c.byCode) >= vhlMaxCeremonies {
			return "", errVHLCeremoniesFull
		}
	}
	for {
		var rnd [vhlCeremonyCodeLen]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return "", fmt.Errorf("rand: %w", err)
		}
		var sb strings.Builder
		for _, b := range rnd[:] {
			sb.WriteByte(vhlCodeAlphabet[int(b)%len(vhlCodeAlphabet)])
		}
		code := sb.String()
		if _, live := c.byCode[code]; live {
			continue
		}
		cer.Code = code
		c.byCode[code] = cer
		return code, nil
	}
}

// get returns a snapshot of the live record for code, or nil when
// unknown/expired. Expired records are purged as a side effect. The
// snapshot (not the shared struct) is returned so callers can read
// its fields without holding the registry lock while complete()
// mutates the live record under it.
func (c *vhlCeremonies) get(code string) *vhlCeremony {
	c.mu.Lock()
	defer c.mu.Unlock()
	cer, ok := c.byCode[code]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.After(cer.ExpiresAt) && cer.CompletedAt.IsZero() {
		c.deleteLocked(code)
		return nil
	}
	if !cer.CompletedAt.IsZero() && now.After(cer.CompletedAt.Add(vhlCompletedGrace)) {
		c.deleteLocked(code)
		return nil
	}
	cp := *cer
	return &cp
}

// complete records the browser's attestation for a pending ceremony.
// It fails when the code is unknown, expired, or already completed
// (single-use: the first submission wins and the code dies with it).
// Stored attestation bytes are globally capped at
// vhlMaxCeremonyAttestationBytes: expired records are purged first,
// then a still-full registry fails closed with
// errVHLCeremonyBytesFull.
func (c *vhlCeremonies) complete(code, attestationB64 string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	if c.attBytes+int64(len(attestationB64)) > vhlMaxCeremonyAttestationBytes {
		return errVHLCeremonyBytesFull
	}
	cer, ok := c.byCode[code]
	if !ok {
		return fmt.Errorf("unknown ceremony")
	}
	now := time.Now()
	if now.After(cer.ExpiresAt) {
		c.deleteLocked(code)
		return fmt.Errorf("ceremony expired")
	}
	if !cer.CompletedAt.IsZero() {
		return fmt.Errorf("ceremony already completed")
	}
	cer.AttestationB64 = attestationB64
	cer.CompletedAt = now
	c.attBytes += int64(len(attestationB64))
	return nil
}

// purgeLocked drops expired records, releasing their attestation
// bytes. Callers must hold c.mu.
func (c *vhlCeremonies) purgeLocked() {
	now := time.Now()
	for code, cer := range c.byCode {
		if cer.CompletedAt.IsZero() {
			if now.After(cer.ExpiresAt) {
				c.deleteLocked(code)
			}
			continue
		}
		if now.After(cer.CompletedAt.Add(vhlCompletedGrace)) {
			c.deleteLocked(code)
		}
	}
}

// vhlSessionUser validates the dashboard session cookie against the
// shared database (the dashboard and relay share one SQLite file, so
// a browser logged into the dashboard presents the same
// courier_session cookie here). It returns nil when there is no
// valid login — the ceremony page and the attestation submission are
// both login-gated, exactly like the dashboard's authenticated
// endpoints.
func (s *Server) vhlSessionUser(r *http.Request) *store.DashboardUser {
	// Cookie name mirrors the dashboard's sessionCookie constant.
	c, err := r.Cookie("courier_session")
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

// vhlCheckCSRF compares the browser-submitted synchronizer token
// against the one stored on the session row, in constant time. The
// ceremony page embeds the token the login-gated page handler
// injected; the attestation POST is also JSON-only (a cross-site
// form cannot produce an application/json body), so token theft via
// plain CSRF is already structurally blocked — this is
// defense in depth, mirroring the dashboard.
func (s *Server) vhlCheckCSRF(r *http.Request, submitted string) bool {
	c, err := r.Cookie("courier_session")
	if err != nil || c.Value == "" || submitted == "" {
		return false
	}
	sum := sha256.Sum256([]byte(c.Value))
	stored, err := s.store.SessionCSRFToken(hex.EncodeToString(sum[:]))
	if err != nil || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(submitted)) == 1
}

// writeVHLJSON writes a JSON response with the standard envelope.
func writeVHLJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// vhlCeremonyCreateReq is the agent's signed ceremony creation
// request. The signature covers address, type, challenge, context,
// and ts (see envelope.VHLCeremonyCreate); credential_ids and rp_id
// are echoed to the browser page and verified independently by the
// agent against its own RP config, so relay tampering there fails
// closed at attestation verification. The context is the
// human-reviewed ceremony context (required for mint, approve, and
// enroll-approver; the page displays it and recomputes the challenge
// from it), also covered by the signature so the relay cannot
// substitute values the human never saw.
type vhlCeremonyCreateReq struct {
	Address       string   `json:"address"`
	Type          string   `json:"type"`
	Challenge     string   `json:"challenge"`
	Context       string   `json:"context,omitempty"`
	CredentialIDs []string `json:"credential_ids,omitempty"`
	RPID          string   `json:"rp_id"`
	Ts            int64    `json:"ts"`
	Sig           string   `json:"sig"`
}

// vhlValidateCeremonyContext checks the agent-supplied ceremony
// context for the types that carry one. The context is what the
// human reviews in the browser before touching their key, so it
// must be present and structurally sound; the page recomputes the
// challenge from the displayed context and refuses to proceed on
// mismatch, and the agent's signature covers the same bytes.
func vhlValidateCeremonyContext(ceremonyType, contextJSON, address string) error {
	if len(contextJSON) > vhlMaxContextJSONBytes {
		return fmt.Errorf("context too large")
	}
	switch ceremonyType {
	case vhlCeremonyTypeEnroll:
		// Enrollment carries no context: the ceremony binds the
		// agent address and RP id only.
		return nil
	case vhlCeremonyTypeMint:
		if contextJSON == "" {
			return fmt.Errorf("context required for mint ceremonies")
		}
		var mc vhl.MintContext
		if err := json.Unmarshal([]byte(contextJSON), &mc); err != nil {
			return fmt.Errorf("bad mint context: %w", err)
		}
		if mc.Issuer != address {
			return fmt.Errorf("mint context issuer does not match creator")
		}
		// Empty scope is valid: it is wildcard authority in the
		// existing session-token semantics (vhl.Token), so the
		// relay must not narrow it here. Token/session ids and a
		// sane lifetime are still required.
		if mc.TokenID == "" || mc.SessionID == "" {
			return fmt.Errorf("mint context missing token/session ids")
		}
		if mc.IssuedAt <= 0 || mc.ExpiresAt <= mc.IssuedAt {
			return fmt.Errorf("mint context has invalid lifetime")
		}
		if _, err := vhl.ParsePresence(mc.Presence); err != nil {
			return fmt.Errorf("mint context presence: %w", err)
		}
		return nil
	case vhlCeremonyTypeApprove:
		if contextJSON == "" {
			return fmt.Errorf("context required for approve ceremonies")
		}
		var ac struct {
			RequestID    string `json:"request_id"`
			ActionHash   string `json:"action_hash"`
			Approver     string `json:"approver"`
			DraftSummary string `json:"draft_summary"`
			NonceB64     string `json:"nonce_b64"`
		}
		if err := json.Unmarshal([]byte(contextJSON), &ac); err != nil {
			return fmt.Errorf("bad approve context: %w", err)
		}
		if ac.RequestID == "" || ac.Approver == "" {
			return fmt.Errorf("approve context missing request_id/approver")
		}
		ah, err := base64.RawURLEncoding.DecodeString(ac.ActionHash)
		if err != nil || len(ah) != 32 {
			return fmt.Errorf("approve context action_hash must be 32 bytes base64url")
		}
		nonce, err := base64.RawURLEncoding.DecodeString(ac.NonceB64)
		if err != nil || len(nonce) != 32 {
			return fmt.Errorf("approve context nonce_b64 must be 32 bytes base64url")
		}
		return nil
	case vhlCeremonyTypeEnrollApprover:
		if contextJSON == "" {
			return fmt.Errorf("context required for enroll-approver ceremonies")
		}
		var ec struct {
			ApproverAddress string `json:"approver_address"`
			AgentAddress    string `json:"agent_address"`
			IssuedAt        int64  `json:"issued_at"`
			ChallengeB64    string `json:"challenge_b64"`
		}
		if err := json.Unmarshal([]byte(contextJSON), &ec); err != nil {
			return fmt.Errorf("bad enroll-approver context: %w", err)
		}
		if _, err := parseAddress(ec.ApproverAddress); err != nil {
			return fmt.Errorf("enroll-approver context: bad approver_address")
		}
		if ec.AgentAddress != address {
			return fmt.Errorf("enroll-approver context agent_address does not match creator")
		}
		ch, err := base64.RawURLEncoding.DecodeString(ec.ChallengeB64)
		if err != nil || len(ch) != 32 {
			return fmt.Errorf("enroll-approver context challenge_b64 must be 32 bytes base64url")
		}
		return nil
	default:
		return fmt.Errorf("unknown ceremony type %q", ceremonyType)
	}
}

// handleVHLCeremonyCreate is POST /v1/vhl/ceremonies: the agent's
// identity-authenticated ceremony creation. Answers with the
// single-use code and the ceremony page path.
func (s *Server) handleVHLCeremonyCreate(w http.ResponseWriter, r *http.Request) {
	var req vhlCeremonyCreateReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	switch req.Type {
	case vhlCeremonyTypeEnroll, vhlCeremonyTypeMint, vhlCeremonyTypeApprove, vhlCeremonyTypeEnrollApprover:
	default:
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be one of enroll, mint, approve, enroll-approver"})
		return
	}
	addr, err := parseAddress(req.Address)
	if err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad address"})
		return
	}
	if req.RPID == "" || len(req.RPID) > 253 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "rp_id required"})
		return
	}
	chal, err := base64.RawURLEncoding.DecodeString(req.Challenge)
	if err != nil || len(chal) != 32 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge must be 32 bytes base64url"})
		return
	}
	if err := vhlValidateCeremonyContext(req.Type, req.Context, req.Address); err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(req.CredentialIDs) > 8 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "too many credential ids"})
		return
	}
	for _, id := range req.CredentialIDs {
		if id == "" || len(id) > 256 {
			writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad credential id"})
			return
		}
	}
	// Freshness bound against replayed creation requests.
	if now := time.Now().Unix(); req.Ts < now-maxSignedRequestAge || req.Ts > now+maxSignedRequestAge {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "stale request"})
		return
	}
	sigBytes, err := decodeSig(req.Sig)
	if err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad sig encoding"})
		return
	}
	if !crypto.Verify(addr[:], envelope.VHLCeremonyCreate(addr[:], req.Type, req.Challenge, req.Context, req.Ts), sigBytes) {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}
	// Global (non-identity) creation rate limit: the per-address
	// limiter below is Sybil-able, so a shared bucket bounds total
	// creation rate across all identities. Checked after signature
	// verification so unauthenticated garbage cannot burn the
	// shared budget and deny service to legitimate creators.
	if !s.ceremonies.globalLimiter.Allow("vhl-ceremony-global") {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if !s.limiter.Allow("vhl-ceremony:" + req.Address) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	now := time.Now()
	code, err := s.ceremonies.create(&vhlCeremony{
		Type:          req.Type,
		Address:       req.Address,
		ChallengeB64:  req.Challenge,
		ContextJSON:   req.Context,
		RPID:          req.RPID,
		CredentialIDs: req.CredentialIDs,
		CreatedAt:     now,
		ExpiresAt:     now.Add(vhlCeremonyTTL),
	})
	if err != nil {
		if errors.Is(err, errVHLCeremoniesFull) {
			writeVHLJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ceremony registry full"})
			return
		}
		writeVHLJSON(w, http.StatusInternalServerError, map[string]string{"error": "code generation failed"})
		return
	}
	writeVHLJSON(w, http.StatusCreated, map[string]any{
		"code":           code,
		"ceremony_path":  "/vhl/ceremony?code=" + code,
		"expires_at":     now.Add(vhlCeremonyTTL).Unix(),
		"expires_in_sec": int(vhlCeremonyTTL.Seconds()),
	})
}

// vhlCeremonyDetails is the login-gated browser view of a ceremony:
// everything the page needs to run the WebAuthn call, and nothing
// the agent must keep secret (the code itself is the capability).
func (s *Server) handleVHLCeremonyDetails(w http.ResponseWriter, r *http.Request) {
	user := s.vhlSessionUser(r)
	if user == nil {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "dashboard login required"})
		return
	}
	cer := s.ceremonies.get(r.PathValue("code"))
	if cer == nil {
		writeVHLJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired ceremony"})
		return
	}
	// The logged-in dashboard user must be bound to the same Courier
	// identity that created the ceremony: otherwise a second human
	// logged into the dashboard on a shared relay could complete (or
	// snoop) someone else's ceremony.
	if user.CourierAddress == "" || user.CourierAddress != cer.Address {
		writeVHLJSON(w, http.StatusForbidden, map[string]string{"error": "ceremony belongs to a different identity"})
		return
	}
	writeVHLJSON(w, http.StatusOK, map[string]any{
		"type":           cer.Type,
		"challenge":      cer.ChallengeB64,
		"context":        cer.ContextJSON,
		"rp_id":          cer.RPID,
		"credential_ids": cer.CredentialIDs,
		"address":        cer.Address,
		"expires_at":     cer.ExpiresAt.Unix(),
		"completed":      !cer.CompletedAt.IsZero(),
	})
}

// vhlCeremonyAttestReq is the browser's ceremony submission.
type vhlCeremonyAttestReq struct {
	Attestation string `json:"attestation"` // base64url ceremony response JSON
	CSRFToken   string `json:"csrf_token"`
}

// handleVHLCeremonyAttest is POST /v1/vhl/ceremonies/{code}/attestation:
// the login-gated browser submission of the ceremony response. The
// relay stores it verbatim for the agent to poll and verify; it
// never interprets it (interpretation is the agent's job, against
// its own RP config).
func (s *Server) handleVHLCeremonyAttest(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON body required"})
		return
	}
	user := s.vhlSessionUser(r)
	if user == nil {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "dashboard login required"})
		return
	}
	var req vhlCeremonyAttestReq
	if err := json.NewDecoder(io.LimitReader(r.Body, vhlMaxAttestationBytes+4096)).Decode(&req); err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !s.vhlCheckCSRF(r, req.CSRFToken) {
		writeVHLJSON(w, http.StatusForbidden, map[string]string{"error": "bad CSRF token"})
		return
	}
	code := r.PathValue("code")
	cer := s.ceremonies.get(code)
	if cer == nil {
		writeVHLJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired ceremony"})
		return
	}
	if user.CourierAddress == "" || user.CourierAddress != cer.Address {
		writeVHLJSON(w, http.StatusForbidden, map[string]string{"error": "ceremony belongs to a different identity"})
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(req.Attestation)
	if err != nil || len(raw) == 0 || len(raw) > vhlMaxAttestationBytes {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad attestation encoding"})
		return
	}
	// Structural sanity only: it must be a JSON object the agent
	// can parse later. Cryptographic verification is the agent's.
	var probe struct {
		Type     string          `json:"type"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.Type == "" || len(probe.Response) == 0 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "attestation is not a WebAuthn response"})
		return
	}
	if err := s.ceremonies.complete(code, req.Attestation); err != nil {
		// complete() only fails on expiry/double-submit races that
		// get() already screened, or on a full attestation store;
		// report without leaking internals.
		if errors.Is(err, errVHLCeremonyBytesFull) {
			writeVHLJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeVHLJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeVHLJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleVHLCeremonyResult is GET /v1/vhl/ceremonies/{code}/result:
// the agent's signed poll. Only the creating identity may read the
// result, and only while the ceremony is live or recently completed.
func (s *Server) handleVHLCeremonyResult(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	address := q.Get("address")
	tsStr := q.Get("ts")
	sigStr := q.Get("sig")
	code := r.PathValue("code")
	addr, err := parseAddress(address)
	if err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad address"})
		return
	}
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad ts"})
		return
	}
	if now := time.Now().Unix(); ts < now-maxSignedRequestAge || ts > now+maxSignedRequestAge {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "stale request"})
		return
	}
	sigBytes, err := decodeSig(sigStr)
	if err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad sig encoding"})
		return
	}
	if !crypto.Verify(addr[:], envelope.VHLCeremonyResult(addr[:], code, ts), sigBytes) {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}

	cer := s.ceremonies.get(code)
	if cer == nil {
		// Unknown or fully expired: the agent cannot distinguish a
		// typo from an expiry, and neither is actionable — report
		// expired so the CLI tells the human the code died.
		writeVHLJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	if cer.Address != address {
		writeVHLJSON(w, http.StatusForbidden, map[string]string{"error": "ceremony belongs to a different identity"})
		return
	}
	if cer.CompletedAt.IsZero() {
		writeVHLJSON(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	}
	writeVHLJSON(w, http.StatusOK, map[string]string{
		"status":      "completed",
		"attestation": cer.AttestationB64,
	})
}

//go:embed static/vhl_ceremony.html
var vhlCeremonyPage []byte

// vhlCeremonyCSRFPlaceholder is replaced with the session's CSRF
// token when the login-gated page handler serves the ceremony page.
const vhlCeremonyCSRFPlaceholder = "<!--CSRF_TOKEN-->"

// handleVHLCeremonyPage is GET /vhl/ceremony: the login-gated browser
// ceremony page. It embeds the session's CSRF token so the
// attestation POST can present the synchronizer token.
func (s *Server) handleVHLCeremonyPage(w http.ResponseWriter, r *http.Request) {
	user := s.vhlSessionUser(r)
	if user == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Login required</h1>` +
			`<p>This VHL ceremony page needs a dashboard login. Log in to the Courier ` +
			`dashboard in another tab, then reload this page.</p></body></html>`))
		return
	}
	// Look up the session's CSRF token for injection.
	c, _ := r.Cookie("courier_session")
	token := ""
	if c != nil {
		sum := sha256.Sum256([]byte(c.Value))
		token, _ = s.store.SessionCSRFToken(hex.EncodeToString(sum[:]))
	}
	page := vhlCeremonyPage
	if bytes.Contains(page, []byte(vhlCeremonyCSRFPlaceholder)) && token != "" {
		page = bytes.ReplaceAll(page, []byte(vhlCeremonyCSRFPlaceholder), []byte(token))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}

// ---- VHL enrollment publication (issue #142) ----
//
// Enrollment *verification* happens agent-side during the ceremony:
// the enrolling agent checks the attestation against its RP config
// and stores the credential in its local registry. Publication here
// is the signed identity→credential binding other agents use for
// *discovery* only: the relay verifies the publisher's identity
// signature and enforces a strictly increasing epoch per address
// (the stale-epoch pattern from the key directory), exactly like the
// key directory it sits next to.

// vhlEnrollmentPublishReq is the agent's signed enrollment
// publication. The signature covers address, credential id, public
// key, RP id, and epoch (envelope.VHLEnrollmentAnnounce); only a
// strictly greater epoch per (address, credential_id) is applied.
// revoked=1 at a higher epoch revokes that binding independently of
// the identity's other credentials.
type vhlEnrollmentPublishReq struct {
	Address       string `json:"address"`
	CredentialID  string `json:"credential_id"`
	CredentialPub string `json:"credential_pub"`
	RPID          string `json:"rp_id"`
	AAGUID        string `json:"aaguid,omitempty"`
	Epoch         int64  `json:"epoch"`
	Revoked       bool   `json:"revoked,omitempty"`
	Sig           string `json:"sig"`
}

// handleVHLEnrollmentPublish is POST /v1/vhl/enrollments.
func (s *Server) handleVHLEnrollmentPublish(w http.ResponseWriter, r *http.Request) {
	var req vhlEnrollmentPublishReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	addr, err := parseAddress(req.Address)
	if err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad address"})
		return
	}
	if req.CredentialID == "" || len(req.CredentialID) > 256 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad credential id"})
		return
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(req.CredentialPub)
	if err != nil || len(pubRaw) == 0 || len(pubRaw) > 512 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad credential_pub"})
		return
	}
	if req.RPID == "" || len(req.RPID) > 253 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad rp_id"})
		return
	}
	if len(req.AAGUID) > 64 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad aaguid"})
		return
	}
	if req.Epoch <= 0 {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "epoch must be positive"})
		return
	}
	sigBytes, err := decodeSig(req.Sig)
	if err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad sig encoding"})
		return
	}
	if !crypto.Verify(addr[:], envelope.VHLEnrollmentAnnounce(addr[:], req.CredentialID, req.CredentialPub, req.RPID, req.Epoch, req.Revoked), sigBytes) {
		writeVHLJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}
	if !s.dirWriteLimiter.Allow("vhl-enroll:" + req.Address) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	applied, err := s.store.SaveVHLEnrollment(&store.VHLEnrollment{
		Address:       req.Address,
		CredentialID:  req.CredentialID,
		CredentialPub: req.CredentialPub,
		RPID:          req.RPID,
		AAGUID:        req.AAGUID,
		Epoch:         req.Epoch,
		Revoked:       req.Revoked,
		Sig:           req.Sig,
	})
	if err != nil {
		writeVHLJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
		return
	}
	if !applied {
		writeVHLJSON(w, http.StatusConflict, map[string]string{"error": "stale epoch: a newer publication already exists"})
		return
	}
	writeVHLJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

// handleVHLEnrollmentLookup is GET /v1/vhl/enrollments/{address}:
// the public discovery read for an identity's published enrollment
// bindings. It serves the full credential set as a JSON list —
// every binding with its revoked flag — so consumers learn about
// revocations instead of silently missing them. The local registry
// stays the trust root: a directory entry can never override a
// local enrollment.
func (s *Server) handleVHLEnrollmentLookup(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("code")
	// The route registers {code} for ceremony paths; enrollments use
	// their own pattern — accept either name.
	if address == "" {
		address = r.PathValue("address")
	}
	if _, err := parseAddress(address); err != nil {
		writeVHLJSON(w, http.StatusBadRequest, map[string]string{"error": "bad address"})
		return
	}
	all, err := s.store.GetVHLEnrollment(address)
	if err == sql.ErrNoRows {
		writeVHLJSON(w, http.StatusNotFound, map[string]string{"error": "no published enrollment"})
		return
	}
	if err != nil {
		writeVHLJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
		return
	}
	out := make([]map[string]any, 0, len(all))
	for _, e := range all {
		out = append(out, map[string]any{
			"address":        e.Address,
			"credential_id":  e.CredentialID,
			"credential_pub": e.CredentialPub,
			"rp_id":          e.RPID,
			"aaguid":         e.AAGUID,
			"epoch":          e.Epoch,
			"revoked":        e.Revoked,
			"sig":            e.Sig,
			"published_at":   e.PublishedAt,
		})
	}
	writeVHLJSON(w, http.StatusOK, out)
}
