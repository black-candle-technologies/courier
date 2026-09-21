// HTTP gateway for the ChatGPT web → Courier bridge (issue #61).
//
// The gateway is a localhost-only service. It owns the bridge identity
// and translates authenticated ingest requests (from the MCP server)
// into ordinary Courier sends via the existing client API — no relay
// changes, no protocol wire changes.
//
// Enforcement order per ingest (fail fast, cheapest checks first):
//
//  1. Token valid, not revoked, not expired → else 401. Unauthenticated
//     attempts are audit-logged, but a coarse per-IP pre-auth limiter
//     429s floods without writing a row (F4).
//  2. Body ≤ 64 KiB (UTF-8 bytes, measured before wrapping) → else 413.
//  3. Recipient in the token's allowlist → else 403 (the allowlist is
//     never disclosed in the error).
//  4. Recipient parses as a Courier address → else 400.
//  5. First-send-per-(token, recipient) confirmation round-trip → else
//     449 confirmation_required. The 449 response itself does not
//     consume rate-limit quota; quota is spent only on actual sends.
//  6. Per-token rate limit → else 429 with Retry-After.
//  7. Wrap + send as the bridge identity, then append the audit record.
//
// Internal-error (500) paths intentionally write no audit row — the
// store may be the thing that's broken; server logs are the backstop.
//
// The MCP server is NOT a trust boundary: the gateway re-validates
// everything. A compromised MCP server gains nothing beyond what its
// configured token allows.
package bridge

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/crypto"
)

// DefaultBodyCap is the 64 KiB ingest body limit, measured on UTF-8
// bytes before the attribution banner is wrapped.
const DefaultBodyCap = 64 * 1024

// ConfirmTTL is how long a pending confirmation token stays valid.
const ConfirmTTL = 10 * time.Minute

// StatusConfirmationRequired is the non-standard status the gateway
// returns when the first send to a recipient needs an explicit human
// confirmation round-trip (plan §7). The MCP layer translates it into
// a user-facing prompt; it is not an error.
const StatusConfirmationRequired = 449

// DisclosureText is the mandatory plain-language non-E2E disclosure.
// It ships in the 449 confirmation payload, the status endpoint, and
// docs/bridge.md (plan §3.3). It names every plaintext hop: the MCP
// server sees tool-call arguments, the gateway sees everything.
const DisclosureText = "Messages sent through this bridge are NOT end-to-end encrypted. " +
	"They pass in plaintext through the MCP server and the bridge gateway (and are visible to OpenAI via ChatGPT web) " +
	"before being delivered as ordinary Courier messages. Do not send secrets. " +
	"Bridged messages are marked as untrusted input and never trigger agent actions without approval."

// BridgeCapability is the contact-discovery capability token the
// bridge identity publishes so clients can verify "this sender is a
// registered bridge" out of band. Note: capability tokens cannot
// contain '=', so the plan's "bridge=chatgpt-web" example is spelled
// with a dash.
const BridgeCapability = "bridge-chatgpt-web"

// Sender delivers a bridge-attributed message. The production
// implementation is *client.Client.SendBridged; tests stub it.
type Sender interface {
	SendBridged(address, wrappedBody string, meta *client.BridgeMeta) (int64, error)
}

// Gateway is the bridge ingest service.
type Gateway struct {
	store     *Store
	sender    Sender
	pepper    string
	address   string // bridge identity address
	gatewayFP string // hex SHA-256 of the bridge Ed25519 public key
	limiter   *RateLimiter
	preAuth   *PreAuthLimiter // coarse per-IP limiter for unauthenticated attempts (F4)
	bodyCap   int
	version   string
	now       func() time.Time // overridable in tests
}

// NewGateway builds a gateway. address is the bridge identity's
// Courier address; edPub is its Ed25519 public key (for the gateway
// fingerprint in bridge metadata).
func NewGateway(store *Store, sender Sender, pepper, address string, edPub []byte, version string) *Gateway {
	fp := sha256.Sum256(edPub)
	return &Gateway{
		store:     store,
		sender:    sender,
		pepper:    pepper,
		address:   address,
		gatewayFP: hex.EncodeToString(fp[:]),
		limiter:   NewRateLimiter(),
		preAuth:   NewPreAuthLimiter(PreAuthLimitPerMinute),
		bodyCap:   DefaultBodyCap,
		version:   version,
		now:       time.Now,
	}
}

// Routes wires the gateway's HTTP endpoints.
func (g *Gateway) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/bridge/health", g.handleHealth)
	mux.HandleFunc("/v1/bridge/ingest", g.handleIngest)
	mux.HandleFunc("/v1/bridge/status", g.handleStatus)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(code int, msg string) map[string]any {
	return map[string]any{"ok": false, "error": msg}
}

// bearerToken extracts the bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// authenticate validates the ingest bearer token: known, not revoked,
// not expired. A nil token with no error is impossible; errors map to
// 401 either way (no oracle: revoked/expired/unknown are
// indistinguishable to the caller).
func (g *Gateway) authenticate(r *http.Request) (*Token, error) {
	raw := bearerToken(r)
	if raw == "" {
		return nil, fmt.Errorf("missing bearer token")
	}
	tok, err := g.store.LookupToken(HashToken(raw, g.pepper))
	if err != nil {
		return nil, err
	}
	if tok == nil || !tok.Active(g.now().Unix()) {
		return nil, fmt.Errorf("invalid token")
	}
	return tok, nil
}

// handleHealth is the unauthenticated liveness probe (monitoring §8).
// It exposes only the version string — no sensitive data.
func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": g.version})
}

// ingestRequest is the MCP server's ingest call. Caller is the
// OAuth-authenticated Black Candle email the MCP server asserts for
// the human behind the request (issue #94); it is recorded in the
// audit log. The gateway treats it as opaque asserted metadata.
type ingestRequest struct {
	Recipient    string `json:"recipient"`
	Body         string `json:"body"`
	ConfirmToken string `json:"confirm_token,omitempty"`
	Caller       string `json:"caller,omitempty"`
}

// maxAuditCallerLen caps the caller identity stored in audit rows.
// The value arrives asserted by our own MCP server, but metadata
// crossing a service boundary gets a bound regardless.
const maxAuditCallerLen = 256

// sanitizeCaller normalizes the asserted caller identity for audit
// storage.
func sanitizeCaller(caller string) string {
	caller = strings.TrimSpace(caller)
	if len(caller) > maxAuditCallerLen {
		caller = caller[:maxAuditCallerLen]
	}
	return caller
}

// confirmationSummary is what the ChatGPT side must present to the
// human before re-calling with the confirm token.
type confirmationSummary struct {
	Recipient  string `json:"recipient"`
	BodySize   int64  `json:"body_size"`
	BodySHA256 string `json:"body_sha256"`
}

// handleIngest validates, confirms, sends, and audits one bridged
// message.
func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	tok, err := g.authenticate(r)
	if err != nil {
		// 401s are audit-logged, so unauthenticated attempts pass a
		// coarse per-IP limiter first: over-limit floods get 429 with
		// no audit row, and the flood is noted in the server logs (F4).
		ip := clientIP(r)
		allowed, retryAfter, logIt := g.preAuth.Allow(ip)
		if logIt {
			log.Printf("bridge: unauthenticated ingest flood from %s (>%d/min); 429 without audit row", ip, PreAuthLimitPerMinute)
		}
		if !allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			writeJSON(w, http.StatusTooManyRequests, errJSON(429, "too many unauthenticated requests"))
			return
		}
		g.audit(nil, "", "", nil, RejectedOutcome(RejectUnauthorized), 0, "")
		writeJSON(w, http.StatusUnauthorized, errJSON(401, "unauthorized"))
		return
	}
	var req ingestRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	if err := dec.Decode(&req); err != nil {
		g.audit(tok, "", "", nil, RejectedOutcome(RejectBadRequest), 0, "bad json")
		writeJSON(w, http.StatusBadRequest, errJSON(400, "bad request"))
		return
	}
	req.Caller = sanitizeCaller(req.Caller)
	now := g.now()
	bodyBytes := len([]byte(req.Body))
	if bodyBytes > g.bodyCap {
		g.audit(tok, req.Caller, req.Recipient, &req.Body, RejectedOutcome(RejectTooLarge), 0,
			fmt.Sprintf("body %d bytes > cap %d", bodyBytes, g.bodyCap))
		writeJSON(w, http.StatusRequestEntityTooLarge, errJSON(413, "body exceeds 64 KiB"))
		return
	}
	allowed := false
	for _, a := range tok.Allowlist {
		if a == req.Recipient {
			allowed = true
			break
		}
	}
	if !allowed {
		// 403 without disclosing the allowlist.
		g.audit(tok, req.Caller, req.Recipient, &req.Body, RejectedOutcome(RejectForbidden), 0, "")
		writeJSON(w, http.StatusForbidden, errJSON(403, "recipient not allowlisted for this token"))
		return
	}
	if _, err := crypto.ParseAddress(req.Recipient); err != nil {
		g.audit(tok, req.Caller, req.Recipient, &req.Body, RejectedOutcome(RejectBadRequest), 0, "bad recipient address")
		writeJSON(w, http.StatusBadRequest, errJSON(400, "bad recipient address"))
		return
	}
	// Wrap before hashing: the audit records the exact bytes sent.
	wrapped := WrapBody(req.Body)
	sum := SHA256Hex([]byte(wrapped))
	// First-send-per-(token, recipient) confirmation round-trip.
	// A presented confirm token is ALWAYS validated and consumed —
	// even when the recipient is already confirmed — so a token can
	// never be silently ignored, and N concurrent ingests presenting
	// the same token collapse to exactly one consuming send (the
	// atomic DELETE ... RETURNING in consumePendingConfirmation
	// admits exactly one winner; issue #84).
	// justConfirmed records that this ingest completed the confirmation
	// ceremony. The recipient is marked confirmed only after the
	// approved first send actually succeeds (fail closed, issue #83):
	// a rate-limited or failed first send must not leave the recipient
	// confirmed for an arbitrary later body.
	justConfirmed := false
	if req.ConfirmToken != "" {
		if err := g.consumePendingConfirmation(tok.ID, req.Recipient, req.ConfirmToken, sum); err != nil {
			g.auditFull(tok, req.Caller, req.Recipient, sum, int64(len(wrapped)), RejectedOutcome(RejectBadRequest), 0, "bad confirm token")
			writeJSON(w, http.StatusBadRequest, errJSON(400, "invalid or expired confirm token"))
			return
		}
		justConfirmed = true
	} else {
		confirmed, err := g.store.IsConfirmed(tok.ID, req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
			return
		}
		if !confirmed {
			ct, err := g.newPendingConfirmation(tok.ID, req.Recipient, sum)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
				return
			}
			g.auditFull(tok, req.Caller, req.Recipient, sum, int64(len(wrapped)), OutcomeConfirmationRequired, 0, "")
			writeJSON(w, StatusConfirmationRequired, map[string]any{
				"ok": false, "error": "confirmation_required",
				"confirm_token": ct,
				"summary":       confirmationSummary{Recipient: req.Recipient, BodySize: int64(len(wrapped)), BodySHA256: sum},
				"disclosure":    DisclosureText,
			})
			return
		}
	}
	// Per-token rate limit. This runs after the confirmation round-trip
	// so the 449 response does not consume quota: one logical first send
	// costs one quota unit, not two (N5).
	if ok, retryAfter := g.limiter.Allow(tok.ID); !ok {
		g.audit(tok, req.Caller, req.Recipient, &req.Body, RejectedOutcome(RejectRateLimited), 0, "")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, errJSON(429, "rate limit exceeded"))
		return
	}
	// Reserve the audit row immutably: the row is appended once and never
	// mutated afterward, so concurrent appends can never link to a
	// row_hash that a later finalization would rewrite (issue #81). The
	// wire metadata references this reserved row's id; the completion
	// event appended below links back to it via SendRef.
	reservedID, err := g.store.AppendAudit(&AuditEntry{
		Ts: now.Unix(), TokenID: tok.ID, TokenLabel: tok.Label,
		Recipient: req.Recipient, BodySHA256: sum, BodySize: int64(len(wrapped)),
		Outcome: OutcomeSendReserved, Caller: req.Caller,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
		return
	}
	meta := &client.BridgeMeta{
		Origin:     client.BridgeOriginChatGPTWeb,
		GatewayFP:  g.gatewayFP,
		TokenLabel: tok.Label,
		AuditID:    reservedID,
	}
	envelopeID, err := g.sender.SendBridged(req.Recipient, wrapped, meta)
	if err != nil {
		if _, aerr := g.store.AppendAudit(&AuditEntry{
			Ts: now.Unix(), TokenID: tok.ID, TokenLabel: tok.Label,
			Recipient: req.Recipient, BodySHA256: sum, BodySize: int64(len(wrapped)),
			Outcome: RejectedOutcome(RejectSendFailed), Reason: err.Error(),
			SendRef: fmt.Sprint(reservedID), Caller: req.Caller,
		}); aerr != nil {
			// The send already failed (502 below); still log the
			// audit failure with the reserved id so the gap is
			// visible (issue #85).
			log.Printf("bridge: audit append failed for failed send (reserved_audit_id=%d): %v",
				reservedID, aerr)
		}
		writeJSON(w, http.StatusBadGateway, errJSON(502, "send failed"))
		return
	}
	if justConfirmed {
		// The approved first send succeeded: record the confirmation
		// (idempotent INSERT OR IGNORE). On DB error, log and continue
		// with the 200 — the ceremony completed and the message was
		// delivered; worst case the next send asks for confirmation
		// again, which is the fail-closed direction.
		if err := g.store.MarkConfirmed(tok.ID, req.Recipient, now.Unix()); err != nil {
			log.Printf("bridge: MarkConfirmed(%s -> %s) failed after successful send: %v",
				tok.ID, req.Recipient, err)
		}
	}
	if _, err := g.store.AppendAudit(&AuditEntry{
		Ts: now.Unix(), TokenID: tok.ID, TokenLabel: tok.Label,
		Recipient: req.Recipient, BodySHA256: sum, BodySize: int64(len(wrapped)),
		Outcome: OutcomeSent, EnvelopeID: envelopeID,
		SendRef: fmt.Sprint(reservedID), Caller: req.Caller,
	}); err != nil {
		// The message WAS delivered, but we could not record it: fail
		// loudly (non-2xx) and log with the reserved audit id so the
		// gap is visible (issue #85). Callers must not blindly retry
		// an audit_failed response — the send already happened.
		log.Printf("bridge: audit append failed for sent message (reserved_audit_id=%d envelope=%d): %v",
			reservedID, envelopeID, err)
		writeJSON(w, http.StatusInternalServerError, errJSON(500, "audit_failed"))
		return
	}
	_ = g.store.RecordUse(tok.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "envelope_id": envelopeID, "audit_id": reservedID,
	})
}

// audit appends a metadata-only audit row for a rejected (or
// unauthenticated) ingest. body may be nil when unknown; only its hash
// and size are ever stored.
func (g *Gateway) audit(tok *Token, caller, recipient string, body *string, outcome string, envelopeID int64, reason string) {
	var tokenID, label string
	if tok != nil {
		tokenID, label = tok.ID, tok.Label
	}
	var sum string
	var size int64
	if body != nil {
		wrapped := WrapBody(*body)
		sum = SHA256Hex([]byte(wrapped))
		size = int64(len(wrapped))
	}
	if _, err := g.store.AppendAudit(&AuditEntry{
		Ts: g.now().Unix(), TokenID: tokenID, TokenLabel: label,
		Recipient: recipient, BodySHA256: sum, BodySize: size,
		Outcome: outcome, EnvelopeID: envelopeID, Reason: reason, Caller: caller,
	}); err != nil {
		// Rejection/unauthenticated audits are best-effort, but a
		// failure must be visible in the logs, not silently dropped
		// (issue #85).
		log.Printf("bridge: audit append failed (outcome=%s recipient=%s): %v", outcome, recipient, err)
	}
}

// auditFull is audit with precomputed hash/size (used when the wrapped
// body is already in hand).
func (g *Gateway) auditFull(tok *Token, caller, recipient, sum string, size int64, outcome string, envelopeID int64, reason string) {
	if _, err := g.store.AppendAudit(&AuditEntry{
		Ts: g.now().Unix(), TokenID: tok.ID, TokenLabel: tok.Label,
		Recipient: recipient, BodySHA256: sum, BodySize: size,
		Outcome: outcome, EnvelopeID: envelopeID, Reason: reason, Caller: caller,
	}); err != nil {
		// Best-effort audit, but failures must be visible in the logs,
		// not silently dropped (issue #85).
		log.Printf("bridge: audit append failed (outcome=%s recipient=%s): %v", outcome, recipient, err)
	}
}

// newPendingConfirmation creates a single-use confirm token bound to
// (token, recipient), valid for ConfirmTTL. Expired pendings are swept
// opportunistically.
func (g *Gateway) newPendingConfirmation(tokenID, recipient, bodySHA string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	raw := hex.EncodeToString(b[:])
	now := g.now()
	_, err := g.store.db.Exec(
		`DELETE FROM pending_confirmations WHERE expires_at < ?`, now.Unix())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(raw))
	_, err = g.store.db.Exec(
		`INSERT INTO pending_confirmations(token,token_id,recipient,body_sha256,created_at,expires_at)
		 VALUES(?,?,?,?,?,?)`,
		hex.EncodeToString(sum[:]), tokenID, recipient, bodySHA, now.Unix(), now.Add(ConfirmTTL).Unix())
	if err != nil {
		return "", err
	}
	return raw, nil
}

// consumePendingConfirmation validates a confirm token and consumes it
// (single-use). The token is bound to the body it was issued for: the
// presented body's hash must match the stored body_sha256, otherwise a
// token approved for one message could be replayed for a different
// message, defeating the first-send human-approval control (F1).
// On success the caller marks the recipient confirmed.
//
// Validation and consumption are ATOMIC: a single DELETE ... RETURNING
// statement both checks the token's existence and removes it, so two
// concurrent ingests presenting the same token cannot both consume it
// (issue #84). A presented-but-unknown token is an error, never a
// silent pass.
func (g *Gateway) consumePendingConfirmation(tokenID, recipient, raw, bodySHA string) error {
	sum := sha256.Sum256([]byte(raw))
	tokHex := hex.EncodeToString(sum[:])
	var dbTokenID, dbRecipient, dbBodySHA string
	var expiresAt int64
	err := g.store.db.QueryRow(
		`DELETE FROM pending_confirmations WHERE token=? RETURNING token_id,recipient,body_sha256,expires_at`,
		tokHex,
	).Scan(&dbTokenID, &dbRecipient, &dbBodySHA, &expiresAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("unknown confirm token")
	}
	if err != nil {
		return fmt.Errorf("consume confirm token: %w", err)
	}
	// Single-use: the row is already deleted by the statement above,
	// regardless of whether the binding checks below pass.
	if dbTokenID != tokenID || dbRecipient != recipient || dbBodySHA != bodySHA {
		return fmt.Errorf("confirm token does not match")
	}
	if g.now().Unix() > expiresAt {
		return fmt.Errorf("confirm token expired")
	}
	return nil
}

// clientIP extracts the client IP from the request's remote address,
// for the pre-auth limiter (F4). The gateway is localhost-only by
// default, so this is normally 127.0.0.1 or ::1.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IsConfirmed reports whether (token, recipient) completed the
// confirmation round-trip.
func (s *Store) IsConfirmed(tokenID, recipient string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM confirmations WHERE token_id=? AND recipient=?`, tokenID, recipient).Scan(&n)
	return n > 0, err
}

// MarkConfirmed records a completed confirmation round-trip.
func (s *Store) MarkConfirmed(tokenID, recipient string, at int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO confirmations(token_id,recipient,confirmed_at) VALUES(?,?,?)`,
		tokenID, recipient, at)
	return err
}

// statusResponse backs the MCP bridge_status tool: token scope and
// quota, plus the mandatory disclosure.
type statusResponse struct {
	OK                 bool     `json:"ok"`
	Label              string   `json:"label"`
	Allowlist          []string `json:"allowlist"`
	PerMinuteRemaining int      `json:"per_minute_remaining"`
	PerHourRemaining   int      `json:"per_hour_remaining"`
	RateLimits         struct {
		PerMinute int `json:"per_minute"`
		PerHour   int `json:"per_hour"`
		Burst     int `json:"burst"`
	} `json:"rate_limits"`
	BodyCapBytes int    `json:"body_cap_bytes"`
	ExpiresAt    int64  `json:"expires_at"`
	Disclosure   string `json:"disclosure"`
}

// handleStatus returns the token's scope and remaining quota.
func (g *Gateway) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	tok, err := g.authenticate(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errJSON(401, "unauthorized"))
		return
	}
	var resp statusResponse
	resp.OK = true
	resp.Label = tok.Label
	resp.Allowlist = tok.Allowlist
	resp.PerMinuteRemaining, resp.PerHourRemaining = g.limiter.Remaining(tok.ID)
	resp.RateLimits.PerMinute = RatePerMinute
	resp.RateLimits.PerHour = RatePerHour
	resp.RateLimits.Burst = RateBurst
	resp.BodyCapBytes = g.bodyCap
	resp.ExpiresAt = tok.ExpiresAt
	resp.Disclosure = DisclosureText
	writeJSON(w, http.StatusOK, resp)
}
