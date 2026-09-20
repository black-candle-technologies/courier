// HTTP gateway for the ChatGPT web → Courier bridge (issue #61).
//
// The gateway is a localhost-only service. It owns the bridge identity
// and translates authenticated ingest requests (from the MCP server)
// into ordinary Courier sends via the existing client API — no relay
// changes, no protocol wire changes.
//
// Enforcement order per ingest (fail fast, cheapest checks first):
//
//  1. Token valid, not revoked, not expired → else 401.
//  2. Body ≤ 64 KiB (UTF-8 bytes, measured before wrapping) → else 413.
//  3. Recipient in the token's allowlist → else 403 (the allowlist is
//     never disclosed in the error).
//  4. Per-token rate limit → else 429 with Retry-After.
//  5. Recipient parses as a Courier address → else 400.
//  6. First-send-per-(token, recipient) confirmation round-trip → else
//     449 confirmation_required.
//  7. Wrap + send as the bridge identity, then append the audit record.
//
// The MCP server is NOT a trust boundary: the gateway re-validates
// everything. A compromised MCP server gains nothing beyond what its
// configured token allows.
package bridge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
// It ships in the MCP tool description, the status endpoint, and
// docs/bridge.md (plan §3.3).
const DisclosureText = "Messages sent through this bridge are NOT end-to-end encrypted. " +
	"They pass in plaintext through the bridge gateway (and are visible to OpenAI via ChatGPT web) " +
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
func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": g.version})
}

// ingestRequest is the MCP server's ingest call.
type ingestRequest struct {
	Recipient    string `json:"recipient"`
	Body         string `json:"body"`
	ConfirmToken string `json:"confirm_token,omitempty"`
}

// confirmationSummary is what the ChatGPT side must present to the
// human before re-calling with the confirm token.
type confirmationSummary struct {
	Recipient  string `json:"recipient"`
	BodySize   int64  `json:"body_size"`
	BodySHA256 string `json:"body_sha256"`
}

// auditReserved is the outcome for an audit row reserved before the
// relay round-trip; FinalizeAudit moves it to its final state.
const auditReserved = "sending"

// handleIngest validates, confirms, sends, and audits one bridged
// message.
func (g *Gateway) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	tok, err := g.authenticate(r)
	if err != nil {
		g.audit(nil, "", nil, RejectedOutcome(RejectUnauthorized), 0, "")
		writeJSON(w, http.StatusUnauthorized, errJSON(401, "unauthorized"))
		return
	}
	var req ingestRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	if err := dec.Decode(&req); err != nil {
		g.audit(tok, "", nil, RejectedOutcome(RejectBadRequest), 0, "bad json")
		writeJSON(w, http.StatusBadRequest, errJSON(400, "bad request"))
		return
	}
	now := g.now()
	bodyBytes := len([]byte(req.Body))
	if bodyBytes > g.bodyCap {
		g.audit(tok, req.Recipient, &req.Body, RejectedOutcome(RejectTooLarge), 0,
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
		g.audit(tok, req.Recipient, &req.Body, RejectedOutcome(RejectForbidden), 0, "")
		writeJSON(w, http.StatusForbidden, errJSON(403, "recipient not allowlisted for this token"))
		return
	}
	if _, err := crypto.ParseAddress(req.Recipient); err != nil {
		g.audit(tok, req.Recipient, &req.Body, RejectedOutcome(RejectBadRequest), 0, "bad recipient address")
		writeJSON(w, http.StatusBadRequest, errJSON(400, "bad recipient address"))
		return
	}
	if ok, retryAfter := g.limiter.Allow(tok.ID); !ok {
		g.audit(tok, req.Recipient, &req.Body, RejectedOutcome(RejectRateLimited), 0, "")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, errJSON(429, "rate limit exceeded"))
		return
	}
	// Wrap before hashing: the audit records the exact bytes sent.
	wrapped := WrapBody(req.Body)
	sum := SHA256Hex([]byte(wrapped))
	// First-send-per-(token, recipient) confirmation round-trip.
	confirmed, err := g.store.IsConfirmed(tok.ID, req.Recipient)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
		return
	}
	if !confirmed {
		if req.ConfirmToken == "" {
			ct, err := g.newPendingConfirmation(tok.ID, req.Recipient, sum)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
				return
			}
			g.auditFull(tok, req.Recipient, sum, int64(len(wrapped)), OutcomeConfirmationRequired, 0, "")
			writeJSON(w, StatusConfirmationRequired, map[string]any{
				"ok": false, "error": "confirmation_required",
				"confirm_token": ct,
				"summary":       confirmationSummary{Recipient: req.Recipient, BodySize: int64(len(wrapped)), BodySHA256: sum},
				"disclosure":    DisclosureText,
			})
			return
		}
		if err := g.consumePendingConfirmation(tok.ID, req.Recipient, req.ConfirmToken); err != nil {
			g.auditFull(tok, req.Recipient, sum, int64(len(wrapped)), RejectedOutcome(RejectBadRequest), 0, "bad confirm token")
			writeJSON(w, http.StatusBadRequest, errJSON(400, "invalid or expired confirm token"))
			return
		}
		if err := g.store.MarkConfirmed(tok.ID, req.Recipient, now.Unix()); err != nil {
			writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
			return
		}
	}
	// Reserve the audit row so the wire metadata can reference it.
	auditID, err := g.store.AppendAudit(&AuditEntry{
		Ts: now.Unix(), TokenID: tok.ID, TokenLabel: tok.Label,
		Recipient: req.Recipient, BodySHA256: sum, BodySize: int64(len(wrapped)),
		Outcome: auditReserved,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
		return
	}
	meta := &client.BridgeMeta{
		Origin:     client.BridgeOriginChatGPTWeb,
		GatewayFP:  g.gatewayFP,
		TokenLabel: tok.Label,
		AuditID:    auditID,
	}
	envelopeID, err := g.sender.SendBridged(req.Recipient, wrapped, meta)
	if err != nil {
		_ = g.store.FinalizeAudit(auditID, RejectedOutcome(RejectSendFailed), 0, err.Error())
		writeJSON(w, http.StatusBadGateway, errJSON(502, "send failed"))
		return
	}
	_ = g.store.FinalizeAudit(auditID, OutcomeSent, envelopeID, "")
	_ = g.store.RecordUse(tok.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "envelope_id": envelopeID, "audit_id": auditID,
	})
}

// audit appends a metadata-only audit row for a rejected (or
// unauthenticated) ingest. body may be nil when unknown; only its hash
// and size are ever stored.
func (g *Gateway) audit(tok *Token, recipient string, body *string, outcome string, envelopeID int64, reason string) {
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
	_, _ = g.store.AppendAudit(&AuditEntry{
		Ts: g.now().Unix(), TokenID: tokenID, TokenLabel: label,
		Recipient: recipient, BodySHA256: sum, BodySize: size,
		Outcome: outcome, EnvelopeID: envelopeID, Reason: reason,
	})
}

// auditFull is audit with precomputed hash/size (used when the wrapped
// body is already in hand).
func (g *Gateway) auditFull(tok *Token, recipient, sum string, size int64, outcome string, envelopeID int64, reason string) {
	_, _ = g.store.AppendAudit(&AuditEntry{
		Ts: g.now().Unix(), TokenID: tok.ID, TokenLabel: tok.Label,
		Recipient: recipient, BodySHA256: sum, BodySize: size,
		Outcome: outcome, EnvelopeID: envelopeID, Reason: reason,
	})
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
// (single-use). On success the caller marks the recipient confirmed.
func (g *Gateway) consumePendingConfirmation(tokenID, recipient, raw string) error {
	sum := sha256.Sum256([]byte(raw))
	var dbTokenID, dbRecipient string
	var expiresAt int64
	err := g.store.db.QueryRow(
		`SELECT token_id,recipient,expires_at FROM pending_confirmations WHERE token=?`,
		hex.EncodeToString(sum[:]),
	).Scan(&dbTokenID, &dbRecipient, &expiresAt)
	if err != nil {
		return fmt.Errorf("unknown confirm token")
	}
	now := g.now().Unix()
	// Single-use: delete regardless of outcome.
	_, _ = g.store.db.Exec(`DELETE FROM pending_confirmations WHERE token=?`, hex.EncodeToString(sum[:]))
	if dbTokenID != tokenID || dbRecipient != recipient {
		return fmt.Errorf("confirm token does not match")
	}
	if now > expiresAt {
		return fmt.Errorf("confirm token expired")
	}
	return nil
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
