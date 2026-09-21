// Read-only admin audit API for the bridge gateway (issue #95).
//
// The hash-chained audit log in bridge.db was previously inspectable
// only via `courier bridge audit` on the VPS. This file exposes the
// same metadata as a read-only HTTP API so the dashboard admin view
// can render it without opening bridge.db itself:
//
//	GET /v1/bridge/audit        list audit rows (newest first; filters: limit, token_label, outcome)
//	GET /v1/bridge/audit/verify verify the hash chain ({ok, chain_ok, checked, first_id})
//
// Authorization is a dedicated admin bearer token, provisioned at
// gateway startup from COURIER_BRIDGE_ADMIN_TOKEN (never the ingest
// tokens — those authorize sends, not reads). The gateway stores only
// the SHA-256 of the secret and compares with constant-time equality.
// The endpoints are dormant (404) when no admin token is configured,
// so a default deployment exposes no new surface at all.
//
// The API is strictly read-only: it serves exactly the metadata the
// audit log already holds (timestamp, token label, recipient, body
// SHA-256, body size, outcome, envelope id, plus the operational
// reason/send_ref fields `courier bridge audit` also prints). Message
// bodies are never logged and never served; no PII beyond what the
// audit log itself records.
//
// The gateway is localhost-only by default, so the token travels over
// loopback. If the dashboard runs on another host, put the gateway
// behind a TLS-terminating reverse proxy you trust (the same warning
// as --allow-remote) — never expose the cleartext bearer over an
// untrusted network.
package bridge

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
)

// DefaultAdminAuditLimit is the default page size for the admin audit
// listing; MaxAdminAuditLimit caps it.
const (
	DefaultAdminAuditLimit = 100
	MaxAdminAuditLimit     = 1000
)

// AuditAdminRow is the JSON shape of one audit row on the read-only
// admin API. It mirrors the metadata-only audit log: no token secrets,
// no chain internals, no message bodies.
type AuditAdminRow struct {
	ID         int64  `json:"id"`
	Ts         int64  `json:"ts"`
	TokenLabel string `json:"token_label"`
	Recipient  string `json:"recipient"`
	BodySHA256 string `json:"body_sha256"`
	BodySize   int64  `json:"body_size"`
	Outcome    string `json:"outcome"`
	EnvelopeID int64  `json:"envelope_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	SendRef    string `json:"send_ref,omitempty"`
}

// AuditAdminVerify is the JSON shape of the chain-verification result.
type AuditAdminVerify struct {
	OK      bool  `json:"ok"`
	ChainOK bool  `json:"chain_ok"`
	Checked int64 `json:"checked"`
	FirstID int64 `json:"first_id"`
}

// SetAdminToken provisions the admin bearer token for the read-only
// audit API. Only the SHA-256 of the secret is kept; the raw secret is
// never stored. An empty token leaves the API dormant (404).
func (g *Gateway) SetAdminToken(raw string) {
	if raw == "" {
		return
	}
	sum := sha256.Sum256([]byte(raw))
	g.adminHash = sum
	g.adminEnabled = true
}

// adminEnabled reports whether the read-only audit API is active.
func (g *Gateway) AdminEnabled() bool { return g.adminEnabled }

// authenticateAdmin validates the admin bearer token: the presented
// token's SHA-256 must equal the provisioned hash in constant time. A
// missing or wrong token is indistinguishable to the caller (401
// either way) and never reveals whether the token is configured.
func (g *Gateway) authenticateAdmin(r *http.Request) bool {
	if !g.adminEnabled {
		return false
	}
	raw := bearerToken(r)
	if raw == "" {
		return false
	}
	sum := sha256.Sum256([]byte(raw))
	return subtle.ConstantTimeCompare(sum[:], g.adminHash[:]) == 1
}

// requireAdmin gates the audit endpoints: 404 when the API is dormant,
// 401 on bad/missing credentials. Failed attempts pass the same coarse
// per-IP pre-auth limiter as unauthenticated ingests, so a flooding
// scanner gets 429 instead of an audit-log row (there is none to write
// here — the audit log records ingests, not reads).
func (g *Gateway) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !g.adminEnabled {
		writeJSON(w, http.StatusNotFound, errJSON(404, "not found"))
		return false
	}
	if !g.authenticateAdmin(r) {
		ip := clientIP(r)
		allowed, retryAfter, logIt := g.preAuth.Allow(ip)
		if logIt {
			log.Printf("bridge: unauthenticated audit API flood from %s; 429 without logging", ip)
		}
		if !allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			writeJSON(w, http.StatusTooManyRequests, errJSON(429, "too many unauthenticated requests"))
			return false
		}
		writeJSON(w, http.StatusUnauthorized, errJSON(401, "unauthorized"))
		return false
	}
	return true
}

// handleAuditList serves GET /v1/bridge/audit: audit rows, newest
// first. Query params: limit (default 100, max 1000), token_label
// (exact), outcome (exact, e.g. "sent" or "rejected:rate_limited").
func (g *Gateway) handleAuditList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	if !g.requireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	limit := DefaultAdminAuditLimit
	if l := q.Get("limit"); l != "" {
		var v int
		if _, err := fmt.Sscanf(l, "%d", &v); err != nil || v < 1 {
			writeJSON(w, http.StatusBadRequest, errJSON(400, `"limit" must be a positive integer`))
			return
		}
		if v > MaxAdminAuditLimit {
			v = MaxAdminAuditLimit
		}
		limit = v
	}
	rows, err := g.store.ListAudit(AuditFilter{
		TokenLabel: q.Get("token_label"),
		Outcome:    q.Get("outcome"),
		Limit:      limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
		return
	}
	out := make([]AuditAdminRow, 0, len(rows))
	for _, e := range rows {
		out = append(out, AuditAdminRow{
			ID:         e.ID,
			Ts:         e.Ts,
			TokenLabel: e.TokenLabel,
			Recipient:  e.Recipient,
			BodySHA256: e.BodySHA256,
			BodySize:   e.BodySize,
			Outcome:    e.Outcome,
			EnvelopeID: e.EnvelopeID,
			Reason:     e.Reason,
			SendRef:    e.SendRef,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rows": out})
}

// handleAuditVerify serves GET /v1/bridge/audit/verify: the hash-chain
// verification result (same semantics as `courier bridge audit
// --verify`). chain_ok=false means tampering or corruption — the
// threat-model caveat from the audit package doc applies: the chain
// detects unsophisticated tampering, not a privileged rewrite of
// bridge.db.
func (g *Gateway) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errJSON(405, "method not allowed"))
		return
	}
	if !g.requireAdmin(w, r) {
		return
	}
	ok, checked, firstID, err := g.store.VerifyAudit()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errJSON(500, "internal error"))
		return
	}
	writeJSON(w, http.StatusOK, AuditAdminVerify{
		OK: true, ChainOK: ok, Checked: checked, FirstID: firstID,
	})
}
