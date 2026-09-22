// Bridge audit admin view (issue #95): the dashboard never opens
// bridge.db itself. The bridge gateway owns that database, so the
// dashboard fetches the read-only audit API (see internal/bridge
// admin.go) over HTTP with a provisioned admin bearer token and
// renders the metadata rows for dashboard admins only.
//
// The view is config-gated like BCT OAuth: both URL and admin token
// must be set, otherwise the route is not registered and the UI never
// renders. The gateway audit API itself is the read-only,
// metadata-only surface — no message bodies, no token secrets — and
// the dashboard adds no further PII.
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/bridge"
)

// BridgeAuditConfig wires the dashboard admin audit view to the bridge
// gateway's read-only audit API (issue #95). URL is the gateway base
// URL (e.g. http://127.0.0.1:8473); AdminToken is the bearer token for
// the gateway's /v1/bridge/audit endpoints (COURIER_BRIDGE_ADMIN_TOKEN
// on the gateway side). Both empty = feature dormant.
type BridgeAuditConfig struct {
	URL        string
	AdminToken string
}

func (c BridgeAuditConfig) enabled() bool { return c.URL != "" && c.AdminToken != "" }

// bridgeAuditClient is a thin client for the gateway's read-only audit
// API. It exists so the dashboard can render the audit log without
// touching bridge.db.
type bridgeAuditClient struct {
	base  string
	token string
	http  *http.Client
}

func newBridgeAuditClient(cfg BridgeAuditConfig) *bridgeAuditClient {
	return &bridgeAuditClient{
		base:  strings.TrimSuffix(cfg.URL, "/"),
		token: cfg.AdminToken,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *bridgeAuditClient) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bridge audit gateway: %w", err)
	}
	return resp, nil
}

// list fetches audit rows (newest first) with the gateway's filters.
func (c *bridgeAuditClient) list(ctx context.Context, label, outcome string, limit int) ([]bridge.AuditAdminRow, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if label != "" {
		q.Set("token_label", label)
	}
	if outcome != "" {
		q.Set("outcome", outcome)
	}
	resp, err := c.get(ctx, "/v1/bridge/audit", q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge audit gateway: list returned %d", resp.StatusCode)
	}
	var out struct {
		OK   bool                   `json:"ok"`
		Rows []bridge.AuditAdminRow `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("bridge audit gateway: bad list response: %w", err)
	}
	if !out.OK {
		return nil, fmt.Errorf("bridge audit gateway: list not ok")
	}
	if out.Rows == nil {
		out.Rows = []bridge.AuditAdminRow{}
	}
	return out.Rows, nil
}

// verify fetches the audit hash-chain verification result.
func (c *bridgeAuditClient) verify(ctx context.Context) (bridge.AuditAdminVerify, error) {
	resp, err := c.get(ctx, "/v1/bridge/audit/verify", nil)
	if err != nil {
		return bridge.AuditAdminVerify{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return bridge.AuditAdminVerify{}, fmt.Errorf("bridge audit gateway: verify returned %d", resp.StatusCode)
	}
	var out bridge.AuditAdminVerify
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return bridge.AuditAdminVerify{}, fmt.Errorf("bridge audit gateway: bad verify response: %w", err)
	}
	if !out.OK {
		return bridge.AuditAdminVerify{}, fmt.Errorf("bridge audit gateway: verify not ok")
	}
	return out, nil
}

// handleBridgeAudit renders the bridge audit admin view (issue #95):
// the metadata-only audit log fetched from the gateway, for dashboard
// admins only. Filters (token label, outcome, limit) ride the query
// string and are passed through to the gateway's read-only API. The
// page shows the chain-verification status alongside the rows.
func (s *Server) handleBridgeAudit(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(r)
	if u == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if u.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}
	// Admin-only: the audit log holds operational metadata (token
	// labels, recipients). Ordinary dashboard users must never see it.
	if !u.IsAdmin {
		http.Error(w, "forbidden: the bridge audit view is restricted to dashboard admins", http.StatusForbidden)
		return
	}
	label := strings.TrimSpace(r.URL.Query().Get("label"))
	outcome := strings.TrimSpace(r.URL.Query().Get("outcome"))
	limit := bridge.DefaultAdminAuditLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v >= 1 && v <= bridge.MaxAdminAuditLimit {
			limit = v
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	rows, listErr := s.bridgeAudit.list(ctx, label, outcome, limit)
	verify, verifyErr := s.bridgeAudit.verify(ctx)
	type rowView struct {
		bridge.AuditAdminRow
		RecipientShort string
		SHA12          string
		OutcomeClass   string
	}
	views := make([]rowView, 0, len(rows))
	for _, e := range rows {
		sha := e.BodySHA256
		if len(sha) > 12 {
			sha = sha[:12]
		}
		views = append(views, rowView{
			AuditAdminRow:  e,
			RecipientShort: senderShort(e.Recipient),
			SHA12:          sha,
			OutcomeClass:   outcomeClass(e.Outcome),
		})
	}
	render(w, auditTmpl, map[string]any{
		"User": u.Username, "Rows": views,
		"Verify": verify, "VerifyErr": verifyErr,
		"ListErr": listErr,
		"Label":   label, "Outcome": outcome, "Limit": limit,
		"BCTEnabled": s.bctEnabled(),
	})
}

// outcomeClass maps an audit outcome to a badge style: sent reads as
// success, in-flight states as neutral, rejections as errors.
func outcomeClass(outcome string) string {
	switch {
	case outcome == bridge.OutcomeSent:
		return "ok"
	case strings.HasPrefix(outcome, "rejected:"):
		return "err"
	default:
		return "neutral"
	}
}

// auditTmpl is the admin audit view: chain-verification status, filter
// form, and the metadata-only audit rows (newest first). Message
// bodies are never logged and never rendered — the table carries only
// what the audit log holds.
const auditTmpl = pageHead + `
<header class="appbar"><div class="appbar-inner">
<a class="back" href="/app" aria-label="Back to messages">‹</a>
<h1>Bridge audit</h1>
<span class="user" title="{{.User}}">{{.User}}</span>
</div></header>
<div class="wrap wide">
{{if .VerifyErr}}
<div class="error" role="alert">Chain verification unavailable: {{.VerifyErr}}. The rows below are still the gateway's current log.</div>
{{else if .Verify.ChainOK}}
<div class="vbanner ok" role="status">✓ Audit chain verified — {{.Verify.Checked}} rows checked{{if gt .Verify.FirstID 1}} (chain starts at row {{.Verify.FirstID}}: older rows pruned per retention){{end}}.</div>
{{else}}
<div class="vbanner err" role="alert">⚠ Audit chain verification FAILED after {{.Verify.Checked}} rows — possible tampering. See docs/bridge.md for the threat model.</div>
{{end}}
{{if .ListErr}}
<div class="error" role="alert">Could not load audit rows: {{.ListErr}}</div>
{{else}}
<form class="afilters" method="get" action="/admin/bridge/audit">
<label>Token label <input type="text" name="label" value="{{.Label}}" placeholder="e.g. lane-chatgpt" autocomplete="off"></label>
<label>Outcome <input type="text" name="outcome" value="{{.Outcome}}" placeholder="sent, rejected:rate_limited, …" autocomplete="off"></label>
<label>Limit <input type="number" name="limit" value="{{.Limit}}" min="1" max="1000"></label>
<button class="btn btn-sm" type="submit">Filter</button>
{{if or .Label .Outcome}}<a class="btn btn-ghost btn-sm" href="/admin/bridge/audit">Clear</a>{{end}}
</form>
<div class="twrap"><table class="tbl">
<thead><tr>
<th>ID</th><th>Time</th><th>Token label</th><th>Recipient</th><th>Size</th><th>Outcome</th><th>Envelope</th><th>Body SHA-256</th><th>Detail</th>
</tr></thead>
<tbody>
{{range .Rows}}<tr>
<td class="mono">{{.ID}}</td>
<td><span class="when" data-ts="{{.Ts}}">{{ago .Ts}}</span></td>
<td>{{.TokenLabel}}</td>
<td class="mono" title="{{.Recipient}}">{{.RecipientShort}}</td>
<td class="num">{{.BodySize}}</td>
<td><span class="obadge {{.OutcomeClass}}">{{.Outcome}}</span></td>
<td class="mono num">{{if .EnvelopeID}}{{.EnvelopeID}}{{else}}—{{end}}</td>
<td class="mono" title="{{.BodySHA256}}">{{.SHA12}}…</td>
<td class="detail">{{if .Reason}}{{.Reason}}{{else if .SendRef}}↩ #{{.SendRef}}{{else}}—{{end}}</td>
</tr>{{end}}
</tbody>
</table></div>
{{if not .Rows}}<div class="card empty"><div class="empty-mark" aria-hidden="true">📋</div><h2>No audit rows</h2><p>Nothing matches these filters yet.</p></div>{{end}}
<p class="hint" style="text-align:left">Metadata only: message bodies are never logged. Same data as <code>courier bridge audit</code> on the VPS.</p>
{{end}}
<footer class="foot">Courier dashboard · bridge audit is restricted to dashboard admins</footer>
</div>` + pageFoot
