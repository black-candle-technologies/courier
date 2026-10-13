package dashboard

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/store"
)

// MobileReadConfig is an opt-in BFF-to-dashboard read boundary. The dedicated
// ServiceKey only authorizes these three read paths; OAuth introspection and the
// existing explicit BCT account link still authorize each owner's message data.
type MobileReadConfig struct {
	AuthURL, AuthAPIKey, ServiceKey string
	ClientIDs                       []string
}

func (s *Server) WithMobileReads(cfg MobileReadConfig) *Server { s.mobile = cfg; return s }
func (s *Server) mobileEnabled() bool {
	return len(s.mobile.ServiceKey) >= 32 && s.mobile.AuthAPIKey != "" && s.mobile.AuthURL != "" && len(s.mobile.ClientIDs) > 0
}
func mobileJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(value)
}
func mobileFailure(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": "Courier request could not be completed."}})
}
func (s *Server) mobileActor(w http.ResponseWriter, r *http.Request) *store.DashboardUser {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	if !s.mobileEnabled() || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Mobile-Service-Key")), []byte(s.mobile.ServiceKey)) != 1 {
		mobileFailure(w, 401, "SERVICE_REQUIRED")
		return nil
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) > 4096 {
		mobileFailure(w, 401, "LOGIN_REQUIRED")
		return nil
	}
	u, err := url.Parse(s.mobile.AuthURL)
	if err != nil || u.User != nil || (u.Scheme != "https" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		mobileFailure(w, 503, "CONFIGURATION_REQUIRED")
		return nil
	}
	body, _ := json.Marshal(map[string]string{"token": strings.TrimPrefix(auth, "Bearer ")})
	req, err := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(s.mobile.AuthURL, "/")+"/internal/v1/oauth/introspect", bytes.NewReader(body))
	if err != nil {
		mobileFailure(w, 503, "AUTH_UNAVAILABLE")
		return nil
	}
	req.Header.Set("X-Api-Key", s.mobile.AuthAPIKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}
	res, err := client.Do(req)
	if err != nil {
		mobileFailure(w, 503, "AUTH_UNAVAILABLE")
		return nil
	}
	defer res.Body.Close()
	var p struct {
		Active   bool   `json:"active"`
		Kind     string `json:"credential_kind"`
		UserID   int64  `json:"user_id"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		GrantID  string `json:"grant_id"`
		User     struct {
			ID       int64 `json:"id"`
			Verified bool  `json:"email_verified"`
		} `json:"user"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&p) != nil {
		mobileFailure(w, 503, "AUTH_UNAVAILABLE")
		return nil
	}
	allowed := false
	for _, id := range s.mobile.ClientIDs {
		if id == p.ClientID {
			allowed = true
		}
	}
	if !p.Active || p.Kind != "oauth_access" || p.GrantID == "" || !allowed || p.UserID <= 0 || p.User.ID != p.UserID || !p.User.Verified || !strings.Contains(" "+p.Scope+" ", " mobile:read ") || !strings.Contains(" "+p.Scope+" ", " courier:messages:read ") {
		mobileFailure(w, 403, "FORBIDDEN")
		return nil
	}
	owner, err := s.store.DashboardUserByBCTUserID(p.UserID)
	if err == sql.ErrNoRows {
		mobileFailure(w, 403, "ACCOUNT_NOT_LINKED")
		return nil
	}
	if err != nil || owner == nil {
		mobileFailure(w, 503, "STORE_UNAVAILABLE")
		return nil
	}
	return owner
}
func (s *Server) mobileOverview(w http.ResponseWriter, r *http.Request) {
	owner := s.mobileActor(w, r)
	if owner == nil {
		return
	}
	count, err := s.store.MobileMessageCount(owner.ID)
	if err != nil {
		mobileFailure(w, 503, "STORE_UNAVAILABLE")
		return
	}
	mobileJSON(w, 200, map[string]any{"message_count": count, "display_message": "Only messages your agent mirrored to Courier dashboard are available.", "capabilities": []string{"list_items", "read_detail", "search"}})
}

type mobileCursor struct {
	UserID  int64  `json:"owner"`
	Query   string `json:"query"`
	Filter  string `json:"filter"`
	Before  int64  `json:"before"`
	Expires int64  `json:"expires"`
}

func (s *Server) encodeMobileCursor(c mobileCursor) string {
	b, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, []byte(s.mobile.ServiceKey))
	m.Write([]byte("BCT-COURIER-CURSOR-V1\n" + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (s *Server) decodeMobileCursor(raw string, owner int64, q, filter string) (int64, bool) {
	if raw == "" {
		return 0, true
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || len(raw) > 2048 {
		return 0, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	m := hmac.New(sha256.New, []byte(s.mobile.ServiceKey))
	m.Write([]byte("BCT-COURIER-CURSOR-V1\n" + parts[0]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return 0, false
	}
	var c mobileCursor
	if json.Unmarshal(b, &c) != nil || c.UserID != owner || c.Query != q || c.Filter != filter || c.Expires < time.Now().Unix() || c.Before <= 0 {
		return 0, false
	}
	return c.Before, true
}
func messageRevision(value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (s *Server) mobileMessages(w http.ResponseWriter, r *http.Request) {
	owner := s.mobileActor(w, r)
	if owner == nil {
		return
	}
	params := r.URL.Query()
	q := params.Get("q")
	filter := params.Get("filter_id")
	if filter == "" {
		filter = "all"
	}
	sort := params.Get("sort_id")
	if sort == "" {
		sort = "created_desc"
	}
	limit := 25
	if params.Get("limit") != "" {
		var err error
		limit, err = strconv.Atoi(params.Get("limit"))
		if err != nil {
			mobileFailure(w, 422, "INVALID_QUERY")
			return
		}
	}
	before, ok := s.decodeMobileCursor(params.Get("cursor"), owner.ID, q, filter)
	if !ok || len(q) > 200 || limit < 1 || limit > 50 || (filter != "all" && filter != "bridged") || sort != "created_desc" {
		mobileFailure(w, 422, "INVALID_QUERY")
		return
	}
	rows, err := s.store.MobileMessages(owner.ID, before, q, filter == "bridged", limit+1)
	if err != nil {
		mobileFailure(w, 503, "STORE_UNAVAILABLE")
		return
	}
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}
	views := []any{}
	for _, m := range rows {
		status := "Mirrored"
		if m.Bridged {
			status = "Bridged · untrusted input"
		}
		snippet := []rune(m.Body)
		if len(snippet) > 160 {
			snippet = snippet[:160]
		}
		views = append(views, map[string]any{"id": strconv.FormatInt(m.ID, 10), "title": m.Sender, "subtitle": string(snippet), "status_label": status, "status_tone": "muted", "action": "open_service_item"})
	}
	var next any
	if hasMore {
		next = s.encodeMobileCursor(mobileCursor{UserID: owner.ID, Query: q, Filter: filter, Before: rows[len(rows)-1].ID, Expires: time.Now().Add(15 * time.Minute).Unix()})
	}
	mobileJSON(w, 200, map[string]any{"schema_version": 1, "screen": map[string]string{"title": "Courier messages"}, "revision": messageRevision(rows), "rows": views, "filters": []any{map[string]string{"id": "all", "label": "All"}, map[string]string{"id": "bridged", "label": "Bridged"}}, "sorts": []any{map[string]string{"id": "created_desc", "label": "Newest first"}}, "selected_filter_id": filter, "selected_sort_id": sort, "next_cursor": next, "has_more": hasMore, "empty_state": nil})
}
func (s *Server) mobileMessageDetail(w http.ResponseWriter, r *http.Request) {
	owner := s.mobileActor(w, r)
	if owner == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		mobileFailure(w, 404, "NOT_FOUND")
		return
	}
	m, err := s.store.MobileMessage(owner.ID, id)
	if err != nil {
		mobileFailure(w, 503, "STORE_UNAVAILABLE")
		return
	}
	if m == nil {
		mobileFailure(w, 404, "NOT_FOUND")
		return
	}
	status := "Agent-mirrored plaintext"
	if m.Bridged {
		status = "Bridged content · untrusted input"
	}
	fields := []any{map[string]string{"id": "body", "label": "Message", "value": m.Body}, map[string]string{"id": "source", "label": "Source", "value": status}, map[string]string{"id": "sent", "label": "Sent", "value": time.Unix(m.SentAt, 0).UTC().Format(time.RFC3339)}}
	mobileJSON(w, 200, map[string]any{"schema_version": 1, "screen": map[string]string{"title": m.Sender}, "fields": fields, "actions": []any{}, "revision": messageRevision(m)})
}
