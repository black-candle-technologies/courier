package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/store"
)

func TestMobileViewsOwnerIsolation(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/mobile.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	alice, err := st.CreateDashboardUser("alice", "hash", "alice-address", "api-alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := st.CreateDashboardUser("bob", "hash", "bob-address", "api-bob")
	if err != nil {
		t.Fatal(err)
	}
	if err = st.LinkBCTAccount(alice.ID, 7, "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if err = st.LinkBCTAccount(bob.ID, 8, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for i, body := range []string{"Alice private message one", "Alice private message two"} {
		if _, err = st.SaveDashboardMessage(alice.ID, int64(i+1), "alice-peer", "", "alice-peer", body, now, now, 0, "", 0, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = st.SaveDashboardMessage(bob.ID, 99, "bob-peer", "", "bob-peer", "Bob secret", now, now, 0, "", 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err = st.SaveDashboardMessage(alice.ID, 100, "alice-peer", "", "alice-peer", "Expired secret", now, now, 0, "", now-1, false); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "auth-service-only" {
			t.Error("missing auth service key")
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		id := 7
		kind := "oauth_access"
		active := true
		if body["token"] == "bob-access" {
			id = 8
		}
		if body["token"] == "pat-access" {
			kind = "pat"
		}
		if body["token"] == "revoked-access" {
			active = false
		}
		json.NewEncoder(w).Encode(map[string]any{"active": active, "credential_kind": kind, "user_id": id, "client_id": "first-party", "scope": "mobile:read courier:messages:read", "grant_id": "grant", "user": map[string]any{"id": id, "email_verified": true}})
	}))
	defer auth.Close()
	key := strings.Repeat("service-read-key", 3)
	handler := New(st).WithMobileReads(MobileReadConfig{AuthURL: auth.URL, AuthAPIKey: "auth-service-only", ServiceKey: key, ClientIDs: []string{"first-party"}}).Routes()
	request := func(path, token, keyValue string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Mobile-Service-Key", keyValue)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, token := range []string{"pat-access", "revoked-access"} {
		if got := request("/internal/mobile/v1/messages", token, key); got.Code != 403 {
			t.Fatalf("token %s got %d", token, got.Code)
		}
	}
	if got := request("/internal/mobile/v1/messages", "alice-access", "wrong"); got.Code != 401 {
		t.Fatalf("service key got %d", got.Code)
	}
	page := request("/internal/mobile/v1/messages?limit=1", "alice-access", key)
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	if strings.Contains(page.Body.String(), "Bob secret") || strings.Contains(page.Body.String(), "Expired secret") {
		t.Fatal("cross-owner or expired message disclosed")
	}
	var parsed struct {
		Rows []struct {
			ID string `json:"id"`
		} `json:"rows"`
		Cursor string `json:"next_cursor"`
		More   bool   `json:"has_more"`
	}
	json.Unmarshal(page.Body.Bytes(), &parsed)
	if len(parsed.Rows) != 1 || !parsed.More || parsed.Cursor == "" {
		t.Fatal("pagination missing", page.Body.String())
	}
	if got := request("/internal/mobile/v1/messages/"+parsed.Rows[0].ID, "bob-access", key); got.Code != 404 {
		t.Fatalf("cross-user object got %d", got.Code)
	}
	if got := request("/internal/mobile/v1/messages?cursor="+parsed.Cursor, "bob-access", key); got.Code != 422 {
		t.Fatalf("cross-user cursor got %d", got.Code)
	}
	if got := request("/internal/mobile/v1/messages?q=changed&cursor="+parsed.Cursor, "alice-access", key); got.Code != 422 {
		t.Fatalf("query cursor got %d", got.Code)
	}
	if got := request("/internal/mobile/v1/messages?cursor="+parsed.Cursor, "alice-access", key); got.Code != 200 || strings.Contains(got.Body.String(), "message two") {
		t.Fatal("second page failure", got.Code, got.Body.String())
	}
}
