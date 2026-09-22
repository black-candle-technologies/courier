// Relay-side advisory bridge flag (issue #98): envelopes from sender
// addresses the operator registered as bridge identities get the
// `bridged:<origin>` sender flag in inbox/subscribe responses. The flag
// is metadata-only and purely additive — no wire or protocol change —
// so old clients ignore the unknown flag value and old relays never
// emit it.
package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/store"
)

func testServerWithBridge(t *testing.T, origins map[string]string) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := DefaultConfig()
	cfg.BridgeOrigins = origins
	return NewWithConfig(st, cfg)
}

func inboxFlags(t *testing.T, srv *Server, recipient *crypto.Identity) [][]string {
	t.Helper()
	req := httptest.NewRequest("GET", signedInboxURL(t, recipient, 0, 50), nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inbox: got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Messages []struct {
			From        string   `json:"from"`
			SenderFlags []string `json:"sender_flags"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	flags := make([][]string, len(out.Messages))
	for i, m := range out.Messages {
		flags[i] = m.SenderFlags
	}
	return flags
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

func TestBridgeFlagMarked(t *testing.T) {
	bridge, _ := crypto.GenerateIdentity()
	plain, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bridgeAddr := crypto.FormatAddress(bridge.EdPub[:])

	srv := testServerWithBridge(t, map[string]string{bridgeAddr: "chatgpt-web"})

	if rec := postSend(t, srv, makeEnvelope(t, bridge, bob, "via bridge")); rec.Code != http.StatusCreated {
		t.Fatalf("bridge send: got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := postSend(t, srv, makeEnvelope(t, plain, bob, "direct")); rec.Code != http.StatusCreated {
		t.Fatalf("direct send: got %d: %s", rec.Code, rec.Body.String())
	}

	flags := inboxFlags(t, srv, bob)
	if len(flags) != 2 {
		t.Fatalf("want 2 messages, got %d", len(flags))
	}
	if !hasFlag(flags[0], "bridged:chatgpt-web") {
		t.Fatalf("bridge message missing bridged:chatgpt-web flag: %v", flags[0])
	}
	for _, f := range flags[1] {
		if strings.HasPrefix(f, "bridged") {
			t.Fatalf("direct message wrongly flagged: %v", flags[1])
		}
	}
}

func TestBridgeFlagAbsentWithoutRegistration(t *testing.T) {
	bridge, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	// No bridge origins configured: no flag, and the unknown-flag
	// tolerance path is exercised by construction (nothing emitted).
	srv := testServerWithBridge(t, nil)
	if rec := postSend(t, srv, makeEnvelope(t, bridge, bob, "hello")); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}
	flags := inboxFlags(t, srv, bob)
	if len(flags) != 1 {
		t.Fatalf("want 1 message, got %d", len(flags))
	}
	for _, f := range flags[0] {
		if strings.HasPrefix(f, "bridged") {
			t.Fatalf("unregistered sender flagged: %v", flags[0])
		}
	}
}

func TestBridgeOriginsValidation(t *testing.T) {
	good, _ := crypto.GenerateIdentity()
	goodAddr := crypto.FormatAddress(good.EdPub[:])
	srv := testServerWithBridge(t, map[string]string{
		goodAddr:       "chatgpt-web",
		"not-an-addr":  "chatgpt-web", // invalid address: dropped
		goodAddr + "x": "chatgpt-web", // corrupt address: dropped
		"ed25519:AAAA": "BAD LABEL!",  // invalid origin label: dropped
	})
	if len(srv.bridgeOrigins) != 1 || srv.bridgeOrigins[goodAddr] != "chatgpt-web" {
		t.Fatalf("want only the valid entry kept, got %v", srv.bridgeOrigins)
	}
}

// The wire shape is unchanged apart from the additive flag value: an
// old client decoding inboxMsgJSON keeps working, because
// sender_flags already existed and unknown values are plain strings.
func TestBridgeFlagWireAdditive(t *testing.T) {
	bridge, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bridgeAddr := crypto.FormatAddress(bridge.EdPub[:])
	srv := testServerWithBridge(t, map[string]string{bridgeAddr: "chatgpt-web"})
	if rec := postSend(t, srv, makeEnvelope(t, bridge, bob, "hello")); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}
	req := httptest.NewRequest("GET", signedInboxURL(t, bob, 0, 50), nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	// An old client only knows these fields; decode must succeed and
	// carry the full existing shape.
	var out struct {
		Messages []struct {
			ID         int64  `json:"id"`
			From       string `json:"from"`
			Eph        string `json:"eph"`
			Nonce      string `json:"nonce"`
			Ct         string `json:"ct"`
			SentAt     int64  `json:"sent_at"`
			ReceivedAt int64  `json:"received_at"`
			Sig        string `json:"sig"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 1 || out.Messages[0].From != bridgeAddr {
		t.Fatalf("old-client decode broken: %+v", out.Messages)
	}
}
