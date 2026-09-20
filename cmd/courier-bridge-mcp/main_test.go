package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeGateway scripts gateway responses for MCP tests.
type fakeGateway struct {
	t      *testing.T
	mu     sync.Mutex
	ingest func(w http.ResponseWriter, r *http.Request)
	status int
}

func (f *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/bridge/ingest":
		f.mu.Lock()
		fn := f.ingest
		f.mu.Unlock()
		fn(w, r)
	case "/v1/bridge/status":
		json.NewEncoder(w).Encode(map[string]any{
			"label":                "test",
			"allowlist":            []string{"ed25519:AAA", "ed25519:BBB"},
			"per_minute_remaining": 9,
			"per_hour_remaining":   99,
			"body_cap_bytes":       65536,
			"disclosure":           "NOT end-to-end encrypted.",
		})
	default:
		http.NotFound(w, r)
	}
}

func jsonBody(t *testing.T, w http.ResponseWriter, code int, v any) {
	t.Helper()
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

// testClient connects an SDK client to a buildServer instance backed by
// the fake gateway.
func testClient(t *testing.T, fg *fakeGateway) *mcp.ClientSession {
	t.Helper()
	fg.t = t
	gw := httptest.NewServer(fg)
	t.Cleanup(gw.Close)

	srv := buildServer(newBridgeClient(gw.URL, "token"))
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	mcpSrv := httptest.NewServer(handler)
	t.Cleanup(mcpSrv.Close)

	cl := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cs, err := cl.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             mcpSrv.URL,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func toolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range res.Content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			t.Fatalf("expected TextContent, got %T", c)
		}
		sb.WriteString(tc.Text)
	}
	return sb.String()
}

func TestSendConfirmationRoundTrip(t *testing.T) {
	var confirmed bool
	fg := &fakeGateway{}
	fg.ingest = func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Recipient    string `json:"recipient"`
			Body         string `json:"body"`
			ConfirmToken string `json:"confirm_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatal(err)
		}
		if in.ConfirmToken == "" {
			if in.Recipient != "ed25519:AAA" || in.Body != "hello" {
				t.Fatalf("unexpected ingest body: %+v", in)
			}
			jsonBody(t, w, 449, map[string]any{
				"error":         "confirmation_required",
				"confirm_token": "ct-1",
				"summary": map[string]any{
					"recipient": "ed25519:AAA", "body_size": 5, "body_sha256": "abc",
				},
				"disclosure": "NOT end-to-end encrypted.",
			})
			return
		}
		if in.ConfirmToken != "ct-1" {
			jsonBody(t, w, 400, map[string]any{"error": "bad confirm token"})
			return
		}
		confirmed = true
		jsonBody(t, w, 200, map[string]any{"envelope_id": 7, "audit_id": 3, "status": "sent"})
	}

	cs := testClient(t, fg)

	// First send: 449 → human-readable confirmation text, not an error.
	res := callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:AAA", "body": "hello",
	})
	if res.IsError {
		t.Fatal("confirmation round-trip must not be an error result")
	}
	text := toolText(t, res)
	if !strings.Contains(text, "CONFIRMATION REQUIRED") ||
		!strings.Contains(text, `confirm_token="ct-1"`) ||
		!strings.Contains(text, "NOT end-to-end encrypted") {
		t.Fatalf("bad confirmation text:\n%s", text)
	}

	// Confirmed send: 200 → success text with ids.
	res = callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:AAA", "body": "hello", "confirm_token": "ct-1",
	})
	if res.IsError {
		t.Fatalf("confirmed send failed: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "Message sent") {
		t.Fatalf("bad success text: %s", toolText(t, res))
	}
	if !confirmed {
		t.Fatal("gateway never saw the confirmed ingest")
	}
}

func TestSendErrors(t *testing.T) {
	fg := &fakeGateway{}
	fg.ingest = func(w http.ResponseWriter, r *http.Request) {
		jsonBody(t, w, 429, map[string]any{"error": "rate limit exceeded"})
	}
	cs := testClient(t, fg)
	res := callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:AAA", "body": "x",
	})
	if !res.IsError {
		t.Fatal("rate-limited send must be an error result")
	}
	if !strings.Contains(toolText(t, res), "rate limit") {
		t.Fatalf("bad error text: %s", toolText(t, res))
	}

	// Missing required fields fail locally, before any gateway call.
	fg.ingest = func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("gateway must not be reached with empty body")
	}
	res = callTool(t, cs, "send_to_agent", map[string]any{"recipient": "ed25519:AAA"})
	if !res.IsError {
		t.Fatal("empty body must be an error result")
	}
}

func TestStatusAndRecipients(t *testing.T) {
	fg := &fakeGateway{}
	fg.ingest = func(w http.ResponseWriter, r *http.Request) { t.Fatal("no ingest expected") }
	cs := testClient(t, fg)

	res := callTool(t, cs, "bridge_status", nil)
	text := toolText(t, res)
	for _, want := range []string{"test", "ed25519:AAA", "ed25519:BBB", "9/min", "99/hour", "NOT end-to-end encrypted"} {
		if !strings.Contains(text, want) {
			t.Fatalf("status missing %q:\n%s", want, text)
		}
	}

	res = callTool(t, cs, "list_bridge_recipients", nil)
	text = toolText(t, res)
	if !strings.Contains(text, "ed25519:AAA") || !strings.Contains(text, "ed25519:BBB") {
		t.Fatalf("recipients missing addresses:\n%s", text)
	}
}

func TestSendToolDescriptionDisclosesNonE2E(t *testing.T) {
	srv := buildServer(newBridgeClient("http://127.0.0.1:1", "x"))
	// The description must lead with the non-E2E warning (plan §3.3).
	if !strings.HasPrefix(sendToolDescription, "⚠️ Messages sent through this tool are NOT end-to-end encrypted") {
		t.Fatalf("send tool description lost its mandatory disclosure:\n%s", sendToolDescription)
	}
	_ = srv
}
