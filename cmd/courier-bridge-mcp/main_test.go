package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeGateway scripts gateway responses for MCP tests.
type fakeGateway struct {
	t      *testing.T
	mu     sync.Mutex
	hits   atomic.Int64
	ingest func(w http.ResponseWriter, r *http.Request)
	status int
}

func (f *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
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

// fakeAuthdUser is the identity a fake authd reports for a token.
type fakeAuthdUser struct {
	id    int64
	email string
}

// fakeAuthd scripts authd's /oauth/userinfo for OAuth tests: tokens
// mapped in users validate, everything else gets 401.
type fakeAuthd struct {
	t     *testing.T
	mu    sync.Mutex
	hits  int
	users map[string]fakeAuthdUser
}

func (f *fakeAuthd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/oauth/userinfo" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	u, ok := f.users[token]
	if !ok {
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":             u.id,
		"email":          u.email,
		"email_verified": true,
	})
}

func (f *fakeAuthd) hitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

// oauthRig is a full MCP server under test: fake authd + fake gateway
// + the production mux (discovery, bearer validation, caller
// allowlist).
type oauthRig struct {
	t      *testing.T
	mcpURL string
	authd  *fakeAuthd
	gw     *fakeGateway
	public string
}

const (
	rigPublicURL = "https://mcp.example.com"
	tokenAlice   = "token-alice-valid"
	tokenBob     = "token-bob-valid"
	tokenBad     = "token-invalid"
)

func newOAuthRig(t *testing.T, allowed []string) *oauthRig {
	t.Helper()
	gw := &fakeGateway{t: t}
	gwSrv := httptest.NewServer(gw)
	t.Cleanup(gwSrv.Close)

	fa := &fakeAuthd{t: t, users: map[string]fakeAuthdUser{
		tokenAlice: {id: 7, email: "alice@example.com"},
		tokenBob:   {id: 9, email: "bob@example.com"},
	}}
	authdSrv := httptest.NewServer(fa)
	t.Cleanup(authdSrv.Close)

	parsed, err := parseAllowedCallers(strings.Join(allowed, ","))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &oauthConfig{
		authdURL:  authdSrv.URL,
		publicURL: rigPublicURL,
		allowed:   parsed,
		cache:     newTokenCache(),
		http:      &http.Client{Timeout: 15 * time.Second},
	}
	srv := buildServer(newBridgeClient(gwSrv.URL, "token"), sendToolDescriptionFor(defaultBodyCapBytes))
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true})
	bearer := auth.RequireBearerToken(cfg.verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: cfg.publicURL + "/.well-known/oauth-protected-resource",
		Scopes:              []string{oauthScopeIdentity},
	})
	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/oauth-protected-resource", protectedResourceMetadata(cfg.publicURL, cfg.authdURL))
	mux.Handle("/", bearer(requireAllowedCaller(mcpHandler, cfg.allowed)))
	mcpSrv := httptest.NewServer(mux)
	t.Cleanup(mcpSrv.Close)

	return &oauthRig{t: t, mcpURL: mcpSrv.URL, authd: fa, gw: gw, public: rigPublicURL}
}

// postMCP posts a raw JSON-RPC request to the rig's MCP endpoint with
// an optional Authorization header value ("": none).
func (r *oauthRig) postMCP(t *testing.T, authorization string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, r.mcpURL, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header
}

// authRoundTripper injects a bearer token into every client request; an
// empty token sends no Authorization header.
type authRoundTripper struct {
	token string
	rt    http.RoundTripper
}

func (a authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	if a.token != "" {
		r2.Header.Set("Authorization", "Bearer "+a.token)
	}
	rt := a.rt
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(r2)
}

// client connects an SDK client to the rig, presenting token (""
// sends nothing). Connect failures are returned, not fatal, so tests
// can assert on rejection.
func (r *oauthRig) client(t *testing.T, token string) (*mcp.ClientSession, error) {
	t.Helper()
	cl := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cs, err := cl.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             r.mcpURL,
		HTTPClient:           &http.Client{Transport: authRoundTripper{token: token}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { cs.Close() })
	return cs, nil
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

// TestProtectedResourceMetadata: the RFC 9728 discovery document is
// served unauthenticated and points at the authorization server.
func TestProtectedResourceMetadata(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	resp, err := http.Get(rig.mcpURL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var doc struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != rigPublicURL {
		t.Fatalf("resource = %q, want %q", doc.Resource, rigPublicURL)
	}
	if len(doc.AuthorizationServers) != 1 {
		t.Fatalf("authorization_servers = %v, want one entry", doc.AuthorizationServers)
	}
	if len(doc.ScopesSupported) != 1 || doc.ScopesSupported[0] != "identity" {
		t.Fatalf("scopes_supported = %v, want [identity]", doc.ScopesSupported)
	}
}

// TestOAuthDiscoveryOn401: unauthenticated callers get a 401 whose
// WWW-Authenticate carries the resource_metadata discovery URL — the
// signal ChatGPT web needs to start the OAuth flow.
func TestOAuthDiscoveryOn401(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	code, hdr := rig.postMCP(t, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("no auth header: status = %d, want 401", code)
	}
	www := hdr.Get("WWW-Authenticate")
	want := `resource_metadata="` + rigPublicURL + `/.well-known/oauth-protected-resource"`
	if !strings.Contains(www, want) {
		t.Fatalf("WWW-Authenticate = %q, want it to contain %q", www, want)
	}
}

// TestOAuthCallerAuth: the full gate matrix. Invalid tokens 401,
// valid-but-unprovisioned callers 403, provisioned callers pass — and
// nobody unauthenticated ever reaches the gateway.
func TestOAuthCallerAuth(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})

	if code, _ := rig.postMCP(t, ""); code != http.StatusUnauthorized {
		t.Fatalf("no auth header: status = %d, want 401", code)
	}
	if code, _ := rig.postMCP(t, "Bearer "+tokenBad); code != http.StatusUnauthorized {
		t.Fatalf("bad token: status = %d, want 401", code)
	}
	if code, _ := rig.postMCP(t, "Bearer "+tokenBob); code != http.StatusForbidden {
		t.Fatalf("unprovisioned caller: status = %d, want 403", code)
	}
	if code, _ := rig.postMCP(t, "Bearer "+tokenAlice); code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Fatalf("provisioned caller rejected: status = %d", code)
	}
	if n := rig.gw.hits.Load(); n != 0 {
		t.Fatalf("gateway was contacted %d times by unauthenticated callers", n)
	}

	// A provisioned caller works end to end over the SDK client.
	cs, err := rig.client(t, tokenAlice)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	res := callTool(t, cs, "list_bridge_recipients", nil)
	if res.IsError {
		t.Fatalf("authenticated tool call failed: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "ed25519:AAA") {
		t.Fatalf("bad recipients text: %s", toolText(t, res))
	}

	// An unprovisioned caller cannot even connect the SDK client.
	if _, err := rig.client(t, tokenBob); err == nil {
		t.Fatal("unprovisioned caller connected the MCP client")
	}
}

// TestOAuthTokenCache: a validated token is revalidated from cache,
// not from authd, on subsequent requests.
func TestOAuthTokenCache(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	cs, err := rig.client(t, tokenAlice)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	callTool(t, cs, "list_bridge_recipients", nil)
	callTool(t, cs, "bridge_status", nil)
	callTool(t, cs, "list_bridge_recipients", nil)
	if n := rig.authd.hitCount(); n != 1 {
		t.Fatalf("authd userinfo hits = %d, want 1 (cached)", n)
	}
}

// TestOAuthNegativeCache: rejected tokens stay rejected without
// hammering authd.
func TestOAuthNegativeCache(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	for i := 0; i < 3; i++ {
		if code, _ := rig.postMCP(t, "Bearer "+tokenBad); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, code)
		}
	}
	if n := rig.authd.hitCount(); n != 1 {
		t.Fatalf("authd userinfo hits = %d, want 1 (negative cached)", n)
	}
}

// TestOAuthAuthdDownFailsClosed: when authd is unreachable the bridge
// denies access instead of failing open.
func TestOAuthAuthdDownFailsClosed(t *testing.T) {
	dead := &oauthConfig{
		authdURL:  "http://127.0.0.1:1",
		publicURL: rigPublicURL,
		allowed:   map[string]bool{"alice@example.com": true},
		cache:     newTokenCache(),
		http:      &http.Client{Timeout: 2 * time.Second},
	}
	bearer := auth.RequireBearerToken(dead.verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: rigPublicURL + "/.well-known/oauth-protected-resource",
		Scopes:              []string{oauthScopeIdentity},
	})
	reached := false
	srv := httptest.NewServer(bearer(requireAllowedCaller(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}), dead.allowed)))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenAlice)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("request succeeded while authd is down: fail-open")
	}
	if reached {
		t.Fatal("inner handler reached while authd is down: fail-open")
	}
}

// TestSendIncludesCallerIdentity: the gateway ingest call carries the
// authenticated caller's email for the audit log.
func TestSendIncludesCallerIdentity(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	var gotCaller string
	rig.gw.ingest = func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Caller string `json:"caller"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotCaller = body.Caller
		jsonBody(t, w, 200, map[string]any{"envelope_id": 1, "audit_id": 2})
	}
	cs, err := rig.client(t, tokenAlice)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	res := callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:AAA", "body": "hello",
	})
	if res.IsError {
		t.Fatalf("send failed: %s", toolText(t, res))
	}
	if gotCaller != "alice@example.com" {
		t.Fatalf("ingest caller = %q, want alice@example.com", gotCaller)
	}
}

// TestParseAllowedCallers: empty fails closed; junk is rejected;
// entries are normalized and de-duplicated.
func TestParseAllowedCallers(t *testing.T) {
	if _, err := parseAllowedCallers(""); err == nil {
		t.Fatal("empty allowlist parsed without error: must fail closed")
	}
	if _, err := parseAllowedCallers("   , "); err == nil {
		t.Fatal("blank allowlist parsed without error: must fail closed")
	}
	if _, err := parseAllowedCallers("not-an-email"); err == nil {
		t.Fatal("non-email caller accepted")
	}
	got, err := parseAllowedCallers("Alice@Example.COM, bob@example.com ,alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["alice@example.com"] || !got["bob@example.com"] {
		t.Fatalf("bad parse result: %v", got)
	}
}

// TestCheckPublicURL: only https origins with no path are usable as
// the RFC 9728 resource identifier.
func TestCheckPublicURL(t *testing.T) {
	for _, bad := range []string{"http://mcp.example.com", "mcp.example.com", "", "https://"} {
		if _, err := checkPublicURL(bad); err == nil {
			t.Fatalf("checkPublicURL(%q) accepted", bad)
		}
	}
	got, err := checkPublicURL("https://mcp.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://mcp.example.com" {
		t.Fatalf("trailing slash not stripped: %q", got)
	}
}

// --- tool behavior tests (auth-agnostic, run as a provisioned caller) ---

func TestSendConfirmationRoundTrip(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	var calls int
	rig.gw.ingest = func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			ConfirmToken string `json:"confirm_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.ConfirmToken == "" {
			jsonBody(t, w, 449, map[string]any{
				"confirm_token": "ctok-1",
				"summary": map[string]any{
					"recipient": "ed25519:AAA", "body_size": 5, "body_sha256": "abc",
				},
				"disclosure": "NOT end-to-end encrypted.",
			})
			return
		}
		if body.ConfirmToken != "ctok-1" {
			jsonBody(t, w, 400, map[string]any{"error": "bad confirm token"})
			return
		}
		jsonBody(t, w, 200, map[string]any{"envelope_id": 42, "audit_id": 7})
	}
	cs, err := rig.client(t, tokenAlice)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	res := callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:AAA", "body": "hello",
	})
	if res.IsError {
		t.Fatalf("first send errored: %s", toolText(t, res))
	}
	txt := toolText(t, res)
	if !strings.Contains(txt, "CONFIRMATION REQUIRED") || !strings.Contains(txt, "ctok-1") {
		t.Fatalf("missing confirmation prompt: %s", txt)
	}
	res = callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:AAA", "body": "hello", "confirm_token": "ctok-1",
	})
	if res.IsError {
		t.Fatalf("confirmed send errored: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "Envelope id 42") {
		t.Fatalf("bad send result: %s", toolText(t, res))
	}
	if calls != 2 {
		t.Fatalf("gateway calls = %d, want 2", calls)
	}
}

func TestSendErrors(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	rig.gw.ingest = func(w http.ResponseWriter, r *http.Request) {
		jsonBody(t, w, 403, map[string]any{"error": "recipient not allowlisted for this token"})
	}
	cs, err := rig.client(t, tokenAlice)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	res := callTool(t, cs, "send_to_agent", map[string]any{
		"recipient": "ed25519:ZZZ", "body": "hi",
	})
	if !res.IsError {
		t.Fatal("expected error for non-allowlisted recipient")
	}
	if !strings.Contains(toolText(t, res), "not allowlisted") {
		t.Fatalf("bad error text: %s", toolText(t, res))
	}
	// Missing fields are rejected client-side without gateway contact.
	before := rig.gw.hits.Load()
	res = callTool(t, cs, "send_to_agent", map[string]any{"recipient": "ed25519:AAA"})
	if !res.IsError {
		t.Fatal("expected error for missing body")
	}
	if rig.gw.hits.Load() != before {
		t.Fatal("gateway contacted for client-side validation failure")
	}
}

func TestStatusAndRecipients(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	cs, err := rig.client(t, tokenAlice)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	res := callTool(t, cs, "bridge_status", nil)
	if res.IsError {
		t.Fatalf("bridge_status failed: %s", toolText(t, res))
	}
	txt := toolText(t, res)
	for _, want := range []string{`Bridge token "test"`, "ed25519:AAA", "ed25519:BBB", "NOT end-to-end encrypted."} {
		if !strings.Contains(txt, want) {
			t.Fatalf("bridge_status missing %q: %s", want, txt)
		}
	}
	res = callTool(t, cs, "list_bridge_recipients", nil)
	if res.IsError {
		t.Fatalf("list_bridge_recipients failed: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "ed25519:BBB") {
		t.Fatalf("bad recipients text: %s", toolText(t, res))
	}
}

// TestDiscoverAdvertisesLatestProtocol pins the ChatGPT-connector fix:
// the MCP handler must run stateless so server/discover advertises
// protocol 2026-07-28 (ChatGPT's openai-mcp client requires it and aborts
// connector setup when it is missing). The rig mirrors production, so a
// raw discover call here exercises the same handler configuration.
func TestDiscoverAdvertisesLatestProtocol(t *testing.T) {
	rig := newOAuthRig(t, []string{"alice@example.com"})
	body := `{"jsonrpc":"2.0","id":"discover-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, err := http.NewRequest(http.MethodPost, rig.mcpURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "server/discover")
	req.Header.Set("Authorization", "Bearer "+tokenAlice)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discover status = %d, body = %s", resp.StatusCode, raw)
	}
	var got struct {
		Result struct {
			SupportedVersions []string `json:"supportedVersions"`
		} `json:"result"`
	}
	// The response is SSE-framed; extract the data: payload.
	line := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "data:") {
			line = strings.TrimPrefix(l, "data:")
		}
	}
	if line == "" {
		t.Fatalf("no SSE data in discover response: %s", raw)
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("bad discover JSON: %v (%s)", err, line)
	}
	found := false
	for _, v := range got.Result.SupportedVersions {
		if v == "2026-07-28" {
			found = true
		}
	}
	if !found {
		t.Fatalf("server/discover missing 2026-07-28, got %v", got.Result.SupportedVersions)
	}
}

func TestSendToolDescriptionDisclosesNonE2E(t *testing.T) {
	if !strings.Contains(sendToolDisclosure, "NOT end-to-end encrypted") {
		t.Fatal("send tool description lost the non-E2E disclosure")
	}
	if !strings.Contains(sendToolDisclosure, "untrusted input") {
		t.Fatal("send tool description lost the untrusted-input warning")
	}
}

// TestSendToolDescriptionHonestAboutEnforcement (issue #86): phase 1
// cannot structurally guarantee untrusted-input enforcement — the
// disclosure must describe the actual control (operator approval rule),
// not claim a guarantee that only arrives in phase 2.
func TestSendToolDescriptionHonestAboutEnforcement(t *testing.T) {
	d := strings.ToLower(sendToolDisclosure)
	if strings.Contains(d, "guarantee") && !strings.Contains(d, "cannot") {
		t.Fatal("description claims an enforcement guarantee it cannot keep")
	}
	if !strings.Contains(d, "explicit approval") {
		t.Fatal("description must name the operator approval rule as the control")
	}
}

// TestSendToolDescriptionForCap pins the advertised body cap to the given
// value so the tool description stays truthful when the gateway cap is
// raised via COURIER_BRIDGE_BODY_CAP_BYTES.
func TestSendToolDescriptionForCap(t *testing.T) {
	d := sendToolDescriptionFor(defaultBodyCapBytes)
	if !strings.Contains(d, "64 KiB (65536 bytes)") {
		t.Fatalf("default cap not advertised, got: %s", d)
	}
	if !strings.Contains(d, "NOT end-to-end encrypted") {
		t.Fatal("cap description lost the non-E2E disclosure")
	}
	d = sendToolDescriptionFor(256 * 1024)
	if !strings.Contains(d, "256 KiB (262144 bytes)") {
		t.Fatalf("raised cap not advertised, got: %s", d)
	}
	// Non-positive falls back to the default rather than advertising nonsense.
	d = sendToolDescriptionFor(0)
	if !strings.Contains(d, "64 KiB (65536 bytes)") {
		t.Fatalf("zero cap did not fall back to default, got: %s", d)
	}
}

// TestFetchBodyCapFallback: when the gateway is unreachable at startup,
// the advertised cap falls back to the default instead of failing.
func TestFetchBodyCapFallback(t *testing.T) {
	b := newBridgeClient("http://127.0.0.1:1", "token") // nothing listens here
	if got := fetchBodyCap(b); got != defaultBodyCapBytes {
		t.Fatalf("fetchBodyCap unreachable = %d, want %d", got, defaultBodyCapBytes)
	}
}
