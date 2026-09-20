package client

import (
	"encoding/json"
	"testing"
)

// Bridged payloads must round-trip through the standard payload
// parser: pre-bridge clients render the banner-in-body per existing v2
// handling (harmless degradation), and the bridge field is additive.
func TestBridgedPayloadRoundTrip(t *testing.T) {
	meta := &BridgeMeta{
		Origin:     BridgeOriginChatGPTWeb,
		GatewayFP:  "deadbeef",
		TokenLabel: "t1",
		AuditID:    7,
	}
	plain, err := encodeBridgedBody("[banner]\nhi", meta)
	if err != nil {
		t.Fatal(err)
	}
	// The wire form is v2 JSON with the bridge object.
	var raw map[string]any
	if err := json.Unmarshal(plain, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["v"] != float64(replyPayloadVersion) {
		t.Fatalf("v = %v", raw["v"])
	}
	bm, ok := raw["bridge"].(map[string]any)
	if !ok {
		t.Fatal("bridge object missing")
	}
	if bm["origin"] != BridgeOriginChatGPTWeb || bm["gateway_fp"] != "deadbeef" ||
		bm["token_label"] != "t1" || bm["audit_id"] != float64(7) {
		t.Fatalf("bridge = %v", bm)
	}
	// Standard parse path yields the body (banner included).
	body, _, _, _ := parseMessagePayload(plain)
	if body != "[banner]\nhi" {
		t.Fatalf("body = %q", body)
	}
}

func TestBridgeGatewayPinning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	addr := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := cfg.AddBridgeGateway("bogus"); err == nil {
		t.Fatal("pinned bogus address")
	}
	if err := cfg.AddBridgeGateway(addr); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddBridgeGateway(addr); err != nil { // idempotent
		t.Fatal(err)
	}
	if len(cfg.BridgeGateways) != 1 {
		t.Fatalf("pins = %v", cfg.BridgeGateways)
	}
	// Persists across reload.
	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.BridgeGateways) != 1 || reloaded.BridgeGateways[0] != addr {
		t.Fatalf("reloaded pins = %v", reloaded.BridgeGateways)
	}
	if err := reloaded.RemoveBridgeGateway(addr); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.BridgeGateways) != 0 {
		t.Fatalf("pins after remove = %v", reloaded.BridgeGateways)
	}
}
