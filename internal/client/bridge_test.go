package client

import (
	"encoding/json"
	"testing"

	"github.com/black-candle-technologies/courier/internal/bridge"
)

// Bridged payloads must round-trip through the standard payload
// parser: pre-bridge clients render the banner-in-body per existing v2
// handling (harmless degradation), and the bridge field is additive.
func TestBridgedPayloadRoundTrip(t *testing.T) {
	meta := &bridge.BridgeMeta{
		Origin:     bridge.BridgeOriginChatGPTWeb,
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
	if bm["origin"] != bridge.BridgeOriginChatGPTWeb || bm["gateway_fp"] != "deadbeef" ||
		bm["token_label"] != "t1" || bm["audit_id"] != float64(7) {
		t.Fatalf("bridge = %v", bm)
	}
	// Standard parse path yields the body (banner included) and the
	// structured bridge metadata.
	body, _, _, _, bmeta := parseMessagePayload(plain)
	if body != "[banner]\nhi" {
		t.Fatalf("body = %q", body)
	}
	if bmeta == nil || *bmeta != *meta {
		t.Fatalf("bridge meta = %+v, want %+v", bmeta, meta)
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

// TestDeriveBridged: the bridged flag is the OR of three independent
// layers (issues #96/#97) — structured payload metadata, the
// recipient's pinned bridge-address list, and the body banner. The pin
// list flags messages from the bridge identity even when payload
// metadata is absent.
func TestDeriveBridged(t *testing.T) {
	bridgeAddr := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	peerAddr := "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	meta := &bridge.BridgeMeta{Origin: bridge.BridgeOriginChatGPTWeb, GatewayFP: "abc"}
	pins := []string{bridgeAddr}
	cases := []struct {
		name string
		from string
		pins []string
		meta *bridge.BridgeMeta
		body string
		want bool
	}{
		{"metadata only", peerAddr, nil, meta, "hi", true},
		{"pin list only", bridgeAddr, pins, nil, "hi", true},
		{"banner only", peerAddr, nil, nil, bridge.WrapBody("hi"), true},
		{"all layers", bridgeAddr, pins, meta, bridge.WrapBody("hi"), true},
		{"ordinary message", peerAddr, nil, nil, "hi", false},
		{"ordinary message with pins", peerAddr, pins, nil, "hi", false},
		// The banner must be a prefix: a banner-like suffix is not
		// attribution and must not mark the message.
		{"banner as suffix", peerAddr, nil, nil, "hi\n" + bridge.BridgeBannerHeader, false},
	}
	for _, tc := range cases {
		if got := deriveBridged(tc.from, tc.pins, tc.meta, tc.body); got != tc.want {
			t.Errorf("%s: deriveBridged = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A peer that self-declares the banner still gets marked: claiming
	// to be bridged can only downgrade a message to untrusted, never
	// upgrade anything to trusted.
	if !deriveBridged(peerAddr, nil, nil, bridge.WrapBody("forged banner")) {
		t.Error("self-declared banner must still mark the message bridged")
	}
}

// TestIsPinnedBridgeGateway: the pin-list layer of deriveBridged reads
// the client's own config — the recipient's trust decision, needing no
// sender cooperation.
func TestIsPinnedBridgeGateway(t *testing.T) {
	cfg := testConfig(t)
	cl := New(cfg)
	addr := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if cl.isPinnedBridgeGateway(addr) {
		t.Fatal("unpinned address reported as pinned")
	}
	if err := cfg.AddBridgeGateway(addr); err != nil {
		t.Fatal(err)
	}
	if !cl.isPinnedBridgeGateway(addr) {
		t.Fatal("pinned address not reported")
	}
	if cl.isPinnedBridgeGateway("ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") {
		t.Fatal("wrong address reported as pinned")
	}
}

// TestBridgedMessageFields: Message carries the typed bridged signal
// (issues #96/#97) through JSON — the serve /inbox endpoint serializes
// Message directly, so the flag must survive the round trip for agent
// consumers.
func TestBridgedMessageFields(t *testing.T) {
	meta := &bridge.BridgeMeta{Origin: bridge.BridgeOriginChatGPTWeb, GatewayFP: "abc"}
	m := Message{ID: 7, From: "ed25519:x", Body: "hi", Bridged: true, Bridge: meta}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Message
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Bridged {
		t.Error("bridged flag lost in JSON round trip")
	}
	if back.Bridge == nil || back.Bridge.Origin != bridge.BridgeOriginChatGPTWeb {
		t.Errorf("bridge meta lost in JSON round trip: %+v", back.Bridge)
	}
	// A non-bridged message omits the fields (omitempty): consumers
	// see no flag rather than a false one.
	plain := Message{ID: 8, From: "ed25519:x", Body: "hi"}
	raw, _ = json.Marshal(plain)
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["bridged"]; ok {
		t.Error("non-bridged message must omit the bridged field")
	}
}
