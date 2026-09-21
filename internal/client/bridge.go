// Bridge messaging (issue #61, phase 1): sending bridge-attributed DMs.
//
// The ChatGPT web → Courier bridge is explicitly NOT end-to-end
// encrypted: the bridge gateway holds a Courier identity and sees every
// bridged message in plaintext before wrapping it into a normal Courier
// envelope. From the gateway onward the message is a standard E2E
// envelope signed by the bridge identity — never impersonating the
// ChatGPT caller. Every bridged message carries attribution in two
// layers: a plaintext body banner (visible on every client ever
// shipped) and structured BridgeMeta inside the E2E payload (for
// clients that render it, phase 2+).
package client

import (
	"encoding/json"
	"fmt"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// BridgeOriginChatGPTWeb identifies the ChatGPT web bridge origin in
// bridge metadata.
const BridgeOriginChatGPTWeb = "chatgpt-web"

// BridgeMeta is the structured bridge attribution riding inside the
// E2E-encrypted v2 payload. It is additive: pre-bridge clients ignore
// the unknown field and render the banner-in-body per existing v2
// handling (harmless degradation).
type BridgeMeta struct {
	// Origin is the bridge source, e.g. "chatgpt-web".
	Origin string `json:"origin"`
	// GatewayFP is the hex SHA-256 of the bridge identity's Ed25519
	// public key, so recipients can pin the expected gateway.
	GatewayFP string `json:"gateway_fp"`
	// TokenLabel is the ingest token label that submitted the message.
	TokenLabel string `json:"token_label,omitempty"`
	// AuditID is the gateway audit-log row for this send.
	AuditID int64 `json:"audit_id,omitempty"`
}

// encodeBridgedBody builds the v2 plaintext for a bridged message:
// banner-wrapped body plus bridge metadata. The v2 form is used even
// though no reply threading is involved, so the metadata has a home.
func encodeBridgedBody(wrappedBody string, meta *BridgeMeta) ([]byte, error) {
	return json.Marshal(replyPayload{
		Version: replyPayloadVersion,
		Body:    wrappedBody,
		Bridge:  meta,
	})
}

// SendBridged sends a bridge-attributed DM to address, which must be a
// full ed25519:... address (no contact-name resolution — the gateway
// works purely in allowlisted addresses). wrappedBody must already
// carry the attribution banner (see internal/bridge.WrapBody); meta
// must be non-nil.
//
// The send follows the normal human-send crypto path: an established
// forward-secrecy session is used when one exists, otherwise the
// standard sealed box. It is recorded in the local sent log like any
// DM so the dashboard threads it.
func (c *Client) SendBridged(address, wrappedBody string, meta *BridgeMeta) (int64, error) {
	if _, err := crypto.ParseAddress(address); err != nil {
		return 0, fmt.Errorf("bad recipient address: %w", err)
	}
	if meta == nil {
		return 0, fmt.Errorf("bridge metadata required")
	}
	plain, err := encodeBridgedBody(wrappedBody, meta)
	if err != nil {
		return 0, fmt.Errorf("encode bridged payload: %w", err)
	}
	// Same FS handling as a normal human send (see send): use the
	// ratchet when a session is established, legacy box otherwise.
	fsOut, err := c.fsPrepareSend(address)
	if err != nil {
		return 0, fmt.Errorf("fs prepare: %w", err)
	}
	defer func() {
		if fsOut != nil {
			fsOut.erase()
			fsOut = nil
		}
	}()
	if fsOut != nil {
		plain, err = fsSealMessage(fsOut, plain)
		if err != nil {
			return 0, fmt.Errorf("fs seal: %w", err)
		}
		fsOut = nil
	}
	return c.sendSealed(address, plain, wrappedBody, 0, "", true, 0)
}

// BridgeGateways manages the pinned bridge-gateway addresses in the
// local config (issue #61). A pinned address lets a recipient's client
// flag messages from the bridge identity as bridged even if payload
// metadata were absent. Rendering from the pin list is a phase-2
// concern; phase 1 only stores the pins.

// AddBridgeGateway pins addr as a trusted bridge gateway. Idempotent.
func (c *Config) AddBridgeGateway(addr string) error {
	if _, err := crypto.ParseAddress(addr); err != nil {
		return fmt.Errorf("bad bridge address: %w", err)
	}
	for _, a := range c.BridgeGateways {
		if a == addr {
			return nil
		}
	}
	c.BridgeGateways = append(c.BridgeGateways, addr)
	return c.Save()
}

// RemoveBridgeGateway unpins addr. It is not an error if absent.
func (c *Config) RemoveBridgeGateway(addr string) error {
	kept := c.BridgeGateways[:0]
	for _, a := range c.BridgeGateways {
		if a != addr {
			kept = append(kept, a)
		}
	}
	c.BridgeGateways = kept
	return c.Save()
}
