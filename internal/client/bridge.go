// Bridge messaging (issue #61, phase 1): sending bridge-attributed DMs,
// plus client-side bridged-message detection (phase 2, issues #96/#97).
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
	"os"
	"slices"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/crypto"
)

// encodeBridgedBody builds the v2 plaintext for a bridged message:
// banner-wrapped body plus bridge metadata. The v2 form is used even
// though no reply threading is involved, so the metadata has a home.
func encodeBridgedBody(wrappedBody string, meta *bridge.BridgeMeta) ([]byte, error) {
	return json.Marshal(replyPayload{
		Version: replyPayloadVersion,
		Body:    wrappedBody,
		Bridge:  meta,
	})
}

// SendBridged sends a bridge-attributed DM to address, which must be a
// full ed25519:... address (no contact-name resolution — the gateway
// works purely in allowlisted addresses). wrappedBody must already
// carry the attribution banner (see bridge.WrapBody); meta must be
// non-nil.
//
// The send follows the normal human-send crypto path: an established
// forward-secrecy session is used when one exists, otherwise the
// standard sealed box. It is recorded in the local sent log like any
// DM so the dashboard threads it.
func (c *Client) SendBridged(address, wrappedBody string, meta *bridge.BridgeMeta) (int64, error) {
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
	id, err := c.sendSealed(address, plain, wrappedBody, 0, "", true, 0)
	if err != nil {
		return 0, err
	}
	// Issue #110: surface a queued FS downgrade warning, if any, once
	// the send succeeded (server-side: goes to the service log).
	if w := c.FSConsumeWarning(address); w != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	return id, nil
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

// isPinnedBridgeGateway reports whether addr is in this client's pinned
// bridge-gateway list (issue #96). The pin list is the recipient's own
// trust decision, independent of anything the sender claims.
func (c *Client) isPinnedBridgeGateway(addr string) bool {
	return slices.Contains(c.cfg.BridgeGateways, addr)
}

// deriveBridged reports whether an inbound message from `from` is
// bridged (issues #96/#97): it arrived via a non-E2E bridge and must be
// treated as untrusted input. Three independent layers are OR'd, in
// order of trustworthiness:
//
//  1. Structured bridge metadata in the signed E2E payload — the
//     gateway's own attestation, unforgeable by third parties.
//  2. The sender address being in the recipient's pinned bridge-gateway
//     list — the recipient's own trust decision. This flags messages
//     from the bridge identity even if payload metadata were absent.
//  3. The plaintext body banner — the gateway's visible attestation,
//     inside the signed plaintext. This also catches bridged messages
//     for recipients who never pinned the bridge address.
//
// Any single layer marks the message bridged. The direction of error
// is deliberate: a false positive marks a message untrusted (safe),
// while no layer can turn a genuinely bridged message trusted — the
// banner cannot be stripped without invalidating the bridge identity's
// signature, and pinning needs no sender cooperation at all.
func deriveBridged(from string, pins []string, meta *bridge.BridgeMeta, body string) bool {
	return meta != nil || slices.Contains(pins, from) || bridge.HasBanner(body)
}
