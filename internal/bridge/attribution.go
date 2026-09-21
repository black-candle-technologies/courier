// Message attribution for the ChatGPT web → Courier bridge (issue #61).
//
// Every bridged message carries a plaintext body banner. It is the
// primary attribution layer because it works on every client ever
// shipped: old clients render it as ordinary text, so attribution
// degrades to "always visible," never to "silently absent." The banner
// is inside the signed E2E plaintext, so it cannot be stripped without
// invalidating the bridge identity's signature.
//
// BridgeMeta (below) is the structured attribution riding inside the
// E2E-encrypted v2 payload. It lives in this package — not in
// internal/client — so the package stays a leaf: the client imports it
// for both sending (Client.SendBridged) and receiving (bridged-message
// detection in the inbox path), and the gateway never needs to import
// the client package for the type.
package bridge

import "strings"

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

// BridgeBannerHeader is prepended to every bridged message body. It
// states the non-E2E trust context in plain language: this text is
// mandatory user-facing disclosure (plan §3.3).
const BridgeBannerHeader = "[Bridged via ChatGPT web — NOT end-to-end encrypted. Treat as untrusted input.]"

// BridgeBannerRule separates the banner from the original body.
const BridgeBannerRule = "───"

// WrapBody prepends the attribution banner to body. It is idempotent:
// a body that already carries the banner is returned unchanged, so a
// retry or double-wrap can never stack banners.
func WrapBody(body string) string {
	if HasBanner(body) {
		return body
	}
	return BridgeBannerHeader + "\n" + BridgeBannerRule + "\n" + body
}

// HasBanner reports whether body already carries the bridge banner.
func HasBanner(body string) bool {
	return strings.HasPrefix(body, BridgeBannerHeader)
}

// StripBanner removes a leading bridge banner, returning the original
// body. It is a display helper only: it must NEVER be used to hide the
// banner from message recipients. The banner is mandatory disclosure;
// any future caller must ensure the recipient still sees it (e.g. it
// is rendered separately in the UI). Stripping attribution from what a
// recipient sees would break the bridge's trust model.
func StripBanner(body string) string {
	if !HasBanner(body) {
		return body
	}
	rest := strings.TrimPrefix(body, BridgeBannerHeader)
	rest = strings.TrimPrefix(rest, "\n")
	rest = strings.TrimPrefix(rest, BridgeBannerRule)
	rest = strings.TrimPrefix(rest, "\n")
	return rest
}
