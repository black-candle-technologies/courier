// Message attribution for the ChatGPT web → Courier bridge (issue #61).
//
// Every bridged message carries a plaintext body banner. It is the
// primary attribution layer because it works on every client ever
// shipped: old clients render it as ordinary text, so attribution
// degrades to "always visible," never to "silently absent." The banner
// is inside the signed E2E plaintext, so it cannot be stripped without
// invalidating the bridge identity's signature.
package bridge

import "strings"

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
// body. It is a display helper only; the banner must always be shown
// to recipients, never silently stripped.
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
