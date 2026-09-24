package vhl

import (
	"crypto/sha256"
	"strconv"
)

// Mint ceremony context (issue #142 review).
//
// The relay-hosted WebAuthn session-mint ceremony shows the human
// exactly what authority they are granting. MintContext is the
// canonical context: counterparty scope, issued/expiry times,
// issuer identity, token/session ids, and the presence the ceremony
// establishes. The WebAuthn challenge for the mint ceremony is
// SessionMintChallenge(ctx) — SHA-256 over a domain separator and
// the canonical context bytes — so the browser can recompute the
// challenge from the displayed context and detect relay tampering,
// and the agent-signed ceremony-create request binds the context
// so the relay cannot substitute different values.
//
// The canonical encoding is byte-exact and documented so the
// browser page can reproduce it:
//
//	{"issuer":<json-string>,"scope":<json-string>,"token_id":<json-string>,"session_id":<json-string>,"issued_at":<int>,"expires_at":<int>,"presence":<json-string>}
//
// with no whitespace; strings JSON-encoded with Go's encoding/json
// escaping. The challenge binds every security-relevant mint
// parameter (scope, lifetime, ids, presence), so a mint assertion
// cannot be transplanted onto a token with different values.

var vhlMintChallengeDomain = []byte("courier-vhl-mint-challenge-v1\x00")

// MintContext describes one session-token mint the human is asked
// to authorize in the browser ceremony.
type MintContext struct {
	Issuer    string `json:"issuer"`     // agent address requesting the mint
	Scope     string `json:"scope"`      // counterparty scope being granted
	TokenID   string `json:"token_id"`   // token id being minted
	SessionID string `json:"session_id"` // session id being minted
	IssuedAt  int64  `json:"issued_at"`  // unix time the token becomes valid
	ExpiresAt int64  `json:"expires_at"` // unix time the token stops being valid
	Presence  string `json:"presence"`   // presence the ceremony establishes (e.g. "fido2_uv")
}

// appendJSONString appends s JSON-encoded (with Go escaping rules)
// to out.
func appendJSONString(out []byte, s string) []byte {
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if r < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hexDigit(byte(r>>4)), hexDigit(byte(r&0xf)))
			} else {
				out = append(out, string(r)...)
			}
		}
	}
	out = append(out, '"')
	return out
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

// Canonical returns the canonical byte encoding of the context, in
// the exact layout documented above.
func (m MintContext) Canonical() []byte {
	out := make([]byte, 0, 128)
	out = append(out, `{"issuer":`...)
	out = appendJSONString(out, m.Issuer)
	out = append(out, `,"scope":`...)
	out = appendJSONString(out, m.Scope)
	out = append(out, `,"token_id":`...)
	out = appendJSONString(out, m.TokenID)
	out = append(out, `,"session_id":`...)
	out = appendJSONString(out, m.SessionID)
	out = append(out, `,"issued_at":`...)
	out = strconv.AppendInt(out, m.IssuedAt, 10)
	out = append(out, `,"expires_at":`...)
	out = strconv.AppendInt(out, m.ExpiresAt, 10)
	out = append(out, `,"presence":`...)
	out = appendJSONString(out, m.Presence)
	out = append(out, '}')
	return out
}

// SessionMintChallenge returns the WebAuthn challenge for a
// session-mint ceremony: SHA-256 over the mint-challenge domain and
// the canonical mint context. The agent uses it to build the
// ceremony challenge and the token's mint challenge; the browser
// recomputes it from the displayed context to validate what the
// human is approving; the receiver recomputes it from the token's
// own fields to verify the embedded mint assertion.
func SessionMintChallenge(ctx MintContext) [32]byte {
	h := sha256.New()
	h.Write(vhlMintChallengeDomain)
	h.Write([]byte{0x00})
	h.Write(ctx.Canonical())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
