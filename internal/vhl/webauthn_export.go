package vhl

import "fmt"

// Exported WebAuthn assertion verification for the relay-ceremony
// client (issue #142 review).
//
// verifyWebAuthnAssertion stays unexported: it takes a parsed
// crypto.PublicKey and is the shared core used by the token mint
// path and the Tier 2 approval path. The ceremony client holds
// enrolled vhl.Credential records (base64url COSE keys), so this
// file is the single thin adapter from a stored credential to the
// core verifier. It parses the credential's public key exactly the
// way the mint path does (credentialKey over the COSE bytes) and
// delegates everything else — challenge equality, origin, RP id,
// UV/user-presence flags, authenticator signature — to the shared
// verifier, so ceremony assertions and in-band assertions are held
// to identical cryptographic checks.

// VerifyAssertionForChallenge verifies a base64url WebAuthn
// get-assertion (as produced by the browser ceremony) against the
// enrolled credential cred: the assertion's clientData challenge
// must equal expectedChallenge, the origin must be one of rp's, the
// authenticator data must name rp's id, and the authenticator
// signature must verify under cred's public key. requireUV demands
// the user-verification flag. On success it returns the
// authenticator's signature counter; sign-count monotonicity is the
// caller's replay control (see policy.go).
func VerifyAssertionForChallenge(cred *Credential, assertionB64 string, expectedChallenge []byte, rp WebAuthnRP, requireUV bool) (uint32, error) {
	if cred == nil {
		return 0, fmt.Errorf("vhl: assertion without credential")
	}
	rawKey, err := b64.DecodeString(cred.PublicKey)
	if err != nil {
		return 0, fmt.Errorf("vhl: credential key: %w", err)
	}
	pub, err := credentialKey(rawKey)
	if err != nil {
		return 0, fmt.Errorf("vhl: credential key: %w", err)
	}
	return verifyWebAuthnAssertion(pub, assertionB64, expectedChallenge, rp, requireUV)
}
