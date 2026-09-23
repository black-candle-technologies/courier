// Crypto-suite registry (issue #138).
//
// A Suite identifies a Courier cryptographic algorithm suite: the
// signature scheme, the key-exchange/encryption scheme, and the
// symmetric AEAD used for message bodies. Every place Courier
// previously assumed Ed25519/X25519 now dispatches on the suite, so a
// future post-quantum suite is an additive upgrade, not a rewrite.
//
// The registry — not a bare list of names — is the source of truth. A
// suite is "known" if and only if it has a registered SuiteDescriptor
// carrying real implementations (address parsing, wire-field
// validation). Adding a second suite means registering a descriptor;
// there is no way to enable a suite's name without its cryptography,
// which rules out the half-upgraded state where a peer advertises a
// suite the code cannot actually execute.
package crypto

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// Suite identifies a Courier cryptographic algorithm suite.
type Suite string

const (
	// SuiteV1 is the 1.0 suite: Ed25519 signatures, X25519 key exchange,
	// NaCl box (XSalsa20-Poly1305) message encryption.
	SuiteV1 Suite = "ed25519-x25519-naclbox-v1"
)

// SuiteDescriptor is the per-suite implementation bundle. Every
// suite-sensitive decision in the relay and the client dispatches
// through Descriptor, so an unregistered suite fails closed at the
// lookup — never as a half-executed v1 path.
type SuiteDescriptor struct {
	Suite Suite
	// AddressPrefix is the address prefix naming this suite
	// ("ed25519:"). An address always identifies its suite, so the
	// suite is authenticated by the address itself, not by a
	// separate unverified label.
	AddressPrefix string
	// ParseIdentity parses the address body (after AddressPrefix)
	// into the suite's opaque identity public-key bytes. It must
	// reject malformed keys loudly.
	ParseIdentity func(body string) ([]byte, error)
	// ValidateEnvelopeFields checks the suite-specific wire shapes of
	// a send request: the ephemeral key and nonce. Ciphertext is
	// opaque bytes to the relay.
	ValidateEnvelopeFields func(eph, nonce []byte) error
	// ValidateKeyFields checks the suite-specific shape of an
	// announced encryption key (key directory).
	ValidateKeyFields func(key []byte) error
	// ValidateSignatureFields checks the suite-specific shape of a
	// signature over envelope bytes (e.g. 64 bytes for Ed25519).
	ValidateSignatureFields func(sig []byte) error
	// VerifySignature verifies a signature over message bytes with the
	// given identity public key. The key bytes come from ParseIdentity,
	// so the descriptor knows their encoding.
	VerifySignature func(pub, msg, sig []byte) bool
	// SealMessage encrypts plaintext to the recipient's encryption
	// public key, returning a fresh ephemeral key, nonce, and
	// ciphertext. The key bytes come from the key directory (or the
	// suite's address-derived-key rule), so the descriptor knows their
	// encoding.
	SealMessage func(toPub, plaintext []byte) (eph, nonce, ct []byte, err error)
	// OpenMessage decrypts a sealed message with the recipient's
	// private key. Private-key bytes are the suite's encoding.
	OpenMessage func(priv, eph, nonce, ct []byte) ([]byte, error)
}

// suiteRegistry holds the registered descriptors in registration order.
// It is populated by init functions; registration panics on duplicates
// so a misconfigured build fails fast instead of serving half a suite.
var suiteRegistry []*SuiteDescriptor

// KnownSuites lists every suite this build implements, in registration
// order. It is derived from the registry — never edited by hand.
var KnownSuites []Suite

func registerSuite(d *SuiteDescriptor) {
	if d.Suite == "" || d.AddressPrefix == "" {
		panic("crypto: suite descriptor needs a suite id and address prefix")
	}
	if d.ParseIdentity == nil || d.ValidateEnvelopeFields == nil || d.ValidateKeyFields == nil ||
		d.ValidateSignatureFields == nil || d.VerifySignature == nil ||
		d.SealMessage == nil || d.OpenMessage == nil {
		panic(fmt.Sprintf("crypto: suite %q registered without implementations", d.Suite))
	}
	for _, e := range suiteRegistry {
		if e.Suite == d.Suite {
			panic(fmt.Sprintf("crypto: duplicate suite %q", d.Suite))
		}
		if e.AddressPrefix == d.AddressPrefix {
			panic(fmt.Sprintf("crypto: duplicate address prefix %q", d.AddressPrefix))
		}
	}
	suiteRegistry = append(suiteRegistry, d)
	KnownSuites = append(KnownSuites, d.Suite)
}

// Descriptor returns the implementation bundle for s, or false if this
// build does not implement the suite. This is the single choke point:
// callers must look the suite up here and use the returned descriptor;
// a missing descriptor is a loud rejection, never a silent v1 fallback.
func Descriptor(s Suite) (*SuiteDescriptor, bool) {
	for _, d := range suiteRegistry {
		if d.Suite == s {
			return d, true
		}
	}
	return nil, false
}

// ValidSuite reports whether s is a suite this build implements — i.e.
// whether it has a registered descriptor with real cryptography behind
// it. A name with no descriptor is not valid.
func ValidSuite(s Suite) bool {
	_, ok := Descriptor(s)
	return ok
}

// ParsedAddress is a parsed Courier address: the suite it belongs to
// plus the opaque identity public-key bytes in that suite's encoding.
// The key bytes must only be interpreted through the suite's
// descriptor — a future suite's key will not be 32 bytes and must
// never be cast to [32]byte by generic code. Use ParseAddress for the
// SuiteV1-only [32]byte compatibility view.
type ParsedAddress struct {
	Suite     Suite
	PublicKey []byte
}

// ParseAddressSuite parses a Courier address and reports the crypto
// suite it belongs to, dispatching on the address prefix through the
// suite registry. Unknown prefixes are rejected loudly — an address
// whose suite this build does not implement must never be silently
// treated as SuiteV1, or messages would be encrypted to keys the
// recipient cannot use.
func ParseAddressSuite(s string) (ParsedAddress, error) {
	var best *SuiteDescriptor
	for _, d := range suiteRegistry {
		if strings.HasPrefix(s, d.AddressPrefix) {
			if best == nil || len(d.AddressPrefix) > len(best.AddressPrefix) {
				best = d
			}
		}
	}
	if best == nil {
		return ParsedAddress{}, fmt.Errorf("unknown address suite in %q (this build implements: %v)", s, KnownSuites)
	}
	raw, err := best.ParseIdentity(strings.TrimPrefix(s, best.AddressPrefix))
	if err != nil {
		return ParsedAddress{}, err
	}
	return ParsedAddress{Suite: best.Suite, PublicKey: raw}, nil
}

// AgreeSuite resolves the effective crypto suite from an optional wire
// suite label and the parsed suites of the parties involved. The wire
// label defaults to SuiteV1 when absent (older peers predate suite
// tagging); the resolved suite must then agree with every party's
// address suite and have a registered descriptor. Anything else is an
// error — a mismatch or an unknown suite is rejected loudly, never
// silently processed as v1. Callers must not rely on relay metadata for
// this: the address suites come from locally parsed addresses.
func AgreeSuite(wire string, parties ...ParsedAddress) (Suite, error) {
	suite := Suite(wire)
	if suite == "" {
		suite = SuiteV1
	}
	desc, ok := Descriptor(suite)
	if !ok {
		return "", fmt.Errorf("unknown crypto suite %q (this build implements: %v)", wire, KnownSuites)
	}
	for _, p := range parties {
		if p.Suite != suite {
			return "", fmt.Errorf("suite %q does not match address suite %q", suite, p.Suite)
		}
	}
	return desc.Suite, nil
}

func init() {
	registerSuite(&SuiteDescriptor{
		Suite:         SuiteV1,
		AddressPrefix: AddressPrefix,
		ParseIdentity: func(body string) ([]byte, error) {
			raw, err := b64.DecodeString(body)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %w", err)
			}
			if len(raw) != PubKeyLen {
				return nil, fmt.Errorf("invalid address: want %d bytes, got %d", PubKeyLen, len(raw))
			}
			return raw, nil
		},
		ValidateEnvelopeFields: func(eph, nonce []byte) error {
			if len(eph) != PubKeyLen {
				return fmt.Errorf(`"eph" must be a %d-byte X25519 public key`, PubKeyLen)
			}
			if len(nonce) != NonceLen {
				return fmt.Errorf(`"nonce" must be a %d-byte nonce`, NonceLen)
			}
			return nil
		},
		ValidateKeyFields: func(key []byte) error {
			if len(key) != PubKeyLen {
				return fmt.Errorf(`"x25519_pub" must be a %d-byte X25519 public key`, PubKeyLen)
			}
			return nil
		},
		ValidateSignatureFields: func(sig []byte) error {
			if len(sig) != ed25519.SignatureSize {
				return fmt.Errorf(`"sig" must be a base64url %d-byte Ed25519 signature`, ed25519.SignatureSize)
			}
			return nil
		},
		VerifySignature: func(pub, msg, sig []byte) bool {
			return Verify(pub, msg, sig)
		},
		SealMessage: func(toPub, plaintext []byte) (eph, nonce, ct []byte, err error) {
			var to [PubKeyLen]byte
			if len(toPub) != PubKeyLen {
				return nil, nil, nil, fmt.Errorf("recipient key: want %d bytes, got %d", PubKeyLen, len(toPub))
			}
			copy(to[:], toPub)
			return Seal(&to, plaintext)
		},
		OpenMessage: func(priv, eph, nonce, ct []byte) ([]byte, error) {
			return Open(priv, eph, nonce, ct)
		},
	})
}
