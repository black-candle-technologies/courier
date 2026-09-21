// Package crypto implements Courier's identity and end-to-end encryption.
//
// Identity (v0.2.0+): a single 32-byte seed derives everything:
//   - Ed25519 keypair: the long-term identity. The public key, formatted as
//     "ed25519:<base64url>", is the agent's address: the phone number (how
//     others reach you) and the signing key (how others verify it's you).
//   - X25519 keypair: derived libsodium-style (xpriv = clamp(SHA512(seed)[0:32])).
//     Anyone can obtain your X25519 public key from your address via the
//     standard Edwards-to-Montgomery birational map, and use it to seal
//     messages to you with NaCl crypto_box.
//
// Messages are sealed with a fresh ephemeral sender key per message and
// signed with the sender's Ed25519 key (sender authentication). The relay
// only ever sees ciphertext.
//
// Forward secrecy, honestly stated: the per-message ephemeral sender key
// means a compromised *sender* key cannot decrypt past messages. The
// recipient's encryption key, however, is long-lived: anyone who captures
// ciphertext and later steals the recipient's encryption private key can
// read it. `courier rotate` (v0.5.0+) retires the recipient encryption key
// and publishes a new one, which bounds that exposure window. Rotate
// regularly, and immediately if compromise is suspected.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

var b64 = base64.RawURLEncoding

// AddressPrefix marks v0.2.0+ Ed25519 addresses. The prefix is part of the
// address: it makes the key type explicit and makes v0.1.0 X25519 addresses
// fail loudly instead of encrypting to a dead key.
const AddressPrefix = "ed25519:"

const (
	// SeedLen is the identity master secret length in bytes.
	SeedLen = 32
	// PubKeyLen is an Ed25519/X25519 public key length in bytes.
	PubKeyLen = 32
	// NonceLen is the NaCl box nonce length in bytes.
	NonceLen = 24
)

// Identity is a Courier agent identity derived from a single seed.
type Identity struct {
	Seed   [32]byte // master secret; never leaves the machine
	EdPub  [32]byte // signing public key; the address material
	EdPriv ed25519.PrivateKey
	XPub   [32]byte // encryption public key (derived)
	XPriv  [32]byte // encryption private key (derived)
}

func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// GenerateIdentity creates a fresh identity from a random seed.
func GenerateIdentity() (*Identity, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	return IdentityFromSeed(seed[:])
}

// IdentityFromSeed derives the full identity from a 32-byte seed.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != SeedLen {
		return nil, fmt.Errorf("seed must be %d bytes", SeedLen)
	}
	var id Identity
	copy(id.Seed[:], seed)

	// Ed25519 long-term identity.
	id.EdPriv = ed25519.NewKeyFromSeed(seed)
	copy(id.EdPub[:], id.EdPriv.Public().(ed25519.PublicKey))

	// X25519 encryption key, libsodium-style: clamp(SHA512(seed)[0:32]).
	h := sha512.Sum512(seed)
	clamp(h[:SeedLen])
	copy(id.XPriv[:], h[:SeedLen])
	xpub, err := curve25519.X25519(id.XPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	copy(id.XPub[:], xpub)
	return &id, nil
}

// Ed25519PubToX25519 converts an Ed25519 public key to its X25519
// equivalent via the birational map u = (1+y)/(1-y). It rejects
// non-canonical encodings.
func Ed25519PubToX25519(pub []byte) ([32]byte, error) {
	var out [32]byte
	if len(pub) != PubKeyLen {
		return out, errors.New("public key must be 32 bytes")
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return out, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	// Round-trip: the encoding must be canonical.
	if !equalBytes(p.Bytes(), pub) {
		return out, errors.New("non-canonical Ed25519 public key encoding")
	}
	_, Y, Z, _ := p.ExtendedCoordinates()
	y := new(field.Element).Multiply(Y, new(field.Element).Invert(Z)) // affine y
	one := new(field.Element).One()
	num := new(field.Element).Add(one, y) // 1+y
	negY := new(field.Element).Negate(y)
	den := new(field.Element).Add(one, negY) // 1-y
	if den.Equal(new(field.Element)) == 1 {
		return out, errors.New("invalid Ed25519 public key: y=1")
	}
	u := new(field.Element).Multiply(num, new(field.Element).Invert(den))
	copy(out[:], u.Bytes())
	return out, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// FormatAddress renders an Ed25519 public key as a Courier address.
func FormatAddress(edPub []byte) string {
	return AddressPrefix + b64.EncodeToString(edPub)
}

// ParseAddress parses a Courier address, strictly requiring the
// "ed25519:" prefix. v0.1.0 bare X25519 addresses are rejected loudly.
func ParseAddress(s string) ([32]byte, error) {
	var out [32]byte
	if !strings.HasPrefix(s, AddressPrefix) {
		return out, fmt.Errorf("address must start with %q (bare v0.1.0 X25519 addresses are not supported; ask the owner for their new address)", AddressPrefix)
	}
	raw, err := b64.DecodeString(strings.TrimPrefix(s, AddressPrefix))
	if err != nil {
		return out, fmt.Errorf("invalid address: %w", err)
	}
	if len(raw) != PubKeyLen {
		return out, fmt.Errorf("invalid address: want %d bytes, got %d", PubKeyLen, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// Sign signs msg with the identity's Ed25519 key.
func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(id.EdPriv, msg)
}

// Verify reports whether sig is a valid Ed25519 signature of msg under pub.
func Verify(pub []byte, msg, sig []byte) bool {
	if len(pub) != PubKeyLen || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// GenerateX25519Keypair creates a fresh random X25519 keypair. Used for
// encryption-key rotation (v0.5.0+): unlike the seed-derived keypair, a
// rotated key can be retired, which bounds the damage of a compromised
// encryption key to messages sent while it was current.
func GenerateX25519Keypair() (pub, priv [32]byte, err error) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return pub, priv, fmt.Errorf("x25519 keygen: %w", err)
	}
	var p, s [32]byte
	copy(p[:], pubKey[:])
	copy(s[:], privKey[:])
	return p, s, nil
}

// Seal encrypts plaintext for the holder of toPub (X25519). A fresh
// ephemeral keypair is generated per message. Returns ephemeral public key,
// nonce, ciphertext (raw bytes; base64url-encode for the wire).
func Seal(toPub *[32]byte, plaintext []byte) (ephPub, nonce, ciphertext []byte, err error) {
	ephPubKey, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ephemeral keygen: %w", err)
	}
	var n [NonceLen]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := box.Seal(nil, plaintext, &n, toPub, ephPriv)
	return ephPubKey[:], n[:], sealed, nil
}

// Open decrypts a message sealed with Seal using the recipient's X25519
// private key.
func Open(priv, ephPub, nonce, ciphertext []byte) ([]byte, error) {
	if len(priv) != PubKeyLen {
		return nil, errors.New("bad private key length")
	}
	if len(ephPub) != PubKeyLen {
		return nil, errors.New("bad ephemeral key length")
	}
	if len(nonce) != NonceLen {
		return nil, errors.New("bad nonce length")
	}
	var p, e [32]byte
	var n [NonceLen]byte
	copy(p[:], priv)
	copy(e[:], ephPub)
	copy(n[:], nonce)
	plain, ok := box.Open(nil, ciphertext, &n, &e, &p)
	if !ok {
		return nil, errors.New("decryption failed: wrong key or corrupted message")
	}
	return plain, nil
}

// ---- Group messaging: symmetric sender keys (issue #32) ----

// GenerateSenderKey creates a fresh 32-byte symmetric sender key. Each
// group member holds one sender key per group; group message bodies are
// sealed under the author's current sender key with secretbox.
func GenerateSenderKey() ([32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("sender key: %w", err)
	}
	return k, nil
}

// SealSymmetric encrypts plaintext under a 32-byte symmetric key with NaCl
// secretbox (XSalsa20-Poly1305), returning a fresh random nonce and the
// ciphertext.
func SealSymmetric(key *[32]byte, plaintext []byte) (nonce, ciphertext []byte, err error) {
	var n [NonceLen]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := secretbox.Seal(nil, plaintext, &n, key)
	return n[:], sealed, nil
}

// OpenSymmetric decrypts a secretbox ciphertext under the symmetric key.
func OpenSymmetric(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != PubKeyLen {
		return nil, errors.New("bad sender key length")
	}
	if len(nonce) != NonceLen {
		return nil, errors.New("bad nonce length")
	}
	var k [32]byte
	var n [NonceLen]byte
	copy(k[:], key)
	copy(n[:], nonce)
	plain, ok := secretbox.Open(nil, ciphertext, &n, &k)
	if !ok {
		return nil, errors.New("decryption failed: wrong key or corrupted message")
	}
	return plain, nil
}
