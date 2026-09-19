// Package crypto implements Courier's end-to-end encryption.
//
// Identity is a single X25519 keypair. The public key, base64url-encoded,
// is the agent's address: it is both the "phone number" (how others reach
// you) and the encryption key (how others encrypt to you). The private key
// never leaves the agent's machine.
//
// Messages are sealed with NaCl crypto_box using a fresh ephemeral sender
// keypair for every message, so each message gets forward secrecy. The
// relay only ever sees ciphertext.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// RawURLEncoding without padding, used for all key material on the wire.
var b64 = base64.RawURLEncoding

const (
	// PubKeyLen is the length of an X25519 public key in bytes.
	PubKeyLen = 32
	// PrivKeyLen is the length of an X25519 private key in bytes.
	PrivKeyLen = 32
	// NonceLen is the length of a NaCl box nonce in bytes.
	NonceLen = 24
)

// GenerateKeypair creates a fresh X25519 identity keypair.
func GenerateKeypair() (pub, priv *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

// EncodeKey renders a 32-byte public key as an address (base64url, no padding).
func EncodeKey(key *[32]byte) string {
	return b64.EncodeToString(key[:])
}

// DecodeKey parses an address back into a 32-byte public key.
func DecodeKey(s string) (*[32]byte, error) {
	return decodeFixed(s, PubKeyLen, "address")
}

// DecodePrivKey parses a base64url private key.
func DecodePrivKey(s string) (*[32]byte, error) {
	return decodeFixed(s, PrivKeyLen, "private key")
}

func decodeFixed(s string, want int, what string) (*[32]byte, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", what, err)
	}
	if len(raw) != want {
		return nil, fmt.Errorf("invalid %s: want %d bytes, got %d", what, want, len(raw))
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

// Seal encrypts plaintext for the holder of toPub. A fresh ephemeral
// keypair is generated per message. It returns the ephemeral public key,
// the nonce, and the ciphertext (all raw bytes; base64url-encode for the wire).
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

// Open decrypts a message sealed with Seal, using the recipient's private key.
func Open(priv, ephPub, nonce, ciphertext []byte) ([]byte, error) {
	if len(priv) != PrivKeyLen {
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
