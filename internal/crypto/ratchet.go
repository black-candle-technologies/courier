// Forward-secrecy ratchet primitives (issue #50, v0.11.0).
//
// This file holds the key-derivation and Diffie-Hellman helpers for
// per-conversation Double-Ratchet-style sessions. The session state
// machine lives in internal/client (fs.go); the wire frames are defined
// there too. Nothing here touches the network.
//
// Construction (all SHA-256 based):
//   - Handshake root: root0 = HKDF(ikm=rk0||dh1||dh2, salt="courier-fs-handshake-v1"||sid).
//     dh1 and dh2 are ephemeral-ephemeral X25519 outputs, so root0 is
//     forward-secret against long-term-key compromise from message one.
//   - DH ratchet step: (root', chain) = HKDF(salt=root, ikm=dhOut,
//     info="courier-fs-root-v1", 64). The old root is erased.
//   - Symmetric chain step: chain' = HMAC(chain, 0x01),
//     msgKey = HMAC(chain, 0x02) (Signal-shaped). msgKey is erased after
//     a single encrypt/decrypt.
//   - Initial directional chains: HMAC(root0, label).
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// FS domain separators. Changing any of these changes every derived key.
const (
	fsHandshakeSaltPrefix = "courier-fs-handshake-v1"
	fsRootInfo            = "courier-fs-root-v1"
	fsChainInitToResp     = "courier-fs-chain-v1:initiator-to-responder"
	fsChainRespToInit     = "courier-fs-chain-v1:responder-to-initiator"
	fsAttachInfo          = "courier-fs-attach-v1"
)

// Zero overwrites b with zeros. Best-effort memory hygiene for erased
// key material: Go offers no locked-memory primitive, so this cannot
// defend against a memory dump — it only ensures the Go heap no longer
// references the key bytes once the caller drops them.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// FSX25519 performs an X25519 Diffie-Hellman between priv and pub.
func FSX25519(priv, pub [32]byte) ([32]byte, error) {
	var out [32]byte
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return out, fmt.Errorf("fs dh: %w", err)
	}
	copy(out[:], shared)
	Zero(shared)
	return out, nil
}

// FSHandshakeRoot derives the session root key from the initiator's
// random rk0 and the two ephemeral-ephemeral DH outputs. sid binds the
// derivation to this session (domain separation across sessions).
func FSHandshakeRoot(rk0, dh1, dh2 [32]byte, sid string) [32]byte {
	var root [32]byte
	ikm := make([]byte, 0, 96)
	ikm = append(ikm, rk0[:]...)
	ikm = append(ikm, dh1[:]...)
	ikm = append(ikm, dh2[:]...)
	salt := append([]byte(fsHandshakeSaltPrefix), sid...)
	r := hkdf.New(sha256.New, ikm, salt, nil)
	_, _ = io.ReadFull(r, root[:])
	Zero(ikm)
	return root
}

// FSInitChain derives one directional chain key from the handshake root.
// initiatorToResponder selects the label; both sides derive both chains.
func FSInitChain(root [32]byte, initiatorToResponder bool) [32]byte {
	label := fsChainInitToResp
	if !initiatorToResponder {
		label = fsChainRespToInit
	}
	mac := hmac.New(sha256.New, root[:])
	mac.Write([]byte(label))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// FSRootStep performs one DH ratchet step: mixes a fresh DH output into
// the root key and derives a new chain key. Returns (newRoot, chainKey).
// The caller must erase the old root and the old chain keys.
func FSRootStep(root, dhOut [32]byte) (newRoot, chainKey [32]byte) {
	r := hkdf.New(sha256.New, dhOut[:], root[:], []byte(fsRootInfo))
	var buf [64]byte
	_, _ = io.ReadFull(r, buf[:])
	copy(newRoot[:], buf[:32])
	copy(chainKey[:], buf[32:])
	Zero(buf[:])
	return newRoot, chainKey
}

// FSChainStep advances a symmetric chain: returns (newChain, msgKey).
// The caller must erase msgKey after a single use and overwrite the old
// chain key.
func FSChainStep(chain [32]byte) (newChain, msgKey [32]byte) {
	mac := hmac.New(sha256.New, chain[:])
	mac.Write([]byte{0x01})
	copy(newChain[:], mac.Sum(nil))
	mac = hmac.New(sha256.New, chain[:])
	mac.Write([]byte{0x02})
	copy(msgKey[:], mac.Sum(nil))
	return newChain, msgKey
}

// FSAttachWrapKey derives the attachment data-key wrap key from an FS
// message key (issue #50 §5): file contents get forward secrecy without
// changing the attachment manifest wire shape.
func FSAttachWrapKey(msgKey [32]byte) [32]byte {
	var out [32]byte
	r := hkdf.New(sha256.New, msgKey[:], nil, []byte(fsAttachInfo))
	_, _ = io.ReadFull(r, out[:])
	return out
}
