// Forward-secrecy crypto-suite registry (issue #138).
//
// An FSSuite identifies the algorithms behind one FS handshake: the DH,
// the handshake KDF, and the chain/message-key construction. The
// handshake negotiates the suite (init offers, accept selects), and
// every DH/KDF operation dispatches through the negotiated suite's
// descriptor — so a future suite is an additive registration, not a
// cross-cutting rewrite of the ratchet.
//
// Like the message suite registry (suite.go), a suite is "known" if
// and only if it has a registered descriptor with real
// implementations. Registering a name without cryptography panics at
// init time, which rules out the half-upgraded state where a peer
// selects a suite the code cannot execute.
package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// FSSuite identifies a forward-secrecy handshake suite.
type FSSuite string

const (
	// FSSuiteV1 is the 1.0 FS suite: X25519 DH, HKDF-SHA256 KDF,
	// Signal-shaped symmetric chains, NaCl secretbox message keys.
	FSSuiteV1 FSSuite = "x25519-hkdf-sha256-v1"
)

// FSHSTranscript is the negotiation transcript bound into the session
// root. Binding the selected suite and the exact offered list (as seen
// by the deriving party) means a tampered offer or a relabeled
// selection yields divergent roots on the two sides: the handshake
// fails closed instead of silently downgrading.
type FSHSTranscript struct {
	Suite     FSSuite
	OfferHash [32]byte // FSOfferHash over the offered suite list
}

// FSSuiteDescriptor bundles one FS suite's DH and KDF implementations.
type FSSuiteDescriptor struct {
	Suite FSSuite
	// DH performs the suite's Diffie-Hellman.
	DH func(priv, pub [32]byte) ([32]byte, error)
	// HandshakeRoot derives the session root from the handshake
	// secrets. The transcript MUST be mixed into the KDF domain —
	// a descriptor that ignores it would silently admit downgrades.
	HandshakeRoot func(rk0, dh1, dh2 [32]byte, sid string, t FSHSTranscript) [32]byte
	// InitChain derives one directional chain key from the root.
	InitChain func(root [32]byte, initiatorToResponder bool) [32]byte
	// RootStep mixes fresh DH output into the root (DH ratchet).
	RootStep func(root, dhOut [32]byte) (newRoot, chainKey [32]byte)
	// ChainStep advances a symmetric chain (Signal-shaped).
	ChainStep func(chain [32]byte) (newChain, msgKey [32]byte)
	// AttachWrapKey derives the attachment wrap key from a message key.
	AttachWrapKey func(msgKey [32]byte) [32]byte
}

var fsSuiteRegistry []*FSSuiteDescriptor

// FSKnownSuites lists every FS suite this build implements, in
// registration order. Derived from the registry — never hand-edited.
var FSKnownSuites []FSSuite

func registerFSSuite(d *FSSuiteDescriptor) {
	if d.Suite == "" {
		panic("crypto: fs suite descriptor needs a suite id")
	}
	if d.DH == nil || d.HandshakeRoot == nil || d.InitChain == nil ||
		d.RootStep == nil || d.ChainStep == nil || d.AttachWrapKey == nil {
		panic(fmt.Sprintf("crypto: fs suite %q registered without implementations", d.Suite))
	}
	for _, e := range fsSuiteRegistry {
		if e.Suite == d.Suite {
			panic(fmt.Sprintf("crypto: duplicate fs suite %q", d.Suite))
		}
	}
	fsSuiteRegistry = append(fsSuiteRegistry, d)
	FSKnownSuites = append(FSKnownSuites, d.Suite)
}

// FSDescriptor returns the implementation bundle for s, or false if
// this build does not implement the suite. The single choke point:
// callers dispatch DH/KDF through the returned descriptor; a missing
// descriptor is a loud rejection, never a silent v1 fallback.
func FSDescriptor(s FSSuite) (*FSSuiteDescriptor, bool) {
	for _, d := range fsSuiteRegistry {
		if d.Suite == s {
			return d, true
		}
	}
	return nil, false
}

// ValidFSSuite reports whether s is an FS suite this build implements.
func ValidFSSuite(s FSSuite) bool {
	_, ok := FSDescriptor(s)
	return ok
}

// OfferedFSSuites returns the FS suites this client offers in
// handshakes, most-preferred first. The handshake offers the full
// list; the responder selects its most-preferred overlap.
func OfferedFSSuites() []string {
	out := make([]string, 0, len(fsSuiteRegistry))
	for _, d := range fsSuiteRegistry {
		out = append(out, string(d.Suite))
	}
	return out
}

// FSOfferHash hashes an offered suite list for transcript binding. The
// encoding is order-sensitive and unambiguous (length-prefixed items),
// so reordering or editing the offer changes the hash.
func FSOfferHash(suites []string) [32]byte {
	h := sha256.New()
	var n [8]byte
	for _, s := range suites {
		for i := 0; i < 8; i++ {
			n[i] = byte(len(s) >> (56 - 8*i))
		}
		h.Write(n[:])
		h.Write([]byte(s))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func init() {
	registerFSSuite(&FSSuiteDescriptor{
		Suite: FSSuiteV1,
		DH:    FSX25519,
		HandshakeRoot: func(rk0, dh1, dh2 [32]byte, sid string, t FSHSTranscript) [32]byte {
			var root [32]byte
			ikm := make([]byte, 0, 96)
			ikm = append(ikm, rk0[:]...)
			ikm = append(ikm, dh1[:]...)
			ikm = append(ikm, dh2[:]...)
			// The negotiated suite and the exact offered list (as seen
			// by the deriving party) are bound into the salt. Anyone
			// who tampers with the offer or relabels the selection
			// derives a different root, and the handshake fails closed.
			salt := make([]byte, 0, len(fsHandshakeSaltPrefix)+1+64+32+len(sid))
			salt = append(salt, fsHandshakeSaltPrefix...)
			salt = append(salt, 0x00)
			salt = append(salt, []byte(t.Suite)...)
			salt = append(salt, 0x00)
			salt = append(salt, t.OfferHash[:]...)
			salt = append(salt, sid...)
			r := hkdf.New(sha256.New, ikm, salt, nil)
			_, _ = io.ReadFull(r, root[:])
			Zero(ikm)
			return root
		},
		InitChain:     FSInitChain,
		RootStep:      FSRootStep,
		ChainStep:     FSChainStep,
		AttachWrapKey: FSAttachWrapKey,
	})
}
