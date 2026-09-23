// FS suite registry and negotiation-transcript tests (issue #138).
package crypto

import (
	"slices"
	"testing"
)

// The v1 suite must be registered with real implementations — a name
// without cryptography is a half-upgraded state the registry refuses
// to represent.
func TestFSDescriptorV1Registered(t *testing.T) {
	desc, ok := FSDescriptor(FSSuiteV1)
	if !ok {
		t.Fatalf("FSDescriptor(%q) not found", FSSuiteV1)
	}
	if desc.DH == nil || desc.HandshakeRoot == nil || desc.InitChain == nil ||
		desc.RootStep == nil || desc.ChainStep == nil || desc.AttachWrapKey == nil {
		t.Fatal("v1 descriptor has nil implementations")
	}
	if !ValidFSSuite(FSSuiteV1) {
		t.Fatal("ValidFSSuite(v1) = false")
	}
}

// Unknown suites are a loud miss, never a silent v1 fallback.
func TestFSDescriptorUnknown(t *testing.T) {
	if _, ok := FSDescriptor("x25519-hkdf-sha256-v99"); ok {
		t.Fatal("unknown suite unexpectedly resolved")
	}
	if ValidFSSuite("x25519-hkdf-sha256-v99") {
		t.Fatal("unknown suite unexpectedly valid")
	}
}

// The handshake offers exactly the implemented suites.
func TestFSOfferedSuites(t *testing.T) {
	want := []string{string(FSSuiteV1)}
	if got := OfferedFSSuites(); !slices.Equal(got, want) {
		t.Fatalf("OfferedFSSuites() = %v, want %v", got, want)
	}
}

// The negotiation transcript is bound into the session root: the same
// handshake secrets with a tampered offer (or a relabeled selection)
// derive a different root, so the two sides cannot agree and the
// handshake fails closed instead of silently downgrading.
func TestFSHandshakeRootBindsTranscript(t *testing.T) {
	desc, ok := FSDescriptor(FSSuiteV1)
	if !ok {
		t.Skip("v1 suite not registered")
	}
	var rk0, dh1, dh2 [32]byte
	for i := range rk0 {
		rk0[i] = byte(i)
		dh1[i] = byte(i + 1)
		dh2[i] = byte(i + 2)
	}
	sid := "test-session"
	offer := []string{string(FSSuiteV1)}
	t1 := FSHSTranscript{Suite: FSSuiteV1, OfferHash: FSOfferHash(offer)}
	root1 := desc.HandshakeRoot(rk0, dh1, dh2, sid, t1)

	// Same transcript → same root (deterministic).
	root1b := desc.HandshakeRoot(rk0, dh1, dh2, sid, t1)
	if root1 != root1b {
		t.Fatal("handshake root not deterministic for identical transcripts")
	}

	// Tampered offer: the middlebox strips a suite the responder never
	// saw. Roots diverge.
	t2 := FSHSTranscript{Suite: FSSuiteV1, OfferHash: FSOfferHash([]string{"stripped-suite", string(FSSuiteV1)})}
	root2 := desc.HandshakeRoot(rk0, dh1, dh2, sid, t2)
	if root1 == root2 {
		t.Fatal("tampered offer produced the same root — downgrade not bound")
	}

	// Relabeled selection: same offer hash, different suite label.
	t3 := FSHSTranscript{Suite: "x25519-hkdf-sha256-v99", OfferHash: FSOfferHash(offer)}
	root3 := desc.HandshakeRoot(rk0, dh1, dh2, sid, t3)
	if root1 == root3 {
		t.Fatal("relabeled selection produced the same root — downgrade not bound")
	}

	// Offer order matters: reordering is a transcript change.
	t4 := FSHSTranscript{Suite: FSSuiteV1, OfferHash: FSOfferHash([]string{string(FSSuiteV1), "extra"})}
	t5 := FSHSTranscript{Suite: FSSuiteV1, OfferHash: FSOfferHash([]string{"extra", string(FSSuiteV1)})}
	if desc.HandshakeRoot(rk0, dh1, dh2, sid, t4) == desc.HandshakeRoot(rk0, dh1, dh2, sid, t5) {
		t.Fatal("reordered offer produced the same root")
	}
}
