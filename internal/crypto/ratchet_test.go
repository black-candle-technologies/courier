// Forward-secrecy KDF tests (issue #50).
package crypto

import (
	"bytes"
	"testing"
)

func TestFSChainStepDeterministic(t *testing.T) {
	var chain [32]byte
	for i := range chain {
		chain[i] = byte(i)
	}
	nc1, mk1 := FSChainStep(chain)
	nc2, mk2 := FSChainStep(chain)
	if nc1 != nc2 || mk1 != mk2 {
		t.Fatal("FSChainStep not deterministic")
	}
	if mk1 == nc1 {
		t.Fatal("message key equals next chain key")
	}
	// Advancing changes the chain: the old chain cannot be recovered
	// from the new one (one-way KDF).
	nc3, _ := FSChainStep(nc1)
	if nc3 == chain || nc3 == nc1 {
		t.Fatal("chain did not advance")
	}
}

func TestFSRootStepDeterministic(t *testing.T) {
	var root, dh [32]byte
	for i := range root {
		root[i] = byte(i)
	}
	for i := range dh {
		dh[i] = byte(255 - i)
	}
	nr1, ck1 := FSRootStep(root, dh)
	nr2, ck2 := FSRootStep(root, dh)
	if nr1 != nr2 || ck1 != ck2 {
		t.Fatal("FSRootStep not deterministic")
	}
	if nr1 == ck1 || nr1 == root {
		t.Fatal("root step did not mix properly")
	}
}

func TestFSHandshakeRootBindsSession(t *testing.T) {
	var rk0, dh1, dh2 [32]byte
	for i := range rk0 {
		rk0[i] = byte(i)
	}
	r1 := FSHandshakeRoot(rk0, dh1, dh2, "c2lkAAAAAAAAAAAAAA")
	r2 := FSHandshakeRoot(rk0, dh1, dh2, "c2lkAAAAAAAAAAAAAA")
	if r1 != r2 {
		t.Fatal("FSHandshakeRoot not deterministic")
	}
	r3 := FSHandshakeRoot(rk0, dh1, dh2, "b3RoAAAAAAAAAAAAAA")
	if r1 == r3 {
		t.Fatal("FSHandshakeRoot does not bind the session id")
	}
}

func TestFSInitChainDirectionSeparation(t *testing.T) {
	var root [32]byte
	for i := range root {
		root[i] = 7
	}
	a := FSInitChain(root, true)
	b := FSInitChain(root, false)
	if a == b {
		t.Fatal("initiator/responder initial chains are identical")
	}
}

func TestFSAttachWrapKeyDerivation(t *testing.T) {
	var mk [32]byte
	for i := range mk {
		mk[i] = byte(i * 3)
	}
	w1 := FSAttachWrapKey(mk)
	w2 := FSAttachWrapKey(mk)
	if w1 != w2 {
		t.Fatal("FSAttachWrapKey not deterministic")
	}
	if bytes.Equal(w1[:], mk[:]) {
		t.Fatal("wrap key equals message key")
	}
}

func TestFSX25519RoundTrip(t *testing.T) {
	pubA, privA, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dh1, err := FSX25519(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	dh2, err := FSX25519(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	if dh1 != dh2 {
		t.Fatal("DH mismatch")
	}
	var zero [32]byte
	if dh1 == zero {
		t.Fatal("DH produced zero")
	}
}
