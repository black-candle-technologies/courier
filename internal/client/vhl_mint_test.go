package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/vhl"
)

// Test mint ceremonies run under this relying party, configured on
// both minter and receiver. It stands in for the dashboard origin
// the real ceremony will use.
var testMintRP = vhl.WebAuthnRP{ID: "dashboard.test", Origins: []string{"https://dashboard.test"}}

// mintFixture is a complete test-side WebAuthn mint ceremony: a
// fresh authenticator key, its enrolled credential id, and the RP.
// The authenticator private key never leaves the test — it stands
// in for the human's security key.
type mintFixture struct {
	credID string
	priv   *ecdsa.PrivateKey
}

// setupMintFixture configures a full mint ceremony for the sender:
// it enrolls a fresh WebAuthn credential for the sender's identity
// in the sender's own registry AND in the recipient's registry (as
// the sender's approver credential), and sets the test relying
// party on both sides. Call it after VHLEnrollApprover.
func setupMintFixture(t *testing.T, env *attachTestEnv) *mintFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var idRaw [6]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		t.Fatal(err)
	}
	fix := &mintFixture{
		credID: "mint-cred-" + base64.RawURLEncoding.EncodeToString(idRaw[:]),
		priv:   priv,
	}
	cred := vhl.Credential{
		ID:         fix.credID,
		Kind:       "webauthn",
		PublicKey:  base64.RawURLEncoding.EncodeToString(coseEncodeTestKey(t, &priv.PublicKey)),
		EnrolledAt: time.Now().Unix(),
		Device:     "test-yubikey",
	}
	env.asSender()
	if err := updateVHL(func(ff *vhlFile) error {
		ff.RP = testMintRP
		return ff.Registry.Enroll(env.senderCfg.Address, "sender", cred)
	}); err != nil {
		t.Fatalf("enroll mint credential (sender): %v", err)
	}
	env.asRecipient()
	if err := updateVHL(func(ff *vhlFile) error {
		ff.RP = testMintRP
		return ff.Registry.Enroll(env.senderCfg.Address, "sender", cred)
	}); err != nil {
		t.Fatalf("enroll mint credential (recipient): %v", err)
	}
	return fix
}

// mint runs the real two-phase mint through the client: begin,
// craft a genuine UV assertion over the pending's challenge with
// the fixture's authenticator key, finish and seal.
func (f *mintFixture) mint(t *testing.T, env *attachTestEnv, scope string) *vhl.SessionToken {
	t.Helper()
	env.asSender()
	pending, err := env.sender.VHLBeginSessionMint(scope, 0)
	if err != nil {
		t.Fatalf("begin mint: %v", err)
	}
	assertion := craftTestAssertion(t, f.priv, pending.Challenge())
	tok, err := env.sender.VHLFinishSessionMint(pending, f.credID, assertion)
	if err != nil {
		t.Fatalf("finish mint: %v", err)
	}
	return tok
}

// coseEncodeTestKey encodes a P-256 public key as a COSE_Key
// (ES256), mirroring the vhl package's test helper.
func coseEncodeTestKey(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	xp := make([]byte, 32)
	yp := make([]byte, 32)
	copy(xp[32-len(xb):], xb)
	copy(yp[32-len(yb):], yb)
	var out []byte
	out = append(out, 0xa5)       // map(5)
	out = append(out, 0x01, 0x02) // 1: 2 (kty EC2)
	out = append(out, 0x03, 0x26) // 3: -7 (alg ES256)
	out = append(out, 0x20, 0x01) // -1: 1 (crv P-256)
	out = append(out, 0x21)       // -2:
	out = append(out, 0x58, 0x20) // bytes(32)
	out = append(out, xp...)
	out = append(out, 0x22)       // -3:
	out = append(out, 0x58, 0x20) // bytes(32)
	out = append(out, yp...)
	return out
}

// craftTestAssertion builds a real WebAuthn get-assertion for the
// fixture credential: clientDataJSON with the mint challenge and
// test origin, authenticatorData for the test RP with UP+UV set,
// and a valid ECDSA signature from the authenticator key.
func craftTestAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte) string {
	t.Helper()
	const flags = 0x01 | 0x04 // user present + user verified
	clientData := map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    "https://dashboard.test",
	}
	cdJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("dashboard.test"))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, flags)
	sc := make([]byte, 4)
	binary.BigEndian.PutUint32(sc, 1)
	authData = append(authData, sc...)

	cdHash := sha256.Sum256(cdJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		t.Fatal(err)
	}
	cred := map[string]any{
		"type": "public-key",
		"response": map[string]string{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdJSON),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestVHLFinishSessionMintFailsClosed pins the client-side
// fail-closed behavior: without a configured relying party, or
// without an enrolled WebAuthn credential, finishing a mint must
// refuse — it never falls back to a caller-asserted ceremony.
func TestVHLFinishSessionMintFailsClosed(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asSender()

	// No RP configured and no credential enrolled: finish refuses.
	pending, err := env.sender.VHLBeginSessionMint("", 0)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := env.sender.VHLFinishSessionMint(pending, "nope", "nope"); err == nil {
		t.Fatal("finish without relying party should fail closed")
	}

	// RP configured but credential not enrolled: still refuses.
	if err := updateVHL(func(ff *vhlFile) error {
		ff.RP = testMintRP
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pending2, err := env.sender.VHLBeginSessionMint("", 0)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := env.sender.VHLFinishSessionMint(pending2, "unenrolled", "nope"); err == nil {
		t.Fatal("finish with unenrolled credential should fail closed")
	}

	// Nil pending refuses.
	if _, err := env.sender.VHLFinishSessionMint(nil, "x", "y"); err == nil {
		t.Fatal("finish with nil pending should fail")
	}

	// Over-24h TTL is rejected at begin.
	if _, err := env.sender.VHLBeginSessionMint("", 25*time.Hour); err == nil {
		t.Fatal("begin with TTL over 24h should fail")
	}
}
