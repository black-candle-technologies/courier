package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/vhl"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mintSendDirectoryToken provisions only a disposable test identity's WebAuthn
// registry, then exercises the real challenge/assertion/token sealing path.
func mintSendDirectoryToken(t *testing.T, cfg *client.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry := vhl.NewRegistry()
	cred := vhl.Credential{ID: "directory-send-fixture", Kind: "webauthn", PublicKey: base64.RawURLEncoding.EncodeToString(directoryCOSEKey(t, &priv.PublicKey)), EnrolledAt: time.Now().Unix(), Device: "disposable test authenticator"}
	if err = registry.Enroll(cfg.Address, "sender", cred); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"registry": registry, "rp": vhl.WebAuthnRP{ID: "dashboard.test", Origins: []string{"https://dashboard.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(home, ".courier", "vhl.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	cl := client.New(cfg)
	pending, err := cl.VHLBeginSessionMint("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cl.VHLFinishSessionMint(pending, cred.ID, directoryMintAssertion(t, priv, pending.Challenge())); err != nil {
		t.Fatal(err)
	}
}

func directoryCOSEKey(t *testing.T, pub *ecdsa.PublicKey) []byte {
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

// directoryMintAssertion builds a real WebAuthn get-assertion for the
// fixture credential: clientDataJSON with the mint challenge and
// test origin, authenticatorData for the test RP with UP+UV set,
// and a valid ECDSA signature from the authenticator key.
func directoryMintAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte) string {
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
