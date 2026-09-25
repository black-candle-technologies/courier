// Package vhltest builds synthetic WebAuthn artifacts — a test
// attestation PKI, packed enrollment ceremonies, and UV assertions —
// so relay/client end-to-end tests can run a full ceremony without a
// physical security key. The attestation CA and leaf are generated
// fresh per test; the authenticator private key never leaves the
// test process, exactly like a real hardware key never reveals its
// secrets. Production code must never import this package.
package vhltest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

// PKI is a synthetic attestation trust root: a self-signed CA plus
// an attestation leaf signed by it, mirroring a YubiKey-style
// attestation chain (CA → leaf). Tests register the CA as the RP's
// attestation root.
type PKI struct {
	// AttestKey signs attestation statements (the authenticator's
	// attestation private key).
	AttestKey *ecdsa.PrivateKey
	// RootKey is the test CA's private key, for issuing additional
	// leaves (e.g. the apple-format leaf, which is issued for the
	// credential key rather than the authenticator attestation key).
	RootKey *ecdsa.PrivateKey
	// AttestDER is the DER-encoded attestation leaf certificate.
	AttestDER []byte
	// RootDER is the DER-encoded self-signed CA certificate.
	RootDER []byte
}

// NewPKI generates a fresh attestation CA and leaf.
func NewPKI(t *testing.T) *PKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vhltest attestation CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	attestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "vhltest authenticator",
			OrganizationalUnit: []string{"Authenticator Attestation"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// The FIDO AAGUID extension, carrying the same zero
		// AAGUID the synthetic authData below uses, so the
		// attestation certificate profile check (see vhl's
		// checkAttestationCertProfile) exercises its match path.
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4},
				Value: make([]byte, 16),
			},
		},
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	attestDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &attestKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return &PKI{AttestKey: attestKey, RootKey: rootKey, AttestDER: attestDER, RootDER: rootDER}
}

// WriteRootFile writes the CA certificate to a temp file and returns
// its path, for RP configs that take X.509 attestation root files.
func (p *PKI) WriteRootFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attest-root.der")
	if err := os.WriteFile(path, p.RootDER, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// FreshChallenge returns 32 cryptographically random bytes, the
// ceremony-challenge shape the vhl package produces.
func FreshChallenge(t *testing.T) []byte {
	t.Helper()
	ch := make([]byte, 32)
	if _, err := rand.Read(ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

// Enrollment is a synthetic packed-attestation registration ceremony.
type Enrollment struct {
	// OuterB64 is the base64url outer JSON the browser would submit.
	OuterB64 string
	// AuthData is the raw authenticator data (for signature checks).
	AuthData []byte
	// CredKey is the enrolled credential's private key (the
	// authenticator's secret; used to craft later assertions).
	CredKey *ecdsa.PrivateKey
	// CredID is the raw credential id.
	CredID []byte
}

// COSEKeyP256 encodes a P-256 public key as a COSE_Key (ES256).
func COSEKeyP256(pub *ecdsa.PublicKey) []byte {
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	xp := make([]byte, 32)
	yp := make([]byte, 32)
	copy(xp[32-len(xb):], xb)
	copy(yp[32-len(yb):], yb)
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, xp...)
	out = append(out, 0x22, 0x58, 0x20)
	out = append(out, yp...)
	return out
}

// Enroll builds a packed-attestation enrollment ceremony over the
// given challenge: a fresh credential key, UP|UV authData, and an
// attestation statement signed by the PKI's attestation key with the
// leaf certificate chained to the test root.
func (p *PKI) Enroll(t *testing.T, rpID, origin string, challenge []byte) *Enrollment {
	t.Helper()
	return p.EnrollWith(t, rpID, origin, challenge, p.AttestKey, p.AttestDER)
}

// EnrollWith is Enroll with an explicit attestation signing key and
// leaf certificate: it builds wrong-signer and cross-PKI cases.
func (p *PKI) EnrollWith(t *testing.T, rpID, origin string, challenge []byte, signKey *ecdsa.PrivateKey, certDER []byte) *Enrollment {
	t.Helper()
	return p.enrollPacked(t, rpID, origin, challenge, signKey, certDER, true)
}

// EnrollSelf builds a packed attestation with no x5c chain (self
// attestation): it must be rejected, since anyone holding the
// challenge could forge it.
func (p *PKI) EnrollSelf(t *testing.T, rpID, origin string, challenge []byte) *Enrollment {
	t.Helper()
	return p.enrollPacked(t, rpID, origin, challenge, p.AttestKey, nil, false)
}

// EnrollNone builds a "none"-format attestation object with an empty
// attStmt: it must be rejected, since "none" carries no
// authenticator proof.
func (p *PKI) EnrollNone(t *testing.T, rpID, origin string, challenge []byte) *Enrollment {
	t.Helper()
	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	authData := p.authData(t, rpID, credID, &credKey.PublicKey)
	clientData := `{"type":"webauthn.create","challenge":"` + b64.EncodeToString(challenge) + `","origin":"` + origin + `"}`
	noneAttObj := cborMap(
		cborTstr("fmt"), cborTstr("none"),
		cborTstr("attStmt"), cborMap(),
		cborTstr("authData"), cborBstr(authData),
	)
	return &Enrollment{
		OuterB64: p.outer(t, credID, clientData, noneAttObj),
		AuthData: authData,
		CredKey:  credKey,
		CredID:   credID,
	}
}

func (p *PKI) authData(t *testing.T, rpID string, credID []byte, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append(append([]byte{}, rpHash[:]...), 0x45, 0, 0, 0, 1) // UP|UV|AT
	authData = append(authData, make([]byte, 16)...)                     // aaguid
	authData = append(authData, 0, 32)                                   // cred id len
	authData = append(authData, credID...)
	authData = append(authData, COSEKeyP256(pub)...)
	return authData
}

func (p *PKI) outer(t *testing.T, credID []byte, clientData string, attObj []byte) string {
	t.Helper()
	resp := `{"clientDataJSON":"` + b64.EncodeToString([]byte(clientData)) +
		`","attestationObject":"` + b64.EncodeToString(attObj) + `"}`
	outer := `{"type":"public-key","id":"` + b64.EncodeToString(credID) +
		`","rawId":"` + b64.EncodeToString(credID) + `","response":` + resp + `}`
	return b64.EncodeToString([]byte(outer))
}

func (p *PKI) enrollPacked(t *testing.T, rpID, origin string, challenge []byte, signKey *ecdsa.PrivateKey, certDER []byte, includeX5C bool) *Enrollment {
	t.Helper()
	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	authData := p.authData(t, rpID, credID, &credKey.PublicKey)
	clientData := `{"type":"webauthn.create","challenge":"` + b64.EncodeToString(challenge) + `","origin":"` + origin + `"}`
	cdHash := sha256.Sum256([]byte(clientData))
	sig := ecdsaSign(t, signKey, authData, cdHash[:])
	var attStmt []byte
	if includeX5C {
		attStmt = cborMap(cborTstr("alg"), cborNeg(-7), cborTstr("sig"), cborBstr(sig), cborTstr("x5c"), cborArray(cborBstr(certDER)))
	} else {
		attStmt = cborMap(cborTstr("alg"), cborNeg(-7), cborTstr("sig"), cborBstr(sig))
	}
	attObj := cborMap(
		cborTstr("fmt"), cborTstr("packed"),
		cborTstr("attStmt"), attStmt,
		cborTstr("authData"), cborBstr(authData),
	)
	return &Enrollment{
		OuterB64: p.outer(t, credID, clientData, attObj),
		AuthData: authData,
		CredKey:  credKey,
		CredID:   credID,
	}
}

// appleAttestationNonceOID is the Apple anonymous-attestation nonce
// extension (WebAuthn §8.8): its value is a DER SEQUENCE holding the
// SHA-256 of authenticatorData || clientDataHash as a [1]-tagged
// OCTET STRING.
var appleAttestationNonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// AppleEnrollOpts tweaks the synthetic apple-format enrollment for
// negative tests.
type AppleEnrollOpts struct {
	// NoNonceExt omits the nonce extension from the attestation leaf.
	NoNonceExt bool
	// WrongNonce embeds a garbage nonce instead of the real one.
	WrongNonce bool
	// KeyMismatch issues the attestation leaf for a different key
	// than the credential key in authenticator data.
	KeyMismatch bool
}

// EnrollApple builds an "apple" (Apple Anonymous Attestation,
// WebAuthn §8.8) enrollment ceremony: the attestation statement
// carries only an x5c chain whose leaf is issued for the credential
// public key and embeds the SHA-256(authData || clientDataHash)
// nonce — the shape Touch ID / Face ID / iCloud Keychain produce
// when the ceremony requests attestation "direct".
func (p *PKI) EnrollApple(t *testing.T, rpID, origin string, challenge []byte) *Enrollment {
	t.Helper()
	return p.EnrollAppleWith(t, rpID, origin, challenge, AppleEnrollOpts{})
}

// EnrollAppleWith is EnrollApple with negative-test tweaks.
func (p *PKI) EnrollAppleWith(t *testing.T, rpID, origin string, challenge []byte, opts AppleEnrollOpts) *Enrollment {
	t.Helper()
	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	authData := p.authData(t, rpID, credID, &credKey.PublicKey)
	clientData := `{"type":"webauthn.create","challenge":"` + b64.EncodeToString(challenge) + `","origin":"` + origin + `"}`
	cdHash := sha256.Sum256([]byte(clientData))

	// The attestation leaf is issued for the credential public key
	// (WebAuthn §8.8 step 5 binds the leaf's subject key to the
	// enrolled credential); the mismatch variant issues it for an
	// unrelated key instead.
	leafKey := &credKey.PublicKey
	if opts.KeyMismatch {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafKey = &other.PublicKey
	}
	var extraExt []pkix.Extension
	if !opts.NoNonceExt {
		nonceInput := append(append([]byte{}, authData...), cdHash[:]...)
		nonce := sha256.Sum256(nonceInput)
		if opts.WrongNonce {
			nonce = sha256.Sum256([]byte("not the ceremony nonce"))
		}
		nonceVal, err := asn1.Marshal(struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}{Nonce: nonce[:]})
		if err != nil {
			t.Fatal(err)
		}
		extraExt = []pkix.Extension{{Id: appleAttestationNonceOID, Value: nonceVal}}
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"AAA Certification"},
			Organization:       []string{"Apple Inc."},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       extraExt,
	}
	rootCert, err := x509.ParseCertificate(p.RootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, leafKey, p.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	attObj := cborMap(
		cborTstr("fmt"), cborTstr("apple"),
		cborTstr("attStmt"), cborMap(cborTstr("x5c"), cborArray(cborBstr(leafDER))),
		cborTstr("authData"), cborBstr(authData),
	)
	return &Enrollment{
		OuterB64: p.outer(t, credID, clientData, attObj),
		AuthData: authData,
		CredKey:  credKey,
		CredID:   credID,
	}
}

// Assert crafts a genuine UV assertion (webauthn.get) over the given
// challenge with the credential private key — what the browser's
// navigator.credentials.get() would return for a mint ceremony.
func (p *PKI) Assert(t *testing.T, credKey *ecdsa.PrivateKey, credID []byte, rpID, origin string, challenge []byte) string {
	t.Helper()
	clientData := `{"type":"webauthn.get","challenge":"` + b64.EncodeToString(challenge) + `","origin":"` + origin + `"}`
	cdHash := sha256.Sum256([]byte(clientData))
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 2) // UP|UV
	sig := ecdsaSign(t, credKey, authData, cdHash[:])
	resp := `{"clientDataJSON":"` + b64.EncodeToString([]byte(clientData)) +
		`","authenticatorData":"` + b64.EncodeToString(authData) +
		`","signature":"` + b64.EncodeToString(sig) + `","userHandle":""}`
	outer := `{"type":"public-key","id":"` + b64.EncodeToString(credID) +
		`","rawId":"` + b64.EncodeToString(credID) + `","response":` + resp + `}`
	return b64.EncodeToString([]byte(outer))
}

// EnrollFidoU2F builds a fido-u2f-format enrollment ceremony: the
// attestation statement signs rawData = 0x00 || rpIdHash ||
// clientDataHash || credentialId || uncompressedPoint with the
// attestation key, and the authData embeds the credential public key
// as raw uncompressed EC coordinates (fido-u2f predates COSE).
func (p *PKI) EnrollFidoU2F(t *testing.T, rpID, origin string, challenge []byte) *Enrollment {
	t.Helper()
	credKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	// fido-u2f authData still carries a COSE key in this stack (the
	// verifier converts it to the 0x04||x||y form for the U2F
	// signed-bytes construction).
	authData := p.authData(t, rpID, credID, &credKey.PublicKey)
	clientData := `{"type":"webauthn.create","challenge":"` + b64.EncodeToString(challenge) + `","origin":"` + origin + `"}`
	cdHash := sha256.Sum256([]byte(clientData))
	rpHash := sha256.Sum256([]byte(rpID))
	rawData := append([]byte{0x00}, rpHash[:]...)
	rawData = append(rawData, cdHash[:]...)
	rawData = append(rawData, credID...)
	rawData = append(rawData, 0x04)
	rawData = append(rawData, credKey.PublicKey.X.FillBytes(make([]byte, 32))...)
	rawData = append(rawData, credKey.PublicKey.Y.FillBytes(make([]byte, 32))...)
	digest := sha256.Sum256(rawData)
	r, s, err := ecdsa.Sign(rand.Reader, p.AttestKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		t.Fatal(err)
	}
	attObj := cborMap(
		cborTstr("fmt"), cborTstr("fido-u2f"),
		cborTstr("attStmt"), cborMap(
			cborTstr("sig"), cborBstr(sig),
			cborTstr("x5c"), cborArray(cborBstr(p.AttestDER)),
		),
		cborTstr("authData"), cborBstr(authData),
	)
	return &Enrollment{
		OuterB64: p.outer(t, credID, clientData, attObj),
		AuthData: authData,
		CredKey:  credKey,
		CredID:   credID,
	}
}

func ecdsaSign(t *testing.T, key *ecdsa.PrivateKey, authData, cdHash []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// --- minimal CBOR encoder for attestation objects ---

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	default:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
}

func cborTstr(s string) []byte { return append(cborHead(3, uint64(len(s))), s...) }
func cborBstr(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborNeg(n int64) []byte   { return cborHead(1, uint64(-1-n)) }
func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}
func cborArray(items ...[]byte) []byte {
	out := cborHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}
