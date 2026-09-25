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
	// AttestDER is the DER-encoded attestation leaf certificate.
	AttestDER []byte
	// RootDER is the DER-encoded self-signed CA certificate.
	RootDER []byte
	// RootKey and RootCert sign Android attestation leaves in
	// tests (the android-key leaf carries the credential key, so
	// each enrollment mints its own leaf).
	RootKey  *ecdsa.PrivateKey
	RootCert *x509.Certificate
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
	return &PKI{AttestKey: attestKey, AttestDER: attestDER, RootDER: rootDER, RootKey: rootKey, RootCert: rootCert}
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

// --- Android Key (android-key) attestation fixtures ---

// androidKeyDescriptionOID mirrors the vhl package's OID: the
// Android KeyStore KeyDescription extension.
var androidKeyDescriptionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Android security levels, mirroring the KeyDescription
// attestationSecurityLevel values.
const (
	androidSecuritySoftware           = 0
	androidSecurityTrustedEnvironment = 1
	androidSecurityStrongBox          = 2
)

// AndroidEnrollOpts tunes the synthetic android-key enrollment for
// negative tests. The zero value is the happy path: StrongBox
// security level, correct challenge, matching key, trusted root,
// valid signature, origin GENERATED and purpose SIGN in the
// TEE-enforced list.
type AndroidEnrollOpts struct {
	// SecurityLevel overrides the KeyDescription
	// attestationSecurityLevel. It applies only when
	// SecurityLevelSet is true (so the zero value keeps the
	// StrongBox happy path while tests can still select
	// Software(0)).
	SecurityLevel    int
	SecurityLevelSet bool
	WrongChallenge   bool // KeyDescription carries the wrong challenge
	KeyMismatch      bool // leaf cert holds a different key than the credential
	NoPurpose        bool // omit purpose SIGN from the TEE authorization list
	PurposeSWOnly    bool // purpose SIGN only in the software list, not TEE
	AllApplications  bool // allApplications present in the TEE list
	NoOrigin         bool // omit origin from the TEE list
	WrongOrigin      bool // origin IMPORTED instead of GENERATED
	WrongRoot        bool // leaf signed by a throwaway CA, not the test root
	BadSig           bool // corrupt the attestation signature
	WrongAlg         bool // attStmt alg -257 instead of -7
	DupX5C           bool // attStmt carries "x5c" twice (must fail closed)
	ExtraStmtField   bool // attStmt carries an unknown extra field
	TrailingJunk     bool // junk bytes appended after the KeyDescription DER
}

// androidAuthListContent concatenates AuthorizationList field
// elements into the SEQUENCE content bytes.
func androidAuthListContent(fields ...[]byte) []byte {
	var content []byte
	for _, f := range fields {
		content = append(content, f...)
	}
	return content
}

// androidExplicitField wraps a value TLV in a context-specific
// constructed EXPLICIT tag, encoding the tag number in
// high-tag-number form when needed (e.g. 600, 702).
func androidExplicitField(tagNo int, value []byte) []byte {
	var tag []byte
	if tagNo < 31 {
		tag = []byte{0xA0 | byte(tagNo)}
	} else {
		tag = []byte{0xBF, 0x80 | byte(tagNo>>7), byte(tagNo & 0x7F)}
	}
	out := append(tag, byte(len(value)))
	return append(out, value...)
}

// androidKeyDescriptionDER builds a minimal but structurally valid
// KeyDescription ASN.1 record. The purpose field is encoded as
// [1] EXPLICIT SET OF INTEGER and origin as [702] EXPLICIT
// INTEGER, matching real Android devices (Go's asn1 would emit
// SEQUENCE instead of SET for the former).
func androidKeyDescriptionDER(t *testing.T, challenge []byte, securityLevel int, opts AndroidEnrollOpts) []byte {
	t.Helper()
	var teeFields [][]byte
	if !opts.NoPurpose && !opts.PurposeSWOnly {
		// [1] EXPLICIT SET { INTEGER 2 }  (purpose SIGN)
		set := []byte{0x31, 0x03, 0x02, 0x01, 0x02}
		teeFields = append(teeFields, androidExplicitField(1, set))
	}
	if !opts.NoOrigin {
		// [702] EXPLICIT INTEGER (origin); 0=GENERATED,
		// 2=IMPORTED.
		origin := 0
		if opts.WrongOrigin {
			origin = 2
		}
		teeFields = append(teeFields, androidExplicitField(702, []byte{0x02, 0x01, byte(origin)}))
	}
	if opts.AllApplications {
		// [600] EXPLICIT NULL — must be absent per WebAuthn
		// §8.4; present here only for the negative test.
		teeFields = append(teeFields, androidExplicitField(600, []byte{0x05, 0x00}))
	}
	var swFields [][]byte
	if opts.PurposeSWOnly {
		set := []byte{0x31, 0x03, 0x02, 0x01, 0x02}
		swFields = append(swFields, androidExplicitField(1, set))
	}
	teeEnforced := asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: androidAuthListContent(teeFields...)}
	softwareEnforced := asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: androidAuthListContent(swFields...)}
	kd := struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		TEEEnforced              asn1.RawValue
	}{
		AttestationVersion:       4,
		AttestationSecurityLevel: asn1.Enumerated(securityLevel),
		KeymasterVersion:         41,
		KeymasterSecurityLevel:   asn1.Enumerated(securityLevel),
		AttestationChallenge:     challenge,
		UniqueID:                 []byte{},
		SoftwareEnforced:         softwareEnforced,
		TEEEnforced:              teeEnforced,
	}
	der, err := asn1.Marshal(kd)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// EnrollAndroidKey builds an android-key enrollment ceremony: a
// fresh credential key, UP|UV authData, and an attestation
// statement in the Android Key Attestation format. The leaf
// certificate's public key is the credential key, its
// KeyDescription extension binds the ceremony challenge, and the
// statement is signed by the credential key — in the Android
// model the hardware proof is the certificate chain to the trust
// anchor, and the signature proves possession at registration.
func (p *PKI) EnrollAndroidKey(t *testing.T, rpID, origin string, challenge []byte, opts AndroidEnrollOpts) *Enrollment {
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

	// The KeyDescription challenge is identical to clientDataHash
	// (WebAuthn §8.4).
	kdChallenge := cdHash[:]
	if opts.WrongChallenge {
		w := sha256.Sum256([]byte("wrong challenge"))
		kdChallenge = w[:]
	}
	level := androidSecurityStrongBox
	if opts.SecurityLevelSet {
		level = opts.SecurityLevel
	}
	kdDER := androidKeyDescriptionDER(t, kdChallenge, level, opts)
	if opts.TrailingJunk {
		kdDER = append(kdDER, 0xDE, 0xAD, 0xBE, 0xEF)
	}

	// The attested key: the credential key, or a different key to
	// exercise the key-binding check.
	leafPub := &credKey.PublicKey
	if opts.KeyMismatch {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafPub = &other.PublicKey
	}
	caCert := p.RootCert
	caKey := p.RootKey
	if opts.WrongRoot {
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrongTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(999),
			Subject:               pkix.Name{CommonName: "wrong root"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		wrongDER, err := x509.CreateCertificate(rand.Reader, wrongTmpl, wrongTmpl, &wrongKey.PublicKey, wrongKey)
		if err != nil {
			t.Fatal(err)
		}
		caCert, err = x509.ParseCertificate(wrongDER)
		if err != nil {
			t.Fatal(err)
		}
		caKey = wrongKey
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		// Real Android leaves use CN "Android Keystore Key" and
		// no OU — the FIDO "Authenticator Attestation" OU
		// requirement must not apply here. They also carry no
		// Basic Constraints extension, so it is deliberately
		// not set (matching real devices keeps the happy path
		// representative).
		Subject:   pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: androidKeyDescriptionOID, Value: kdDER},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}

	sig := ecdsaSign(t, credKey, authData, cdHash[:])
	if opts.BadSig {
		sig = append([]byte{}, sig...)
		sig[len(sig)/2] ^= 0xFF
	}
	alg := int64(-7)
	if opts.WrongAlg {
		alg = -257
	}
	x5c := cborArray(cborBstr(leafDER))
	var attStmt []byte
	switch {
	case opts.DupX5C:
		attStmt = cborMap(
			cborTstr("alg"), cborNeg(alg),
			cborTstr("sig"), cborBstr(sig),
			cborTstr("x5c"), x5c,
			cborTstr("x5c"), x5c,
		)
	case opts.ExtraStmtField:
		attStmt = cborMap(
			cborTstr("alg"), cborNeg(alg),
			cborTstr("sig"), cborBstr(sig),
			cborTstr("x5c"), x5c,
			cborTstr("ver"), cborTstr("1.0"),
		)
	default:
		attStmt = cborMap(
			cborTstr("alg"), cborNeg(alg),
			cborTstr("sig"), cborBstr(sig),
			cborTstr("x5c"), x5c,
		)
	}
	attObj := cborMap(
		cborTstr("fmt"), cborTstr("android-key"),
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
