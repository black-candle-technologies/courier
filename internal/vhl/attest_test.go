package vhl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/vhltest"
)

var attestB64 = base64.RawURLEncoding

func testRP(pki *vhltest.PKI, rpID string) WebAuthnRP {
	return WebAuthnRP{
		ID:               rpID,
		Origins:          []string{"https://example.com"},
		AttestationRoots: []string{attestB64.EncodeToString(pki.RootDER)},
	}
}

// freshChallenge uses the real enrollment-challenge generator so the
// tests exercise the exact bytes the client will send.
func freshChallenge(t *testing.T) []byte {
	t.Helper()
	chal, err := EnrollmentChallenge("ed25519:test", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	return chal
}

func TestEnrollmentChallenge(t *testing.T) {
	c1, err := EnrollmentChallenge("ed25519:alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(c1) != 32 {
		t.Fatalf("challenge length %d, want 32", len(c1))
	}
	c2, err := EnrollmentChallenge("ed25519:alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("challenges must be fresh per call")
	}
	// Bound to the identity: a different address must not collide.
	c3, err := EnrollmentChallenge("ed25519:bob", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c3) {
		t.Fatal("challenge not bound to address")
	}
	if _, err := EnrollmentChallenge("", "example.com"); err == nil {
		t.Fatal("empty address accepted")
	}
	if _, err := EnrollmentChallenge("ed25519:alice", ""); err == nil {
		t.Fatal("empty rp id accepted")
	}
}

func TestVerifyRegistrationPackedHappyPath(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.Enroll(t, "example.com", "https://example.com", chal)
	res, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com"))
	if err != nil {
		t.Fatalf("happy path failed: %v", err)
	}
	if res.CredentialID != attestB64.EncodeToString(cer.CredID) {
		t.Fatalf("credential id mismatch: %q", res.CredentialID)
	}
	fields, err := parseCOSEKey(res.PublicKey)
	if err != nil {
		t.Fatalf("returned public key does not parse: %v", err)
	}
	if alg, _ := fields[3].(int64); alg != -7 {
		t.Fatalf("alg = %v, want -7", alg)
	}
	if res.SignCount != 1 {
		t.Fatalf("sign count = %d, want 1", res.SignCount)
	}
}

func TestVerifyRegistrationFidoU2FHappyPath(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.EnrollFidoU2F(t, "example.com", "https://example.com", chal)
	res, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com"))
	if err != nil {
		t.Fatalf("fido-u2f happy path failed: %v", err)
	}
	if res.CredentialID != attestB64.EncodeToString(cer.CredID) {
		t.Fatalf("credential id mismatch: %q", res.CredentialID)
	}
}

func TestVerifyRegistrationRejectsWrongChallenge(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.Enroll(t, "example.com", "https://example.com", chal)
	other := freshChallenge(t)
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, other, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong challenge accepted")
	}
	// Tampered challenge bytes inside clientDataJSON.
	tampered := append([]byte{}, chal...)
	tampered[0] ^= 0xff
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, tampered, testRP(pki, "example.com")); err == nil {
		t.Fatal("tampered challenge accepted")
	}
}

func TestVerifyRegistrationRejectsWrongOriginAndRPID(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	// Wrong origin in the ceremony.
	cer := pki.Enroll(t, "example.com", "https://evil.com", chal)
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong origin accepted")
	}
	// Right origin, wrong RP id baked into authData.
	cer2 := pki.Enroll(t, "other.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer2.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong rpIdHash accepted")
	}
	// RP config with the wrong origin list.
	cer3 := pki.Enroll(t, "example.com", "https://example.com", chal)
	rp := testRP(pki, "example.com")
	rp.Origins = []string{"https://other.com"}
	if _, err := VerifyRegistrationAttestation(cer3.OuterB64, chal, rp); err == nil {
		t.Fatal("origin not in allowlist accepted")
	}
}

func TestVerifyRegistrationRejectsUntrustedAttestation(t *testing.T) {
	pki := vhltest.NewPKI(t)
	otherPKI := vhltest.NewPKI(t)
	chal := freshChallenge(t)

	// x5c chained to an unknown root: rejected.
	cer2 := otherPKI.Enroll(t, "example.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer2.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("untrusted attestation chain accepted")
	}

	// No attestation roots configured: fail closed.
	cer3 := pki.Enroll(t, "example.com", "https://example.com", chal)
	rp := testRP(pki, "example.com")
	rp.AttestationRoots = nil
	if _, err := VerifyRegistrationAttestation(cer3.OuterB64, chal, rp); err == nil {
		t.Fatal("empty attestation roots accepted")
	}

	// Signature made by a key the certificate does not know (wrong
	// signer, right chain): rejected.
	cer4 := pki.EnrollWith(t, "example.com", "https://example.com", chal, otherPKI.AttestKey, pki.AttestDER)
	if _, err := VerifyRegistrationAttestation(cer4.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("wrong-signer attestation accepted")
	}

	// Packed attestation with no x5c at all (self attestation):
	// rejected — anyone holding the challenge could forge it.
	cer5 := pki.EnrollSelf(t, "example.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer5.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("self attestation accepted")
	}
}

func TestVerifyRegistrationRejectsNoneAttestation(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	// A hand-built "none" attestation object with empty attStmt must
	// be rejected even though its challenge/origin/rpId check out:
	// "none" carries no authenticator proof.
	cer := pki.EnrollNone(t, "example.com", "https://example.com", chal)
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com")); err == nil {
		t.Fatal("\"none\" attestation accepted")
	} else if got := fmt.Sprint(err); !strings.Contains(got, "none") {
		t.Fatalf("expected a none-attestation rejection, got: %v", err)
	}
}

func TestVerifyRegistrationRejectsGarbage(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	rp := testRP(pki, "example.com")
	for name, input := range map[string]string{
		"bad base64": "!!!",
		"bad json":   attestB64.EncodeToString([]byte("not json")),
		"empty":      "",
		"wrong type": attestB64.EncodeToString([]byte(`{"type":"weird"}`)),
		"truncated":  attestB64.EncodeToString([]byte(`{"type":"public-key","id":"eA","rawId":"eA","response":{"clientDataJSON":"QQ","attestationObject":"QQ"}}`)),
		"no rp":      "",
	} {
		in := input
		if name == "no rp" {
			badRP := rp
			badRP.ID = ""
			if _, err := VerifyRegistrationAttestation(
				attestB64.EncodeToString([]byte(`{"type":"public-key"}`)), chal, badRP); err == nil {
				t.Fatalf("%s accepted", name)
			}
			continue
		}
		if _, err := VerifyRegistrationAttestation(in, chal, rp); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// FuzzCborDecoder feeds hostile bytes into every decoder entry point:
// the decoder must return an error, never panic or loop forever.
func FuzzCborDecoder(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x80},
		{0xa3, 0x63, 0x66, 0x6d, 0x74}, // map{1: "fmt"} truncated
		{0xa3, 0x63, 0x66, 0x6d, 0x74, 0x66, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x64}, // map{"fmt":"packed"}
		{0x5f, 0xff}, // indefinite-length (unsupported)
		{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d := &cborDecoder{buf: data}
		_ = d.skipValue()
		d = &cborDecoder{buf: data}
		_, _ = d.readBstr()
		d = &cborDecoder{buf: data}
		_, _ = d.readTstr()
		d = &cborDecoder{buf: data}
		_, _ = d.readArrayLen()
		d = &cborDecoder{buf: data}
		_, _ = d.readMapLen()
		d = &cborDecoder{buf: data}
		_, _ = d.readInt()
		_, _ = parseAttestationObject(data)
	})
}

// profileLeaf builds a CA and a profile-satisfying attestation leaf
// (mirroring the FIDO2 authenticator profile), applying mutate to
// the leaf template/key so each negative case can break one
// requirement. It returns the parsed leaf and the 16-byte AAGUID
// baked into the leaf's AAGUID extension.
func profileLeaf(t *testing.T, mutate func(tmpl *x509.Certificate, key **ecdsa.PrivateKey)) (*x509.Certificate, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aaguid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "test authenticator",
			OrganizationalUnit: []string{"Authenticator Attestation"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: aaguid},
		},
	}
	if mutate != nil {
		mutate(tmpl, &leafKey)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, aaguid
}

// profileAuthData returns minimal authenticator data with the AT
// flag set and the given AAGUID, plus the corresponding no-AT
// variant for the extension-present-without-attested-data case.
func profileAuthData(aaguid []byte) (withAT, withoutAT []byte) {
	mk := func(flags byte) []byte {
		ad := make([]byte, 0, 53)
		ad = append(ad, make([]byte, 32)...) // rpIdHash
		ad = append(ad, flags)
		ad = append(ad, 0, 0, 0, 1) // signCount
		ad = append(ad, aaguid...)
		return ad
	}
	return mk(authFlagUserPresent | authFlagAttestedData), mk(authFlagUserPresent)
}

func TestAttestationCertProfileHappyPath(t *testing.T) {
	leaf, aaguid := profileLeaf(t, nil)
	withAT, _ := profileAuthData(aaguid)
	if err := checkAttestationCertProfile(leaf, withAT, -7); err != nil {
		t.Fatalf("profile-satisfying leaf should pass: %v", err)
	}
}

func TestAttestationCertProfileNoAAGUIDExtension(t *testing.T) {
	// The AAGUID extension is optional (many real authenticators
	// omit it); its absence must not break the happy path.
	leaf, aaguid := profileLeaf(t, func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
		tmpl.ExtraExtensions = nil
	})
	withAT, _ := profileAuthData(aaguid)
	if err := checkAttestationCertProfile(leaf, withAT, -7); err != nil {
		t.Fatalf("leaf without AAGUID extension should pass: %v", err)
	}
}

func TestAttestationCertProfileNegative(t *testing.T) {
	_, wantAAGUID := profileLeaf(t, nil) // canonical AAGUID for authData construction
	withAT, withoutAT := profileAuthData(wantAAGUID)

	cases := []struct {
		name    string
		mutate  func(tmpl *x509.Certificate, key **ecdsa.PrivateKey)
		auth    func() []byte
		alg     int64
		wantErr string
	}{
		{
			name: "wrong OU",
			mutate: func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
				tmpl.Subject.OrganizationalUnit = []string{"Web Server"}
			},
			auth:    func() []byte { return withAT },
			alg:     -7,
			wantErr: "OU",
		},
		{
			name: "CA leaf",
			mutate: func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
				tmpl.IsCA = true
				tmpl.KeyUsage = x509.KeyUsageCertSign
			},
			auth:    func() []byte { return withAT },
			alg:     -7,
			wantErr: "CA",
		},
		{
			name: "missing basic constraints",
			mutate: func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
				tmpl.BasicConstraintsValid = false
			},
			auth:    func() []byte { return withAT },
			alg:     -7,
			wantErr: "end-entity",
		},
		{
			name: "missing digitalSignature usage",
			mutate: func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
				tmpl.KeyUsage = 0
			},
			auth:    func() []byte { return withAT },
			alg:     -7,
			wantErr: "digitalSignature",
		},
		{
			name: "AAGUID mismatch",
			mutate: func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
				tmpl.ExtraExtensions[0].Value = []byte{
					0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
					0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
				}
			},
			auth:    func() []byte { return withAT },
			alg:     -7,
			wantErr: "AAGUID",
		},
		{
			name:    "AAGUID extension without attested data",
			mutate:  nil,
			auth:    func() []byte { return withoutAT },
			alg:     -7,
			wantErr: "authenticator data has none",
		},
		{
			name: "ES256 with P-384 key",
			mutate: func(tmpl *x509.Certificate, key **ecdsa.PrivateKey) {
				p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				*key = p384
			},
			auth:    func() []byte { return withAT },
			alg:     -7,
			wantErr: "P-256",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf, _ := profileLeaf(t, tc.mutate)
			if err := checkAttestationCertProfile(leaf, tc.auth(), tc.alg); err == nil {
				t.Fatalf("%s: want profile rejection, got nil", tc.name)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s: want error containing %q, got %q", tc.name, tc.wantErr, err)
			}
		})
	}
}

func TestVerifyRegistrationAndroidKeyHappyPath(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.EnrollAndroidKey(t, "example.com", "https://example.com", chal, vhltest.AndroidEnrollOpts{})
	res, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com"))
	if err != nil {
		t.Fatalf("android-key happy path failed: %v", err)
	}
	if res.CredentialID != attestB64.EncodeToString(cer.CredID) {
		t.Fatalf("credential id mismatch: %q", res.CredentialID)
	}
	// The enrolled key must be exactly the attested credential key.
	if want := vhltest.COSEKeyP256(&cer.CredKey.PublicKey); !bytes.Equal(res.PublicKey, want) {
		t.Fatalf("enrolled public key does not match the attested credential key")
	}
	if res.SignCount != 1 {
		t.Fatalf("sign count = %d, want 1", res.SignCount)
	}
}

func TestVerifyRegistrationAndroidKeyTrustedEnvironment(t *testing.T) {
	pki := vhltest.NewPKI(t)
	chal := freshChallenge(t)
	cer := pki.EnrollAndroidKey(t, "example.com", "https://example.com", chal,
		vhltest.AndroidEnrollOpts{SecurityLevelSet: true, SecurityLevel: 1})
	if _, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com")); err != nil {
		t.Fatalf("TrustedEnvironment must be accepted: %v", err)
	}
}

func TestVerifyRegistrationAndroidKeyRejectsNonconforming(t *testing.T) {
	cases := []struct {
		name    string
		opts    vhltest.AndroidEnrollOpts
		wantErr string
	}{
		{"wrong attestationChallenge", vhltest.AndroidEnrollOpts{WrongChallenge: true}, "attestation challenge does not match"},
		{"key mismatch", vhltest.AndroidEnrollOpts{KeyMismatch: true}, "does not match the enrolled credential key"},
		{"software security level", vhltest.AndroidEnrollOpts{SecurityLevelSet: true, SecurityLevel: 0}, "not hardware-backed"},
		{"duplicate x5c key", vhltest.AndroidEnrollOpts{DupX5C: true}, "duplicate key"},
		{"extra statement field", vhltest.AndroidEnrollOpts{ExtraStmtField: true}, "must be exactly {alg, sig, x5c}"},
		{"trailing DER junk", vhltest.AndroidEnrollOpts{TrailingJunk: true}, "trailing bytes"},
		{"untrusted root", vhltest.AndroidEnrollOpts{WrongRoot: true}, "does not chain to a configured trust anchor"},
		{"bad signature", vhltest.AndroidEnrollOpts{BadSig: true}, "signature invalid"},
		{"wrong alg", vhltest.AndroidEnrollOpts{WrongAlg: true}, "unsupported alg"},
		{"no purpose SIGN", vhltest.AndroidEnrollOpts{NoPurpose: true}, "does not grant purpose SIGN"},
		{"purpose only in software list", vhltest.AndroidEnrollOpts{PurposeSWOnly: true}, "does not grant purpose SIGN"},
		{"allApplications present", vhltest.AndroidEnrollOpts{AllApplications: true}, "allApplications"},
		{"origin not generated", vhltest.AndroidEnrollOpts{WrongOrigin: true}, "not generated on-device"},
		{"origin missing", vhltest.AndroidEnrollOpts{NoOrigin: true}, "not generated on-device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pki := vhltest.NewPKI(t)
			chal := freshChallenge(t)
			cer := pki.EnrollAndroidKey(t, "example.com", "https://example.com", chal, tc.opts)
			_, err := VerifyRegistrationAttestation(cer.OuterB64, chal, testRP(pki, "example.com"))
			if err == nil {
				t.Fatalf("%s: want rejection, got nil", tc.name)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s: want error containing %q, got %q", tc.name, tc.wantErr, err)
			}
		})
	}
}

func TestParseAndroidAuthList(t *testing.T) {
	// Hand-built AuthorizationList DER. Field encodings:
	//   purpose  = A1 05 31 03 02 01 02        ([1] EXPLICIT SET { INTEGER 2 })
	//   origin   = BF 85 3E 03 02 01 00        ([702] EXPLICIT INTEGER 0)
	//   allApps  = BF 84 58 02 05 00           ([600] EXPLICIT NULL)
	purpose := []byte{0xA1, 0x05, 0x31, 0x03, 0x02, 0x01, 0x02}
	origin := []byte{0xBF, 0x85, 0x3E, 0x03, 0x02, 0x01, 0x00}
	allApps := []byte{0xBF, 0x84, 0x58, 0x02, 0x05, 0x00}
	seq := func(fields ...[]byte) []byte {
		var c []byte
		for _, f := range fields {
			c = append(c, f...)
		}
		return append([]byte{0x30, byte(len(c))}, c...)
	}
	cases := []struct {
		name    string
		der     []byte
		wantErr string
		check   func(*androidAuthList) error
	}{
		{
			name: "valid purpose and origin",
			der:  seq(purpose, origin),
			check: func(l *androidAuthList) error {
				if !l.purposePresent || len(l.purposes) != 1 || l.purposes[0] != 2 {
					return errTest("purposes not parsed")
				}
				if !l.originPresent || l.origin != 0 {
					return errTest("origin not parsed")
				}
				if l.allApplications {
					return errTest("spurious allApplications")
				}
				return nil
			},
		},
		{
			name: "unknown field skipped",
			der:  seq(purpose, origin, []byte{0xA2, 0x03, 0x02, 0x01, 0x05}),
			check: func(l *androidAuthList) error {
				if !l.purposePresent || !l.originPresent {
					return errTest("known fields lost")
				}
				return nil
			},
		},
		{
			name:    "duplicate purpose rejected",
			der:     seq(purpose, purpose),
			wantErr: "duplicate field",
		},
		{
			name:    "allApplications detected",
			der:     seq(purpose, origin, allApps),
			wantErr: "",
			check: func(l *androidAuthList) error {
				if !l.allApplications {
					return errTest("allApplications not detected")
				}
				return nil
			},
		},
		{
			name:    "non-minimal length rejected",
			der:     append([]byte{0x30, 0x81, 0x0D}, seq(purpose, origin)[2:]...),
			wantErr: "non-minimal",
		},
		{
			name:    "truncated list rejected",
			der:     []byte{0x30, 0x0D, 0xA1, 0x05},
			wantErr: "length exceeds",
		},
		{
			name:    "SET instead of SEQUENCE rejected",
			der:     []byte{0x31, 0x00},
			wantErr: "not a SEQUENCE",
		},
		{
			name:    "purpose as SEQUENCE rejected",
			der:     seq([]byte{0xA1, 0x04, 0x30, 0x02, 0x02, 0x01, 0x02}),
			wantErr: "want SET",
		},
		{
			name:    "trailing bytes after SET rejected",
			der:     seq([]byte{0xA1, 0x06, 0x31, 0x03, 0x02, 0x01, 0x02, 0x00}),
			wantErr: "trailing bytes",
		},
		{
			name:    "negative origin rejected",
			der:     seq(purpose, []byte{0xBF, 0x85, 0x3E, 0x03, 0x02, 0x01, 0xFF}),
			wantErr: "negative INTEGER",
		},
		{
			name:    "non-minimal INTEGER rejected",
			der:     seq(purpose, []byte{0xBF, 0x85, 0x3E, 0x04, 0x02, 0x02, 0x00, 0x00}),
			wantErr: "non-minimal INTEGER",
		},
		{
			name:    "empty input rejected",
			der:     []byte{},
			wantErr: "not a SEQUENCE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := parseAndroidAuthList(tc.der)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %q", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				if cerr := tc.check(l); cerr != nil {
					t.Fatal(cerr)
				}
			}
		})
	}
}

func errTest(s string) error { return fmt.Errorf("%s", s) }
