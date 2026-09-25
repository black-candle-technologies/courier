package vhl

// WebAuthn registration (attestation) verification (issue #142).
//
// Session-token minting needs an authenticator assertion, and that
// assertion is only meaningful if the credential was enrolled in a
// genuine ceremony. This file verifies the *registration* ceremony —
// the navigator.credentials.create() response the browser produces
// during `courier vhl enroll-webauthn`:
//
//   - the clientData challenge is the enrollment challenge the agent
//     issued (what-you-sign-is-what-you-saw),
//   - the origin is one the relying party expects,
//   - the authenticator data names the relying party id, carries the
//     user-presence AND user-verification flags (enrolled credentials
//     mint at fido2_uv strength, so enrollment without UV is useless),
//     and carries attested credential data,
//   - the attestation statement is a real authenticator attestation
//     chaining to an operator-configured trust anchor.
//
// The trust-anchor requirement is the load-bearing part. A "none"
// attestation carries no proof at all, and a self attestation is
// signed by the very key being enrolled — anyone holding the
// ceremony challenge (including a compromised relay, which sees
// every challenge the agent submits) can fabricate either one and
// enroll an attacker key. Only an attestation statement whose
// certificate chain terminates at a configured trust anchor
// (rp.AttestationRoots) proves a real authenticator was involved.
// Enrollment therefore fails closed with no trust anchors
// configured, and rejects "none" and self attestations outright.
//
// Supported formats: "packed" (x5c only), "fido-u2f", and
// "android-key" (Android Key Attestation, WebAuthn §8.4). Anything
// else — "tpm", "apple", "none" — is rejected with a clear error,
// never silently accepted.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// webauthnCreateCredential is the JSON the enrollment ceremony
// produces (the PublicKeyCredential shape from
// navigator.credentials.create()).
type webauthnCreateCredential struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
}

// RegistrationResult is a verified enrollment ceremony: the new
// credential's id, its COSE-encoded public key, the authenticator
// model (AAGUID), and the initial signature counter.
type RegistrationResult struct {
	CredentialID string
	PublicKey    []byte // COSE_Key bytes, as stored on the enrollment record
	AAGUID       string // hex of the 16-byte AAGUID, "" when zero
	SignCount    uint32
}

// enrollmentChallengeDomain separates enrollment challenges from
// every other challenge in the system.
var enrollmentChallengeDomain = []byte("courier-vhl-enroll-v1\x00")

// EnrollmentChallenge issues the challenge for a WebAuthn
// registration ceremony. It binds the operator's identity address
// and the relying party id alongside fresh randomness, so a
// challenge issued for one identity or RP can never authorize an
// enrollment for another.
func EnrollmentChallenge(address, rpID string) ([]byte, error) {
	if address == "" {
		return nil, fmt.Errorf("enrollment challenge without identity address")
	}
	if rpID == "" {
		return nil, fmt.Errorf("enrollment challenge without relying party id")
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	h := sha256.New()
	h.Write(enrollmentChallengeDomain)
	h.Write([]byte(address))
	h.Write([]byte{0})
	h.Write([]byte(rpID))
	h.Write([]byte{0})
	h.Write(rnd[:])
	return h.Sum(nil), nil
}

// attestationObject is the parsed CBOR attestation object.
type attestationObject struct {
	Format   string
	AuthData []byte
	Stmt     map[string]any // "alg" int64, "sig" []byte, "x5c" [][]byte
	// StmtKeys records the attStmt map's keys in wire order,
	// including unknown keys that were skipped during decode, so
	// format verifiers can enforce a closed statement map.
	StmtKeys []string
}

// parseAttestationObject decodes the CBOR attestation object:
// {"fmt": tstr, "authData": bstr, "attStmt": map}.
func parseAttestationObject(raw []byte) (*attestationObject, error) {
	d := &cborDecoder{buf: raw}
	n, err := d.readMapLen()
	if err != nil {
		return nil, fmt.Errorf("attestation object: %w", err)
	}
	out := &attestationObject{Stmt: map[string]any{}}
	for i := 0; i < n; i++ {
		k, err := d.readTstr()
		if err != nil {
			return nil, fmt.Errorf("attestation object key: %w", err)
		}
		switch k {
		case "fmt":
			s, err := d.readTstr()
			if err != nil {
				return nil, fmt.Errorf("attestation fmt: %w", err)
			}
			out.Format = s
		case "authData":
			b, err := d.readBstr()
			if err != nil {
				return nil, fmt.Errorf("attestation authData: %w", err)
			}
			out.AuthData = b
		case "attStmt":
			m, err := d.readMapLen()
			if err != nil {
				return nil, fmt.Errorf("attestation attStmt: %w", err)
			}
			seen := map[string]bool{}
			for j := 0; j < m; j++ {
				sk, err := d.readTstr()
				if err != nil {
					return nil, fmt.Errorf("attStmt key: %w", err)
				}
				// Duplicate statement keys fail closed: with
				// last-wins map semantics a second "x5c" could
				// silently replace the attested chain.
				if seen[sk] {
					return nil, fmt.Errorf("attestation attStmt: duplicate key %q", sk)
				}
				seen[sk] = true
				out.StmtKeys = append(out.StmtKeys, sk)
				switch sk {
				case "alg":
					v, err := d.readInt()
					if err != nil {
						return nil, fmt.Errorf("attStmt alg: %w", err)
					}
					out.Stmt["alg"] = v
				case "sig":
					b, err := d.readBstr()
					if err != nil {
						return nil, fmt.Errorf("attStmt sig: %w", err)
					}
					out.Stmt["sig"] = b
				case "x5c":
					an, err := d.readArrayLen()
					if err != nil {
						return nil, fmt.Errorf("attStmt x5c: %w", err)
					}
					var chain [][]byte
					for k := 0; k < an; k++ {
						b, err := d.readBstr()
						if err != nil {
							return nil, fmt.Errorf("attStmt x5c[%d]: %w", k, err)
						}
						chain = append(chain, b)
					}
					out.Stmt["x5c"] = chain
				default:
					if err := d.skipValue(); err != nil {
						return nil, fmt.Errorf("attStmt %s: %w", sk, err)
					}
				}
			}
		default:
			if err := d.skipValue(); err != nil {
				return nil, fmt.Errorf("attestation object %s: %w", k, err)
			}
		}
	}
	if d.off != len(d.buf) {
		return nil, fmt.Errorf("attestation object: %d trailing bytes", len(d.buf)-d.off)
	}
	if out.Format == "" {
		return nil, fmt.Errorf("attestation object without fmt")
	}
	if len(out.AuthData) == 0 {
		return nil, fmt.Errorf("attestation object without authData")
	}
	return out, nil
}

// VerifyRegistrationAttestation verifies a WebAuthn registration
// ceremony response. attestationB64 is base64url of the
// PublicKeyCredential JSON from navigator.credentials.create();
// expectedChallenge is the enrollment challenge the agent issued;
// rp configures the relying party, including the attestation trust
// anchors (rp.AttestationRoots) the attestation statement must
// chain to.
//
// On success it returns the new credential. The caller enrolls it
// locally and publishes the signed enrollment statement; the relay
// that ferried the ceremony learns nothing it can reuse.
func VerifyRegistrationAttestation(attestationB64 string, expectedChallenge []byte, rp WebAuthnRP) (*RegistrationResult, error) {
	if rp.ID == "" || len(rp.Origins) == 0 {
		return nil, fmt.Errorf("enrollment: no relying party configured")
	}
	if len(rp.AttestationRoots) == 0 {
		return nil, fmt.Errorf("enrollment: no attestation trust anchors configured (rp.attestation_roots) — refusing to enroll on an unverifiable ceremony")
	}
	rawJSON, err := b64.DecodeString(attestationB64)
	if err != nil {
		return nil, fmt.Errorf("enrollment: attestation: %w", err)
	}
	var cc webauthnCreateCredential
	if err := json.Unmarshal(rawJSON, &cc); err != nil {
		return nil, fmt.Errorf("enrollment: attestation json: %w", err)
	}
	if cc.Type != "" && cc.Type != "public-key" {
		return nil, fmt.Errorf("enrollment: bad credential type %q", cc.Type)
	}
	clientDataJSON, err := b64.DecodeString(cc.Response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("enrollment: clientDataJSON: %w", err)
	}
	attObjRaw, err := b64.DecodeString(cc.Response.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("enrollment: attestationObject: %w", err)
	}

	var cd webauthnClientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return nil, fmt.Errorf("enrollment: clientData json: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("enrollment: clientData type %q (want webauthn.create)", cd.Type)
	}
	ch, err := b64.DecodeString(cd.Challenge)
	if err != nil {
		return nil, fmt.Errorf("enrollment: challenge: %w", err)
	}
	if subtle.ConstantTimeCompare(ch, expectedChallenge) != 1 {
		return nil, fmt.Errorf("enrollment: challenge is not the issued enrollment challenge")
	}
	originOK := false
	for _, o := range rp.Origins {
		if subtle.ConstantTimeCompare([]byte(cd.Origin), []byte(o)) == 1 {
			originOK = true
			break
		}
	}
	if !originOK {
		return nil, fmt.Errorf("enrollment: origin %q not allowed", cd.Origin)
	}

	attObj, err := parseAttestationObject(attObjRaw)
	if err != nil {
		return nil, err
	}
	authData := attObj.AuthData
	if len(authData) < 37 {
		return nil, fmt.Errorf("enrollment: authenticatorData too short")
	}
	rpIDHash := authData[:32]
	wantRPIDHash := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(rpIDHash, wantRPIDHash[:]) != 1 {
		return nil, fmt.Errorf("enrollment: rp id mismatch")
	}
	flags := authData[32]
	if flags&authFlagUserPresent == 0 {
		return nil, fmt.Errorf("enrollment: user-presence flag not set")
	}
	// Enrolled credentials mint session tokens at fido2_uv strength:
	// a credential enrolled without user verification could never
	// complete a mint, so enrollment without UV is rejected now
	// rather than failing mysteriously at mint time.
	if flags&authFlagUserVerified == 0 {
		return nil, fmt.Errorf("enrollment: user-verification flag not set (this credential could never mint a session token)")
	}
	if flags&authFlagAttestedData == 0 {
		return nil, fmt.Errorf("enrollment: attested credential data missing")
	}
	signCount := binary.BigEndian.Uint32(authData[33:37])

	// Attested credential data: AAGUID(16) || credIdLen(2) ||
	// credentialId || credentialPublicKey (COSE_Key).
	acd := authData[37:]
	if len(acd) < 18 {
		return nil, fmt.Errorf("enrollment: attested credential data truncated")
	}
	aaguid := acd[:16]
	credIDLen := int(binary.BigEndian.Uint16(acd[16:18]))
	if credIDLen <= 0 || credIDLen > 1023 || len(acd) < 18+credIDLen {
		return nil, fmt.Errorf("enrollment: bad credential id length %d", credIDLen)
	}
	credID := acd[18 : 18+credIDLen]
	coseRaw := acd[18+credIDLen:]
	// The COSE key is CBOR-length-delimited: find its exact end,
	// slice precisely those bytes, then validate the key shape
	// (parseCOSEKey + credentialKey reject unsupported
	// curves/algorithms and trailing garbage).
	coseEnd := coseKeyEnd(coseRaw)
	if coseEnd <= 0 || coseEnd > len(coseRaw) {
		return nil, fmt.Errorf("enrollment: credential public key: undecodable COSE key")
	}
	coseKey := bytes.Clone(coseRaw[:coseEnd])
	if _, err := parseCOSEKey(coseKey); err != nil {
		return nil, fmt.Errorf("enrollment: credential public key: %w", err)
	}
	if _, err := credentialKey(coseKey); err != nil {
		return nil, fmt.Errorf("enrollment: credential public key: %w", err)
	}

	clientDataHash := sha256.Sum256(clientDataJSON)
	if err := verifyAttestationStatement(attObj, authData, clientDataHash[:], coseKey, rp, time.Now()); err != nil {
		return nil, err
	}

	var aaguidHex string
	if !isZeroAAGUID(aaguid) {
		aaguidHex = fmt.Sprintf("%x", aaguid)
	}
	return &RegistrationResult{
		CredentialID: b64.EncodeToString(credID),
		PublicKey:    coseKey,
		AAGUID:       aaguidHex,
		SignCount:    signCount,
	}, nil
}

// coseKeyEnd finds the end offset of the CBOR-encoded COSE_Key at
// the start of buf by walking its entries.
func coseKeyEnd(buf []byte) int {
	d := &cborDecoder{buf: buf}
	n, err := d.readMapLen()
	if err != nil {
		return 0
	}
	for i := 0; i < n; i++ {
		if _, err := d.readInt(); err != nil {
			return 0
		}
		if err := d.skipValue(); err != nil {
			return 0
		}
	}
	return d.off
}

func isZeroAAGUID(aaguid []byte) bool {
	for _, b := range aaguid {
		if b != 0 {
			return false
		}
	}
	return true
}

// verifyAttestationStatement verifies the attestation statement for
// a registration ceremony. Only formats with a certificate chain to
// a configured trust anchor are accepted: "packed" with x5c,
// "fido-u2f", and "android-key". "none" carries no proof and self
// attestations are signed by the enrolled key itself — both are
// forgeable by anyone holding the ceremony challenge, so both fail
// closed.
func verifyAttestationStatement(attObj *attestationObject, authData, clientDataHash, coseKey []byte, rp WebAuthnRP, now time.Time) error {
	switch attObj.Format {
	case "packed":
		return verifyPackedAttestation(attObj, authData, clientDataHash, rp, now)
	case "fido-u2f":
		return verifyFidoU2FAttestation(attObj, authData, clientDataHash, rp, now)
	case "android-key":
		return verifyAndroidKeyAttestation(attObj, authData, clientDataHash, coseKey, rp, now)
	case "none":
		return fmt.Errorf("enrollment: attestation format %q carries no authenticator proof — refusing (request attestation \"direct\" in the ceremony)", attObj.Format)
	default:
		return fmt.Errorf("enrollment: unsupported attestation format %q", attObj.Format)
	}
}

// attestationRoots builds the trust-anchor pool from the RP config.
func attestationRoots(rp WebAuthnRP) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for i, raw := range rp.AttestationRoots {
		der, err := b64.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("enrollment: attestation root %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("enrollment: attestation root %d: %w", i, err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// verifyAttestationChain checks that the leaf certificate chains to
// a configured trust anchor. Intermediates come from the attestation
// statement itself; the roots are operator-configured and never
// taken from the statement (that would be trusting the prover for
// the trust root).
func verifyAttestationChain(x5c [][]byte, rp WebAuthnRP, now time.Time) (*x509.Certificate, error) {
	if len(x5c) == 0 {
		return nil, fmt.Errorf("enrollment: attestation without certificate chain — refusing (self attestations prove nothing to a verifier)")
	}
	leaf, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return nil, fmt.Errorf("enrollment: attestation leaf certificate: %w", err)
	}
	roots, err := attestationRoots(rp)
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range x5c[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("enrollment: attestation intermediate certificate: %w", err)
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("enrollment: attestation certificate does not chain to a configured trust anchor: %w", err)
	}
	return leaf, nil
}

// aaguidExtensionOID is the FIDO AAGUID extension found in
// authenticator attestation certificates.
var aaguidExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// checkAttestationCertProfile enforces the attestation certificate
// profile (issue #142 review). Chain validation alone accepts any
// certificate chaining to a trust anchor — including CA certificates
// and non-authenticator leaves — so both attestation formats call
// this after the chain check. The profile requires:
//   - X.509 v3,
//   - a non-CA end entity (BasicConstraintsValid && !IsCA),
//   - digitalSignature key usage,
//   - subject OU "Authenticator Attestation",
//   - when the AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4) is
//     present, its value equals the 16-byte AAGUID in authData,
//   - for ES256 (alg -7): a P-256 public key (the existing
//     key-type/curve check).
//
// Anything outside the profile fails closed: a certificate the
// profile rejects proves nothing about the authenticator.
func checkAttestationCertProfile(leaf *x509.Certificate, authData []byte, alg int64) error {
	if leaf.Version != 3 {
		return fmt.Errorf("enrollment: attestation leaf is not X.509 v3 (got v%d)", leaf.Version)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return fmt.Errorf("enrollment: attestation leaf must be a non-CA end-entity certificate")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("enrollment: attestation leaf lacks digitalSignature key usage")
	}
	ouOK := false
	for _, ou := range leaf.Subject.OrganizationalUnit {
		if ou == "Authenticator Attestation" {
			ouOK = true
			break
		}
	}
	if !ouOK {
		return fmt.Errorf("enrollment: attestation leaf subject lacks OU \"Authenticator Attestation\"")
	}
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(aaguidExtensionOID) {
			continue
		}
		// The extension value must be exactly the AAGUID bytes
		// from the authenticator data: rpIdHash[32] ||
		// flags[1] || signCount[4] || aaguid[16]. Without
		// attested credential data there is no AAGUID to compare
		// against — fail closed.
		if len(authData) < 53 || authData[32]&authFlagAttestedData == 0 {
			return fmt.Errorf("enrollment: attestation leaf carries an AAGUID but authenticator data has none")
		}
		if subtle.ConstantTimeCompare(ext.Value, authData[37:53]) != 1 {
			return fmt.Errorf("enrollment: attestation leaf AAGUID does not match authenticator data")
		}
	}
	if alg == -7 { // ES256
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return fmt.Errorf("enrollment: attestation leaf key is not P-256 for ES256")
		}
	}
	return nil
}

// verifyPackedAttestation verifies a "packed" attestation statement:
// the leaf certificate must chain to a trust anchor, and its
// signature over authenticatorData || SHA-256(clientDataJSON) must
// verify. The statement's alg names the signature algorithm;
// ES256 (-7) is what real authenticators use.
func verifyPackedAttestation(attObj *attestationObject, authData, clientDataHash []byte, rp WebAuthnRP, now time.Time) error {
	alg, _ := attObj.Stmt["alg"].(int64)
	sig, _ := attObj.Stmt["sig"].([]byte)
	x5c, _ := attObj.Stmt["x5c"].([][]byte)
	if len(sig) == 0 {
		return fmt.Errorf("enrollment: packed attestation without signature")
	}
	leaf, err := verifyAttestationChain(x5c, rp, now)
	if err != nil {
		return err
	}
	if err := checkAttestationCertProfile(leaf, authData, alg); err != nil {
		return err
	}
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash...)
	switch alg {
	case -7: // ES256
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("enrollment: packed attestation alg ES256 but leaf key is %T", leaf.PublicKey)
		}
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return fmt.Errorf("enrollment: packed attestation signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("enrollment: packed attestation with unsupported alg %d", alg)
	}
}

// verifyFidoU2FAttestation verifies a "fido-u2f" attestation
// statement: the leaf certificate must chain to a trust anchor, and
// its ES256 signature over the U2F registration bytes must verify.
// The signed bytes bind the rpIdHash, the clientDataHash, the new
// credential id, and the credential public key in U2F uncompressed
// form (derived here from the COSE key the authenticator attested).
func verifyFidoU2FAttestation(attObj *attestationObject, authData, clientDataHash []byte, rp WebAuthnRP, now time.Time) error {
	sig, _ := attObj.Stmt["sig"].([]byte)
	x5c, _ := attObj.Stmt["x5c"].([][]byte)
	if len(sig) == 0 {
		return fmt.Errorf("enrollment: fido-u2f attestation without signature")
	}
	leaf, err := verifyAttestationChain(x5c, rp, now)
	if err != nil {
		return err
	}
	// fido-u2f registration signatures are ECDSA P-256/SHA-256
	// (ES256, COSE alg -7). The fido-u2f format only constrains the
	// leaf key: unlike packed, real U2F attestation certificates
	// often carry no basic-constraints extension and no
	// "Authenticator Attestation" OU, so the packed certificate
	// profile must not apply here.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("enrollment: fido-u2f attestation leaf key is not P-256")
	}
	if leaf.IsCA {
		return fmt.Errorf("enrollment: fido-u2f attestation leaf must not be a CA")
	}
	// Rebuild the U2F signed bytes from the attested credential
	// data: 0x00 || rpIdHash || clientDataHash || credentialId ||
	// publicKey (65-byte uncompressed P-256).
	acd := authData[37:]
	if len(acd) < 18 {
		return fmt.Errorf("enrollment: fido-u2f attested data truncated")
	}
	credIDLen := int(binary.BigEndian.Uint16(acd[16:18]))
	if len(acd) < 18+credIDLen {
		return fmt.Errorf("enrollment: fido-u2f credential id truncated")
	}
	credID := acd[18 : 18+credIDLen]
	coseEnd := coseKeyEnd(acd[18+credIDLen:])
	coseKey := acd[18+credIDLen : 18+credIDLen+coseEnd]
	fields, err := parseCOSEKey(coseKey)
	if err != nil {
		return fmt.Errorf("enrollment: fido-u2f cose key: %w", err)
	}
	xb, _ := fields[-2].([]byte)
	yb, _ := fields[-3].([]byte)
	if len(xb) != 32 || len(yb) != 32 {
		return fmt.Errorf("enrollment: fido-u2f credential key is not P-256")
	}
	u2fPub := make([]byte, 0, 65)
	u2fPub = append(u2fPub, 0x04)
	u2fPub = append(u2fPub, xb...)
	u2fPub = append(u2fPub, yb...)
	signed := make([]byte, 0, 1+32+32+len(credID)+65)
	signed = append(signed, 0x00)
	signed = append(signed, authData[:32]...)
	signed = append(signed, clientDataHash...)
	signed = append(signed, credID...)
	signed = append(signed, u2fPub...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("enrollment: fido-u2f attestation signature invalid")
	}
	return nil
}

// Android Key Attestation (WebAuthn §8.4, "android-key").
//
// Android platform authenticators — e.g. a phone used as the
// authenticator over the WebAuthn hybrid (QR-code) transport — can
// return hardware-backed attestations where Apple's can only
// return "none" for synced passkeys: the leaf certificate's public
// key IS the enrolled credential key, and the leaf carries the
// Android KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17)
// binding the ceremony challenge. The chain terminates at Google's
// Hardware Attestation Root CA, which the operator pins in
// rp.AttestationRoots alongside the other vendor roots — trust
// anchors are always operator-configured, never the system pool
// and never anything the statement itself asserts.
//
// Verification, in order:
//  1. the attStmt map is exactly {alg, sig, x5c} (the WebAuthn CDDL
//     defines no other members; unknown fields fail closed),
//  2. alg is ES256 (-7), the only algorithm Android WebAuthn
//     credentials use,
//  3. the x5c chain anchors to a configured trust anchor,
//  4. the leaf matches the Android attestation certificate
//     profile and carries the KeyDescription extension,
//  5. the KeyDescription parses with no trailing DER bytes, its
//     attestationChallenge equals
//     SHA-256(authenticatorData || clientDataHash), and its
//     attestationSecurityLevel is hardware (never Software),
//  6. the AuthorizationList grants purpose SIGN,
//  7. the leaf public key equals the enrolled credential key
//     (P-256 coordinate comparison),
//  8. sig verifies over authenticatorData || clientDataHash with
//     the leaf key.
//
// A note on what the signature proves: in the Android attestation
// model sig is made by the attested key itself, so the signature
// alone proves only possession. The hardware proof is the
// certificate chain to Google's root plus the challenge-bound
// KeyDescription — that is what stops a challenge holder from
// fabricating an enrollment.

// androidKeyDescriptionOID is the Android KeyStore attestation
// extension: the KeyDescription record describing the attested key.
var androidKeyDescriptionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Android KeyStore security levels (KeyDescription
// attestationSecurityLevel / keymasterSecurityLevel).
const (
	androidSecuritySoftware           = 0
	androidSecurityTrustedEnvironment = 1
	androidSecurityStrongBox          = 2
)

// androidKeyPurposeSign is KeyProperties.PURPOSE_SIGN: the key may
// create signatures. A WebAuthn credential key must grant it.
const androidKeyPurposeSign = 2

// androidAuthorizationList is the subset of Android's
// AuthorizationList this verifier needs. The full list carries
// dozens of optional context-tagged fields; only purpose ([1]
// EXPLICIT SET OF INTEGER) is extracted, the rest are ignored.
// (encoding/asn1 tolerates the trailing fields.)
type androidAuthorizationList struct {
	Purpose asn1.RawValue `asn1:"explicit,optional,tag:1"`
}

// androidKeyDescription is the ASN.1 KeyDescription in the
// attestation extension:
//
//	KeyDescription ::= SEQUENCE {
//	    attestationVersion         INTEGER,
//	    attestationSecurityLevel   SecurityLevel,
//	    keymasterVersion           INTEGER,
//	    keymasterSecurityLevel     SecurityLevel,
//	    attestationChallenge       OCTET_STRING,
//	    uniqueId                   OCTET_STRING,
//	    softwareEnforced           AuthorizationList,
//	    teeEnforced                AuthorizationList,
//	}
type androidKeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         androidAuthorizationList
	TEEEnforced              androidAuthorizationList
}

// parseAndroidKeyDescription parses the KeyDescription extension
// value, failing closed on any trailing bytes after the DER —
// trailing junk after a valid record must not be silently
// ignored.
func parseAndroidKeyDescription(ext []byte) (*androidKeyDescription, error) {
	var kd androidKeyDescription
	rest, err := asn1.Unmarshal(ext, &kd)
	if err != nil {
		return nil, fmt.Errorf("enrollment: android-key KeyDescription: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("enrollment: android-key KeyDescription has %d trailing bytes", len(rest))
	}
	return &kd, nil
}

// androidKeyPurposes returns the union of purpose values granted in
// the software-enforced and TEE-enforced authorization lists.
// Purpose is checked in both lists rather than only teeEnforced:
// the property that matters for enrollment is that the key is
// authorized to sign, and real devices vary in which list carries
// it (the live-device retest will confirm placement).
func androidKeyPurposes(lists ...androidAuthorizationList) ([]int, error) {
	var out []int
	for _, l := range lists {
		p := l.Purpose
		if p.Class == 0 && p.Tag == 0 && !p.IsCompound {
			continue // purpose absent from this list
		}
		if p.Class != 2 || p.Tag != 1 || !p.IsCompound {
			return nil, fmt.Errorf("enrollment: android-key purpose field has unexpected tag (class %d tag %d)", p.Class, p.Tag)
		}
		ints, err := parseDERIntegerSet(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("enrollment: android-key purpose set: %w", err)
		}
		out = append(out, ints...)
	}
	return out, nil
}

// parseDERIntegerSet parses a DER SET OF INTEGER (or, leniently, a
// SEQUENCE OF INTEGER — some encoders use it) into its values.
// Values are bounded: purpose tags are small constants, and an
// unbounded bignum here would only ever feed a membership test.
func parseDERIntegerSet(der []byte) ([]int, error) {
	if len(der) < 2 || (der[0] != 0x31 && der[0] != 0x30) {
		return nil, fmt.Errorf("expected SET or SEQUENCE, got tag 0x%02x", der[0]&0xff)
	}
	inner, err := derContent(der)
	if err != nil {
		return nil, err
	}
	var out []int
	for len(inner) > 0 {
		if inner[0] != 0x02 {
			return nil, fmt.Errorf("expected INTEGER, got tag 0x%02x", inner[0])
		}
		vb, err := derContent(inner)
		if err != nil {
			return nil, err
		}
		if len(vb) == 0 || len(vb) > 4 || vb[0]&0x80 != 0 || (len(vb) > 1 && vb[0] == 0x00 && vb[1]&0x80 == 0) {
			return nil, fmt.Errorf("bad INTEGER encoding")
		}
		v := 0
		for _, b := range vb {
			v = v<<8 | int(b)
		}
		// Advance past this INTEGER element: its tag+length
		// header plus the value bytes just consumed.
		hl, _ := derTagLen(inner)
		inner = inner[hl+len(vb):]
		out = append(out, v)
	}
	return out, nil
}

// derTagLen parses a DER tag+length header, returning the total
// header length and the content length.
func derTagLen(b []byte) (headerLen int, contentLen int) {
	if len(b) < 2 {
		return 0, -1
	}
	lb := b[1]
	if lb&0x80 == 0 {
		return 2, int(lb)
	}
	n := int(lb & 0x7f)
	if n == 0 || n > 4 || len(b) < 2+n {
		return 0, -1
	}
	contentLen = 0
	for _, c := range b[2 : 2+n] {
		contentLen = contentLen<<8 | int(c)
	}
	return 2 + n, contentLen
}

// derContent returns the content bytes of one DER TLV at the start
// of b, erroring on truncation or absurd lengths.
func derContent(b []byte) ([]byte, error) {
	hl, cl := derTagLen(b)
	if cl < 0 || hl+cl > len(b) {
		return nil, fmt.Errorf("truncated or overlong DER value")
	}
	return b[hl : hl+cl], nil
}

// checkAndroidAttestationCertProfile enforces the Android
// attestation certificate profile. Unlike the FIDO packed profile,
// Android leaves carry no "Authenticator Attestation" OU (real
// leaves use CN "Android Keystore Key"), so the profile requires:
//   - X.509 v3,
//   - a non-CA end entity,
//   - digitalSignature key usage,
//   - the KeyDescription extension (its contents are verified
//     separately),
//   - for ES256 (alg -7): a P-256 public key.
func checkAndroidAttestationCertProfile(leaf *x509.Certificate, alg int64) error {
	if leaf.Version != 3 {
		return fmt.Errorf("enrollment: android-key leaf is not X.509 v3 (got v%d)", leaf.Version)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return fmt.Errorf("enrollment: android-key leaf must be a non-CA end-entity certificate")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("enrollment: android-key leaf lacks digitalSignature key usage")
	}
	if !hasExtensionOID(leaf, androidKeyDescriptionOID) {
		return fmt.Errorf("enrollment: android-key leaf lacks the KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17)")
	}
	if alg == -7 { // ES256
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return fmt.Errorf("enrollment: android-key leaf key is not P-256 for ES256")
		}
	}
	return nil
}

func hasExtensionOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// androidStmtKeysEqual reports whether the attStmt key set is
// exactly want. Duplicates are already rejected by the decoder, so
// set equality on the wire-order key list is exact.
func androidStmtKeysEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// verifyAndroidKeyAttestation verifies an "android-key" attestation
// statement (WebAuthn §8.4). See the format overview above for the
// check order and the threat model.
func verifyAndroidKeyAttestation(attObj *attestationObject, authData, clientDataHash, coseKey []byte, rp WebAuthnRP, now time.Time) error {
	// The statement map is closed: exactly {alg, sig, x5c}.
	if !androidStmtKeysEqual(attObj.StmtKeys, []string{"alg", "sig", "x5c"}) {
		return fmt.Errorf("enrollment: android-key attestation statement must be exactly {alg, sig, x5c} (got %q)", attObj.StmtKeys)
	}
	alg, _ := attObj.Stmt["alg"].(int64)
	if alg != -7 {
		return fmt.Errorf("enrollment: android-key attestation with unsupported alg %d (want ES256/-7)", alg)
	}
	sig, _ := attObj.Stmt["sig"].([]byte)
	if len(sig) == 0 {
		return fmt.Errorf("enrollment: android-key attestation without signature")
	}
	x5c, _ := attObj.Stmt["x5c"].([][]byte)

	leaf, err := verifyAttestationChain(x5c, rp, now)
	if err != nil {
		return err
	}
	if err := checkAndroidAttestationCertProfile(leaf, alg); err != nil {
		return err
	}

	// The KeyDescription binds this attestation to the ceremony:
	// its attestationChallenge must equal
	// SHA-256(authenticatorData || clientDataHash), so a
	// challenge holder cannot transplant a genuine device's
	// attestation onto their own ceremony.
	var kdDER []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(androidKeyDescriptionOID) {
			kdDER = ext.Value
			break
		}
	}
	kd, err := parseAndroidKeyDescription(kdDER)
	if err != nil {
		return err
	}
	// The security level gates what the attestation is WORTH. A
	// Software level means the Android OS asserted its own
	// key's provenance — a compromised OS can forge exactly
	// that, so it proves nothing to a verifier. VHL enrolls
	// credentials that mint session tokens; only hardware-rooted
	// proof (TrustedEnvironment or StrongBox) clears the bar.
	switch kd.AttestationSecurityLevel {
	case androidSecurityTrustedEnvironment, androidSecurityStrongBox:
	default:
		return fmt.Errorf("enrollment: android-key attestation security level %d is not hardware-backed (need TrustedEnvironment or StrongBox)", kd.AttestationSecurityLevel)
	}
	bound := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	if subtle.ConstantTimeCompare(kd.AttestationChallenge, bound[:]) != 1 {
		return fmt.Errorf("enrollment: android-key attestation challenge does not match this ceremony")
	}
	purposes, err := androidKeyPurposes(kd.SoftwareEnforced, kd.TEEEnforced)
	if err != nil {
		return err
	}
	signOK := false
	for _, p := range purposes {
		if p == androidKeyPurposeSign {
			signOK = true
			break
		}
	}
	if !signOK {
		return fmt.Errorf("enrollment: android-key attested key does not grant purpose SIGN")
	}

	// The attested key must BE the enrolled credential key: the
	// leaf certificate's subject public key and the COSE key in
	// the authenticator data are compared coordinate-wise. Without
	// this, a genuine device's attestation could be replayed to
	// enroll an attacker-chosen key.
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafPub.Curve != elliptic.P256() {
		return fmt.Errorf("enrollment: android-key leaf key is not P-256")
	}
	credPubIface, err := credentialKey(coseKey)
	if err != nil {
		return fmt.Errorf("enrollment: android-key credential public key: %w", err)
	}
	credPub, ok := credPubIface.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("enrollment: android-key credential key is not ECDSA")
	}
	if leafPub.X.Cmp(credPub.X) != 0 || leafPub.Y.Cmp(credPub.Y) != 0 {
		return fmt.Errorf("enrollment: android-key leaf key does not match the enrolled credential key")
	}

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(leafPub, digest[:], sig) {
		return fmt.Errorf("enrollment: android-key attestation signature invalid")
	}
	return nil
}
