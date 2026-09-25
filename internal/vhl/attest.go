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
//     attestationChallenge is identical to clientDataHash
//     (WebAuthn §8.4 — not the SafetyNet-style
//     SHA-256(authData || clientDataHash) nonce), and its
//     attestationSecurityLevel is hardware (never Software),
//  6. the AuthorizationLists satisfy the WebAuthn §8.4 checks:
//     allApplications absent from both lists, and —
//     Courier's policy is hardware-only, so per the spec the
//     teeEnforced list alone governs — origin is
//     KM_ORIGIN_GENERATED and purpose grants KM_PURPOSE_SIGN,
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

// androidKeyOriginGenerated is KeyProperties.ORIGIN_GENERATED: the
// key was generated inside the Android KeyStore, not imported. A
// WebAuthn credential key must be device-generated.
const androidKeyOriginGenerated = 0

// androidAuthList is the parsed subset of Android's
// AuthorizationList this verifier enforces. The full list carries
// dozens of optional context-tagged fields; only purpose ([1]),
// allApplications ([600]) and origin ([702]) are extracted, the
// rest are skipped with strict bounds checks.
type androidAuthList struct {
	purposes        []int
	purposePresent  bool
	allApplications bool
	origin          int
	originPresent   bool
}

// parseAndroidAuthList parses one AuthorizationList SEQUENCE,
// enforcing the WebAuthn §8.4 checks: allApplications must be
// absent, and (for the hardware-only policy, from the teeEnforced
// list) origin must be KM_ORIGIN_GENERATED and purpose must grant
// KM_PURPOSE_SIGN. Unknown fields are skipped with strict bounds
// checks; duplicate fields fail closed.
func parseAndroidAuthList(der []byte) (*androidAuthList, error) {
	if len(der) < 2 || der[0] != 0x30 {
		return nil, fmt.Errorf("enrollment: android-key authorization list is not a SEQUENCE")
	}
	_, _, _, content, total, err := derParseTLV(der)
	if err != nil {
		return nil, fmt.Errorf("enrollment: android-key authorization list: %w", err)
	}
	if total != len(der) {
		return nil, fmt.Errorf("enrollment: android-key authorization list has trailing bytes")
	}
	out := &androidAuthList{}
	seen := map[int]bool{}
	for len(content) > 0 {
		class, constructed, tagNo, value, vtotal, err := derParseTLV(content)
		if err != nil {
			return nil, fmt.Errorf("enrollment: android-key authorization list field: %w", err)
		}
		if class != 2 || !constructed {
			return nil, fmt.Errorf("enrollment: android-key authorization list field is not context-specific constructed")
		}
		if seen[tagNo] {
			return nil, fmt.Errorf("enrollment: android-key authorization list has duplicate field %d", tagNo)
		}
		seen[tagNo] = true
		// Each field is [n] EXPLICIT <value>: the element
		// content is the wrapped value's TLV.
		switch tagNo {
		case 1: // purpose: SET OF INTEGER
			ints, err := derStrictIntegerSet(value)
			if err != nil {
				return nil, fmt.Errorf("enrollment: android-key purpose: %w", err)
			}
			out.purposes = ints
			out.purposePresent = true
		case 600: // allApplications: must be absent
			out.allApplications = true
		case 702: // origin: single INTEGER
			v, err := derStrictInteger(value)
			if err != nil {
				return nil, fmt.Errorf("enrollment: android-key origin: %w", err)
			}
			out.origin = v
			out.originPresent = true
		default:
			// Ignored: the verifier only enforces the
			// WebAuthn §8.4 authorization-list checks.
		}
		content = content[vtotal:]
	}
	return out, nil
}

// derParseTLV parses one DER tag-length-value at the start of b,
// returning the tag class (0=universal, 2=context-specific), the
// constructed bit, the tag number (high-tag-number form decoded),
// the content bytes, and the total TLV length. Lengths must be
// definite and minimal; indefinite or overlong forms fail closed.
// Bounds are checked by subtraction so a forged length cannot
// overflow on any target.
func derParseTLV(b []byte) (class int, constructed bool, tagNo int, value []byte, total int, err error) {
	if len(b) < 2 {
		err = fmt.Errorf("truncated tag")
		return
	}
	class = int(b[0] >> 6)
	constructed = b[0]&0x20 != 0
	tagNo = int(b[0] & 0x1f)
	pos := 1
	if tagNo == 31 {
		// High-tag-number form: base-128, big-endian.
		tagNo = 0
		for {
			if pos >= len(b) {
				err = fmt.Errorf("truncated tag number")
				return
			}
			c := b[pos]
			pos++
			if tagNo > (1<<20)>>7 {
				err = fmt.Errorf("tag number too large")
				return
			}
			tagNo = tagNo<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if pos >= len(b) {
		err = fmt.Errorf("truncated length")
		return
	}
	lb := b[pos]
	pos++
	var contentLen int
	if lb&0x80 == 0 {
		contentLen = int(lb)
	} else {
		n := int(lb & 0x7f)
		if n == 0 || n > 4 || len(b)-pos < n {
			err = fmt.Errorf("bad length encoding")
			return
		}
		if b[pos] == 0x00 {
			err = fmt.Errorf("non-minimal length encoding")
			return
		}
		for _, c := range b[pos : pos+n] {
			contentLen = contentLen<<8 | int(c)
		}
		pos += n
		// Minimal form: the length must not have fit in
		// fewer bytes.
		if contentLen < 128 || (n > 1 && contentLen < 1<<(8*(n-1))) {
			err = fmt.Errorf("non-minimal length encoding")
			return
		}
	}
	if contentLen > len(b)-pos {
		err = fmt.Errorf("length exceeds input")
		return
	}
	value = b[pos : pos+contentLen]
	total = pos + contentLen
	return
}

// derStrictIntegerSet parses exactly one DER SET OF INTEGER,
// requiring the SET tag, minimal length encoding, minimal
// non-negative INTEGER encodings, and no trailing bytes.
func derStrictIntegerSet(der []byte) ([]int, error) {
	class, constructed, tagNo, content, total, err := derParseTLV(der)
	if err != nil {
		return nil, err
	}
	if class != 0 || !constructed || tagNo != 17 {
		return nil, fmt.Errorf("want SET, got class %d tag %d", class, tagNo)
	}
	if total != len(der) {
		return nil, fmt.Errorf("trailing bytes after SET")
	}
	var out []int
	for len(content) > 0 {
		v, vtotal, err := derStrictIntegerTLV(content)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		content = content[vtotal:]
	}
	return out, nil
}

// derStrictInteger parses exactly one DER INTEGER TLV: minimal
// non-negative encoding, values capped well above the small
// constants this verifier compares.
func derStrictInteger(der []byte) (int, error) {
	v, total, err := derStrictIntegerTLV(der)
	if err != nil {
		return 0, err
	}
	if total != len(der) {
		return 0, fmt.Errorf("trailing bytes after INTEGER")
	}
	return v, nil
}

func derStrictIntegerTLV(b []byte) (v, total int, err error) {
	class, constructed, tagNo, value, total, err := derParseTLV(b)
	if err != nil {
		return 0, 0, err
	}
	if class != 0 || constructed || tagNo != 2 {
		return 0, 0, fmt.Errorf("want INTEGER, got class %d tag %d", class, tagNo)
	}
	if len(value) == 0 || len(value) > 4 {
		return 0, 0, fmt.Errorf("bad INTEGER length %d", len(value))
	}
	if value[0]&0x80 != 0 {
		return 0, 0, fmt.Errorf("negative INTEGER")
	}
	if len(value) > 1 && value[0] == 0x00 && value[1]&0x80 == 0 {
		return 0, 0, fmt.Errorf("non-minimal INTEGER encoding")
	}
	for _, c := range value {
		v = v<<8 | int(c)
	}
	return v, total, nil
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
//
// The authorization lists are captured raw: their context-tagged
// fields need a stricter parser than encoding/asn1's (notably
// [1] EXPLICIT SET OF INTEGER for purpose), so they are decoded
// by parseAndroidAuthList.
type androidKeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TEEEnforced              asn1.RawValue
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
	if kd.SoftwareEnforced.Class != 0 || kd.SoftwareEnforced.Tag != 16 || !kd.SoftwareEnforced.IsCompound ||
		kd.TEEEnforced.Class != 0 || kd.TEEEnforced.Tag != 16 || !kd.TEEEnforced.IsCompound {
		return nil, fmt.Errorf("enrollment: android-key authorization lists are not SEQUENCEs")
	}
	return &kd, nil
}

// checkAndroidAttestationCertProfile enforces the Android
// attestation certificate profile. Unlike the FIDO packed profile,
// Android leaves carry no "Authenticator Attestation" OU (real
// leaves use CN "Android Keystore Key") and no Basic Constraints
// extension (Go reports BasicConstraintsValid=false when it is
// absent, so requiring it would reject compliant leaves) — the
// profile requires:
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
	if leaf.IsCA {
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
	// per WebAuthn §8.4 its attestationChallenge is identical to
	// clientDataHash. (The SHA-256(authData || clientDataHash)
	// nonce pattern belongs to SafetyNet, not android-key; the
	// signature below already covers authData || clientDataHash.)
	// Comparing against clientDataHash stops a challenge holder
	// from transplanting a genuine device's attestation onto
	// their own ceremony.
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
	if subtle.ConstantTimeCompare(kd.AttestationChallenge, clientDataHash) != 1 {
		return fmt.Errorf("enrollment: android-key attestation challenge does not match this ceremony")
	}
	// WebAuthn §8.4 authorization-list checks. allApplications
	// must be absent from both lists (the credential is scoped
	// to the RP ID, never usable by any app). Courier's policy
	// is hardware-only, so per the spec the teeEnforced list
	// alone governs the remaining checks: the key must have
	// been generated on-device and must be authorized to sign.
	swEnforced, err := parseAndroidAuthList(kd.SoftwareEnforced.FullBytes)
	if err != nil {
		return err
	}
	teeEnforced, err := parseAndroidAuthList(kd.TEEEnforced.FullBytes)
	if err != nil {
		return err
	}
	if swEnforced.allApplications || teeEnforced.allApplications {
		return fmt.Errorf("enrollment: android-key attested key is not scoped to this RP (allApplications present)")
	}
	if !teeEnforced.originPresent || teeEnforced.origin != androidKeyOriginGenerated {
		return fmt.Errorf("enrollment: android-key attested key was not generated on-device")
	}
	signOK := false
	for _, p := range teeEnforced.purposes {
		if p == androidKeyPurposeSign {
			signOK = true
			break
		}
	}
	if !teeEnforced.purposePresent || !signOK {
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
