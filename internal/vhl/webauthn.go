package vhl

// WebAuthn assertion verification (issue #142).
//
// A Tier 2 attestation with a fido2 proof is only as strong as the
// cryptographic check on the assertion: the schema (credential id +
// assertion fields present) proves nothing by itself. This file
// verifies the assertion for real:
//
//   - the clientData challenge is the action hash
//     (what-you-sign-is-what-you-saw),
//   - the origin is one the relying party expects,
//   - the authenticator data names the relying party id and carries
//     the user-presence (and user-verification, when required) flags,
//   - the signature over the assertion verifies under the enrolled
//     credential public key: SHA-256(authenticatorData ||
//     SHA-256(clientDataJSON)) for ES256 (the digest, never the
//     pre-image), the concatenation itself for EdDSA,
//   - the authenticator's signature counter strictly increases per
//     credential (the replay control; see policy.go).
//
// The ceremony that *produces* the assertion (the dashboard driving
// navigator.credentials.get) is a separate follow-up; the schema is
// stable so artifacts stay forward-compatible. Until a relying party
// is configured, fido2 proofs fail closed.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// WebAuthnRP configures the relying party the verifier expects. Both
// fields are required for fido2 proof verification; when empty,
// fido2 proofs fail closed.
type WebAuthnRP struct {
	// ID is the relying party id (e.g. the dashboard's effective
	// domain). The authenticator data must hash to SHA256(ID).
	ID string
	// Origins lists the allowed clientData origins (e.g.
	// "https://dashboard.example.com").
	Origins []string
	// AttestationRoots holds the attestation trust anchors for
	// enrollment ceremonies: base64url-encoded DER certificates
	// (e.g. the authenticator vendor's attestation root CA). The
	// registration attestation statement must chain to one of
	// these; without any configured roots, enrollment fails
	// closed. "none" and self attestations are always rejected:
	// they carry no proof a real authenticator was involved, so
	// anyone holding the ceremony challenge (including a
	// compromised relay, which sees every challenge) could forge
	// them and enroll an attacker key.
	AttestationRoots []string `json:"attestation_roots,omitempty"`
}

// credentialKey parses an enrolled WebAuthn credential public key.
// The enrollment record stores base64url-encoded COSE_Key bytes
// (RFC 8152) as produced by the authenticator at registration.
// Supported: ES256 (ECDSA P-256) and EdDSA (Ed25519).
func credentialKey(raw []byte) (crypto.PublicKey, error) {
	fields, err := parseCOSEKey(raw)
	if err != nil {
		return nil, err
	}
	kty, ok := fields[1].(int64)
	if !ok {
		return nil, fmt.Errorf("cose: missing kty")
	}
	alg, _ := fields[3].(int64)
	switch kty {
	case 2: // EC2
		if alg != -7 {
			return nil, fmt.Errorf("cose: unsupported EC2 alg %d (want ES256/-7)", alg)
		}
		crv, _ := fields[-1].(int64)
		if crv != 1 {
			return nil, fmt.Errorf("cose: unsupported EC2 curve %d (want P-256/1)", crv)
		}
		xb, ok := fields[-2].([]byte)
		yb, ok2 := fields[-3].([]byte)
		if !ok || !ok2 || len(xb) != 32 || len(yb) != 32 {
			return nil, fmt.Errorf("cose: bad P-256 coordinates")
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}, nil
	case 1: // OKP
		if alg != -8 {
			return nil, fmt.Errorf("cose: unsupported OKP alg %d (want EdDSA/-8)", alg)
		}
		crv, _ := fields[-1].(int64)
		if crv != 6 {
			return nil, fmt.Errorf("cose: unsupported OKP curve %d (want Ed25519/6)", crv)
		}
		xb, ok := fields[-2].([]byte)
		if !ok || len(xb) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("cose: bad Ed25519 key")
		}
		return ed25519.PublicKey(bytes.Clone(xb)), nil
	default:
		return nil, fmt.Errorf("cose: unsupported kty %d", kty)
	}
}

// coseField is a decoded COSE map value: int64 or []byte.
type coseField = any

// parseCOSEKey decodes the flat integer-keyed map of a COSE_Key. It
// implements only the CBOR subset COSE keys need: maps, integer keys
// (positive and negative), integer and byte-string values.
func parseCOSEKey(raw []byte) (map[int64]coseField, error) {
	d := &cborDecoder{buf: raw}
	n, err := d.readMapLen()
	if err != nil {
		return nil, fmt.Errorf("cose: %w", err)
	}
	out := make(map[int64]coseField, n)
	for i := 0; i < n; i++ {
		k, err := d.readInt()
		if err != nil {
			return nil, fmt.Errorf("cose key: %w", err)
		}
		v, err := d.readIntOrBytes()
		if err != nil {
			return nil, fmt.Errorf("cose value: %w", err)
		}
		out[k] = v
	}
	if d.off != len(d.buf) {
		return nil, fmt.Errorf("cose: %d trailing bytes", len(d.buf)-d.off)
	}
	return out, nil
}

// cborDecoder is a minimal CBOR reader for COSE_Key maps.
type cborDecoder struct {
	buf []byte
	off int
}

func (d *cborDecoder) readByte() (byte, error) {
	if d.off >= len(d.buf) {
		return 0, fmt.Errorf("truncated")
	}
	b := d.buf[d.off]
	d.off++
	return b, nil
}

func (d *cborDecoder) readUintArg(info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		b, err := d.readByte()
		return uint64(b), err
	case info == 25:
		if d.off+2 > len(d.buf) {
			return 0, fmt.Errorf("truncated")
		}
		v := binary.BigEndian.Uint16(d.buf[d.off:])
		d.off += 2
		return uint64(v), nil
	case info == 26:
		if d.off+4 > len(d.buf) {
			return 0, fmt.Errorf("truncated")
		}
		v := binary.BigEndian.Uint32(d.buf[d.off:])
		d.off += 4
		return uint64(v), nil
	case info == 27:
		if d.off+8 > len(d.buf) {
			return 0, fmt.Errorf("truncated")
		}
		v := binary.BigEndian.Uint64(d.buf[d.off:])
		d.off += 8
		return v, nil
	default:
		return 0, fmt.Errorf("unsupported arg %d", info)
	}
}

// readInt reads a CBOR integer (major types 0 and 1).
func (d *cborDecoder) readInt() (int64, error) {
	b, err := d.readByte()
	if err != nil {
		return 0, err
	}
	major, info := b>>5, b&0x1f
	v, err := d.readUintArg(info)
	if err != nil {
		return 0, err
	}
	switch major {
	case 0:
		if v > 1<<63-1 {
			return 0, fmt.Errorf("integer overflow")
		}
		return int64(v), nil
	case 1:
		if v > 1<<63-1 {
			return 0, fmt.Errorf("integer overflow")
		}
		return -1 - int64(v), nil
	default:
		return 0, fmt.Errorf("want integer, got major %d", major)
	}
}

// readIntOrBytes reads a CBOR integer or byte string.
func (d *cborDecoder) readIntOrBytes() (any, error) {
	b, err := d.readByte()
	if err != nil {
		return nil, err
	}
	major, info := b>>5, b&0x1f
	switch major {
	case 0, 1:
		d.off-- // re-read as integer
		return d.readInt()
	case 2:
		n, err := d.readUintArg(info)
		if err != nil {
			return nil, err
		}
		// Bounds-check against the remaining buffer, not via
		// off+n: a huge n would wrap uint64(off)+n and then go
		// negative through int(n), panicking the slice below.
		if n > uint64(len(d.buf)-d.off) {
			return nil, fmt.Errorf("truncated byte string")
		}
		out := bytes.Clone(d.buf[d.off : d.off+int(n)])
		d.off += int(n)
		return out, nil
	default:
		return nil, fmt.Errorf("want integer or bytes, got major %d", major)
	}
}

func (d *cborDecoder) readMapLen() (int, error) {
	b, err := d.readByte()
	if err != nil {
		return 0, err
	}
	if b>>5 != 5 {
		return 0, fmt.Errorf("want map, got major %d", b>>5)
	}
	n, err := d.readUintArg(b & 0x1f)
	if err != nil {
		return 0, err
	}
	if n > 32 {
		return 0, fmt.Errorf("map too large")
	}
	return int(n), nil
}

// readTstr reads a CBOR text string (major type 3).
func (d *cborDecoder) readTstr() (string, error) {
	b, err := d.readByte()
	if err != nil {
		return "", err
	}
	if b>>5 != 3 {
		return "", fmt.Errorf("want text string, got major %d", b>>5)
	}
	n, err := d.readUintArg(b & 0x1f)
	if err != nil {
		return "", err
	}
	if n > uint64(len(d.buf)-d.off) {
		return "", fmt.Errorf("truncated text string")
	}
	out := string(d.buf[d.off : d.off+int(n)])
	d.off += int(n)
	return out, nil
}

// readBstr reads a CBOR byte string (major type 2) as a standalone value.
func (d *cborDecoder) readBstr() ([]byte, error) {
	b, err := d.readByte()
	if err != nil {
		return nil, err
	}
	if b>>5 != 2 {
		return nil, fmt.Errorf("want byte string, got major %d", b>>5)
	}
	n, err := d.readUintArg(b & 0x1f)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.buf)-d.off) {
		return nil, fmt.Errorf("truncated byte string")
	}
	out := bytes.Clone(d.buf[d.off : d.off+int(n)])
	d.off += int(n)
	return out, nil
}

// readArrayLen reads a CBOR array header (major type 4) and returns
// the element count.
func (d *cborDecoder) readArrayLen() (int, error) {
	b, err := d.readByte()
	if err != nil {
		return 0, err
	}
	if b>>5 != 4 {
		return 0, fmt.Errorf("want array, got major %d", b>>5)
	}
	n, err := d.readUintArg(b & 0x1f)
	if err != nil {
		return 0, err
	}
	if n > 32 {
		return 0, fmt.Errorf("array too large")
	}
	return int(n), nil
}

// skipValue skips one CBOR value of any supported shape: integers,
// byte/text strings, arrays, and maps (recursively).
func (d *cborDecoder) skipValue() error {
	b, err := d.readByte()
	if err != nil {
		return err
	}
	major, info := b>>5, b&0x1f
	switch major {
	case 0, 1:
		_, err := d.readUintArg(info)
		return err
	case 2, 3:
		n, err := d.readUintArg(info)
		if err != nil {
			return err
		}
		if n > uint64(len(d.buf)-d.off) {
			return fmt.Errorf("truncated string")
		}
		d.off += int(n)
		return nil
	case 4:
		n, err := d.readUintArg(info)
		if err != nil {
			return err
		}
		if n > 32 {
			return fmt.Errorf("array too large")
		}
		for i := 0; i < int(n); i++ {
			if err := d.skipValue(); err != nil {
				return err
			}
		}
		return nil
	case 5:
		n, err := d.readUintArg(info)
		if err != nil {
			return err
		}
		if n > 32 {
			return fmt.Errorf("map too large")
		}
		for i := 0; i < int(n); i++ {
			if err := d.skipValue(); err != nil {
				return err
			}
			if err := d.skipValue(); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported major type %d", major)
	}
}

// webauthnAssertion is the JSON the ceremony produces (the
// PublicKeyCredential shape from navigator.credentials.get).
type webauthnAssertion struct {
	Type     string `json:"type"`
	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		Signature         string `json:"signature"`
	} `json:"response"`
}

type webauthnClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

const (
	authFlagUserPresent   = 0x01
	authFlagUserVerified  = 0x04
	authFlagAttestedData  = 0x40
	authFlagExtensionData = 0x80
)

// verifyWebAuthnAssertion cryptographically verifies a WebAuthn
// get-assertion. expectedChallenge is the action hash the human
// reviewed; rp configures the relying party; requireUV demands the
// user-verification flag (FIDO2UV) rather than presence alone.
//
// On success it returns the authenticator's signature counter
// (authData bytes 33..37): the caller enforces strict monotonicity
// per credential as the replay control (see policy.go). ES256 signs
// SHA-256(authData || SHA-256(clientDataJSON)) and Go's ecdsa package
// takes that digest — passing the pre-image would silently verify
// nothing. EdDSA signs the concatenation itself (no pre-hash).
func verifyWebAuthnAssertion(credPub crypto.PublicKey, assertionB64 string, expectedChallenge []byte, rp WebAuthnRP, requireUV bool) (uint32, error) {
	if rp.ID == "" || len(rp.Origins) == 0 {
		return 0, fmt.Errorf("fido2: no relying party configured")
	}
	rawJSON, err := b64.DecodeString(assertionB64)
	if err != nil {
		return 0, fmt.Errorf("fido2: assertion: %w", err)
	}
	var as webauthnAssertion
	if err := json.Unmarshal(rawJSON, &as); err != nil {
		return 0, fmt.Errorf("fido2: assertion json: %w", err)
	}
	if as.Type != "" && as.Type != "public-key" {
		return 0, fmt.Errorf("fido2: bad credential type %q", as.Type)
	}
	authData, err := b64.DecodeString(as.Response.AuthenticatorData)
	if err != nil {
		return 0, fmt.Errorf("fido2: authenticatorData: %w", err)
	}
	clientDataJSON, err := b64.DecodeString(as.Response.ClientDataJSON)
	if err != nil {
		return 0, fmt.Errorf("fido2: clientDataJSON: %w", err)
	}
	sig, err := b64.DecodeString(as.Response.Signature)
	if err != nil {
		return 0, fmt.Errorf("fido2: signature: %w", err)
	}

	var cd webauthnClientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return 0, fmt.Errorf("fido2: clientData json: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return 0, fmt.Errorf("fido2: clientData type %q (want webauthn.get)", cd.Type)
	}
	ch, err := b64.DecodeString(cd.Challenge)
	if err != nil {
		return 0, fmt.Errorf("fido2: challenge: %w", err)
	}
	// Constant-time: the challenge is the action hash — an
	// exact-match value where prefix games must not pass.
	if subtle.ConstantTimeCompare(ch, expectedChallenge) != 1 {
		return 0, fmt.Errorf("fido2: challenge is not the action hash")
	}
	originOK := false
	for _, o := range rp.Origins {
		if subtle.ConstantTimeCompare([]byte(cd.Origin), []byte(o)) == 1 {
			originOK = true
			break
		}
	}
	if !originOK {
		return 0, fmt.Errorf("fido2: origin %q not allowed", cd.Origin)
	}

	if len(authData) < 37 {
		return 0, fmt.Errorf("fido2: authenticatorData too short")
	}
	rpIDHash := authData[:32]
	wantRPIDHash := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(rpIDHash, wantRPIDHash[:]) != 1 {
		return 0, fmt.Errorf("fido2: rp id mismatch")
	}
	flags := authData[32]
	if flags&authFlagUserPresent == 0 {
		return 0, fmt.Errorf("fido2: user-presence flag not set")
	}
	if requireUV && flags&authFlagUserVerified == 0 {
		return 0, fmt.Errorf("fido2: user-verification flag not set")
	}
	signCount := binary.BigEndian.Uint32(authData[33:37])

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+32)
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)

	switch k := credPub.(type) {
	case *ecdsa.PublicKey:
		// WebAuthn ES256 signs the digest, not the pre-image.
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return 0, fmt.Errorf("fido2: signature invalid")
		}
		return signCount, nil
	case ed25519.PublicKey:
		if len(sig) != ed25519.SignatureSize {
			return 0, fmt.Errorf("fido2: bad ed25519 signature length")
		}
		if !ed25519.Verify(k, signed, sig) {
			return 0, fmt.Errorf("fido2: signature invalid")
		}
		return signCount, nil
	default:
		return 0, fmt.Errorf("fido2: unsupported credential key type %T", credPub)
	}
}
