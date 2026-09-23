package envelope

import "encoding/binary"

// VHL ceremony-transport canonical signing layouts (issue #142).
//
// The relay hosts the WebAuthn ceremony transport: the agent creates
// a short-lived ceremony record, the human completes the ceremony in
// their browser, and the agent polls for the result. Every
// agent-authenticated ceremony request is signed by the Ed25519
// identity key over a domain-separated canonical form that binds the
// address, so a signature made for one address can never authorize
// another, and a fresh timestamp, so captured requests cannot be
// replayed past the relay's signed-request age bound.

var vhlCeremonyCreateDomain = []byte("courier-vhl-ceremony-create-v1\x00")
var vhlCeremonyResultDomain = []byte("courier-vhl-ceremony-result-v1\x00")
var vhlEnrollmentAnnounceDomain = []byte("courier-vhl-enrollment-announce-v1\x00")

// VHLCeremonyCreate returns the exact bytes covered by a ceremony
// creation signature: the agent's address, the ceremony type
// ("enroll" or "mint"), the challenge the authenticator must answer
// (already base64url-encoded by the caller), and the unix timestamp.
// The timestamp lets the relay reject replays outside its
// signed-request age bound.
func VHLCeremonyCreate(addressEd25519 []byte, ceremonyType, challenge string, ts int64) []byte {
	out := make([]byte, 0, len(vhlCeremonyCreateDomain)+32+len(ceremonyType)+len(challenge)+8)
	out = append(out, vhlCeremonyCreateDomain...)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (address key)
	out = append(out, ceremonyType...)
	out = append(out, 0x00)
	out = append(out, challenge...)
	out = append(out, 0x00)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// VHLCeremonyResult returns the exact bytes covered by a ceremony
// result-poll signature: the agent's address, the ceremony code,
// and the unix timestamp. Only the address that created the
// ceremony may poll its result.
func VHLCeremonyResult(addressEd25519 []byte, code string, ts int64) []byte {
	out := make([]byte, 0, len(vhlCeremonyResultDomain)+32+len(code)+8)
	out = append(out, vhlCeremonyResultDomain...)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (address key)
	out = append(out, code...)
	out = append(out, 0x00)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	out = append(out, b[:]...)
	return out
}

// VHLEnrollmentAnnounce returns the exact bytes covered by a VHL
// enrollment publication signature: the identity address, the
// WebAuthn credential id, the credential public key (base64url COSE),
// the relying party id, and the monotonic epoch. The epoch must
// strictly increase, so a captured old announcement cannot be
// replayed to resurrect a revoked credential.
func VHLEnrollmentAnnounce(addressEd25519 []byte, credentialID, credentialPub, rpID string, epoch int64) []byte {
	out := make([]byte, 0, len(vhlEnrollmentAnnounceDomain)+32+len(credentialID)+len(credentialPub)+len(rpID)+8)
	out = append(out, vhlEnrollmentAnnounceDomain...)
	out = append(out, addressEd25519...) // 32 bytes Ed25519 (address key)
	out = append(out, credentialID...)
	out = append(out, 0x00)
	out = append(out, credentialPub...)
	out = append(out, 0x00)
	out = append(out, rpID...)
	out = append(out, 0x00)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(epoch))
	out = append(out, b[:]...)
	return out
}
