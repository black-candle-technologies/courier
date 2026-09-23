package store

import (
	"fmt"
)

// ---- VHL enrollment directory (issue #142) ----
//
// A VHL enrollment statement is a signed binding of a Courier
// identity to a WebAuthn credential: the identity owner enrolls
// their authenticator (proving a real ceremony to the enrolling
// agent), signs the binding with the identity key, and publishes it
// here. Other agents use it for *discovery* — the receiver-local
// enrollment registry stays the trust root and no directory entry
// can ever override a local enrollment (directory poisoning then
// buys an attacker nothing).
//
// The relay verifies the publication signature and enforces a
// strictly increasing epoch per address, exactly like the key
// directory: only the address owner can publish, and a captured old
// publication cannot resurrect a revoked credential.

// VHLEnrollment is one published WebAuthn credential binding.
type VHLEnrollment struct {
	Address       string // ed25519:<base64url> owner identity
	CredentialID  string // base64url WebAuthn credential id
	CredentialPub string // base64url COSE_Key public key
	RPID          string // relying party id the credential is enrolled under
	AAGUID        string // hex authenticator model, "" when unknown
	Epoch         int64  // monotonic; strictly increasing updates only
	Sig           string // base64url Ed25519 signature (see envelope.VHLEnrollmentAnnounce)
	PublishedAt   int64
}

// SaveVHLEnrollment inserts or updates an enrollment publication.
// Only a strictly greater epoch is applied (the stale-epoch pattern
// from the key directory); anything else is a no-op returning
// applied=false. The caller verifies the signature and ownership
// before calling.
func (s *Store) SaveVHLEnrollment(e *VHLEnrollment) (bool, error) {
	res, err := s.db.Exec(
		`INSERT INTO vhl_enrollments (address, credential_id, credential_pub, rp_id, aaguid, epoch, signature, published_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%s','now'))
		 ON CONFLICT(address) DO UPDATE SET credential_id = excluded.credential_id, credential_pub = excluded.credential_pub,
		 rp_id = excluded.rp_id, aaguid = excluded.aaguid, epoch = excluded.epoch, signature = excluded.signature,
		 published_at = strftime('%s','now')
		 WHERE excluded.epoch > vhl_enrollments.epoch`,
		e.Address, e.CredentialID, e.CredentialPub, e.RPID, e.AAGUID, e.Epoch, e.Sig,
	)
	if err != nil {
		return false, fmt.Errorf("save vhl enrollment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("save vhl enrollment: %w", err)
	}
	return n > 0, nil // 0 rows: stale epoch, nothing changed
}

// GetVHLEnrollment returns the published enrollment for an address,
// or sql.ErrNoRows if the owner never published one.
func (s *Store) GetVHLEnrollment(address string) (*VHLEnrollment, error) {
	var e VHLEnrollment
	err := s.db.QueryRow(
		`SELECT address, credential_id, credential_pub, rp_id, aaguid, epoch, signature, published_at
		 FROM vhl_enrollments WHERE address = ?`,
		address,
	).Scan(&e.Address, &e.CredentialID, &e.CredentialPub, &e.RPID, &e.AAGUID, &e.Epoch, &e.Sig, &e.PublishedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}
