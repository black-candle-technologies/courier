package store

import (
	"database/sql"
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
// Publication is per credential, keyed on (address, credential_id)
// (migration v26): each binding carries its own strictly increasing
// epoch and its own revoked flag, so an identity can publish
// several credentials, rotate them, and revoke one without
// touching the others. The relay verifies the publication signature
// and enforces a strictly increasing epoch per binding, exactly
// like the key directory: only the address owner can publish, and a
// captured old publication cannot resurrect a revoked credential.

// VHLEnrollment is one published WebAuthn credential binding.
type VHLEnrollment struct {
	Address       string // ed25519:<base64url> owner identity
	CredentialID  string // base64url WebAuthn credential id
	CredentialPub string // base64url COSE_Key public key
	RPID          string // relying party id the credential is enrolled under
	AAGUID        string // hex authenticator model, "" when unknown
	Epoch         int64  // monotonic per (address, credential_id); strictly increasing updates only
	Revoked       bool   // set by publishing with revoked=1 at a higher epoch
	Sig           string // base64url Ed25519 signature (see envelope.VHLEnrollmentAnnounce)
	PublishedAt   int64
}

// vhlEnrollmentsPerCredential reports whether the vhl_enrollments
// table is in the per-credential (migration v26) shape: a revoked
// column plus a composite primary key on (address, credential_id)
// in that order. Used by the migration's complete/up guards.
func vhlEnrollmentsPerCredential(q querier) (bool, error) {
	has, err := columnExists(q, "vhl_enrollments", "revoked")
	if err != nil || !has {
		return false, err
	}
	rows, err := q.Query(`PRAGMA table_info("vhl_enrollments")`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	pk := map[string]int{}
	for rows.Next() {
		var cid, notnull, pkord int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pkord); err != nil {
			return false, err
		}
		if pkord > 0 {
			pk[name] = pkord
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return len(pk) == 2 && pk["address"] == 1 && pk["credential_id"] == 2, nil
}

// SaveVHLEnrollment inserts or updates one enrollment binding.
// Only a strictly greater epoch for the same (address,
// credential_id) is applied (the stale-epoch pattern from the key
// directory); anything else is a no-op returning applied=false. A
// publication with revoked=1 at a higher epoch revokes that binding
// independently of the identity's other credentials. The caller
// verifies the signature and ownership before calling.
func (s *Store) SaveVHLEnrollment(e *VHLEnrollment) (bool, error) {
	revoked := 0
	if e.Revoked {
		revoked = 1
	}
	res, err := s.db.Exec(
		`INSERT INTO vhl_enrollments (address, credential_id, credential_pub, rp_id, aaguid, epoch, revoked, signature, published_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now'))
		 ON CONFLICT(address, credential_id) DO UPDATE SET credential_pub = excluded.credential_pub,
		 rp_id = excluded.rp_id, aaguid = excluded.aaguid, epoch = excluded.epoch, revoked = excluded.revoked,
		 signature = excluded.signature, published_at = strftime('%s','now')
		 WHERE excluded.epoch > vhl_enrollments.epoch`,
		e.Address, e.CredentialID, e.CredentialPub, e.RPID, e.AAGUID, e.Epoch, revoked, e.Sig,
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

// GetVHLEnrollment returns every published enrollment binding for
// an address — the identity's full credential set, each with its
// revoked flag. Callers filter out revoked bindings themselves;
// the directory never hides a revocation (a revoked row still
// listed is how a consumer learns the credential died). It returns
// sql.ErrNoRows when the owner never published anything.
func (s *Store) GetVHLEnrollment(address string) ([]*VHLEnrollment, error) {
	rows, err := s.db.Query(
		`SELECT address, credential_id, credential_pub, rp_id, aaguid, epoch, revoked, signature, published_at
		 FROM vhl_enrollments WHERE address = ? ORDER BY credential_id`,
		address,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*VHLEnrollment
	for rows.Next() {
		var e VHLEnrollment
		var revoked int
		if err := rows.Scan(&e.Address, &e.CredentialID, &e.CredentialPub, &e.RPID, &e.AAGUID,
			&e.Epoch, &revoked, &e.Sig, &e.PublishedAt); err != nil {
			return nil, err
		}
		e.Revoked = revoked != 0
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, sql.ErrNoRows
	}
	return out, nil
}
