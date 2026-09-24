package store

import (
	"database/sql"
	"testing"
)

// VHL enrollment directory tests (issue #142): the relay stores the
// signed identity→credential binding with a strictly increasing
// epoch per (address, credential_id) binding (the stale-epoch
// pattern from the key directory). Publication is per credential:
// several credentials per identity, independent revocation.
// Signature verification and ownership are the HTTP layer's job; the
// store enforces monotonicity.

func testVHLEnrollment(addr, credID string, epoch int64) *VHLEnrollment {
	return &VHLEnrollment{
		Address:       addr,
		CredentialID:  credID,
		CredentialPub: "pub-" + credID,
		RPID:          "example.com",
		AAGUID:        "1234",
		Epoch:         epoch,
		Sig:           "sig-" + credID,
	}
}

func testVHLEnrollmentGet(t *testing.T, s *Store, addr, credID string) *VHLEnrollment {
	t.Helper()
	all, err := s.GetVHLEnrollment(addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.CredentialID == credID {
			return e
		}
	}
	t.Fatalf("credential %q not in published set for %s", credID, addr)
	return nil
}

func TestVHLEnrollmentRoundtrip(t *testing.T) {
	s := testStore(t)
	addr := "ed25519:test1"
	if _, err := s.GetVHLEnrollment(addr); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows, got %v", err)
	}
	applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 1000))
	if err != nil || !applied {
		t.Fatalf("save: applied=%v err=%v", applied, err)
	}
	got := testVHLEnrollmentGet(t, s, addr, "cred-a")
	if got.Epoch != 1000 || got.RPID != "example.com" || got.Revoked {
		t.Fatalf("bad roundtrip: %+v", got)
	}
}

func TestVHLEnrollmentStaleEpochNoop(t *testing.T) {
	s := testStore(t)
	addr := "ed25519:test2"
	if _, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 1000)); err != nil {
		t.Fatal(err)
	}
	// Stale epoch: no-op, old value retained.
	applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 999))
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("stale epoch applied")
	}
	got := testVHLEnrollmentGet(t, s, addr, "cred-a")
	if got.Epoch != 1000 {
		t.Fatalf("epoch rewound to %d", got.Epoch)
	}
	// Same epoch: also a no-op (strictly increasing only).
	if applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 1000)); err != nil || applied {
		t.Fatalf("same epoch: applied=%v err=%v", applied, err)
	}
	// Newer epoch replaces the same binding.
	e := testVHLEnrollment(addr, "cred-a", 1001)
	e.CredentialPub = "pub-new"
	applied, err = s.SaveVHLEnrollment(e)
	if err != nil || !applied {
		t.Fatalf("newer epoch: applied=%v err=%v", applied, err)
	}
	got = testVHLEnrollmentGet(t, s, addr, "cred-a")
	if got.CredentialPub != "pub-new" || got.Epoch != 1001 {
		t.Fatalf("replacement not applied: %+v", got)
	}
}

// Two credentials for one identity are published independently:
// the epoch of one binding never gates the other.
func TestVHLEnrollmentTwoCredentialsOneAddress(t *testing.T) {
	s := testStore(t)
	addr := "ed25519:test3"
	if _, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-b", 1000)); err != nil {
		t.Fatal(err)
	}
	all, err := s.GetVHLEnrollment(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 bindings, got %d", len(all))
	}
	// Updating one binding leaves the other untouched.
	e := testVHLEnrollment(addr, "cred-a", 1001)
	e.CredentialPub = "pub-a2"
	if applied, err := s.SaveVHLEnrollment(e); err != nil || !applied {
		t.Fatalf("update cred-a: applied=%v err=%v", applied, err)
	}
	if got := testVHLEnrollmentGet(t, s, addr, "cred-b"); got.Epoch != 1000 {
		t.Fatalf("cred-b changed by cred-a update: %+v", got)
	}
	// A stale epoch for cred-b is still rejected even though
	// cred-a moved on: monotonicity is per binding.
	if applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-b", 999)); err != nil || applied {
		t.Fatalf("stale epoch for cred-b: applied=%v err=%v", applied, err)
	}
}

// Revoking one binding (revoked=1 at a higher epoch) marks only
// that binding; the identity's other credentials stay discoverable.
func TestVHLEnrollmentRevokeOneBinding(t *testing.T) {
	s := testStore(t)
	addr := "ed25519:test4"
	if _, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-b", 1000)); err != nil {
		t.Fatal(err)
	}
	rev := testVHLEnrollment(addr, "cred-a", 1001)
	rev.Revoked = true
	if applied, err := s.SaveVHLEnrollment(rev); err != nil || !applied {
		t.Fatalf("revoke: applied=%v err=%v", applied, err)
	}
	all, err := s.GetVHLEnrollment(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 bindings (revoked rows stay listed), got %d", len(all))
	}
	if got := testVHLEnrollmentGet(t, s, addr, "cred-a"); !got.Revoked {
		t.Fatalf("cred-a not marked revoked: %+v", got)
	}
	if got := testVHLEnrollmentGet(t, s, addr, "cred-b"); got.Revoked {
		t.Fatalf("cred-b wrongly revoked: %+v", got)
	}
	// A stale non-revoked re-publication cannot resurrect it.
	if applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, "cred-a", 1000)); err != nil || applied {
		t.Fatalf("stale un-revoke: applied=%v err=%v", applied, err)
	}
	if got := testVHLEnrollmentGet(t, s, addr, "cred-a"); !got.Revoked {
		t.Fatal("revocation lost to stale epoch")
	}
}
