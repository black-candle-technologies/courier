package store

import (
	"database/sql"
	"testing"
)

// VHL enrollment directory tests (issue #142): the relay stores the
// signed identity→credential binding with a strictly increasing
// epoch per address (the stale-epoch pattern from the key
// directory). Signature verification and ownership are the HTTP
// layer's job; the store enforces monotonicity.

func testVHLEnrollment(addr string, epoch int64) *VHLEnrollment {
	return &VHLEnrollment{
		Address:       addr,
		CredentialID:  "cred-" + addr,
		CredentialPub: "pub-" + addr,
		RPID:          "example.com",
		AAGUID:        "1234",
		Epoch:         epoch,
		Sig:           "sig-" + addr,
	}
}

func TestVHLEnrollmentRoundtrip(t *testing.T) {
	s := testStore(t)
	addr := "ed25519:test1"
	if _, err := s.GetVHLEnrollment(addr); err != sql.ErrNoRows {
		t.Fatalf("want ErrNoRows, got %v", err)
	}
	applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, 1000))
	if err != nil || !applied {
		t.Fatalf("save: applied=%v err=%v", applied, err)
	}
	got, err := s.GetVHLEnrollment(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialID != "cred-"+addr || got.Epoch != 1000 || got.RPID != "example.com" {
		t.Fatalf("bad roundtrip: %+v", got)
	}
}

func TestVHLEnrollmentStaleEpochNoop(t *testing.T) {
	s := testStore(t)
	addr := "ed25519:test2"
	if _, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, 1000)); err != nil {
		t.Fatal(err)
	}
	// Stale epoch: no-op, old value retained.
	applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, 999))
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("stale epoch applied")
	}
	got, err := s.GetVHLEnrollment(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 1000 {
		t.Fatalf("epoch rewound to %d", got.Epoch)
	}
	// Same epoch: also a no-op (strictly increasing only).
	if applied, err := s.SaveVHLEnrollment(testVHLEnrollment(addr, 1000)); err != nil || applied {
		t.Fatalf("same epoch: applied=%v err=%v", applied, err)
	}
	// Newer epoch replaces.
	e := testVHLEnrollment(addr, 1001)
	e.CredentialID = "cred-new"
	applied, err = s.SaveVHLEnrollment(e)
	if err != nil || !applied {
		t.Fatalf("newer epoch: applied=%v err=%v", applied, err)
	}
	got, err = s.GetVHLEnrollment(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialID != "cred-new" || got.Epoch != 1001 {
		t.Fatalf("replacement not applied: %+v", got)
	}
}
