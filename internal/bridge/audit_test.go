package bridge

import (
	"sync"
	"testing"
	"time"
)

func TestAuditAppendVerify(t *testing.T) {
	s := testStore(t)
	var ids []int64
	for i := 0; i < 5; i++ {
		id, err := s.AppendAudit(&AuditEntry{
			Ts: time.Now().Unix(), TokenID: "tid", TokenLabel: "tl",
			Recipient: testAddr(byte(i)), BodySHA256: SHA256Hex([]byte{byte(i)}),
			BodySize: 10, Outcome: OutcomeSent, EnvelopeID: int64(100 + i),
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	ok, checked, firstID, err := s.VerifyAudit()
	if err != nil || !ok {
		t.Fatalf("verify: %v ok=%v", err, ok)
	}
	if checked != 5 {
		t.Fatalf("checked %d rows, want 5", checked)
	}
	if firstID != ids[0] {
		t.Fatalf("firstID %d, want %d", firstID, ids[0])
	}
}

func TestAuditTamperDetected(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(&AuditEntry{
			Ts: time.Now().Unix(), TokenID: "tid", TokenLabel: "tl",
			Recipient: testAddr(byte(i)), BodySHA256: "abc", BodySize: 1,
			Outcome: OutcomeSent,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Tamper with a row's outcome without fixing the hash.
	if _, err := s.db.Exec(`UPDATE audit SET outcome='rejected:x' WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	ok, _, _, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tampered chain verified clean")
	}
}

func TestAuditGapDetected(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(&AuditEntry{
			Ts: time.Now().Unix(), TokenID: "tid", TokenLabel: "tl",
			Recipient: testAddr(byte(i)), BodySHA256: "abc", BodySize: 1,
			Outcome: OutcomeSent,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Delete the middle row: the link breaks.
	if _, err := s.db.Exec(`DELETE FROM audit WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	ok, _, _, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("gapped chain verified clean")
	}
}

func TestAuditPrune(t *testing.T) {
	s := testStore(t)
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	for i := 0; i < 3; i++ {
		if _, err := s.AppendAudit(&AuditEntry{
			Ts: old, TokenID: "tid", TokenLabel: "tl",
			Recipient: testAddr(byte(i)), BodySHA256: "abc", BodySize: 1,
			Outcome: OutcomeSent,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AppendAudit(&AuditEntry{
		Ts: time.Now().Unix(), TokenID: "tid", TokenLabel: "tl",
		Recipient: testAddr(9), BodySHA256: "def", BodySize: 1,
		Outcome: OutcomeSent,
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneAudit(time.Now().Add(-DefaultAuditRetention).Unix())
	if err != nil || n != 3 {
		t.Fatalf("prune: %v %d", err, n)
	}
	// The pruned chain still verifies; firstID reports the prune point.
	ok, checked, firstID, err := s.VerifyAudit()
	if err != nil || !ok {
		t.Fatalf("verify after prune: %v ok=%v", err, ok)
	}
	if checked != 1 || firstID != 4 {
		t.Fatalf("checked=%d firstID=%d, want 1/4", checked, firstID)
	}
}

func TestAuditListFilter(t *testing.T) {
	s := testStore(t)
	for _, tc := range []struct{ label, outcome string }{
		{"a", OutcomeSent}, {"b", RejectedOutcome(RejectForbidden)}, {"a", OutcomeSent},
	} {
		if _, err := s.AppendAudit(&AuditEntry{
			Ts: time.Now().Unix(), TokenID: "tid", TokenLabel: tc.label,
			Recipient: testAddr(1), BodySHA256: "abc", BodySize: 1,
			Outcome: tc.outcome,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListAudit(AuditFilter{TokenLabel: "a"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("filter by label: %v %d", err, len(rows))
	}
	rows, err = s.ListAudit(AuditFilter{Outcome: RejectedOutcome(RejectForbidden)})
	if err != nil || len(rows) != 1 {
		t.Fatalf("filter by outcome: %v %d", err, len(rows))
	}
	rows, err = s.ListAudit(AuditFilter{Limit: 2})
	if err != nil || len(rows) != 2 {
		t.Fatalf("limit: %v %d", err, len(rows))
	}
	// Newest first.
	if rows[0].ID < rows[1].ID {
		t.Fatal("not newest-first")
	}
}

// TestAuditConcurrentAppends (F2): concurrent appends must not fork
// the hash chain. Without serialization, two ingests can read the same
// chain head and insert rows with the same prev_hash.
func TestAuditConcurrentAppends(t *testing.T) {
	s := testStore(t)
	const goroutines = 16
	const perG = 25
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perG)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				_, err := s.AppendAudit(&AuditEntry{
					Ts: int64(g*perG + i), TokenID: "t", TokenLabel: "l",
					Recipient: testAddr(1), BodySHA256: "s", BodySize: 1,
					Outcome: OutcomeSent,
				})
				if err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	ok, checked, _, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("audit chain forked under concurrent appends")
	}
	if checked != goroutines*perG {
		t.Fatalf("checked = %d, want %d", checked, goroutines*perG)
	}
}
