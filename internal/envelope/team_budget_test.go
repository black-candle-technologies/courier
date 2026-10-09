package envelope

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestTeamTypedSizeBoundaries(t *testing.T) {
	r := teamTestRoster(t)
	c := teamTestConsent(t, r.TeamRoot, 1, 2, "1", "alice", 1)
	_, tr := teamTestTransfer(t, r, 1, 3, nil)
	// Escapes exercise exact encoding/json accounting, even on semantically
	// invalid strings. Payload validation remains a separate, subsequent gate.
	r.Slug = `a<>&"\`
	h := r.GenesisRoot
	r.PreviousHash = &h
	values := []any{r, &r, c.Invitation, &c.Invitation, c.Acceptance, &c.Acceptance, tr, &tr}
	for _, v := range values {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		l := teamTestLimits()
		l.MaxObjectBytes = len(raw)
		l.MaxChainBytes = len(raw)
		n, err := teamEncodedSize(v, l, len(raw))
		if err != nil || n != len(raw) {
			t.Fatalf("%T size %d/%d: %v", v, n, len(raw), err)
		}
		if _, err = teamEncodedSize(v, l, len(raw)-1); !errors.Is(err, ErrTeamLimit) {
			t.Fatalf("%T remaining: %v", v, err)
		}
		l.MaxObjectBytes--
		if _, err = teamEncodedSize(v, l, len(raw)); !errors.Is(err, ErrTeamLimit) {
			t.Fatalf("%T object: %v", v, err)
		}
	}
	r.Slug = "crew"
	r.PreviousHash = nil
	raw, _ := json.Marshal(r)
	l := teamTestLimits()
	l.MaxObjectBytes = len(raw)
	l.MaxChainBytes = len(raw)
	if _, err := CanonicalTeamPayload(r, l); err != nil {
		t.Fatal(err)
	}
	l.MaxObjectBytes--
	if _, err := CanonicalTeamPayload(r, l); !errors.Is(err, ErrTeamLimit) {
		t.Fatal(err)
	}
	for _, v := range []any{nil, (*TeamRoster)(nil), struct{}{}, map[string]string{}} {
		if _, err := teamEncodedSize(v, teamTestLimits(), 10000); !errors.Is(err, ErrTeamWire) {
			t.Fatalf("%T: %v", v, err)
		}
	}
}

func TestTeamVerifierTypedBudgets(t *testing.T) {
	l := teamTestLimits()
	r := teamTestRoster(t)
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	c := teamTestConsent(t, r.TeamRoot, 1, 2, "1", "alice", 1)
	_, tr := teamTestTransfer(t, r, 1, 3, nil)
	huge := strings.Repeat("x", 1<<20) // Bounded fixture, allocated before verifier.
	badR := r
	badR.Signatures = []TeamSignature{{Sig: huge}}
	badI := c.Invitation
	badI.Signatures = []TeamSignature{{Sig: huge}}
	badA := c.Acceptance
	badA.MemberAddress = huge
	badT := tr
	badT.PreviousCertificateHash = &huge
	cases := map[string]func() error{
		"chain roster": func() error {
			_, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{badR}, nil, nil, nil, teamTestNow(), l)
			return e
		},
		"chain certificate": func() error {
			_, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r}, []TeamOwnerTransition{badT}, nil, nil, teamTestNow(), l)
			return e
		},
		"chain invitation": func() error {
			_, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r}, nil, []TeamConsent{{badI, c.Acceptance}}, nil, teamTestNow(), l)
			return e
		},
		"chain acceptance": func() error {
			_, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r}, nil, []TeamConsent{{c.Invitation, badA}}, nil, teamTestNow(), l)
			return e
		},
		"owner proof":        func() error { _, _, e := VerifyTeamOwnerProof(r.TeamRoot, []TeamOwnerTransition{badT}, l); return e },
		"consent invitation": func() error { return VerifyTeamConsent(badI, c.Acceptance, r.TeamRoot, r.Owner, "1", teamTestNow(), l) },
		"consent acceptance": func() error { return VerifyTeamConsent(c.Invitation, badA, r.TeamRoot, r.Owner, "1", teamTestNow(), l) },
		"payload":            func() error { _, e := CanonicalTeamPayload(badR, l); return e },
		"hash":               func() error { _, e := TeamPayloadHash(&badR, l); return e },
		"signing bytes":      func() error { _, e := TeamSigningBytes(badR, l); return e },
		"sign": func() error {
			_, e := MakeTeamSignature(badR, "owner", r.Owner, func([]byte) ([]byte, error) { t.Fatal("sign callback invoked"); return nil, nil }, l)
			return e
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if e := f(); !errors.Is(e, ErrTeamLimit) {
				t.Fatal(e)
			}
		})
	}
	for _, mutate := range []func(*TeamRoster){
		func(x *TeamRoster) { x.Members = make([]TeamMember, l.MaxMembers+1) },
		func(x *TeamRoster) { x.Signatures = make([]TeamSignature, l.MaxArrayItems+1) },
		func(x *TeamRoster) { x.Members = []TeamMember{{Handle: huge}} },
		func(x *TeamRoster) { x.GenesisNonce = huge },
	} {
		x := r
		mutate(&x)
		if _, e := CanonicalTeamPayload(x, l); !errors.Is(e, ErrTeamLimit) {
			t.Fatal(e)
		}
	}
	badTime := TeamChainResult{ExpiresAt: huge}
	if e := TeamCanSend(badTime, teamTestNow()); !errors.Is(e, ErrTeamWire) {
		t.Fatal(e)
	}
	if _, e := NewTeamRoot(r.RelayOrigin, huge, r.GenesisNonce, l); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
	if teamAddress(huge) || teamB64(huge, 32) {
		t.Fatal("oversized encoding accepted")
	}
	// Safe reproduction of the old marshal-before-limit path, using only 1 MiB.
	legacy := testing.Benchmark(func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			raw, e := json.Marshal(badR)
			if e != nil || len(raw) <= l.MaxObjectBytes {
				b.Fatal("fixture", e)
			}
		}
	})
	t.Logf("old marshal-first 1 MiB fixture: %d bytes/op", legacy.AllocedBytesPerOp())
	// No serialization-sized allocation on rejection. Benchmark's fixture and
	// closures are outside measurement; this threshold is far below 1 MiB.
	result := testing.Benchmark(func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			if e := cases["chain roster"](); !errors.Is(e, ErrTeamLimit) {
				b.Fatal(e)
			}
		}
	})
	t.Logf("1 MiB rejected typed signature: %d bytes/op, %d allocs/op", result.AllocedBytesPerOp(), result.AllocsPerOp())
	if result.AllocedBytesPerOp() > 32<<10 {
		t.Fatalf("unbounded rejection allocation: %d", result.AllocedBytesPerOp())
	}
}

func TestTeamCumulativeTypedBudgets(t *testing.T) {
	r := teamTestRoster(t)
	c := teamTestConsent(t, r.TeamRoot, 1, 2, "1", "alice", 1)
	_, tr := teamTestTransfer(t, r, 1, 3, nil)
	l := teamTestLimits()
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	next := teamTestNext(t, r)
	next.Signatures = []TeamSignature{teamTestSign(t, next, "owner", 1)}
	rawR, _ := json.Marshal(r)
	rawNext, _ := json.Marshal(next)
	l.MaxObjectBytes = max(len(rawR), len(rawNext))
	l.MaxChainBytes = len(rawR) + len(rawNext)
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, next}, nil, nil, nil, teamTestNow(), l); e != nil {
		t.Fatal(e)
	}
	l.MaxChainBytes--
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, next}, nil, nil, nil, teamTestNow(), l); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
	l = teamTestLimits()
	a, _ := json.Marshal(c.Invitation)
	b, _ := json.Marshal(c.Acceptance)
	l.MaxObjectBytes = max(len(a), len(b))
	l.MaxChainBytes = len(a) + len(b)
	if e := VerifyTeamConsent(c.Invitation, c.Acceptance, r.TeamRoot, r.Owner, "1", teamTestNow(), l); e != nil {
		t.Fatal(e)
	}
	l.MaxChainBytes--
	if e := VerifyTeamConsent(c.Invitation, c.Acceptance, r.TeamRoot, r.Owner, "1", teamTestNow(), l); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
	l = teamTestLimits()
	l.MaxChainObjects = 1
	if e := VerifyTeamConsent(c.Invitation, c.Acceptance, r.TeamRoot, r.Owner, "1", teamTestNow(), l); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
	l = teamTestLimits()
	raw, _ := json.Marshal(tr)
	l.MaxObjectBytes = len(raw)
	l.MaxChainBytes = len(raw)
	if _, _, e := VerifyTeamOwnerProof(r.TeamRoot, []TeamOwnerTransition{tr}, l); e != nil {
		t.Fatal(e)
	}
	if _, _, e := VerifyTeamOwnerProof(r.TeamRoot, []TeamOwnerTransition{tr, tr}, l); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
	l = teamTestLimits()
	l.MaxChainBytes = math.MaxInt
	for _, total := range []int{-1, math.MaxInt, math.MaxInt - 1} {
		before := total
		if e := teamBudget(r, l, &total); !errors.Is(e, ErrTeamLimit) || total != before {
			t.Fatalf("overflow/atomicity: %d -> %d: %v", before, total, e)
		}
	}
	budget := teamSizeBudget{remaining: math.MaxInt, limits: l}
	if e := budget.add(math.MaxInt); e != nil {
		t.Fatal(e)
	}
	if e := budget.add(1); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
}

func FuzzTeamTypedBudget(f *testing.F) {
	for _, s := range []string{"", `<>&"\`, "hello", "\x00", "é"} {
		f.Add(s, uint16(2048))
	}
	f.Fuzz(func(t *testing.T, s string, cap uint16) {
		if len(s) > 4096 {
			t.Skip()
		}
		r := TeamRoster{Slug: s, Members: []TeamMember{{Handle: s}}, Signatures: []TeamSignature{{Sig: s}}, PreviousHash: &s}
		l := teamTestLimits()
		l.MaxObjectBytes = int(cap) + 512
		l.MaxStringBytes = 512
		raw, _ := json.Marshal(r)
		n, e := teamEncodedSize(r, l, l.MaxObjectBytes)
		if e == nil && (n != len(raw) || n > l.MaxObjectBytes) {
			t.Fatalf("size %d actual %d cap %d", n, len(raw), l.MaxObjectBytes)
		}
		if e != nil && !errors.Is(e, ErrTeamLimit) && !errors.Is(e, ErrTeamWire) {
			t.Fatal(e)
		}
		_, e = CanonicalTeamPayload(r, l)
		if e == nil {
			t.Fatal("malformed payload accepted")
		}
	})
}
