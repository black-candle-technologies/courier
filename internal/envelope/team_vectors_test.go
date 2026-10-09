package envelope

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestTeamGoldenVectors(t *testing.T) {
	data, e := os.ReadFile("testdata/team/golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Root    TeamRoot `json:"root"`
		Vectors []struct {
			Name       string          `json:"name"`
			Wire       json.RawMessage `json:"wire"`
			Canonical  string          `json:"canonical_payload"`
			SigningHex string          `json:"signing_hex"`
			Hash       string          `json:"payload_hash"`
		} `json:"vectors"`
	}
	if e = json.Unmarshal(data, &fixture); e != nil {
		t.Fatal(e)
	}
	var rosters []TeamRoster
	var certs []TeamOwnerTransition
	var consent TeamConsent
	for _, v := range fixture.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var object TeamPayload
			var err error
			switch v.Name {
			case "invitation":
				consent.Invitation, err = ParseTeamInvitation(v.Wire, teamTestLimits())
				object = consent.Invitation
			case "acceptance":
				consent.Acceptance, err = ParseTeamAcceptance(v.Wire, teamTestLimits())
				object = consent.Acceptance
			case "transition":
				var c TeamOwnerTransition
				c, err = ParseTeamOwnerTransition(v.Wire, teamTestLimits())
				object = c
				certs = append(certs, c)
			default:
				var r TeamRoster
				r, err = ParseTeamRoster(v.Wire, teamTestLimits())
				object = r
				rosters = append(rosters, r)
			}
			if err != nil {
				t.Fatal(err)
			}
			b, err := CanonicalTeamPayload(object, teamTestLimits())
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != v.Canonical {
				t.Fatal("canonical mismatch")
			}
			s, err := TeamSigningBytes(object, teamTestLimits())
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(s) != v.SigningHex {
				t.Fatal("signing mismatch")
			}
			h, err := TeamPayloadHash(object, teamTestLimits())
			if err != nil || h != v.Hash {
				t.Fatal("hash mismatch", h, err)
			}
		})
	}
	result, e := VerifyTeamChain(fixture.Root, rosters, certs, []TeamConsent{consent}, nil, teamTestNow().Add(96*time.Hour), teamTestLimits())
	if e != nil || !result.Checkpoint.Deleted {
		t.Fatal(result, e)
	}
	// Verify Go produces the identical synthetic owner signature, independently
	// of the reference script's Node crypto implementation.
	signature := teamTestSign(t, rosters[0], "owner", 1)
	if signature != rosters[0].Signatures[0] {
		t.Fatal("cross-language signature mismatch")
	}
}

func FuzzTeamWire(f *testing.F) {
	r := teamTestRoster(f)
	r.Signatures = []TeamSignature{teamTestSign(f, r, "owner", 1)}
	c := teamTestConsent(f, r.TeamRoot, 1, 2, "1", "alice", 1)
	_, cert := teamTestTransfer(f, r, 1, 3, nil)
	for _, v := range []any{r, c.Invitation, c.Acceptance, cert} {
		f.Add(teamTestBytes(f, v))
	}
	f.Add([]byte(`{"x":null,"x":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l := teamTestLimits()
		if len(b) > l.MaxObjectBytes {
			return
		}
		canonical, e := CanonicalTeamJSON(b, l)
		if e == nil {
			again, e := CanonicalTeamJSON(canonical, l)
			if e != nil || !bytes.Equal(canonical, again) {
				t.Fatal("non-idempotent JCS")
			}
		}
		if r, e := ParseTeamRoster(b, l); e == nil {
			round := teamTestBytes(t, r)
			if _, e := ParseTeamRoster(round, l); e != nil {
				t.Fatal(e)
			}
			_, _ = VerifyTeamChain(r.TeamRoot, []TeamRoster{r}, nil, nil, nil, teamTestNow(), l)
		}
		if v, e := ParseTeamInvitation(b, l); e == nil {
			if _, e := TeamSigningBytes(v, l); e != nil {
				t.Fatal(e)
			}
		}
		if v, e := ParseTeamAcceptance(b, l); e == nil {
			if _, e := TeamPayloadHash(v, l); e != nil {
				t.Fatal(e)
			}
		}
		if v, e := ParseTeamOwnerTransition(b, l); e == nil {
			_, _, _ = VerifyTeamOwnerProof(v.TeamRoot, []TeamOwnerTransition{v}, l)
		}
	})
}

func BenchmarkTeamChain(b *testing.B) {
	for _, count := range []int{1, 64, 256} {
		b.Run(fmtTeamCount(count), func(b *testing.B) {
			l := teamTestLimits()
			r := teamTestRoster(b)
			consents := make([]TeamConsent, 0, count)
			for n := 0; n < count; n++ {
				c := teamTestConsent(b, r.TeamRoot, 1, byte(n), "1", fmtTeamCount(n), byte(n))
				h, e := TeamPayloadHash(c.Acceptance, l)
				if e != nil {
					b.Fatal(e)
				}
				consents = append(consents, c)
				r.Members = append(r.Members, TeamMember{c.Acceptance.Handle, c.Acceptance.MemberAddress, h})
			}
			r.Signatures = []TeamSignature{teamTestSign(b, r, "owner", 1)}
			rosterBytes := len(teamTestBytes(b, r))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r}, nil, consents, nil, teamTestNow(), l); e != nil {
					b.Fatal(e)
				}
			}
			b.ReportMetric(float64(rosterBytes), "roster_bytes")
		})
	}
}
func fmtTeamCount(n int) string {
	const digits = "0123456789"
	return "m" + string([]byte{digits[n/100%10], digits[n/10%10], digits[n%10]})
}

func FuzzTeamChainBinding(f *testing.F) {
	f.Add("2", "2", byte(0))
	f.Add("3", "2", byte(1))
	f.Add("18446744073709551615", "2", byte(2))
	f.Fuzz(func(t *testing.T, version, epoch string, mutation byte) {
		if len(version) > 20 || len(epoch) > 20 {
			return
		}
		r := teamTestRoster(t)
		r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
		next, cert := teamTestTransfer(t, r, 1, 3, nil)
		next.Version = version
		next.OwnerEpoch = epoch
		switch mutation % 4 {
		case 1:
			next.PreviousHash = &r.GenesisRoot
		case 2:
			next.OwnerTransitionHash = &r.GenesisRoot
		case 3:
			next.Owner = r.Owner
		}
		// Re-sign admissible shapes, so the oracle reaches chain checks rather than
		// merely rediscovering invalid signatures on mutated bytes.
		if next.validate(teamTestLimits(), false) != nil {
			return
		}
		if _, e := TeamSigningBytes(next, teamTestLimits()); e != nil {
			return
		}
		next.Signatures = []TeamSignature{teamTestSign(t, next, "old_owner", 1), teamTestSign(t, next, "new_owner", 3)}
		_, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, next}, []TeamOwnerTransition{cert}, nil, nil, teamTestNow(), teamTestLimits())
		shouldPass := version == "2" && epoch == "2" && mutation%4 == 0
		if (e == nil) != shouldPass {
			t.Fatalf("binding accepted=%v expected=%v", e == nil, shouldPass)
		}
	})
}

func BenchmarkTeamHistory(b *testing.B) {
	for _, count := range []int{1, 128, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			l := teamTestLimits()
			r := teamTestRoster(b)
			chain := make([]TeamRoster, 0, count)
			for n := 0; n < count; n++ {
				if n > 0 {
					r = teamTestNext(b, r)
				}
				r.Signatures = []TeamSignature{teamTestSign(b, r, "owner", 1)}
				chain = append(chain, r)
			}
			bytes := 0
			for _, r := range chain {
				bytes += len(teamTestBytes(b, r))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, e := VerifyTeamChain(r.TeamRoot, chain, nil, nil, nil, teamTestNow(), l); e != nil {
					b.Fatal(e)
				}
			}
			b.ReportMetric(float64(bytes), "chain_bytes")
		})
	}
}
