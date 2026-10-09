package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
)

func teamTestConsent(t testing.TB, root TeamRoot, ownerKey, memberKey byte, epoch, handle string, nonce byte) TeamConsent {
	t.Helper()
	owner, _ := teamTestKey(ownerKey)
	member, _ := teamTestKey(memberKey)
	random := make([]byte, 32)
	random[0] = nonce
	binding := TeamConsentBinding{TeamRoot: root, Owner: owner, OwnerEpoch: epoch, InviteID: base64.RawURLEncoding.EncodeToString(random), Nonce: base64.RawURLEncoding.EncodeToString(append([]byte{nonce + 1}, random[1:]...)), Handle: handle, MemberAddress: member, Visibility: TeamPrivate, HistoryDisclosure: TeamHistoryDisclosure, RemovalPolicy: TeamRemovalPolicy, IssuedAt: "2026-10-08T00:00:00Z", ExpiresAt: "2026-10-09T00:00:00Z"}
	i := TeamInvitation{TeamConsentBinding: binding, Schema: TeamInvitationSchema, Suite: "ed25519-x25519-naclbox-v1"}
	i.Signatures = []TeamSignature{teamTestSign(t, i, "owner", ownerKey)}
	h, e := TeamPayloadHash(i, teamTestLimits())
	if e != nil {
		t.Fatal(e)
	}
	a := TeamAcceptance{TeamConsentBinding: binding, Schema: TeamAcceptanceSchema, Suite: i.Suite, InvitationHash: h, AcceptedAt: "2026-10-08T00:00:00Z"}
	a.Signatures = []TeamSignature{teamTestSign(t, a, "member", memberKey)}
	return TeamConsent{i, a}
}
func teamTestNext(t testing.TB, r TeamRoster) TeamRoster {
	t.Helper()
	h, e := TeamPayloadHash(r, teamTestLimits())
	if e != nil {
		t.Fatal(e)
	}
	v, e := teamCounter(r.Version)
	if e != nil {
		t.Fatal(e)
	}
	r.Version = fmt.Sprint(v + 1)
	r.PreviousHash = &h
	r.OwnerTransitionHash = nil
	r.Signatures = nil
	return r
}
func teamTestTransfer(t testing.TB, r TeamRoster, oldKey, newKey byte, prior *string) (TeamRoster, TeamOwnerTransition) {
	t.Helper()
	next := teamTestNext(t, r)
	newOwner, _ := teamTestKey(newKey)
	next.Owner = newOwner
	epoch, _ := teamCounter(r.OwnerEpoch)
	next.OwnerEpoch = fmt.Sprint(epoch + 1)
	c := TeamOwnerTransition{TeamRoot: r.TeamRoot, Schema: TeamTransitionSchema, Suite: r.Suite, PreviousCertificateHash: prior, OldOwner: r.Owner, NewOwner: newOwner, NewOwnerEpoch: next.OwnerEpoch, EffectiveVersion: next.Version, PreviousRosterHash: *next.PreviousHash}
	c.Signatures = []TeamSignature{teamTestSign(t, c, "old_owner", oldKey), teamTestSign(t, c, "new_owner", newKey)}
	h, e := TeamPayloadHash(c, teamTestLimits())
	if e != nil {
		t.Fatal(e)
	}
	next.OwnerTransitionHash = &h
	next.Signatures = []TeamSignature{teamTestSign(t, next, "old_owner", oldKey), teamTestSign(t, next, "new_owner", newKey)}
	return next, c
}

func TestTeamChainLifecycle(t *testing.T) {
	l := teamTestLimits()
	root := teamTestRoot(t)
	consent := teamTestConsent(t, root, 1, 2, "1", "alice", 1)
	r := teamTestRoster(t)
	h, _ := TeamPayloadHash(consent.Acceptance, l)
	r.Members = []TeamMember{{"alice", consent.Acceptance.MemberAddress, h}}
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	chain := []TeamRoster{r}
	consents := []TeamConsent{consent}
	verify := func(rs []TeamRoster, cs []TeamOwnerTransition, ds []TeamConsent, floor *TeamCheckpoint, now time.Time) (TeamChainResult, error) {
		return VerifyTeamChain(root, rs, cs, ds, floor, now, l)
	}
	first, e := verify(chain, nil, consents, nil, teamTestNow())
	if e != nil {
		t.Fatal(e)
	}
	if e = TeamCanSend(first, teamTestNow()); e != nil {
		t.Fatal(e)
	}
	if _, e = verify(chain, nil, consents, &first.Checkpoint, teamTestNow()); e != nil {
		t.Fatal("idempotence", e)
	}
	fork := first.Checkpoint
	fork.Hash = "sha256:" + fmt.Sprintf("%064d", 0)
	if _, e = verify(chain, nil, consents, &fork, teamTestNow()); !errors.Is(e, ErrTeamChain) {
		t.Fatal("fork", e)
	}
	rollback := first.Checkpoint
	rollback.Version = "2"
	if _, e = verify(chain, nil, consents, &rollback, teamTestNow()); !errors.Is(e, ErrTeamChain) {
		t.Fatal("rollback", e)
	}
	next, cert := teamTestTransfer(t, r, 1, 3, nil)
	chain = append(chain, next)
	certs := []TeamOwnerTransition{cert}
	result, e := verify(chain, certs, consents, &first.Checkpoint, teamTestNow())
	if e != nil {
		t.Fatal(e)
	}
	if result.Owner != next.Owner || result.OwnerEpoch != "2" {
		t.Fatal(result)
	}
	// Renew after old snapshots and old consent expire. Historical admission is
	// checked at its signed issuance, not at the current clock.
	renewal := teamTestNext(t, next)
	renewal.IssuedAt = "2026-10-10T00:00:00Z"
	renewal.ExpiresAt = "2026-10-11T00:00:00Z"
	renewal.Signatures = []TeamSignature{teamTestSign(t, renewal, "owner", 3)}
	chain = append(chain, renewal)
	later := teamTestNow().Add(48 * time.Hour)
	result, e = verify(chain, certs, consents, nil, later)
	if e != nil {
		t.Fatal("expired history", e)
	}
	if _, e = verify(chain, certs, consents, nil, later.Add(24*time.Hour)); !errors.Is(e, ErrTeamFreshness) {
		t.Fatal("expired terminal", e)
	}
	tomb := teamTestNext(t, renewal)
	tomb.Status = "deleted"
	tomb.Members = []TeamMember{}
	tomb.Signatures = []TeamSignature{teamTestSign(t, tomb, "owner", 3)}
	chain = append(chain, tomb)
	result, e = verify(chain, certs, consents, nil, later.Add(72*time.Hour))
	if e != nil || !result.Checkpoint.Deleted {
		t.Fatal("expired tombstone", result, e)
	}
	if !errors.Is(TeamCanSend(result, later), ErrTeamDeleted) {
		t.Fatal("tombstone send")
	}
	revived := teamTestNext(t, tomb)
	revived.Status = "active"
	revived.Signatures = []TeamSignature{teamTestSign(t, revived, "owner", 3)}
	if _, e = verify(append(chain, revived), certs, consents, nil, later); !errors.Is(e, ErrTeamDeleted) {
		t.Fatal("revival", e)
	}
}

func TestTeamChainNegative(t *testing.T) {
	l := teamTestLimits()
	r := teamTestRoster(t)
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	next, cert := teamTestTransfer(t, r, 1, 2, nil)
	cases := map[string]func(*TeamRoster, *TeamOwnerTransition){
		"owner epoch":              func(r *TeamRoster, c *TeamOwnerTransition) { r.OwnerEpoch = "3" },
		"version gap":              func(r *TeamRoster, c *TeamOwnerTransition) { r.Version = "3" },
		"certificate version":      func(r *TeamRoster, c *TeamOwnerTransition) { c.EffectiveVersion = "3" },
		"certificate prior roster": func(r *TeamRoster, c *TeamOwnerTransition) { c.PreviousRosterHash = r.GenesisRoot },
		"certificate prior cert":   func(r *TeamRoster, c *TeamOwnerTransition) { h := r.GenesisRoot; c.PreviousCertificateHash = &h },
		"certificate epoch":        func(r *TeamRoster, c *TeamOwnerTransition) { c.NewOwnerEpoch = "3" },
		"certificate root":         func(r *TeamRoster, c *TeamOwnerTransition) { c.TeamID = r.GenesisRoot },
		"wrong chain hash":         func(r *TeamRoster, c *TeamOwnerTransition) { h := r.GenesisRoot; r.PreviousHash = &h },
		"wrong certificate":        func(r *TeamRoster, c *TeamOwnerTransition) { h := r.GenesisRoot; r.OwnerTransitionHash = &h },
		"missing certificate hash": func(r *TeamRoster, c *TeamOwnerTransition) { r.OwnerTransitionHash = nil },
		"wrong signer": func(r *TeamRoster, c *TeamOwnerTransition) {
			r.Signatures = []TeamSignature{teamTestSign(t, *r, "owner", 1)}
		},
		"future": func(r *TeamRoster, c *TeamOwnerTransition) {
			r.IssuedAt = "2026-10-09T00:00:00Z"
			r.ExpiresAt = "2026-10-10T00:00:00Z"
		},
		"backwards time": func(r *TeamRoster, c *TeamOwnerTransition) {
			r.IssuedAt = "2026-10-07T00:00:00Z"
			r.ExpiresAt = "2026-10-08T00:00:00Z"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n, c := next, cert
			mutate(&n, &c)
			if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, n}, []TeamOwnerTransition{c}, nil, nil, teamTestNow(), l); e == nil {
				t.Fatal("accepted invalid chain")
			}
		})
	}
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, next}, nil, nil, nil, teamTestNow(), l); e == nil {
		t.Fatal("missing cert")
	}
	// A second transfer needs the first certificate hash; valid two-hop proof.
	hash, _ := TeamPayloadHash(cert, l)
	third, cert2 := teamTestTransfer(t, next, 2, 3, &hash)
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, next, third}, []TeamOwnerTransition{cert, cert2}, nil, nil, teamTestNow(), l); e != nil {
		t.Fatal(e)
	}
	if _, _, e := VerifyTeamOwnerProof(r.TeamRoot, []TeamOwnerTransition{cert2}, l); e == nil {
		t.Fatal("proof gap")
	}
	if _, _, e := VerifyTeamOwnerProof(r.TeamRoot, []TeamOwnerTransition{cert, cert}, l); e == nil {
		t.Fatal("reused epoch")
	}
	n := teamTestNext(t, r)
	n.Version = "18446744073709551615"
	n.Signatures = []TeamSignature{teamTestSign(t, n, "owner", 1)}
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, n}, nil, nil, nil, teamTestNow(), l); e == nil {
		t.Fatal("overflow gap")
	}
}

func TestTeamConsentBindings(t *testing.T) {
	l := teamTestLimits()
	root := teamTestRoot(t)
	c := teamTestConsent(t, root, 1, 2, "1", "alice", 1)
	if e := VerifyTeamConsent(c.Invitation, c.Acceptance, root, root.GenesisOwner, "1", teamTestNow(), l); e != nil {
		t.Fatal(e)
	}
	mutations := map[string]func(*TeamAcceptance){
		"nonce": func(a *TeamAcceptance) { a.Nonce = a.InviteID }, "invite ID": func(a *TeamAcceptance) { a.InviteID = a.Nonce }, "handle": func(a *TeamAcceptance) { a.Handle = "other" }, "member": func(a *TeamAcceptance) { a.MemberAddress = a.Owner }, "owner": func(a *TeamAcceptance) { a.Owner = a.MemberAddress }, "epoch": func(a *TeamAcceptance) { a.OwnerEpoch = "2" }, "invitation hash": func(a *TeamAcceptance) { a.InvitationHash = a.GenesisRoot }, "expiry": func(a *TeamAcceptance) { a.ExpiresAt = "2026-10-08T23:00:00Z" }, "origin": func(a *TeamAcceptance) { a.RelayOrigin = "https://other.example" }, "team": func(a *TeamAcceptance) { a.TeamID = a.GenesisRoot }, "visibility": func(a *TeamAcceptance) { a.Visibility = "public" }, "history": func(a *TeamAcceptance) { a.HistoryDisclosure = "none" }, "removal": func(a *TeamAcceptance) { a.RemovalPolicy = "independent" }, "accepted expired": func(a *TeamAcceptance) { a.AcceptedAt = a.ExpiresAt },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			a := c.Acceptance
			mutate(&a)
			if e := VerifyTeamConsent(c.Invitation, a, root, root.GenesisOwner, "1", teamTestNow(), l); e == nil {
				t.Fatal("accepted unbound consent")
			}
		})
	}
	if e := VerifyTeamConsent(c.Invitation, c.Acceptance, root, root.GenesisOwner, "2", teamTestNow(), l); e == nil {
		t.Fatal("stale owner")
	}
	expiry, _ := teamTime(c.Invitation.ExpiresAt)
	if e := VerifyTeamConsent(c.Invitation, c.Acceptance, root, root.GenesisOwner, "1", expiry, l); !errors.Is(e, ErrTeamFreshness) {
		t.Fatal(e)
	}
	// Strict parsers for all three other wire shapes.
	if _, e := ParseTeamInvitation(teamTestBytes(t, c.Invitation), l); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseTeamAcceptance(teamTestBytes(t, c.Acceptance), l); e != nil {
		t.Fatal(e)
	}
	r := teamTestRoster(t)
	_, cert := teamTestTransfer(t, r, 1, 2, nil)
	if _, e := ParseTeamOwnerTransition(teamTestBytes(t, cert), l); e != nil {
		t.Fatal(e)
	}
}

func TestTeamReadmissionRequiresNewConsent(t *testing.T) {
	l := teamTestLimits()
	r := teamTestRoster(t)
	c := teamTestConsent(t, r.TeamRoot, 1, 2, "1", "alice", 1)
	h, _ := TeamPayloadHash(c.Acceptance, l)
	member := TeamMember{"alice", c.Acceptance.MemberAddress, h}
	r.Members = []TeamMember{member}
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	removed := teamTestNext(t, r)
	removed.Members = []TeamMember{}
	removed.Signatures = []TeamSignature{teamTestSign(t, removed, "owner", 1)}
	rejoined := teamTestNext(t, removed)
	rejoined.Members = []TeamMember{member}
	rejoined.Signatures = []TeamSignature{teamTestSign(t, rejoined, "owner", 1)}
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, removed, rejoined}, nil, []TeamConsent{c}, nil, teamTestNow(), l); e == nil {
		t.Fatal("reused removed consent")
	}
	fresh := teamTestConsent(t, r.TeamRoot, 1, 2, "1", "alice", 8)
	freshHash, _ := TeamPayloadHash(fresh.Acceptance, l)
	rejoined.Members = []TeamMember{{"alice", fresh.Acceptance.MemberAddress, freshHash}}
	rejoined.Signatures = []TeamSignature{teamTestSign(t, rejoined, "owner", 1)}
	if _, e := VerifyTeamChain(r.TeamRoot, []TeamRoster{r, removed, rejoined}, nil, []TeamConsent{c, fresh}, nil, teamTestNow(), l); e != nil {
		t.Fatal(e)
	}
}
