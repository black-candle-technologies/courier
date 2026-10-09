package envelope

import (
	"encoding/json"
	"math"
	"strconv"
	"time"
)

// TeamCheckpoint is a historical lower bound, supplied from independently
// trusted durable state. The verifier returns one only after checking a full
// chain. Persistence, wall-clock rollback defense and CAS belong to C/D.
type TeamCheckpoint struct {
	Root    TeamRoot
	Version string
	Hash    string
	Deleted bool
}
type TeamChainResult struct {
	Checkpoint          TeamCheckpoint
	Owner               string
	OwnerEpoch          string
	LastCertificateHash *string
	ExpiresAt           string
}
type TeamConsent struct {
	Invitation TeamInvitation
	Acceptance TeamAcceptance
}

// VerifyTeamConsent checks exact signed consent binding at the supplied
// admission time. It does not consume an invite, establish current ownership or
// read cancellation state; those are mandatory atomic publication checks in C.
func VerifyTeamConsent(i TeamInvitation, a TeamAcceptance, root TeamRoot, owner, epoch string, at time.Time, l TeamLimits) error {
	if e := i.validate(l, true); e != nil {
		return e
	}
	if e := a.validate(l, true); e != nil {
		return e
	}
	if i.TeamRoot != root || i.Owner != owner || i.OwnerEpoch != epoch || i.TeamConsentBinding != a.TeamConsentBinding {
		return ErrTeamBinding
	}
	hash, e := TeamPayloadHash(i, l)
	if e != nil {
		return e
	}
	if hash != a.InvitationHash {
		return ErrTeamBinding
	}
	if e = verifyTeamSignatures(i, i.Signatures, []TeamSignature{{Role: "owner", Address: i.Owner}}, l); e != nil {
		return e
	}
	if e = verifyTeamSignatures(a, a.Signatures, []TeamSignature{{Role: "member", Address: a.MemberAddress}}, l); e != nil {
		return e
	}
	issued, _ := teamTime(i.IssuedAt)
	expires, _ := teamTime(i.ExpiresAt)
	accepted, _ := teamTime(a.AcceptedAt)
	if at.IsZero() || at.Before(issued) || at.Before(accepted) || !at.Before(expires) {
		return ErrTeamFreshness
	}
	return nil
}

// VerifyTeamOwnerProof verifies a member-free historical ownership proof from
// an independently pinned creation root. It cannot establish latest-owner
// freshness or activate a team. Full roster verification must later bind each
// certificate to its exact effective snapshot and predecessor hash.
func VerifyTeamOwnerProof(root TeamRoot, certs []TeamOwnerTransition, l TeamLimits) (string, string, error) {
	if e := l.Validate(); e != nil {
		return "", "", e
	}
	if e := root.validate(l); e != nil {
		return "", "", e
	}
	if len(certs) > l.MaxChainObjects {
		return "", "", ErrTeamLimit
	}
	owner := root.GenesisOwner
	epoch := uint64(1)
	version := uint64(1)
	var previous *string
	total := 0
	for _, c := range certs {
		if e := teamBudget(c, l, &total); e != nil {
			return "", "", e
		}
		if e := c.validate(l, true); e != nil {
			return "", "", e
		}
		nextEpoch, _ := teamCounter(c.NewOwnerEpoch)
		nextVersion, _ := teamCounter(c.EffectiveVersion)
		if c.TeamRoot != root || c.OldOwner != owner || epoch == math.MaxUint64 || nextEpoch != epoch+1 || nextVersion <= version || !sameTeamHash(c.PreviousCertificateHash, previous) {
			return "", "", ErrTeamChain
		}
		if e := verifyTeamSignatures(c, c.Signatures, []TeamSignature{{Role: "old_owner", Address: c.OldOwner}, {Role: "new_owner", Address: c.NewOwner}}, l); e != nil {
			return "", "", e
		}
		h, e := TeamPayloadHash(c, l)
		if e != nil {
			return "", "", e
		}
		previous = &h
		owner = c.NewOwner
		epoch = nextEpoch
		version = nextVersion
	}
	return owner, strconv.FormatUint(epoch, 10), nil
}

func sameTeamHash(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func teamBudget(v any, l TeamLimits, total *int) error {
	b, e := json.Marshal(v)
	if e != nil {
		return ErrTeamWire
	}
	if len(b) > l.MaxObjectBytes || len(b) > l.MaxChainBytes-*total {
		return ErrTeamLimit
	}
	*total += len(b)
	return nil
}

// VerifyTeamChain verifies a complete genesis-to-terminal chain and all member
// consent records. Historical expiry is permitted; every issued time must be
// monotonic and no later than now. An active terminal head must be unexpired;
// a valid terminal tombstone succeeds (Deleted=true) even after its expiry.
// No output authorizes sending until D persists it under its checkpoint lock.
// All certificates/consents must be used exactly once; unchanged member tuples
// retain consent, while every addition/rebinding/rejoin needs fresh consent.
func VerifyTeamChain(root TeamRoot, rosters []TeamRoster, certs []TeamOwnerTransition, consents []TeamConsent, floor *TeamCheckpoint, now time.Time, l TeamLimits) (TeamChainResult, error) {
	fail := func(e error) (TeamChainResult, error) { return TeamChainResult{}, e }
	if e := l.Validate(); e != nil {
		return fail(e)
	}
	if e := root.validate(l); e != nil {
		return fail(e)
	}
	if now.IsZero() {
		return fail(ErrTeamFreshness)
	}
	if len(rosters) == 0 || len(rosters) > l.MaxChainObjects || len(certs) > l.MaxChainObjects-len(rosters) || len(consents) > (l.MaxChainObjects-len(rosters)-len(certs))/2 {
		return fail(ErrTeamLimit)
	}
	total := 0
	for _, r := range rosters {
		if e := teamBudget(r, l, &total); e != nil {
			return fail(e)
		}
	}
	for _, c := range certs {
		if e := teamBudget(c, l, &total); e != nil {
			return fail(e)
		}
	}
	consentByHash := map[string]TeamConsent{}
	for _, c := range consents {
		if e := teamBudget(c.Invitation, l, &total); e != nil {
			return fail(e)
		}
		if e := teamBudget(c.Acceptance, l, &total); e != nil {
			return fail(e)
		}
		h, e := TeamPayloadHash(c.Acceptance, l)
		if e != nil {
			return fail(e)
		}
		if _, exists := consentByHash[h]; exists {
			return fail(ErrTeamChain)
		}
		consentByHash[h] = c
	}
	// Independently check the complete compact proof before matching snapshots.
	if _, _, e := VerifyTeamOwnerProof(root, certs, l); e != nil {
		return fail(e)
	}
	if floor != nil {
		if floor.Root != root || !teamHashPattern.MatchString(floor.Hash) {
			return fail(ErrTeamBinding)
		}
		v, e := teamCounter(floor.Version)
		if e != nil || v == 0 {
			return fail(ErrTeamChain)
		}
	}
	floorSeen := floor == nil
	owner := root.GenesisOwner
	epoch := "1"
	previousHash := ""
	previousVersion := uint64(0)
	var previousTime time.Time
	var certificateHash *string
	certIndex := 0
	members := map[string]TeamMember{}
	usedConsents := map[string]bool{}
	usedInvites := map[string]bool{}
	var result TeamChainResult
	for index, r := range rosters {
		if e := r.validate(l, true); e != nil {
			return fail(teamError("roster", e))
		}
		if r.TeamRoot != root {
			return fail(ErrTeamBinding)
		}
		version, _ := teamCounter(r.Version)
		issued, _ := teamTime(r.IssuedAt)
		if previousVersion == math.MaxUint64 || version != previousVersion+1 || issued.Before(previousTime) || issued.After(now) {
			return fail(ErrTeamChain)
		}
		if index > 0 && (r.PreviousHash == nil || *r.PreviousHash != previousHash) {
			return fail(ErrTeamChain)
		}
		expected := []TeamSignature{{Role: "owner", Address: owner}}
		if r.Owner != owner {
			if r.Status != "active" || certIndex >= len(certs) {
				return fail(ErrTeamChain)
			}
			c := certs[certIndex]
			oldEpoch, _ := teamCounter(epoch)
			newEpoch, _ := teamCounter(r.OwnerEpoch)
			if oldEpoch == math.MaxUint64 || newEpoch != oldEpoch+1 || c.OldOwner != owner || c.NewOwner != r.Owner || c.NewOwnerEpoch != r.OwnerEpoch || c.EffectiveVersion != r.Version || c.PreviousRosterHash != previousHash || !sameTeamHash(c.PreviousCertificateHash, certificateHash) {
				return fail(ErrTeamChain)
			}
			h, e := TeamPayloadHash(c, l)
			if e != nil {
				return fail(e)
			}
			if r.OwnerTransitionHash == nil || *r.OwnerTransitionHash != h {
				return fail(ErrTeamChain)
			}
			expected = []TeamSignature{{Role: "old_owner", Address: owner}, {Role: "new_owner", Address: r.Owner}}
			certificateHash = &h
			certIndex++
			owner = r.Owner
			epoch = r.OwnerEpoch
		} else if r.OwnerEpoch != epoch || r.OwnerTransitionHash != nil {
			return fail(ErrTeamChain)
		}
		if e := verifyTeamSignatures(r, r.Signatures, expected, l); e != nil {
			return fail(e)
		}
		nextMembers := map[string]TeamMember{}
		for _, m := range r.Members {
			if old, ok := members[m.Address]; !ok || old != m {
				consent, exists := consentByHash[m.ConsentHash]
				if !exists || usedConsents[m.ConsentHash] || usedInvites[consent.Invitation.InviteID] {
					return fail(ErrTeamBinding)
				}
				if consent.Acceptance.Handle != m.Handle || consent.Acceptance.MemberAddress != m.Address {
					return fail(ErrTeamBinding)
				}
				if e := VerifyTeamConsent(consent.Invitation, consent.Acceptance, root, owner, epoch, issued, l); e != nil {
					return fail(e)
				}
				usedConsents[m.ConsentHash] = true
				usedInvites[consent.Invitation.InviteID] = true
			}
			nextMembers[m.Address] = m
		}
		members = nextMembers
		hash, e := TeamPayloadHash(r, l)
		if e != nil {
			return fail(e)
		}
		if floor != nil && r.Version == floor.Version {
			if hash != floor.Hash || (r.Status == "deleted") != floor.Deleted {
				return fail(ErrTeamChain)
			}
			floorSeen = true
		}
		previousHash = hash
		previousVersion = version
		previousTime = issued
		result = TeamChainResult{TeamCheckpoint{root, r.Version, hash, r.Status == "deleted"}, owner, epoch, certificateHash, r.ExpiresAt}
		if r.Status == "deleted" && index != len(rosters)-1 {
			return fail(ErrTeamDeleted)
		}
	}
	if !floorSeen || certIndex != len(certs) || len(usedConsents) != len(consentByHash) {
		return fail(ErrTeamChain)
	}
	if !result.Checkpoint.Deleted {
		expires, _ := teamTime(result.ExpiresAt)
		if !now.Before(expires) {
			return fail(ErrTeamFreshness)
		}
	}
	return result, nil
}

// TeamCanSend makes terminal deletion explicit for callers consuming a checked
// result. It rechecks expiry immediately before submission; it is not a trust
// store or a replacement for fetching/persisting the current verified head.
func TeamCanSend(result TeamChainResult, now time.Time) error {
	if result.Checkpoint.Deleted {
		return ErrTeamDeleted
	}
	expires, e := teamTime(result.ExpiresAt)
	if e != nil {
		return e
	}
	if now.IsZero() || !now.Before(expires) {
		return ErrTeamFreshness
	}
	return nil
}
