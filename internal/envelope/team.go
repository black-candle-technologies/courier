package envelope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	couriercrypto "github.com/black-candle-technologies/courier/internal/crypto"
)

const (
	TeamRosterSchema      = "courier.team.roster.v1"
	TeamInvitationSchema  = "courier.team.invitation.v1"
	TeamAcceptanceSchema  = "courier.team.acceptance.v1"
	TeamTransitionSchema  = "courier.team.owner-transition.v1"
	TeamPrivate           = "private"
	TeamHistoryDisclosure = "current_and_future_members"
	TeamRemovalPolicy     = "owner_dependent_with_local_blocking"
)

var (
	ErrTeamWire      = errors.New("invalid team wire data")
	ErrTeamLimit     = errors.New("team resource limit")
	ErrTeamSignature = errors.New("invalid team signature")
	ErrTeamBinding   = errors.New("team binding mismatch")
	ErrTeamChain     = errors.New("invalid team chain")
	ErrTeamFreshness = errors.New("team freshness failure")
	ErrTeamDeleted   = errors.New("team is deleted")
)

// TeamRoot is public identity material, not evidence of trust. GenesisRoot is
// the hash of a member-free creation commitment, avoiding circular consent.
// The caller must independently pin this tuple before validation can authorize
// anything. Packet B never creates keys, pins, stores or network requests.
type TeamRoot struct {
	RelayOrigin  string `json:"relay_origin"`
	TeamID       string `json:"team_id"`
	GenesisOwner string `json:"genesis_owner"`
	GenesisNonce string `json:"genesis_nonce"`
	GenesisRoot  string `json:"genesis_root"`
}

type TeamSignature struct {
	Role    string `json:"role"`
	Address string `json:"address"`
	Sig     string `json:"sig"`
}
type TeamMember struct {
	Handle      string `json:"handle"`
	Address     string `json:"address"`
	ConsentHash string `json:"consent_hash"`
}

// TeamRoster also represents a tombstone: status=deleted and members=[]. A
// tombstone uses the roster signing domain and cannot have successors.
type TeamRoster struct {
	TeamRoot
	Schema              string          `json:"schema"`
	Suite               string          `json:"suite"`
	Slug                string          `json:"slug"`
	Version             string          `json:"version"`
	PreviousHash        *string         `json:"previous_hash"`
	Owner               string          `json:"owner"`
	OwnerEpoch          string          `json:"owner_epoch"`
	OwnerTransitionHash *string         `json:"owner_transition_hash"`
	IssuedAt            string          `json:"issued_at"`
	ExpiresAt           string          `json:"expires_at"`
	Status              string          `json:"status"`
	Visibility          string          `json:"visibility"`
	HistoryDisclosure   string          `json:"history_disclosure"`
	RemovalPolicy       string          `json:"removal_policy"`
	Members             []TeamMember    `json:"members"`
	Signatures          []TeamSignature `json:"signatures"`
}

type TeamConsentBinding struct {
	TeamRoot
	Owner             string `json:"owner"`
	OwnerEpoch        string `json:"owner_epoch"`
	InviteID          string `json:"invite_id"`
	Nonce             string `json:"nonce"`
	Handle            string `json:"handle"`
	MemberAddress     string `json:"member_address"`
	Visibility        string `json:"visibility"`
	HistoryDisclosure string `json:"history_disclosure"`
	RemovalPolicy     string `json:"removal_policy"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
}

type TeamInvitation struct {
	TeamConsentBinding
	Schema     string          `json:"schema"`
	Suite      string          `json:"suite"`
	Signatures []TeamSignature `json:"signatures"`
}

type TeamAcceptance struct {
	TeamConsentBinding
	Schema         string          `json:"schema"`
	Suite          string          `json:"suite"`
	InvitationHash string          `json:"invitation_hash"`
	AcceptedAt     string          `json:"accepted_at"`
	Signatures     []TeamSignature `json:"signatures"`
}

type TeamOwnerTransition struct {
	TeamRoot
	Schema                  string          `json:"schema"`
	Suite                   string          `json:"suite"`
	PreviousCertificateHash *string         `json:"previous_certificate_hash"`
	OldOwner                string          `json:"old_owner"`
	NewOwner                string          `json:"new_owner"`
	NewOwnerEpoch           string          `json:"new_owner_epoch"`
	EffectiveVersion        string          `json:"effective_version"`
	PreviousRosterHash      string          `json:"previous_roster_hash"`
	Signatures              []TeamSignature `json:"signatures"`
}

var teamName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
var teamHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var teamDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

func teamCounter(s string) (uint64, error) {
	if !teamDecimal.MatchString(s) {
		return 0, ErrTeamWire
	}
	v, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return 0, ErrTeamWire
	}
	return v, nil
}
func teamB64(s string, n int) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == n && base64.RawURLEncoding.EncodeToString(b) == s
}
func teamAddress(s string) bool {
	p, e := couriercrypto.ParseAddressSuite(s)
	return e == nil && p.Suite == couriercrypto.SuiteV1 && couriercrypto.FormatAddress(p.PublicKey) == s
}
func teamHash(b []byte) string        { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func teamOptionalHash(s *string) bool { return s == nil || teamHashPattern.MatchString(*s) }

// teamOrigin accepts only already normalized ASCII HTTPS origins. It does not
// import client (which depends on envelope) or mutate Packet A normalization.
func teamOrigin(s string) bool {
	if len(s) > 253+16 {
		return false
	}
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	host := u.Hostname()
	if host != strings.ToLower(host) || strings.ContainsAny(host, "%\\") {
		return false
	}
	if ip := net.ParseIP(host); ip == nil {
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
	} else if strings.Contains(host, ":") && ip.String() != host {
		return false
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 || n == 443 || strconv.FormatUint(n, 10) != port {
			return false
		}
	}
	canonicalHost := host
	if strings.Contains(host, ":") {
		canonicalHost = "[" + host + "]"
	}
	if port != "" {
		canonicalHost = net.JoinHostPort(host, port)
	}
	return s == "https://"+canonicalHost
}

// NewTeamRoot derives public identifiers from caller-supplied creation entropy.
// No randomness or key generation is performed here.
func NewTeamRoot(origin, owner, nonce string, l TeamLimits) (TeamRoot, error) {
	if !teamOrigin(origin) || !teamAddress(owner) || !teamB64(nonce, 32) {
		return TeamRoot{}, ErrTeamWire
	}
	b, e := json.Marshal(map[string]string{"relay_origin": origin, "genesis_owner": owner, "genesis_nonce": nonce})
	if e != nil {
		return TeamRoot{}, e
	}
	b, e = CanonicalTeamJSON(b, l)
	if e != nil {
		return TeamRoot{}, e
	}
	return TeamRoot{origin, teamHash(append([]byte("courier.team.id.v1\x00"), b...)), owner, nonce, teamHash(append([]byte("courier.team.genesis.v1\x00"), b...))}, nil
}
func (r TeamRoot) validate(l TeamLimits) error {
	want, e := NewTeamRoot(r.RelayOrigin, r.GenesisOwner, r.GenesisNonce, l)
	if e != nil {
		return e
	}
	if want != r {
		return ErrTeamBinding
	}
	return nil
}
func teamTime(s string) (time.Time, error) {
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	if e != nil || t.Year() < 1 || t.Format("2006-01-02T15:04:05Z") != s {
		return time.Time{}, ErrTeamWire
	}
	return t, nil
}
func teamWindow(issued, expires string, maxSeconds int64) error {
	a, e := teamTime(issued)
	if e != nil {
		return e
	}
	b, e := teamTime(expires)
	if e != nil {
		return e
	}
	if !b.After(a) || b.Sub(a) > time.Duration(maxSeconds)*time.Second {
		return ErrTeamFreshness
	}
	return nil
}
func teamPolicy(v, h, r string) bool {
	return v == TeamPrivate && h == TeamHistoryDisclosure && r == TeamRemovalPolicy
}
func teamSignatureShape(s []TeamSignature) error {
	if len(s) < 1 || len(s) > 2 {
		return ErrTeamSignature
	}
	for _, v := range s {
		if !teamAddress(v.Address) || !teamB64(v.Sig, 64) || (v.Role != "owner" && v.Role != "old_owner" && v.Role != "new_owner" && v.Role != "member") {
			return ErrTeamSignature
		}
	}
	return nil
}

func (r TeamRoster) validate(l TeamLimits, signatures bool) error {
	if e := l.Validate(); e != nil {
		return e
	}
	if e := r.TeamRoot.validate(l); e != nil {
		return e
	}
	v, e := teamCounter(r.Version)
	if e != nil || v == 0 {
		return ErrTeamWire
	}
	epoch, e := teamCounter(r.OwnerEpoch)
	if e != nil || epoch == 0 {
		return ErrTeamWire
	}
	if r.Schema != TeamRosterSchema || r.Suite != string(couriercrypto.SuiteV1) || !teamName.MatchString(r.Slug) || !teamAddress(r.Owner) || !teamOptionalHash(r.PreviousHash) || !teamOptionalHash(r.OwnerTransitionHash) || !teamPolicy(r.Visibility, r.HistoryDisclosure, r.RemovalPolicy) {
		return ErrTeamWire
	}
	if (v == 1) != (r.PreviousHash == nil) {
		return ErrTeamChain
	}
	if v == 1 && (r.Owner != r.GenesisOwner || epoch != 1 || r.OwnerTransitionHash != nil || r.Status != "active") {
		return ErrTeamChain
	}
	if r.Status != "active" && r.Status != "deleted" {
		return ErrTeamWire
	}
	if r.Members == nil {
		return ErrTeamWire
	}
	if len(r.Members) > l.MaxMembers {
		return ErrTeamLimit
	}
	if r.Status == "deleted" && (len(r.Members) != 0 || r.OwnerTransitionHash != nil) {
		return ErrTeamChain
	}
	if e := teamWindow(r.IssuedAt, r.ExpiresAt, 86400); e != nil {
		return e
	}
	addresses := map[string]bool{}
	last := ""
	for _, m := range r.Members {
		if !teamName.MatchString(m.Handle) || m.Handle <= last || !teamAddress(m.Address) || addresses[m.Address] || !teamHashPattern.MatchString(m.ConsentHash) {
			return ErrTeamWire
		}
		last = m.Handle
		addresses[m.Address] = true
	}
	if signatures {
		return teamSignatureShape(r.Signatures)
	}
	return nil
}
func (b TeamConsentBinding) validate(l TeamLimits) error {
	if e := b.TeamRoot.validate(l); e != nil {
		return e
	}
	epoch, e := teamCounter(b.OwnerEpoch)
	if e != nil || epoch == 0 {
		return ErrTeamWire
	}
	if !teamAddress(b.Owner) || !teamAddress(b.MemberAddress) || !teamName.MatchString(b.Handle) || !teamB64(b.InviteID, 32) || !teamB64(b.Nonce, 32) || !teamPolicy(b.Visibility, b.HistoryDisclosure, b.RemovalPolicy) {
		return ErrTeamWire
	}
	return teamWindow(b.IssuedAt, b.ExpiresAt, l.InvitationLifetimeSeconds)
}
func (i TeamInvitation) validate(l TeamLimits, signatures bool) error {
	if e := l.Validate(); e != nil {
		return e
	}
	if i.Schema != TeamInvitationSchema || i.Suite != string(couriercrypto.SuiteV1) {
		return ErrTeamWire
	}
	if e := i.TeamConsentBinding.validate(l); e != nil {
		return e
	}
	if signatures {
		return teamSignatureShape(i.Signatures)
	}
	return nil
}
func (a TeamAcceptance) validate(l TeamLimits, signatures bool) error {
	if e := l.Validate(); e != nil {
		return e
	}
	if a.Schema != TeamAcceptanceSchema || a.Suite != string(couriercrypto.SuiteV1) || !teamHashPattern.MatchString(a.InvitationHash) {
		return ErrTeamWire
	}
	if e := a.TeamConsentBinding.validate(l); e != nil {
		return e
	}
	t, e := teamTime(a.AcceptedAt)
	if e != nil {
		return e
	}
	start, _ := teamTime(a.IssuedAt)
	end, _ := teamTime(a.ExpiresAt)
	if t.Before(start) || !t.Before(end) {
		return ErrTeamFreshness
	}
	if signatures {
		return teamSignatureShape(a.Signatures)
	}
	return nil
}
func (c TeamOwnerTransition) validate(l TeamLimits, signatures bool) error {
	if e := l.Validate(); e != nil {
		return e
	}
	if e := c.TeamRoot.validate(l); e != nil {
		return e
	}
	epoch, e := teamCounter(c.NewOwnerEpoch)
	if e != nil || epoch < 2 {
		return ErrTeamWire
	}
	version, e := teamCounter(c.EffectiveVersion)
	if e != nil || version < 2 {
		return ErrTeamWire
	}
	if c.Schema != TeamTransitionSchema || c.Suite != string(couriercrypto.SuiteV1) || !teamAddress(c.OldOwner) || !teamAddress(c.NewOwner) || c.OldOwner == c.NewOwner || !teamOptionalHash(c.PreviousCertificateHash) || !teamHashPattern.MatchString(c.PreviousRosterHash) {
		return ErrTeamWire
	}
	if signatures {
		return teamSignatureShape(c.Signatures)
	}
	return nil
}

func ParseTeamRoster(raw []byte, l TeamLimits) (TeamRoster, error) {
	var v TeamRoster
	e := parseTeam(raw, &v, l)
	if e == nil {
		e = v.validate(l, true)
	}
	return v, e
}
func ParseTeamInvitation(raw []byte, l TeamLimits) (TeamInvitation, error) {
	var v TeamInvitation
	e := parseTeam(raw, &v, l)
	if e == nil {
		e = v.validate(l, true)
	}
	return v, e
}
func ParseTeamAcceptance(raw []byte, l TeamLimits) (TeamAcceptance, error) {
	var v TeamAcceptance
	e := parseTeam(raw, &v, l)
	if e == nil {
		e = v.validate(l, true)
	}
	return v, e
}
func ParseTeamOwnerTransition(raw []byte, l TeamLimits) (TeamOwnerTransition, error) {
	var v TeamOwnerTransition
	e := parseTeam(raw, &v, l)
	if e == nil {
		e = v.validate(l, true)
	}
	return v, e
}

// TeamPayload is sealed to the four v1 schemas. CanonicalTeamPayload excludes
// signatures and validates fields. It does not assert signature, trust, consent,
// chain continuity, or freshness. Payload hashes are SHA256(JCS(payload)); schema
// is inside the hash. Signing bytes additionally prefix schema + NUL.
type TeamPayload interface{ validate(TeamLimits, bool) error }

func CanonicalTeamPayload(v TeamPayload, l TeamLimits) ([]byte, error) {
	if v == nil {
		return nil, ErrTeamWire
	}
	switch x := v.(type) {
	case *TeamRoster:
		if x == nil {
			return nil, ErrTeamWire
		}
	case *TeamInvitation:
		if x == nil {
			return nil, ErrTeamWire
		}
	case *TeamAcceptance:
		if x == nil {
			return nil, ErrTeamWire
		}
	case *TeamOwnerTransition:
		if x == nil {
			return nil, ErrTeamWire
		}
	}
	if e := v.validate(l, false); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	obj, e := teamJSON(raw, l)
	if e != nil {
		return nil, e
	}
	m, ok := obj.(map[string]any)
	if !ok {
		return nil, ErrTeamWire
	}
	delete(m, "signatures")
	return appendTeamJSON(nil, m), nil
}
func TeamPayloadHash(v TeamPayload, l TeamLimits) (string, error) {
	b, e := CanonicalTeamPayload(v, l)
	if e != nil {
		return "", e
	}
	return teamHash(b), nil
}
func TeamSigningBytes(v TeamPayload, l TeamLimits) ([]byte, error) {
	b, e := CanonicalTeamPayload(v, l)
	if e != nil {
		return nil, e
	}
	var obj map[string]any
	if e = json.Unmarshal(b, &obj); e != nil {
		return nil, e
	}
	s, ok := obj["schema"].(string)
	if !ok {
		return nil, ErrTeamWire
	}
	return append([]byte(s+"\x00"), b...), nil
}

// MakeTeamSignature calls a caller-supplied signing capability and verifies its
// output through SuiteV1. It never obtains a key or authorizes a signing action.
func MakeTeamSignature(v TeamPayload, role, address string, sign func([]byte) ([]byte, error), l TeamLimits) (TeamSignature, error) {
	if sign == nil || !teamAddress(address) {
		return TeamSignature{}, ErrTeamSignature
	}
	b, e := TeamSigningBytes(v, l)
	if e != nil {
		return TeamSignature{}, e
	}
	sig, e := sign(b)
	if e != nil {
		return TeamSignature{}, e
	}
	s := TeamSignature{role, address, base64.RawURLEncoding.EncodeToString(sig)}
	if e = verifyTeamSignatures(v, []TeamSignature{s}, []TeamSignature{{Role: role, Address: address}}, l); e != nil {
		return TeamSignature{}, e
	}
	return s, nil
}
func verifyTeamSignatures(v TeamPayload, actual, expected []TeamSignature, l TeamLimits) error {
	if len(actual) != len(expected) {
		return ErrTeamSignature
	}
	b, e := TeamSigningBytes(v, l)
	if e != nil {
		return e
	}
	desc, ok := couriercrypto.Descriptor(couriercrypto.SuiteV1)
	if !ok {
		return ErrTeamSignature
	}
	for i, s := range actual {
		if s.Role != expected[i].Role || s.Address != expected[i].Address || !teamAddress(s.Address) || !teamB64(s.Sig, 64) {
			return ErrTeamSignature
		}
		p, e := couriercrypto.ParseAddressSuite(s.Address)
		if e != nil {
			return ErrTeamSignature
		}
		sig, _ := base64.RawURLEncoding.DecodeString(s.Sig)
		if desc.ValidateSignatureFields(sig) != nil || !desc.VerifySignature(p.PublicKey, b, sig) {
			return ErrTeamSignature
		}
	}
	return nil
}

func teamError(where string, e error) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", where, e)
}
