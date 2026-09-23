// Contact-discovery directory client (issue #39).
//
// Handles are convenience aliases bound to Ed25519 identities by signed
// relay registrations. This file implements the client side: register,
// update, transfer, deregister, lookup, search, reverse lookup, handle
// resolution for `courier send`, and the signed introduction-envelope
// protocol for private handles.
package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// DirectoryProfile is a served directory entry: allowed fields only,
// plus the signature binding the handle to the address. Sig verifies
// as a registration signature by Address, or — after a transfer — as a
// transfer signature by TransferFrom.
type DirectoryProfile struct {
	Handle        string   `json:"handle"`
	Address       string   `json:"address"`
	Capabilities  []string `json:"capabilities"`
	ContactPolicy string   `json:"contact_policy"`
	Visibility    string   `json:"visibility"`
	Epoch         int64    `json:"epoch"`
	Sig           string   `json:"sig"`
	TransferFrom  string   `json:"transfer_from,omitempty"`
	RegisteredAt  int64    `json:"registered_at"`
}

// verifyDirectoryProfile checks the owner-signed binding of a served
// profile before the client trusts its address. A registration or
// update is signed by the profile's own address over the register
// canonical form; a transferred handle carries the previous holder's
// transfer signature plus transfer_from naming the key it verifies
// against. A profile that verifies neither way is rejected outright —
// the client never resolves a handle to an unverified address.
func verifyDirectoryProfile(p *DirectoryProfile) error {
	addrEd, err := crypto.ParseAddress(p.Address)
	if err != nil {
		return fmt.Errorf("bad profile address: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.Sig)
	if err != nil {
		return fmt.Errorf("bad profile signature: %w", err)
	}
	caps := normalizeCaps(p.Capabilities)
	canon := envelope.DirectoryRegister(p.Handle, addrEd[:], p.Epoch,
		p.Visibility, p.ContactPolicy, caps)
	if crypto.Verify(addrEd[:], canon, sig) {
		return nil
	}
	if p.TransferFrom != "" {
		prevEd, err := crypto.ParseAddress(p.TransferFrom)
		if err != nil {
			return fmt.Errorf("bad transfer_from address: %w", err)
		}
		tcanon := envelope.DirectoryTransfer(p.Handle, addrEd[:], p.Epoch)
		if crypto.Verify(prevEd[:], tcanon, sig) {
			return nil
		}
	}
	return fmt.Errorf("directory profile signature verification failed for @%s", p.Handle)
}

// nextDirectoryEpoch allocates a strictly increasing directory epoch,
// persisted in the config so restarts cannot reuse one.
func (c *Client) nextDirectoryEpoch() (int64, error) {
	var epoch int64
	if err := c.cfg.Update(func(fresh *Config) error {
		now := time.Now().Unix()
		epoch = now
		if epoch <= fresh.DirectoryEpoch {
			epoch = fresh.DirectoryEpoch + 1
		}
		fresh.DirectoryEpoch = epoch
		return nil
	}); err != nil {
		return 0, err
	}
	return epoch, nil
}

// DirectoryRegister registers (or updates, if already held) a handle.
// Visibility defaults to private; the relay upserts epoch-monotonically.
func (c *Client) DirectoryRegister(handle, visibility string, caps []string, policy string) error {
	handle, err := envelope.NormalizeHandle(handle)
	if err != nil {
		return err
	}
	if err := envelope.ValidateCapabilities(caps); err != nil {
		return err
	}
	caps = advertiseFSCap(normalizeCaps(caps))
	if visibility == "" {
		visibility = envelope.DirectoryPrivate
	}
	switch visibility {
	case envelope.DirectoryPublic, envelope.DirectoryUnlisted, envelope.DirectoryPrivate:
	default:
		return fmt.Errorf("visibility must be public, unlisted, or private")
	}
	if policy == "" {
		policy = envelope.DirectoryPolicyOpen
	}
	switch policy {
	case envelope.DirectoryPolicyOpen, envelope.DirectoryPolicyContacts:
	default:
		return fmt.Errorf("contact policy must be open or contacts")
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	epoch, err := c.nextDirectoryEpoch()
	if err != nil {
		return err
	}
	addrEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return err
	}
	canon := envelope.DirectoryRegister(handle, addrEd[:], epoch, visibility, policy, caps)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/directory", map[string]any{
		"handle": handle, "address": c.cfg.Address,
		"capabilities": caps, "contact_policy": policy,
		"visibility": visibility, "epoch": epoch,
		"sig": base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return relayErr(data)
	}
	_ = c.cfg.Update(func(fresh *Config) error {
		fresh.DirectoryHandle = handle
		return nil
	})
	return nil
}

func normalizeCaps(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, cp := range caps {
		if n := strings.ToLower(strings.TrimSpace(cp)); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// advertiseFSCap returns caps with the FS capability token added so
// v0.11.0+ clients announce forward-secrecy support (issue #50). If the
// user's own tokens already fill the directory's capability budget, the
// user's tokens win and fs is left out rather than clobbering one.
func advertiseFSCap(caps []string) []string {
	with := withFSCap(caps)
	if len(with) == len(caps) {
		return caps
	}
	if err := envelope.ValidateCapabilities(with); err != nil {
		return caps
	}
	return with
}

// DirectoryUpdate updates the agent's registered handle entry. Fields
// left empty keep their current values (fetched via lookup).
func (c *Client) DirectoryUpdate(visibility string, caps []string, policy string, clearCaps bool) error {
	if c.cfg.DirectoryHandle == "" {
		return fmt.Errorf("no handle registered (see `courier directory register`)")
	}
	current, err := c.DirectoryLookup(c.cfg.DirectoryHandle)
	if err != nil {
		return fmt.Errorf("cannot read current entry: %w", err)
	}
	if visibility == "" {
		visibility = current.Visibility
	}
	if policy == "" {
		policy = current.ContactPolicy
	}
	if !clearCaps && caps == nil {
		caps = current.Capabilities
	}
	// Bypass the register path's handle bookkeeping: update reuses the
	// same signed endpoint with a fresh epoch.
	handle, err := envelope.NormalizeHandle(c.cfg.DirectoryHandle)
	if err != nil {
		return err
	}
	if err := envelope.ValidateCapabilities(caps); err != nil {
		return err
	}
	caps = normalizeCaps(caps)
	// An explicit --clear-caps is honored literally: we don't re-add fs
	// when the user just asked for an empty capability set.
	if !(clearCaps && len(caps) == 0) {
		caps = advertiseFSCap(caps)
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	epoch, err := c.nextDirectoryEpoch()
	if err != nil {
		return err
	}
	addrEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return err
	}
	canon := envelope.DirectoryRegister(handle, addrEd[:], epoch, visibility, policy, caps)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/directory", map[string]any{
		"handle": handle, "address": c.cfg.Address,
		"capabilities": caps, "contact_policy": policy,
		"visibility": visibility, "epoch": epoch,
		"sig": base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return relayErr(data)
	}
	return nil
}

// DirectoryUnregister deletes the agent's handle registration. This is
// the holder's own choice; operator takedowns use tombstones instead.
func (c *Client) DirectoryUnregister() error {
	if c.cfg.DirectoryHandle == "" {
		return fmt.Errorf("no handle registered (see `courier directory register`)")
	}
	handle, err := envelope.NormalizeHandle(c.cfg.DirectoryHandle)
	if err != nil {
		return err
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	epoch, err := c.nextDirectoryEpoch()
	if err != nil {
		return err
	}
	addrEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return err
	}
	canon := envelope.DirectoryDeregister(handle, addrEd[:], epoch)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/directory", map[string]any{
		"handle": handle, "address": c.cfg.Address,
		"epoch": epoch, "deregister": true,
		"sig": base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return relayErr(data)
	}
	_ = c.cfg.Update(func(fresh *Config) error {
		fresh.DirectoryHandle = ""
		return nil
	})
	return nil
}

// DirectoryTransfer signs a handle over to a new owner address. Only the
// current holder can authorize a transfer: no release-and-re-register
// race for a squatter to win.
func (c *Client) DirectoryTransfer(handle, toAddress string) error {
	handle, err := envelope.NormalizeHandle(handle)
	if err != nil {
		return err
	}
	toEd, err := crypto.ParseAddress(toAddress)
	if err != nil {
		return fmt.Errorf("bad destination address: %w", err)
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	epoch, err := c.nextDirectoryEpoch()
	if err != nil {
		return err
	}
	canon := envelope.DirectoryTransfer(handle, toEd[:], epoch)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/directory/transfer", map[string]any{
		"handle": handle, "to_address": toAddress, "epoch": epoch,
		"sig": base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return relayErr(data)
	}
	if c.cfg.DirectoryHandle == handle {
		_ = c.cfg.Update(func(fresh *Config) error {
			fresh.DirectoryHandle = ""
			return nil
		})
	}
	return nil
}

// signedDirectoryGet performs an identity-signed directory query
// (lookup/search/reverse), binding the query to the querier (T2).
func (c *Client) signedDirectoryGet(op, query string, params url.Values) ([]byte, int, error) {
	hc, err := c.httpClient()
	if err != nil {
		return nil, 0, err
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, 0, err
	}
	qEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return nil, 0, err
	}
	ts := time.Now().Unix()
	sig := id.Sign(envelope.DirectoryQuery(qEd[:], op, query, ts))
	params.Set("querier", c.cfg.Address)
	params.Set("ts", fmt.Sprintf("%d", ts))
	params.Set("sig", base64.RawURLEncoding.EncodeToString(sig))
	resp, err := hc.Get(c.cfg.RelayURL + "/v1/directory/" + op + "?" + params.Encode())
	if err != nil {
		return nil, 0, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return data, resp.StatusCode, nil
}

// DirectoryLookup resolves one handle exactly. Private handles and
// unknown handles both return 404 — indistinguishable by design.
func (c *Client) DirectoryLookup(handle string) (*DirectoryProfile, error) {
	handle, err := envelope.NormalizeHandle(handle)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Set("handle", handle)
	data, code, err := c.signedDirectoryGet("lookup", handle, params)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, fmt.Errorf("no such handle")
	}
	if code == http.StatusGone {
		var tomb struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(data, &tomb)
		return nil, fmt.Errorf("handle was removed by operator takedown: %s", tomb.Reason)
	}
	if code != http.StatusOK {
		return nil, relayErr(data)
	}
	var p DirectoryProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("bad relay response: %w", err)
	}
	if err := verifyDirectoryProfile(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DirectorySearch prefix-searches public handles (≥2 chars, ≤20
// results). There is deliberately no list-all endpoint.
func (c *Client) DirectorySearch(prefix string) ([]DirectoryProfile, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len([]rune(prefix)) < envelope.DirectorySearchMinLen {
		return nil, fmt.Errorf("search prefix must be at least 2 characters")
	}
	params := url.Values{}
	params.Set("q", prefix)
	data, code, err := c.signedDirectoryGet("search", prefix, params)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, relayErr(data)
	}
	var out struct {
		Results []DirectoryProfile `json:"results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("bad relay response: %w", err)
	}
	for i := range out.Results {
		if err := verifyDirectoryProfile(&out.Results[i]); err != nil {
			return nil, err
		}
	}
	return out.Results, nil
}

// DirectoryReverse returns the listed (non-private) handle(s) for an
// address the querier already knows. Used for dashboard handle display.
func (c *Client) DirectoryReverse(address string) ([]DirectoryProfile, error) {
	if _, err := crypto.ParseAddress(address); err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Set("address", address)
	data, code, err := c.signedDirectoryGet("reverse", address, params)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, relayErr(data)
	}
	var rout struct {
		Results []DirectoryProfile `json:"results"`
	}
	if err := json.Unmarshal(data, &rout); err != nil {
		return nil, fmt.Errorf("bad relay response: %w", err)
	}
	for i := range rout.Results {
		if err := verifyDirectoryProfile(&rout.Results[i]); err != nil {
			return nil, err
		}
	}
	return rout.Results, nil
}

// PeerHandle resolves a peer address to a display handle for the
// dashboard, with a 24h local cache so the per-minute push does not
// query the relay for every thread.
func (c *Client) PeerHandle(address string) string {
	if c.cfg.HandleCache != nil {
		if e, ok := c.cfg.HandleCache[address]; ok &&
			time.Now().Unix()-e.At < 24*3600 {
			return e.Handle
		}
	}
	profiles, err := c.DirectoryReverse(address)
	handle := ""
	if err == nil && len(profiles) > 0 {
		handle = profiles[0].Handle
	}
	_ = c.cfg.Update(func(fresh *Config) error {
		if fresh.HandleCache == nil {
			fresh.HandleCache = make(map[string]HandleCacheEntry)
		}
		fresh.HandleCache[address] = HandleCacheEntry{Handle: handle, At: time.Now().Unix()}
		// Bound the cache; drop oldest beyond 500 entries.
		if len(fresh.HandleCache) > 500 {
			oldest, oldestK := time.Now().Unix(), ""
			for k, v := range fresh.HandleCache {
				if v.At < oldest {
					oldest, oldestK = v.At, k
				}
			}
			if oldestK != "" {
				delete(fresh.HandleCache, oldestK)
			}
		}
		return nil
	})
	return handle
}

// ResolveHandleTarget accepts "@handle" or "handle:<name>" and resolves
// it via directory lookup, returning the address and profile. It returns
// isHandle=false for non-handle inputs (caller falls back to normal
// address/contact resolution).
func (c *Client) ResolveHandleTarget(toOrName string) (address string, profile *DirectoryProfile, isHandle bool, err error) {
	name := ""
	switch {
	case strings.HasPrefix(toOrName, "@"):
		name = toOrName[1:]
		isHandle = true
	case strings.HasPrefix(toOrName, "handle:"):
		name = strings.TrimPrefix(toOrName, "handle:")
		isHandle = true
	}
	if !isHandle {
		return "", nil, false, nil
	}
	p, err := c.DirectoryLookup(name)
	if err != nil {
		return "", nil, true, err
	}
	return p.Address, p, true, nil
}

// ---- introduction protocol (private handles) ----

// introductionMagic marks DMs that belong to the introduction protocol
// layer. They are recorded as pending introductions and surfaced with a
// readable body; they are never silently swallowed.
const introductionMagic = 1

// introductionPayload is the wire format for introduction protocol DMs:
// introduction requests ("request": asker → mutual contact) and
// introductions ("introduction": mutual contact → target).
type introductionPayload struct {
	Magic         int    `json:"ci"`
	Type          string `json:"t"` // "request" | "introduction"
	Handle        string `json:"h,omitempty"`
	Subject       string `json:"s,omitempty"`
	SubjectHandle string `json:"sh,omitempty"`
	Note          string `json:"n,omitempty"`
	Ts            int64  `json:"ts"`
	Sig           string `json:"sig"`
}

// parseIntroductionPayload returns the introduction payload if plain is
// one, following the group-DM detection pattern.
func parseIntroductionPayload(plain []byte) (introductionPayload, bool) {
	var p introductionPayload
	if json.Unmarshal(plain, &p) != nil {
		return p, false
	}
	if p.Magic != introductionMagic || p.Ts <= 0 || p.Sig == "" {
		return p, false
	}
	switch p.Type {
	case "request":
		return p, p.Handle != ""
	case "introduction":
		return p, p.Subject != ""
	}
	return p, false
}

// PendingIntroduction is a recorded introduction request or
// introduction awaiting the user's decision.
type PendingIntroduction struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"` // "request" | "introduction"
	From          string `json:"from"` // sender address
	Handle        string `json:"handle,omitempty"`
	Subject       string `json:"subject,omitempty"`
	SubjectHandle string `json:"subject_handle,omitempty"`
	Note          string `json:"note,omitempty"`
	Ts            int64  `json:"ts"`
	EnvelopeID    int64  `json:"envelope_id"`
	Dismissed     bool   `json:"dismissed,omitempty"`
}

// RequestIntroduction asks a mutual contact (who must be in your
// contacts) to introduce you to the owner of handle. The request travels
// as a normal E2E DM; the contact decides whether to forward it.
func (c *Client) RequestIntroduction(mutualContact, handle, note string) error {
	introducer, err := c.cfg.ResolveRecipient(mutualContact)
	if err != nil {
		return err
	}
	// ResolveRecipient accepts raw addresses too; introductions require
	// a real mutual contact the user can vouch for.
	known := false
	for _, addr := range c.cfg.Contacts {
		if addr == introducer {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("introductions require a mutual contact: %q is not in your contacts", mutualContact)
	}
	handle, err = envelope.NormalizeHandle(handle)
	if err != nil {
		return err
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	meEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return err
	}
	introEd, err := crypto.ParseAddress(introducer)
	if err != nil {
		return err
	}
	ts := time.Now().Unix()
	canon := envelope.IntroductionRequest(meEd[:], introEd[:], handle, ts)
	sig := id.Sign(canon)
	p := introductionPayload{
		Magic: introductionMagic, Type: "request",
		Handle: handle, Note: note, Ts: ts,
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err := c.Send(introducer, string(raw)); err != nil {
		return err
	}
	return nil
}

// recordIntroduction validates an incoming introduction payload and, if
// legitimate, records it as pending and returns a human-readable body
// for display. Invalid payloads (bad signature, unknown parties) return
// ok=false and the raw JSON flows through as an ordinary message.
func (c *Client) recordIntroduction(from string, envelopeID int64, p introductionPayload) (display string, ok bool) {
	fromEd, err := crypto.ParseAddress(from)
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.Sig)
	if err != nil || len(sig) != 64 {
		return "", false
	}
	meEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return "", false
	}
	// Freshness: introductions are DMs; the envelope already carries
	// sent_at, but the payload timestamp must be sane too.
	if now := time.Now().Unix(); p.Ts < now-7*24*3600 || p.Ts > now+3600 {
		return "", false
	}
	contacts := c.cfg.contactAddressSet()
	switch p.Type {
	case "request":
		// The requester must be someone I know — I only introduce
		// people I can vouch for.
		if !contacts[from] {
			return "", false
		}
		canon := envelope.IntroductionRequest(fromEd[:], meEd[:], p.Handle, p.Ts)
		if !crypto.Verify(fromEd[:], canon, sig) {
			return "", false
		}
		handle, err := envelope.NormalizeHandle(p.Handle)
		if err != nil {
			return "", false
		}
		name := c.contactNameFor(from)
		c.storeIntroduction(PendingIntroduction{
			ID:         fmt.Sprintf("req-%d-%s", p.Ts, shortAddr(from)),
			Kind:       "request",
			From:       from,
			Handle:     handle,
			Note:       p.Note,
			Ts:         p.Ts,
			EnvelopeID: envelopeID,
		})
		display = fmt.Sprintf("[introduction request] %s asks you to introduce them to @%s", name, handle)
		if p.Note != "" {
			display += fmt.Sprintf(": %q", p.Note)
		}
		return display, true
	case "introduction":
		// The introducer must be a mutual contact: introductions are
		// only trustworthy from people I know.
		if !contacts[from] {
			return "", false
		}
		subEd, err := crypto.ParseAddress(p.Subject)
		if err != nil {
			return "", false
		}
		canon := envelope.Introduction(fromEd[:], subEd[:], meEd[:], p.Ts)
		if !crypto.Verify(fromEd[:], canon, sig) {
			return "", false
		}
		name := c.contactNameFor(from)
		subName := p.SubjectHandle
		if subName == "" {
			subName = shortAddr(p.Subject)
		} else {
			subName = "@" + subName
		}
		c.storeIntroduction(PendingIntroduction{
			ID:            fmt.Sprintf("intro-%d-%s", p.Ts, shortAddr(from)),
			Kind:          "introduction",
			From:          from,
			Subject:       p.Subject,
			SubjectHandle: p.SubjectHandle,
			Note:          p.Note,
			Ts:            p.Ts,
			EnvelopeID:    envelopeID,
		})
		display = fmt.Sprintf("[introduction] %s introduces %s", name, subName)
		if p.Note != "" {
			display += fmt.Sprintf(": %q", p.Note)
		}
		return display, true
	}
	return "", false
}

// contactNameFor returns the contact name for an address, or a
// truncated address when unknown.
func (c *Client) contactNameFor(address string) string {
	for name, addr := range c.cfg.Contacts {
		if addr == address {
			return name
		}
	}
	return shortAddr(address)
}

// ContactDisplayName returns the display name for an address, for the
// CLI's contacts list/show, send, and inbox output. The order is
// deliberate (#146: display defaults to the directory handle; the
// local alias is the optional override):
//
//  1. the local address-book name when the address is a contact —
//     either a handle taken as the name at add time or an explicit
//     private alias;
//  2. the peer's known directory handle (24h-cached reverse lookup)
//     when the address is not a contact;
//  3. a truncated address as the last resort.
//
// Exported for CLI display.
func (c *Client) ContactDisplayName(address string) string {
	if name := c.cfg.contactNameForAddress(address); name != "" {
		return name
	}
	if h := c.PeerHandle(address); h != "" {
		return h
	}
	return shortAddr(address)
}

func shortAddr(address string) string {
	s := strings.TrimPrefix(address, crypto.AddressPrefix)
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

// storeIntroduction records a pending introduction, replacing any
// earlier entry with the same ID.
func (c *Client) storeIntroduction(pi PendingIntroduction) {
	_ = c.cfg.Update(func(fresh *Config) error {
		kept := fresh.Introductions[:0]
		for _, e := range fresh.Introductions {
			if e.ID != pi.ID {
				kept = append(kept, e)
			}
		}
		fresh.Introductions = append(kept, pi)
		return nil
	})
}

// PendingIntroductions lists non-dismissed pending introductions,
// newest first.
func (c *Client) PendingIntroductions() []PendingIntroduction {
	var out []PendingIntroduction
	for _, pi := range c.cfg.Introductions {
		if !pi.Dismissed {
			out = append(out, pi)
		}
	}
	return out
}

// findIntroduction locates a pending introduction by ID prefix.
func (c *Client) findIntroduction(id string) (*PendingIntroduction, error) {
	var match *PendingIntroduction
	for i := range c.cfg.Introductions {
		pi := &c.cfg.Introductions[i]
		if pi.Dismissed {
			continue
		}
		if pi.ID == id || strings.HasPrefix(pi.ID, id) {
			if match != nil {
				return nil, fmt.Errorf("ambiguous introduction id %q", id)
			}
			cp := *pi
			match = &cp
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no pending introduction %q", id)
	}
	return match, nil
}

// DismissIntroduction drops a pending introduction without acting on it.
func (c *Client) DismissIntroduction(id string) error {
	pi, err := c.findIntroduction(id)
	if err != nil {
		return err
	}
	return c.cfg.Update(func(fresh *Config) error {
		for i := range fresh.Introductions {
			if fresh.Introductions[i].ID == pi.ID {
				fresh.Introductions[i].Dismissed = true
			}
		}
		return nil
	})
}

// AcceptIntroductionRequest forwards an introduction request to the
// target: the introducer resolves the target from their own knowledge —
// directory lookup for listed handles, or a contact whose name matches
// the handle for private ones (which is exactly why the introduction
// path exists) — and sends the signed introduction envelope as a DM.
// The request is marked handled either way.
func (c *Client) AcceptIntroductionRequest(id, note string) error {
	pi, err := c.findIntroduction(id)
	if err != nil {
		return err
	}
	if pi.Kind != "request" {
		return fmt.Errorf("%q is an introduction, not a request", id)
	}
	// Resolve the target: I must actually know the person I'm
	// introducing. Listed handles resolve via the directory; private
	// handles resolve via my own contacts by name.
	var targetAddr string
	if p, lerr := c.DirectoryLookup(pi.Handle); lerr == nil {
		targetAddr = p.Address
	} else if addr, ok := c.cfg.Contacts[pi.Handle]; ok {
		targetAddr = addr
	} else {
		return fmt.Errorf("cannot resolve @%s: private handle and not a contact — add the target as a contact first", pi.Handle)
	}
	idn, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	meEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return err
	}
	subEd, err := crypto.ParseAddress(pi.From)
	if err != nil {
		return err
	}
	tgtEd, err := crypto.ParseAddress(targetAddr)
	if err != nil {
		return err
	}
	// Carry the requester's public handle when they have one, so the
	// target can decide whether to accept.
	var subjectHandle string
	if rev, rerr := c.DirectoryReverse(pi.From); rerr == nil && len(rev) > 0 {
		subjectHandle = rev[0].Handle
	}
	fwdNote := strings.TrimSpace(note)
	if pi.Note != "" {
		if fwdNote == "" {
			fwdNote = pi.Note
		} else {
			fwdNote += " / " + pi.Note
		}
	}
	ts := time.Now().Unix()
	canon := envelope.Introduction(meEd[:], subEd[:], tgtEd[:], ts)
	sig := idn.Sign(canon)
	p := introductionPayload{
		Magic: introductionMagic, Type: "introduction",
		Subject: pi.From, SubjectHandle: subjectHandle,
		Note: fwdNote, Ts: ts,
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err := c.Send(targetAddr, string(raw)); err != nil {
		return fmt.Errorf("could not deliver introduction: %w", err)
	}
	return c.DismissIntroduction(pi.ID)
}

// AcceptIntroduction accepts an introduction: the subject joins the
// recipient's contacts (mutual opt-in, second half) and receives a
// greeting DM. The introducer is not notified — acceptance is between
// the recipient and the subject.
func (c *Client) AcceptIntroduction(id, greet string) error {
	pi, err := c.findIntroduction(id)
	if err != nil {
		return err
	}
	if pi.Kind != "introduction" {
		return fmt.Errorf("%q is an introduction request, not an introduction", id)
	}
	// The introducer must still be a contact at accept time.
	if !c.cfg.contactAddressSet()[pi.From] {
		return fmt.Errorf("introducer is no longer in your contacts")
	}
	name := pi.SubjectHandle
	if name == "" || !contactNameRe.MatchString(name) || c.cfg.Contacts[name] != "" {
		name = c.requestContactName(pi.Subject)
	}
	if err := c.cfg.AddContact(name, pi.Subject); err != nil {
		return fmt.Errorf("could not add contact: %w", err)
	}
	if strings.TrimSpace(greet) == "" {
		greet = fmt.Sprintf("Hi — %s introduced us on Courier. Nice to meet you!", c.contactNameFor(pi.From))
	}
	if _, err := c.Send(pi.Subject, greet); err != nil {
		return fmt.Errorf("contact added as %q, but the greeting failed to send: %w", name, err)
	}
	return c.DismissIntroduction(pi.ID)
}
