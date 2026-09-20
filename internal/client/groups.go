// Group messaging (issue #32).
//
// Signal-style sender keys: every member holds one symmetric sender key
// per group and distributes it to the other members via pairwise-encrypted
// direct messages. Group messages are sealed under the author's current
// sender key with secretbox; on member removal every remaining member
// rotates their sender key so the removed member cannot decrypt later
// messages.
//
// Local state lives in ~/.courier/groups.json (0600). Membership itself
// is relay-authoritative: the relay verifies the admin's signature on
// every membership-control message and enforces strict epoch order, and
// only current members may post to or read a group.
package client

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// ---- group protocol direct-message payloads ----

// groupDMMagic marks direct messages that belong to the group protocol
// layer. They are consumed silently and never surface as chat messages.
const groupDMMagic = 1

// groupDMPayload is the wire format for group protocol direct messages:
// sender-key distributions ("key") and group invitations ("invite").
// g is the group ID; for invites, keys carries every current member's
// sender key and cur is the join cursor (the relay's max envelope id at
// add time, so the new member does not fetch pre-join history).
type groupDMPayload struct {
	Magic  int                       `json:"cg"`
	Type   string                    `json:"t"`
	Group  string                    `json:"g"`
	Name   string                    `json:"name,omitempty"`
	Admin  string                    `json:"admin,omitempty"`
	Roster []string                  `json:"roster,omitempty"`
	Keys   map[string]groupSenderKey `json:"keys,omitempty"`
	Key    string                    `json:"k,omitempty"`
	Epoch  int64                     `json:"e,omitempty"`
	Cursor int64                     `json:"cur,omitempty"`
}

// parseGroupDMPayload returns the group protocol payload if plain is one,
// and false otherwise. Only well-formed payloads with a recognized type
// are intercepted; anything else is delivered as a normal message.
func parseGroupDMPayload(plain []byte) (groupDMPayload, bool) {
	var p groupDMPayload
	if json.Unmarshal(plain, &p) != nil {
		return p, false
	}
	if p.Magic != groupDMMagic || p.Group == "" {
		return p, false
	}
	switch p.Type {
	case "key", "invite":
		return p, true
	}
	return p, false
}

// ---- local group state ----

// groupSenderKey is one member's current sender key: base64url 32 bytes
// plus the epoch it was issued at.
type groupSenderKey struct {
	Key   string `json:"k"`
	Epoch int64  `json:"e"`
}

// groupState is one group's local record.
type groupState struct {
	ID           string                    `json:"id"`
	Name         string                    `json:"name"`
	Admin        string                    `json:"admin"`
	Roster       []string                  `json:"roster"`
	MyKey        string                    `json:"my_key"`
	MyEpoch      int64                     `json:"my_epoch"`
	Keys         map[string]groupSenderKey `json:"keys"`
	InboxCursor  int64                     `json:"inbox_cursor"`
	ControlEpoch int64                     `json:"control_epoch"`
	Removed      bool                      `json:"removed,omitempty"`
}

// groupsFilePath is ~/.courier/groups.json.
func groupsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "groups.json"), nil
}

func loadGroupsLocked() (map[string]*groupState, error) {
	p, err := groupsFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*groupState{}, nil
		}
		return nil, err
	}
	gs := map[string]*groupState{}
	if err := json.Unmarshal(data, &gs); err != nil {
		return nil, fmt.Errorf("groups.json: %w", err)
	}
	return gs, nil
}

func saveGroupsLocked(gs map[string]*groupState) error {
	p, err := groupsFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(gs, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "groups-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, p)
}

// updateGroups performs an atomic read-modify-write of groups.json under
// the cross-process config lock (same discipline as Config.Update).
func updateGroups(fn func(map[string]*groupState) error) error {
	return withConfigLock(func() error {
		gs, err := loadGroupsLocked()
		if err != nil {
			return err
		}
		if err := fn(gs); err != nil {
			return err
		}
		return saveGroupsLocked(gs)
	})
}

// loadGroups returns a copy of the local group records.
func loadGroups() (map[string]*groupState, error) {
	var gs map[string]*groupState
	if err := withConfigLock(func() error {
		var err error
		gs, err = loadGroupsLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return gs, nil
}

// ---- helpers ----

func inRoster(roster []string, addr string) bool {
	for _, m := range roster {
		if m == addr {
			return true
		}
	}
	return false
}

func removeFromRoster(roster []string, addr string) []string {
	out := roster[:0]
	for _, m := range roster {
		if m != addr {
			out = append(out, m)
		}
	}
	return out
}

// newSenderKey generates a fresh sender key at the given epoch.
func newSenderKey(epoch int64) (groupSenderKey, error) {
	k, err := crypto.GenerateSenderKey()
	if err != nil {
		return groupSenderKey{}, err
	}
	return groupSenderKey{
		Key:   base64.RawURLEncoding.EncodeToString(k[:]),
		Epoch: epoch,
	}, nil
}

// senderKeyBytes decodes a stored sender key.
func senderKeyBytes(sk groupSenderKey) ([32]byte, error) {
	var k [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(sk.Key)
	if err != nil || len(raw) != 32 {
		return k, errors.New("bad sender key")
	}
	copy(k[:], raw)
	return k, nil
}

// postGroupControl signs and submits one membership-control message.
// On success it applies the roster change locally and returns the
// relay's max envelope id for the group (the join cursor for adds).
func (c *Client) postGroupControl(g *groupState, action, target string) (int64, error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return 0, err
	}
	me := c.cfg.Address
	epoch := g.ControlEpoch + 1
	sig := id.Sign(envelope.GroupControl(g.ID, action, target, me, epoch))
	data, code, err := c.post("/v1/groups/control", map[string]any{
		"group":  g.ID,
		"action": action,
		"target": target,
		"admin":  me,
		"epoch":  epoch,
		"sig":    base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, relayErr(data)
	}
	var out struct {
		Epoch int64 `json:"epoch"`
		MaxID int64 `json:"max_id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, fmt.Errorf("bad relay response: %w", err)
	}
	err = updateGroups(func(gs map[string]*groupState) error {
		cur := gs[g.ID]
		if cur == nil {
			return fmt.Errorf("group %s disappeared", g.ID)
		}
		if cur.ControlEpoch != epoch-1 {
			return fmt.Errorf("group state changed concurrently; retry")
		}
		switch action {
		case envelope.GroupControlAdd:
			if !inRoster(cur.Roster, target) {
				cur.Roster = append(cur.Roster, target)
			}
		case envelope.GroupControlRemove:
			cur.Roster = removeFromRoster(cur.Roster, target)
			delete(cur.Keys, target)
		case envelope.GroupControlTransferAdmin:
			cur.Admin = target
		}
		cur.ControlEpoch = epoch
		return nil
	})
	if err != nil {
		return 0, err
	}
	return out.MaxID, nil
}

// distributeMyKey DMs my current sender key to every roster member
// except myself.
func (c *Client) distributeMyKey(g *groupState) error {
	raw, err := json.Marshal(groupDMPayload{
		Magic: groupDMMagic, Type: "key", Group: g.ID,
		Key: g.MyKey, Epoch: g.MyEpoch,
	})
	if err != nil {
		return err
	}
	for _, m := range g.Roster {
		if m == c.cfg.Address {
			continue
		}
		if _, err := c.Send(m, string(raw)); err != nil {
			return fmt.Errorf("distribute key to %s: %w", m, err)
		}
	}
	return nil
}

// rotateMyKeyLocked generates a new sender key at the next epoch and DMs
// it to the remaining members. Called after a removal so the removed
// member cannot decrypt later messages.
func (c *Client) rotateMyKey(g *groupState) error {
	sk, err := newSenderKey(g.MyEpoch + 1)
	if err != nil {
		return err
	}
	g.MyKey = sk.Key
	g.MyEpoch = sk.Epoch
	g.Keys[c.cfg.Address] = sk
	return c.distributeMyKey(g)
}

// ---- public API ----

// GroupCreate creates a group, registers it with the relay (the creator
// becomes the initial admin), and adds each address in members.
func (c *Client) GroupCreate(name string, members []string) (*groupState, error) {
	if len(name) > 200 {
		return nil, errors.New("group name must be at most 200 characters")
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, err
	}
	me := c.cfg.Address
	var rawID [16]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return nil, fmt.Errorf("group id: %w", err)
	}
	groupID := envelope.FormatGroupID(rawID)
	sk, err := newSenderKey(1)
	if err != nil {
		return nil, err
	}
	// Register the group: the creator signs the create control and
	// becomes the initial admin and sole member (epoch 1).
	sig := id.Sign(envelope.GroupControl(groupID, envelope.GroupControlCreate, "", me, 1))
	data, code, err := c.post("/v1/groups/control", map[string]any{
		"group":  groupID,
		"name":   name,
		"action": envelope.GroupControlCreate,
		"admin":  me,
		"epoch":  1,
		"sig":    base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, err
	}
	if code != http.StatusCreated {
		return nil, relayErr(data)
	}
	g := &groupState{
		ID:           groupID,
		Name:         name,
		Admin:        me,
		Roster:       []string{me},
		MyKey:        sk.Key,
		MyEpoch:      sk.Epoch,
		Keys:         map[string]groupSenderKey{me: sk},
		ControlEpoch: 1,
	}
	if err := updateGroups(func(gs map[string]*groupState) error {
		gs[groupID] = g
		return nil
	}); err != nil {
		return nil, err
	}
	for _, m := range members {
		if err := c.GroupAdd(groupID, m); err != nil {
			return g, fmt.Errorf("group created but adding %s failed: %w", m, err)
		}
	}
	return g, nil
}

// GroupAdd adds addr to the group (admin only) and DMs them an invitation
// carrying the roster, every member's current sender key, and the join
// cursor.
func (c *Client) GroupAdd(groupID, addr string) error {
	target, err := c.cfg.ResolveRecipient(addr)
	if err != nil {
		return err
	}
	if _, err := crypto.ParseAddress(target); err != nil {
		return err
	}
	gs, err := loadGroups()
	if err != nil {
		return err
	}
	g := gs[groupID]
	if g == nil {
		return fmt.Errorf("unknown group %s", groupID)
	}
	if g.Removed {
		return fmt.Errorf("you are no longer a member of %s", groupID)
	}
	if g.Admin != c.cfg.Address {
		return fmt.Errorf("only the group admin can add members")
	}
	if inRoster(g.Roster, target) {
		return fmt.Errorf("%s is already in the group", target)
	}
	maxID, err := c.postGroupControl(g, envelope.GroupControlAdd, target)
	if err != nil {
		return err
	}
	// DM the invitation: roster, current sender keys, and the join
	// cursor. The invite is pairwise-encrypted to the new member.
	invite := groupDMPayload{
		Magic: groupDMMagic, Type: "invite", Group: g.ID,
		Name: g.Name, Admin: g.Admin,
		Roster: append(append([]string{}, g.Roster...), target),
		Keys:   map[string]groupSenderKey{},
		Cursor: maxID,
	}
	for m, sk := range g.Keys {
		invite.Keys[m] = sk
	}
	invite.Keys[c.cfg.Address] = groupSenderKey{Key: g.MyKey, Epoch: g.MyEpoch}
	raw, err := json.Marshal(invite)
	if err != nil {
		return err
	}
	if _, err := c.Send(target, string(raw)); err != nil {
		return fmt.Errorf("send invite: %w", err)
	}
	return nil
}

// GroupRemove removes addr from the group (admin only) and rotates the
// admin's sender key, distributing the new key to the remaining members
// so the removed member cannot decrypt later messages.
func (c *Client) GroupRemove(groupID, addr string) error {
	target, err := c.cfg.ResolveRecipient(addr)
	if err != nil {
		return err
	}
	gs, err := loadGroups()
	if err != nil {
		return err
	}
	g := gs[groupID]
	if g == nil {
		return fmt.Errorf("unknown group %s", groupID)
	}
	if g.Removed {
		return fmt.Errorf("you are no longer a member of %s", groupID)
	}
	if g.Admin != c.cfg.Address {
		return fmt.Errorf("only the group admin can remove members")
	}
	if target == c.cfg.Address {
		return fmt.Errorf("cannot remove yourself; transfer adminship first")
	}
	if !inRoster(g.Roster, target) {
		return fmt.Errorf("%s is not in the group", target)
	}
	if _, err := c.postGroupControl(g, envelope.GroupControlRemove, target); err != nil {
		return err
	}
	// Forward secrecy on removal: rotate my sender key and distribute
	// the new key to the remaining members. Every other remaining
	// member rotates their own key when they observe the remove control
	// in GroupInbox.
	return updateGroups(func(gs map[string]*groupState) error {
		cur := gs[groupID]
		if cur == nil {
			return fmt.Errorf("group %s disappeared", groupID)
		}
		return c.rotateMyKey(cur)
	})
}

// GroupTransferAdmin transfers group adminship to addr (admin only).
func (c *Client) GroupTransferAdmin(groupID, addr string) error {
	target, err := c.cfg.ResolveRecipient(addr)
	if err != nil {
		return err
	}
	gs, err := loadGroups()
	if err != nil {
		return err
	}
	g := gs[groupID]
	if g == nil {
		return fmt.Errorf("unknown group %s", groupID)
	}
	if g.Removed {
		return fmt.Errorf("you are no longer a member of %s", groupID)
	}
	if g.Admin != c.cfg.Address {
		return fmt.Errorf("only the group admin can transfer adminship")
	}
	if !inRoster(g.Roster, target) {
		return fmt.Errorf("%s is not in the group", target)
	}
	_, err = c.postGroupControl(g, envelope.GroupControlTransferAdmin, target)
	return err
}

// GroupSend seals body under my current sender key and posts it to the
// group. Returns the relay envelope id.
func (c *Client) GroupSend(groupID, body string) (int64, error) {
	gs, err := loadGroups()
	if err != nil {
		return 0, err
	}
	g := gs[groupID]
	if g == nil {
		return 0, fmt.Errorf("unknown group %s", groupID)
	}
	if g.Removed {
		return 0, fmt.Errorf("you are no longer a member of %s", groupID)
	}
	if !inRoster(g.Roster, c.cfg.Address) {
		return 0, fmt.Errorf("you are not in the group roster")
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return 0, err
	}
	fromEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return 0, err
	}
	key, err := senderKeyBytes(groupSenderKey{Key: g.MyKey})
	if err != nil {
		return 0, err
	}
	pt, err := json.Marshal(map[string]string{"t": "m", "b": body})
	if err != nil {
		return 0, err
	}
	nonce, ct, err := crypto.SealSymmetric(&key, pt)
	if err != nil {
		return 0, err
	}
	var eph [32]byte
	if _, err := rand.Read(eph[:]); err != nil {
		return 0, fmt.Errorf("eph: %w", err)
	}
	sentAt := time.Now().Unix()
	sig := id.Sign(envelope.GroupCanonical(groupID, fromEd[:], g.MyEpoch, eph[:], nonce, sentAt, ct))
	data, code, err := c.post("/v1/send", map[string]any{
		"to":        groupID,
		"from":      c.cfg.Address,
		"eph":       base64.RawURLEncoding.EncodeToString(eph[:]),
		"nonce":     base64.RawURLEncoding.EncodeToString(nonce),
		"ct":        base64.RawURLEncoding.EncodeToString(ct),
		"sent_at":   sentAt,
		"sig":       base64.RawURLEncoding.EncodeToString(sig),
		"kind":      "group",
		"key_epoch": g.MyEpoch,
	})
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, relayErr(data)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, fmt.Errorf("bad relay response: %w", err)
	}
	// Best-effort local record, like Send.
	_ = appendSentLog(SentEntry{CourierID: out.ID, To: groupID, Body: body, SentAt: sentAt})
	return out.ID, nil
}

// groupInboxResponse is the wire format of GET /v1/inbox for a group.
type groupInboxResponse struct {
	Group    string `json:"group"`
	Messages []struct {
		ID         int64  `json:"id"`
		From       string `json:"from"`
		Eph        string `json:"eph"`
		Nonce      string `json:"nonce"`
		Ct         string `json:"ct"`
		KeyEpoch   int64  `json:"key_epoch"`
		SentAt     int64  `json:"sent_at"`
		ReceivedAt int64  `json:"received_at"`
		Sig        string `json:"sig"`
	} `json:"messages"`
	Controls []struct {
		Action string `json:"action"`
		Target string `json:"target"`
		Admin  string `json:"admin"`
		Epoch  int64  `json:"epoch"`
		Sig    string `json:"sig"`
	} `json:"controls"`
}

// GroupInbox fetches the group's envelopes and membership-control feed,
// applies new controls (verifying the admin's signature on each), and
// returns decrypted messages. Removed members get an error: the relay
// refuses their reads.
//
// Control processing may rotate my sender key (on observing a removal)
// and DM the new key to the remaining members — this is what gives
// removal its forward secrecy even when the admin's own client is the
// only one guaranteed online at removal time.
func (c *Client) GroupInbox(groupID string) ([]Message, error) {
	gs, err := loadGroups()
	if err != nil {
		return nil, err
	}
	g := gs[groupID]
	if g == nil {
		return nil, fmt.Errorf("unknown group %s", groupID)
	}
	if g.Removed {
		return nil, fmt.Errorf("you were removed from %s", groupID)
	}
	hc, err := c.httpClient()
	if err != nil {
		return nil, err
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, err
	}
	memberEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return nil, err
	}
	const limit = 50
	ts := time.Now().Unix()
	sig := id.Sign(envelope.GroupInboxRequest(groupID, memberEd[:], g.InboxCursor, limit, ts))
	u := fmt.Sprintf("%s/v1/inbox?to=%s&member=%s&after=%d&limit=%d&ts=%d&sig=%s",
		c.cfg.RelayURL, url.QueryEscape(groupID), url.QueryEscape(c.cfg.Address),
		g.InboxCursor, limit, ts, base64.RawURLEncoding.EncodeToString(sig))
	resp, err := hc.Get(u)
	if err != nil {
		return nil, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusForbidden {
		// The relay is authoritative about membership: a 403 here
		// proves I am no longer a member. Record it locally so the
		// group shows as removed even though the control feed is
		// unreadable.
		_ = updateGroups(func(gs map[string]*groupState) error {
			if cur := gs[groupID]; cur != nil {
				cur.Removed = true
			}
			return nil
		})
		return nil, fmt.Errorf("you were removed from %s", groupID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, relayErr(data)
	}
	var in groupInboxResponse
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("bad relay response: %w", err)
	}

	seen := c.seenEnvelopeSet()
	var newHashes []string
	var out []Message
	skipped := 0
	lastID := g.InboxCursor
	removed := false

	// 1. Membership controls, in epoch order. Each must be signed by the
	// admin I currently know and carry exactly the next epoch; anything
	// else aborts the sync rather than applying a forked history.
	for _, ctl := range in.Controls {
		if ctl.Epoch <= g.ControlEpoch {
			continue
		}
		if ctl.Epoch != g.ControlEpoch+1 {
			return nil, fmt.Errorf("group %s: control epoch gap (have %d, got %d)",
				groupID, g.ControlEpoch, ctl.Epoch)
		}
		adminEd, err := crypto.ParseAddress(ctl.Admin)
		if err != nil {
			return nil, fmt.Errorf("group %s: bad control admin: %w", groupID, err)
		}
		sigRaw, err := base64.RawURLEncoding.DecodeString(ctl.Sig)
		if err != nil || len(sigRaw) != 64 {
			return nil, fmt.Errorf("group %s: bad control signature", groupID)
		}
		canon := envelope.GroupControl(groupID, ctl.Action, ctl.Target, ctl.Admin, ctl.Epoch)
		if !crypto.Verify(adminEd[:], canon, sigRaw) {
			return nil, fmt.Errorf("group %s: control signature verification failed", groupID)
		}
		// The signer must be the admin I know: the relay only accepts
		// controls from the current admin, so a control signed by anyone
		// else means a forked or tampered feed.
		if ctl.Admin != g.Admin {
			return nil, fmt.Errorf("group %s: control not signed by the group admin", groupID)
		}
		switch ctl.Action {
		case envelope.GroupControlCreate:
			// Only meaningful when bootstrapping from scratch; the
			// normal paths (create/invite) already set epoch 1.
			if g.ControlEpoch != 0 {
				return nil, fmt.Errorf("group %s: unexpected create control at epoch %d", groupID, ctl.Epoch)
			}
			g.Admin = ctl.Admin
			g.Roster = []string{ctl.Admin}
		case envelope.GroupControlAdd:
			if !inRoster(g.Roster, ctl.Target) {
				g.Roster = append(g.Roster, ctl.Target)
			}
		case envelope.GroupControlRemove:
			g.Roster = removeFromRoster(g.Roster, ctl.Target)
			delete(g.Keys, ctl.Target)
			if ctl.Target == c.cfg.Address {
				removed = true
			} else {
				// Someone else was removed: rotate my sender key so
				// the removed member cannot decrypt my later messages.
				if err := c.rotateMyKey(g); err != nil {
					return nil, fmt.Errorf("rekey after removal: %w", err)
				}
			}
		case envelope.GroupControlTransferAdmin:
			g.Admin = ctl.Target
		default:
			return nil, fmt.Errorf("group %s: unknown control action %q", groupID, ctl.Action)
		}
		g.ControlEpoch = ctl.Epoch
		if removed {
			break
		}
	}
	if removed {
		g.Removed = true
		if err := updateGroups(func(gs map[string]*groupState) error {
			gs[groupID] = g
			return nil
		}); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("you were removed from %s", groupID)
	}

	// 2. Messages.
	for _, m := range in.Messages {
		if m.ID > lastID {
			lastID = m.ID
		}
		h := envelope.DedupHash(groupID, m.From, m.Eph, m.Nonce, m.SentAt, m.Ct, m.Sig)
		if seen[h] {
			skipped++
			continue
		}
		fromEd, err := crypto.ParseAddress(m.From)
		if err != nil {
			skipped++
			continue
		}
		eph, err1 := base64.RawURLEncoding.DecodeString(m.Eph)
		nonce, err2 := base64.RawURLEncoding.DecodeString(m.Nonce)
		ct, err3 := base64.RawURLEncoding.DecodeString(m.Ct)
		sigRaw, err4 := base64.RawURLEncoding.DecodeString(m.Sig)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			skipped++
			continue
		}
		// Re-verify the group signature client-side (the relay verified
		// it too): the key epoch is covered, binding the envelope to the
		// exact sender key that must open it.
		canon := envelope.GroupCanonical(groupID, fromEd[:], m.KeyEpoch, eph, nonce, m.SentAt, ct)
		if !crypto.Verify(fromEd[:], canon, sigRaw) {
			skipped++
			continue
		}
		sk, ok := g.Keys[m.From]
		if !ok || sk.Epoch != m.KeyEpoch {
			// Missing key or sender rotated past what I hold (e.g. I
			// missed a key-distribution DM): cannot decrypt; skip
			// without stalling the cursor.
			skipped++
			continue
		}
		key, err := senderKeyBytes(sk)
		if err != nil {
			skipped++
			continue
		}
		plain, err := crypto.OpenSymmetric(key[:], nonce, ct)
		if err != nil {
			skipped++
			continue
		}
		var body struct {
			T string `json:"t"`
			B string `json:"b"`
		}
		if json.Unmarshal(plain, &body) != nil || body.T != "m" {
			skipped++
			continue
		}
		out = append(out, Message{
			ID: m.ID, From: m.From, Body: body.B,
			SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
		})
		seen[h] = true
		newHashes = append(newHashes, h)
	}
	c.recordSeenEnvelopes(newHashes)
	g.InboxCursor = lastID
	if err := updateGroups(func(gs map[string]*groupState) error {
		gs[groupID] = g
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GroupList returns the local group records, oldest first.
func (c *Client) GroupList() ([]*groupState, error) {
	gs, err := loadGroups()
	if err != nil {
		return nil, err
	}
	out := make([]*groupState, 0, len(gs))
	for _, g := range gs {
		out = append(out, g)
	}
	return out, nil
}

// handleGroupDM consumes one group protocol direct message from from:
// sender-key distributions update the key table, and invitations join
// the group (generating my own sender key and distributing it).
func (c *Client) handleGroupDM(from string, p groupDMPayload) {
	if _, err := envelope.ParseGroupID(p.Group); err != nil {
		return
	}
	switch p.Type {
	case "key":
		raw, err := base64.RawURLEncoding.DecodeString(p.Key)
		if err != nil || len(raw) != 32 || p.Epoch <= 0 {
			return
		}
		_ = updateGroups(func(gs map[string]*groupState) error {
			g := gs[p.Group]
			if g == nil || g.Removed {
				// Unknown group (the invite may not have arrived yet)
				// or a group I'm out of: nothing to do. The invite
				// itself carries current keys, so a raced key DM is
				// not needed for correctness.
				return nil
			}
			if g.Keys == nil {
				g.Keys = map[string]groupSenderKey{}
			}
			if cur, ok := g.Keys[from]; !ok || p.Epoch > cur.Epoch {
				g.Keys[from] = groupSenderKey{Key: p.Key, Epoch: p.Epoch}
			}
			return nil
		})
	case "invite":
		if _, err := crypto.ParseAddress(p.Admin); err != nil {
			return
		}
		if p.Admin != from {
			// Invites come from the admin who performed the add.
			return
		}
		if !inRoster(p.Roster, from) || !inRoster(p.Roster, c.cfg.Address) {
			return
		}
		for m := range p.Keys {
			if _, err := crypto.ParseAddress(m); err != nil {
				return
			}
		}
		sk, err := newSenderKey(1)
		if err != nil {
			return
		}
		joined := false
		_ = updateGroups(func(gs map[string]*groupState) error {
			if _, ok := gs[p.Group]; ok {
				return nil // idempotent: already joined
			}
			keys := map[string]groupSenderKey{}
			for m, k := range p.Keys {
				keys[m] = k
			}
			keys[c.cfg.Address] = sk
			gs[p.Group] = &groupState{
				ID:           p.Group,
				Name:         p.Name,
				Admin:        p.Admin,
				Roster:       append([]string{}, p.Roster...),
				MyKey:        sk.Key,
				MyEpoch:      sk.Epoch,
				Keys:         keys,
				InboxCursor:  p.Cursor,
				ControlEpoch: 1,
			}
			joined = true
			return nil
		})
		if !joined {
			return
		}
		// Distribute my sender key to the other members. Best effort:
		// a missed DM is repaired on the next removal rekey.
		gs, err := loadGroups()
		if err != nil {
			return
		}
		if g := gs[p.Group]; g != nil {
			_ = c.distributeMyKey(g)
		}
	}
}
