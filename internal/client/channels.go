// OOB-code private channels (issue #48, phase 2).
//
// A channel is a small private group for the team-agent case, bootstrapped
// by a short out-of-band code. Client-side only: no relay changes. Channel
// protocol DMs are pairwise E2E-encrypted Courier messages with a magic
// marker, consumed by the channel layer exactly like group DMs (issue
// #32) — they never surface as chat messages.
//
// The OOB code carries only the join secret (15 random bytes, 120 bits),
// rendered as 6 groups of 4 base32 characters; the joiner supplies the
// inviter's address separately. Codes are single-use and expire after
// 24h. Proving possession of a code received out of band IS the
// verification ceremony: both sides mark the counterparty verified
// (phase 1) when a join completes.
//
// Local state lives in ~/.courier/channels.json (0600).
package client

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// ---- channel protocol direct-message payloads ----

// channelDMMagic marks direct messages that belong to the channel
// protocol layer. They are consumed silently and never surface as chat
// messages.
const channelDMMagic = 2

// Channel protocol DM types.
const (
	channelJoinRequest = "join-request"
	channelJoinAccept  = "join-accept"
	channelMsg         = "msg"
	channelRekey       = "rekey"
	channelLeave       = "leave"
)

// channelDMPayload is the wire format for channel protocol direct
// messages. Secret is base64url: the join secret on join-request, the
// channel secret on join-accept/rekey. Nonce/CT carry a secretbox-sealed
// channel message on msg.
type channelDMPayload struct {
	Magic   int      `json:"cc"`
	Type    string   `json:"t"`
	Channel string   `json:"ch,omitempty"`
	Secret  string   `json:"s,omitempty"`
	Epoch   int64    `json:"e,omitempty"`
	Name    string   `json:"name,omitempty"`
	Roster  []string `json:"roster,omitempty"`
	Admin   string   `json:"admin,omitempty"`
	Nonce   string   `json:"n,omitempty"`
	CT      string   `json:"ct,omitempty"`
}

// parseChannelDMPayload returns the channel protocol payload if plain is
// one, and false otherwise. Only well-formed payloads with a recognized
// type are intercepted; anything else falls through as an ordinary
// message — never silently swallowed.
func parseChannelDMPayload(plain []byte) (channelDMPayload, bool) {
	var p channelDMPayload
	if json.Unmarshal(plain, &p) != nil {
		return p, false
	}
	if p.Magic != channelDMMagic || p.Type == "" {
		return p, false
	}
	switch p.Type {
	case channelJoinRequest, channelJoinAccept, channelMsg, channelRekey, channelLeave:
		return p, true
	}
	return p, false
}

// ---- OOB join codes ----

// joinCodeBytes is the entropy in one OOB join code: 120 bits, rendered
// as 24 base32 characters in 6 groups of 4.
const joinCodeBytes = 15

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatJoinCode renders raw join-secret bytes as a human-friendly OOB
// code: 6 groups of 4 characters (e.g. ABCD-EFGH-IJKL-MNOP-QRST-UVWX).
func FormatJoinCode(raw []byte) (string, error) {
	if len(raw) != joinCodeBytes {
		return "", fmt.Errorf("join secret must be %d bytes", joinCodeBytes)
	}
	s := b32NoPad.EncodeToString(raw)
	var groups []string
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, "-"), nil
}

// ParseJoinCode parses an OOB code back to raw join-secret bytes,
// tolerating hyphens, spaces, and lowercase.
func ParseJoinCode(code string) ([]byte, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(code, "-", ""), " ", ""))
	raw, err := b32NoPad.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("bad join code: %w", err)
	}
	if len(raw) != joinCodeBytes {
		return nil, fmt.Errorf("bad join code: wrong length")
	}
	return raw, nil
}

// ---- local channel state ----

// channelMessage is one message in a channel's local log.
type channelMessage struct {
	From   string `json:"from"`
	Body   string `json:"body"`
	SentAt int64  `json:"sent_at"`
}

// channelState is one channel's local record.
type channelState struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Secret   string           `json:"secret"` // base64url 32-byte channel key
	Epoch    int64            `json:"epoch"`
	Roster   []string         `json:"roster"`
	Admin    string           `json:"admin"`
	JoinedAt int64            `json:"joined_at"`
	Messages []channelMessage `json:"messages,omitempty"`
}

// channelInvite is a pending single-use OOB invitation.
type channelInvite struct {
	Secret    string `json:"secret"` // base64url join secret
	ChannelID string `json:"channel_id"`
	CreatedAt int64  `json:"created_at"`
	Used      bool   `json:"used"`
}

// channelStore is the whole channels.json document.
type channelStore struct {
	Channels map[string]*channelState  `json:"channels"`
	Invites  map[string]*channelInvite `json:"invites"` // keyed by base64url join secret
	Pending  map[string]int64          `json:"pending_joins,omitempty"` // inviter address -> unix ts
}

// channelInviteTTL bounds how long an OOB code stays redeemable.
const channelInviteTTL = 24 * 3600

// maxChannelMessages caps the local per-channel message log.
const maxChannelMessages = 500

func channelsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "channels.json"), nil
}

func loadChannelsLocked() (*channelStore, error) {
	p, err := channelsFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &channelStore{
				Channels: map[string]*channelState{},
				Invites:  map[string]*channelInvite{},
			}, nil
		}
		return nil, err
	}
	var cs channelStore
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, err
	}
	if cs.Channels == nil {
		cs.Channels = map[string]*channelState{}
	}
	if cs.Invites == nil {
		cs.Invites = map[string]*channelInvite{}
	}
	return &cs, nil
}

func saveChannelsLocked(cs *channelStore) error {
	p, err := channelsFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "channels-*.tmp")
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

// updateChannels performs an atomic read-modify-write of channels.json
// under the cross-process config lock (same discipline as Config.Update).
func updateChannels(fn func(*channelStore) error) error {
	return withConfigLock(func() error {
		cs, err := loadChannelsLocked()
		if err != nil {
			return err
		}
		if err := fn(cs); err != nil {
			return err
		}
		return saveChannelsLocked(cs)
	})
}

// loadChannels returns a copy of the local channel store.
func loadChannels() (*channelStore, error) {
	var cs *channelStore
	if err := withConfigLock(func() error {
		var err error
		cs, err = loadChannelsLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return cs, nil
}

// newChannelID mints a channel id: "ch_" + 26 base32 chars (128 bits).
func newChannelID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "ch_" + strings.ToLower(b32NoPad.EncodeToString(raw[:])), nil
}

func channelSecretBytes(secret string) ([32]byte, error) {
	var k [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 {
		return k, fmt.Errorf("bad channel secret")
	}
	copy(k[:], raw)
	return k, nil
}

func inChannelRoster(roster []string, addr string) bool {
	for _, m := range roster {
		if m == addr {
			return true
		}
	}
	return false
}

func removeFromChannelRoster(roster []string, addr string) []string {
	out := roster[:0]
	for _, m := range roster {
		if m != addr {
			out = append(out, m)
		}
	}
	return out
}

// ---- channel operations ----

// ChannelCreate creates a local private channel and returns it. The
// creator is the admin and the only member; others join via OOB codes
// minted with ChannelInvite.
func (c *Client) ChannelCreate(name string) (*channelState, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("channel name must not be empty")
	}
	if len(name) > 64 {
		return nil, fmt.Errorf("channel name must be at most 64 characters")
	}
	id, err := newChannelID()
	if err != nil {
		return nil, err
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	ch := &channelState{
		ID:       id,
		Name:     name,
		Secret:   base64.RawURLEncoding.EncodeToString(key[:]),
		Epoch:    1,
		Roster:   []string{c.cfg.Address},
		Admin:    c.cfg.Address,
		JoinedAt: time.Now().Unix(),
	}
	if err := updateChannels(func(cs *channelStore) error {
		cs.Channels[id] = ch
		return nil
	}); err != nil {
		return nil, err
	}
	return ch, nil
}

// ChannelInvite mints a single-use OOB join code for the channel and
// returns the human-friendly code. The operator conveys it out of band;
// it expires after 24h.
func (c *Client) ChannelInvite(channelID string) (string, error) {
	var raw [joinCodeBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	code, err := FormatJoinCode(raw[:])
	if err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw[:])
	err = updateChannels(func(cs *channelStore) error {
		ch := cs.Channels[channelID]
		if ch == nil {
			return fmt.Errorf("unknown channel %q", channelID)
		}
		if ch.Admin != c.cfg.Address {
			return fmt.Errorf("only the channel admin can invite")
		}
		cs.Invites[secret] = &channelInvite{
			Secret:    secret,
			ChannelID: channelID,
			CreatedAt: time.Now().Unix(),
			Used:      false,
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// sendChannelDM marshals a channel protocol payload and DMs it to addr.
func (c *Client) sendChannelDM(addr string, p channelDMPayload) error {
	p.Magic = channelDMMagic
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = c.Send(addr, string(raw))
	return err
}

// ChannelJoin sends a join request to the inviter and waits (up to 60s,
// polling the inbox) for the join-accept. The inviter's address may be a
// contact name. On success both sides mark the counterparty verified —
// the OOB code exchange is the verification ceremony (issue #48 phase 1).
func (c *Client) ChannelJoin(inviter, code string) error {
	inviterAddr, err := c.cfg.ResolveRecipient(inviter)
	if err != nil {
		return err
	}
	secret, err := ParseJoinCode(code)
	if err != nil {
		return err
	}
	if err := c.sendChannelDM(inviterAddr, channelDMPayload{
		Type:   channelJoinRequest,
		Secret: base64.RawURLEncoding.EncodeToString(secret),
	}); err != nil {
		return fmt.Errorf("join request failed: %w", err)
	}
	if err := updateChannels(func(cs *channelStore) error {
		if cs.Pending == nil {
			cs.Pending = map[string]int64{}
		}
		cs.Pending[inviterAddr] = time.Now().Unix()
		return nil
	}); err != nil {
		return err
	}
	// Wait for the inviter's agent to process the request (it polls its
	// own inbox about every minute, faster with the wake daemon).
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		cs, err := loadChannels()
		if err != nil {
			continue
		}
		for _, ch := range cs.Channels {
			if ch.Admin == inviterAddr && inChannelRoster(ch.Roster, c.cfg.Address) {
				return nil
			}
		}
		// Drain the inbox so the accept is processed promptly.
		_, _, _, _, _ = c.Inbox(0, 50)
	}
	return fmt.Errorf("join request sent but no accept arrived within 60s; the inviter's agent may be offline — retry `courier channel join` later")
}

// channelMsgInner is the secretbox-sealed body of a channel message.
type channelMsgInner struct {
	Body   string `json:"b"`
	SentAt int64  `json:"t"`
}

// ChannelSend seals the message under the channel secret and DMs it to
// every roster member except self.
func (c *Client) ChannelSend(channelID, body string) error {
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("message must not be empty")
	}
	cs, err := loadChannels()
	if err != nil {
		return err
	}
	ch := cs.Channels[channelID]
	if ch == nil {
		return fmt.Errorf("unknown channel %q", channelID)
	}
	key, err := channelSecretBytes(ch.Secret)
	if err != nil {
		return err
	}
	inner, err := json.Marshal(channelMsgInner{Body: body, SentAt: time.Now().Unix()})
	if err != nil {
		return err
	}
	nonce, ct, err := crypto.SealSymmetric(&key, inner)
	if err != nil {
		return err
	}
	p := channelDMPayload{
		Type:    channelMsg,
		Channel: channelID,
		Epoch:   ch.Epoch,
		Nonce:   base64.RawURLEncoding.EncodeToString(nonce),
		CT:      base64.RawURLEncoding.EncodeToString(ct),
	}
	for _, m := range ch.Roster {
		if m == c.cfg.Address {
			continue
		}
		if err := c.sendChannelDM(m, p); err != nil {
			return fmt.Errorf("send to %s: %w", m, err)
		}
	}
	appendChannelMessage(channelID, channelMessage{From: c.cfg.Address, Body: body, SentAt: time.Now().Unix()})
	return nil
}

// appendChannelMessage appends to a channel's local log (best effort,
// capped).
func appendChannelMessage(channelID string, m channelMessage) {
	_ = updateChannels(func(cs *channelStore) error {
		ch := cs.Channels[channelID]
		if ch == nil {
			return nil
		}
		ch.Messages = append(ch.Messages, m)
		if len(ch.Messages) > maxChannelMessages {
			ch.Messages = ch.Messages[len(ch.Messages)-maxChannelMessages:]
		}
		return nil
	})
}

// ChannelMessages returns the channel's local message log, oldest first.
func (c *Client) ChannelMessages(channelID string) ([]channelMessage, error) {
	cs, err := loadChannels()
	if err != nil {
		return nil, err
	}
	ch := cs.Channels[channelID]
	if ch == nil {
		return nil, fmt.Errorf("unknown channel %q", channelID)
	}
	out := make([]channelMessage, len(ch.Messages))
	copy(out, ch.Messages)
	return out, nil
}

// ChannelList returns all local channels.
func (c *Client) ChannelList() ([]*channelState, error) {
	cs, err := loadChannels()
	if err != nil {
		return nil, err
	}
	out := make([]*channelState, 0, len(cs.Channels))
	for _, ch := range cs.Channels {
		out = append(out, ch)
	}
	return out, nil
}

// ChannelRemoveMember drops a member (admin only), rotates the channel
// secret, and distributes the new secret to the remaining members — the
// removed member cannot read later messages.
func (c *Client) ChannelRemoveMember(channelID, addr string) error {
	memberAddr, err := c.cfg.ResolveRecipient(addr)
	if err != nil {
		return err
	}
	if memberAddr == c.cfg.Address {
		return fmt.Errorf("use `courier channel leave` to leave a channel yourself")
	}
	var newSecret string
	var newEpoch int64
	var roster []string
	err = updateChannels(func(cs *channelStore) error {
		ch := cs.Channels[channelID]
		if ch == nil {
			return fmt.Errorf("unknown channel %q", channelID)
		}
		if ch.Admin != c.cfg.Address {
			return fmt.Errorf("only the channel admin can remove members")
		}
		if !inChannelRoster(ch.Roster, memberAddr) {
			return fmt.Errorf("%s is not a member of %q", addr, ch.Name)
		}
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		newSecret = base64.RawURLEncoding.EncodeToString(key[:])
		newEpoch = ch.Epoch + 1
		ch.Secret = newSecret
		ch.Epoch = newEpoch
		ch.Roster = removeFromChannelRoster(ch.Roster, memberAddr)
		roster = append([]string{}, ch.Roster...)
		return nil
	})
	if err != nil {
		return err
	}
	p := channelDMPayload{
		Type:    channelRekey,
		Channel: channelID,
		Secret:  newSecret,
		Epoch:   newEpoch,
		Roster:  roster,
		Admin:   c.cfg.Address,
	}
	for _, m := range roster {
		if m == c.cfg.Address {
			continue
		}
		if err := c.sendChannelDM(m, p); err != nil {
			return fmt.Errorf("rekey to %s: %w", m, err)
		}
	}
	return nil
}

// ChannelLeave drops the local channel record and notifies the admin.
func (c *Client) ChannelLeave(channelID string) error {
	cs, err := loadChannels()
	if err != nil {
		return err
	}
	ch := cs.Channels[channelID]
	if ch == nil {
		return fmt.Errorf("unknown channel %q", channelID)
	}
	admin := ch.Admin
	if err := updateChannels(func(cs *channelStore) error {
		delete(cs.Channels, channelID)
		return nil
	}); err != nil {
		return err
	}
	if admin != c.cfg.Address {
		_ = c.sendChannelDM(admin, channelDMPayload{Type: channelLeave, Channel: channelID})
	}
	return nil
}

// ---- inbound channel protocol ----

// handleChannelDM consumes one channel protocol direct message from from.
// Malformed or unauthorized payloads are ignored; anything that is not a
// well-formed channel payload never reaches here (parseChannelDMPayload
// falls through to ordinary delivery).
func (c *Client) handleChannelDM(from string, p channelDMPayload) {
	switch p.Type {
	case channelJoinRequest:
		c.handleChannelJoinRequest(from, p)
	case channelJoinAccept:
		c.handleChannelJoinAccept(from, p)
	case channelMsg:
		c.handleChannelMsg(from, p)
	case channelRekey:
		c.handleChannelRekey(from, p)
	case channelLeave:
		_ = updateChannels(func(cs *channelStore) error {
			if ch := cs.Channels[p.Channel]; ch != nil {
				ch.Roster = removeFromChannelRoster(ch.Roster, from)
			}
			return nil
		})
	}
}

// handleChannelJoinRequest validates a join request against a pending
// invite and, on success, adds the joiner to the roster and DMs back the
// channel state. The invite is single-use. A joiner who is a named
// contact is marked verified: code possession is the OOB ceremony.
func (c *Client) handleChannelJoinRequest(from string, p channelDMPayload) {
	secretRaw, err := base64.RawURLEncoding.DecodeString(p.Secret)
	if err != nil || len(secretRaw) != joinCodeBytes {
		return
	}
	var accept channelDMPayload
	err = updateChannels(func(cs *channelStore) error {
		inv := cs.Invites[p.Secret]
		if inv == nil || inv.Used {
			return fmt.Errorf("no such invite")
		}
		if time.Now().Unix()-inv.CreatedAt > channelInviteTTL {
			return fmt.Errorf("invite expired")
		}
		ch := cs.Channels[inv.ChannelID]
		if ch == nil || ch.Admin != c.cfg.Address {
			return fmt.Errorf("no such channel")
		}
		inv.Used = true
		if !inChannelRoster(ch.Roster, from) {
			ch.Roster = append(ch.Roster, from)
		}
		accept = channelDMPayload{
			Type:    channelJoinAccept,
			Channel: ch.ID,
			Secret:  ch.Secret,
			Epoch:   ch.Epoch,
			Name:    ch.Name,
			Roster:  append([]string{}, ch.Roster...),
			Admin:   ch.Admin,
		}
		return nil
	})
	if err != nil {
		return
	}
	_ = c.sendChannelDM(from, accept)
	// Best effort: the joiner proved possession of an OOB code, which is
	// the verification ceremony (phase 1).
	_ = c.MarkContactVerifiedByAddress(from)
}

// handleChannelJoinAccept stores the channel from a join-accept DM. The
// accept must come from the inviter we asked, while our request is still
// pending, and the roster must contain both parties.
func (c *Client) handleChannelJoinAccept(from string, p channelDMPayload) {
	if _, err := crypto.ParseAddress(from); err != nil {
		return
	}
	if _, err := channelSecretBytes(p.Secret); err != nil {
		return
	}
	if p.Admin != from {
		return
	}
	if !inChannelRoster(p.Roster, from) || !inChannelRoster(p.Roster, c.cfg.Address) {
		return
	}
	if p.Epoch <= 0 || strings.TrimSpace(p.Name) == "" {
		return
	}
	joined := false
	_ = updateChannels(func(cs *channelStore) error {
		ts, ok := cs.Pending[from]
		if !ok || time.Now().Unix()-ts > 600 {
			return fmt.Errorf("no pending join")
		}
		if _, exists := cs.Channels[p.Channel]; exists {
			delete(cs.Pending, from)
			return nil // idempotent: already joined
		}
		cs.Channels[p.Channel] = &channelState{
			ID:       p.Channel,
			Name:     p.Name,
			Secret:   p.Secret,
			Epoch:    p.Epoch,
			Roster:   append([]string{}, p.Roster...),
			Admin:    p.Admin,
			JoinedAt: time.Now().Unix(),
		}
		delete(cs.Pending, from)
		joined = true
		return nil
	})
	if !joined {
		return
	}
	// The inviter gave us a code out of band: verification ceremony
	// complete (phase 1).
	_ = c.MarkContactVerifiedByAddress(from)
}

// handleChannelMsg decrypts a channel message and appends it to the
// local log. Messages from non-members or on a stale epoch are dropped.
func (c *Client) handleChannelMsg(from string, p channelDMPayload) {
	nonce, err1 := base64.RawURLEncoding.DecodeString(p.Nonce)
	ct, err2 := base64.RawURLEncoding.DecodeString(p.CT)
	if err1 != nil || err2 != nil {
		return
	}
	var body string
	var sentAt int64
	_ = updateChannels(func(cs *channelStore) error {
		ch := cs.Channels[p.Channel]
		if ch == nil || !inChannelRoster(ch.Roster, from) {
			return fmt.Errorf("not a member")
		}
		if p.Epoch != ch.Epoch {
			return fmt.Errorf("stale epoch")
		}
		key, err := channelSecretBytes(ch.Secret)
		if err != nil {
			return err
		}
		plain, err := crypto.OpenSymmetric(key[:], nonce, ct)
		if err != nil {
			return err
		}
		var inner channelMsgInner
		if err := json.Unmarshal(plain, &inner); err != nil || strings.TrimSpace(inner.Body) == "" {
			return fmt.Errorf("bad inner message")
		}
		body = inner.Body
		sentAt = inner.SentAt
		ch.Messages = append(ch.Messages, channelMessage{From: from, Body: body, SentAt: sentAt})
		if len(ch.Messages) > maxChannelMessages {
			ch.Messages = ch.Messages[len(ch.Messages)-maxChannelMessages:]
		}
		return nil
	})
}

// handleChannelRekey applies an admin's secret rotation. Only the admin's
// DM is honored, and only forward in epoch.
func (c *Client) handleChannelRekey(from string, p channelDMPayload) {
	if _, err := channelSecretBytes(p.Secret); err != nil {
		return
	}
	_ = updateChannels(func(cs *channelStore) error {
		ch := cs.Channels[p.Channel]
		if ch == nil || from != ch.Admin {
			return fmt.Errorf("not admin")
		}
		if p.Epoch <= ch.Epoch {
			return fmt.Errorf("stale epoch")
		}
		for _, m := range p.Roster {
			if _, err := crypto.ParseAddress(m); err != nil {
				return fmt.Errorf("bad roster")
			}
		}
		if !inChannelRoster(p.Roster, c.cfg.Address) {
			return fmt.Errorf("removed")
		}
		ch.Secret = p.Secret
		ch.Epoch = p.Epoch
		ch.Roster = append([]string{}, p.Roster...)
		return nil
	})
}
