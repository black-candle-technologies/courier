// Opt-in delivery receipts (issue #52).
//
// Receipts are strictly opt-in per contact: nothing about the reader's
// activity ever leaves the machine unless the reader explicitly enabled
// receipts for the sender (`courier contacts delivery-receipts-on
// <name>`). Default is off everywhere.
//
// A receipt is an ordinary encrypted DM envelope (kind "dm") carrying a
// small JSON payload with the receipt magic, so the relay sees only
// standard envelope metadata — sender, recipient, timestamp — and
// cannot tell a receipt from chat. The envelope's Ed25519 signature
// authenticates `from`; replay safety comes from the per-consumer seen
// sets plus local (sender, envelope) dedup. Receipts are machine
// protocol traffic: they are sent via sendProtocolDM (never logged to
// ~/.courier/sent.jsonl) and consumed silently, never surfaced as chat.
//
// The only receipt type is "delivery": the inbox consumer first
// delivered the envelope. Read receipts were cut pre-launch (#146) —
// delivery confirmation is the whole feature. Receipt payloads of type
// "read" from older clients are recognized and silently dropped so they
// never surface as chat text.
//
// Held message requests never generate receipts; group messages are out
// of scope. Dashboard thread opens are future work (the dashboard
// server holds no keys to sign with).
package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// ---- wire format ----

// receiptDMMagic marks direct messages that belong to the receipt
// protocol layer. Group is 1 (cg), channel is 2 (cc); receipts are 3.
const receiptDMMagic = 3

// Receipt types. Only "delivery" is emitted; "read" is recognized for
// backward compatibility with older clients and silently dropped —
// read receipts were cut pre-launch (#146).
const (
	receiptDelivery = "delivery"
	receiptRead     = "read" // retired; recognized, never recorded
)

// receiptDMPayload is the wire format for receipt protocol direct
// messages. MsgID is the relay envelope id of the acknowledged message;
// At is unix seconds when the receipt was generated.
type receiptDMPayload struct {
	Magic int    `json:"cr"`
	Type  string `json:"t"`
	MsgID int64  `json:"m"`
	At    int64  `json:"at"`
}

// parseReceiptDMPayload returns the receipt protocol payload if plain is
// one, and false otherwise. Only well-formed payloads with a recognized
// type are intercepted; anything else falls through as an ordinary
// message — never silently swallowed.
func parseReceiptDMPayload(plain []byte) (receiptDMPayload, bool) {
	var p receiptDMPayload
	if json.Unmarshal(plain, &p) != nil {
		return p, false
	}
	if p.Magic != receiptDMMagic || p.Type == "" || p.MsgID <= 0 || p.At <= 0 {
		return p, false
	}
	switch p.Type {
	case receiptDelivery, receiptRead:
		return p, true
	}
	return p, false
}

// ---- opt-in state (config.json) ----

// ReceiptsEnabledFor reports whether this agent opted into sending
// delivery receipts to the given address (issue #52). Default is
// off: receipts never leave the machine unless explicitly enabled with
// `courier contacts delivery-receipts-on <name>`.
func (c *Config) ReceiptsEnabledFor(address string) bool {
	return c.ReceiptContacts[address]
}

// SetReceiptsOptIn records the per-contact receipt opt-in choice.
// Enabling is always an explicit user action; disabling is always
// allowed and also happens implicitly when the contact is removed.
func (c *Config) SetReceiptsOptIn(address string, on bool) error {
	if _, err := crypto.ParseAddress(address); err != nil {
		return fmt.Errorf("bad address: %w", err)
	}
	return c.Update(func(fresh *Config) error {
		if on {
			if fresh.ReceiptContacts == nil {
				fresh.ReceiptContacts = map[string]bool{}
			}
			fresh.ReceiptContacts[address] = true
		} else {
			delete(fresh.ReceiptContacts, address)
		}
		return nil
	})
}

// contactNameForAddress returns the contact name for an address, or ""
// when the address is not a named contact.
func (c *Config) contactNameForAddress(address string) string {
	for name, addr := range c.Contacts {
		if addr == address {
			return name
		}
	}
	return ""
}

// ---- receipt traffic state (~/.courier/receipts.json) ----

// receiptRecord is the received-receipt state for one sent message:
// the first delivery timestamp reported by the peer.
type receiptRecord struct {
	DeliveryAt int64 `json:"delivery_at,omitempty"`
}

// receiptStore is the whole receipts.json document.
type receiptStore struct {
	// Received maps "peer-address|envelope-id" to the receipts the peer
	// sent back for my outbound message.
	Received map[string]*receiptRecord `json:"received,omitempty"`
	// Sent maps "peer-address|envelope-id|type" to the unix time I sent
	// that receipt: dedup so each receipt fires at most once.
	Sent map[string]int64 `json:"sent,omitempty"`
}

// maxReceiptRecords bounds the received-receipt table; maxSentReceipts
// bounds the sent-receipt dedup table. Oldest entries are pruned.
const (
	maxReceiptRecords = 500
	maxSentReceipts   = 2000
)

// receiptClockSkew is the tolerated future skew on a receipt's `at`
// timestamp before it is rejected as absurd.
const receiptClockSkew = 300

func receiptsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "receipts.json"), nil
}

func receivedReceiptKey(peer string, msgID int64) string {
	return fmt.Sprintf("%s|%d", peer, msgID)
}

func sentReceiptKey(peer string, msgID int64) string {
	return fmt.Sprintf("%s|%d", peer, msgID)
}

func loadReceiptsLocked() (*receiptStore, error) {
	p, err := receiptsFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &receiptStore{
				Received: map[string]*receiptRecord{},
				Sent:     map[string]int64{},
			}, nil
		}
		return nil, err
	}
	var rs receiptStore
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	if rs.Received == nil {
		rs.Received = map[string]*receiptRecord{}
	}
	if rs.Sent == nil {
		rs.Sent = map[string]int64{}
	}
	return &rs, nil
}

func saveReceiptsLocked(rs *receiptStore) error {
	p, err := receiptsFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "receipts-*.tmp")
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

// updateReceipts performs an atomic read-modify-write of receipts.json
// under the cross-process config lock (same discipline as channels.json
// and Config.Update), pruning both tables to their bounds afterwards.
func updateReceipts(fn func(*receiptStore) error) error {
	return withConfigLock(func() error {
		rs, err := loadReceiptsLocked()
		if err != nil {
			return err
		}
		if err := fn(rs); err != nil {
			return err
		}
		pruneReceiptStore(rs)
		return saveReceiptsLocked(rs)
	})
}

// loadReceipts returns a copy of the receipt store.
func loadReceipts() (*receiptStore, error) {
	var rs *receiptStore
	if err := withConfigLock(func() error {
		var err error
		rs, err = loadReceiptsLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return rs, nil
}

func receiptLastTouch(r *receiptRecord) int64 {
	return r.DeliveryAt
}

// pruneReceiptStore drops the oldest entries beyond the table bounds.
func pruneReceiptStore(rs *receiptStore) {
	if len(rs.Received) > maxReceiptRecords {
		keys := make([]string, 0, len(rs.Received))
		for k := range rs.Received {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return receiptLastTouch(rs.Received[keys[i]]) < receiptLastTouch(rs.Received[keys[j]])
		})
		for _, k := range keys[:len(keys)-maxReceiptRecords] {
			delete(rs.Received, k)
		}
	}
	if len(rs.Sent) > maxSentReceipts {
		keys := make([]string, 0, len(rs.Sent))
		for k := range rs.Sent {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return rs.Sent[keys[i]] < rs.Sent[keys[j]] })
		for _, k := range keys[:len(keys)-maxSentReceipts] {
			delete(rs.Sent, k)
		}
	}
}

// ---- sending receipts ----

// sendDeliveryReceipt fires a delivery receipt for one newly delivered
// envelope. It is idempotent: each (peer, envelope) fires at most once,
// recorded before sending so a retry or concurrent delivery cannot
// double-send. The DM bypasses the sent log (sendProtocolDM): receipts
// are machine traffic, not chat. Best-effort: a receipt must never fail
// message delivery, so callers ignore the error. Callers must have
// already checked the opt-in.
//
// Note: keys written by older clients included a "|delivery" type
// suffix, so a message delivered before this upgrade may send one more
// duplicate receipt after upgrade. Harmless: the receiving side is
// idempotent.
func (c *Client) sendDeliveryReceipt(peer string, msgID int64) {
	key := sentReceiptKey(peer, msgID)
	var already bool
	if err := updateReceipts(func(rs *receiptStore) error {
		if _, ok := rs.Sent[key]; ok {
			already = true
			return nil
		}
		rs.Sent[key] = time.Now().Unix()
		return nil
	}); err != nil {
		return
	}
	if already {
		return
	}
	p := receiptDMPayload{Magic: receiptDMMagic, Type: receiptDelivery, MsgID: msgID, At: time.Now().Unix()}
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	_, _ = c.sendProtocolDM(peer, string(raw))
}

// ---- receiving receipts ----

// handleReceiptDM consumes one receipt protocol direct message from
// from. The envelope signature already authenticated `from`; the receipt
// is recorded only if it references a sent envelope this client can find
// (matching courier id and recipient) and carries a sane timestamp —
// receipts for unknown envelopes are dropped, never displayed.
func (c *Client) handleReceiptDM(from string, p receiptDMPayload) {
	if _, err := crypto.ParseAddress(from); err != nil {
		return
	}
	sent, err := readSentLog()
	if err != nil {
		return
	}
	var entry *SentEntry
	for i := range sent {
		if sent[i].CourierID == p.MsgID && sent[i].To == from {
			entry = &sent[i]
			break
		}
	}
	if entry == nil {
		return // not a message I sent to this peer: drop
	}
	now := time.Now().Unix()
	if p.At < entry.SentAt || p.At > now+receiptClockSkew {
		return // absurd timestamp: drop
	}
	key := receivedReceiptKey(from, p.MsgID)
	_ = updateReceipts(func(rs *receiptStore) error {
		// First receipt wins: replays are idempotent. "read" receipts
		// from older clients are recognized above but never recorded
		// (#146): read receipts were cut, and silently dropping the
		// payload keeps it from surfacing as chat text.
		switch p.Type {
		case receiptDelivery:
			rec := rs.Received[key]
			if rec == nil {
				rec = &receiptRecord{}
				rs.Received[key] = rec
			}
			if rec.DeliveryAt == 0 {
				rec.DeliveryAt = p.At
			}
		case receiptRead:
			// retired: drop silently, store nothing
		}
		return nil
	})
}

// ---- surfacing ----

// ReceiptInfo is the receipt status of one sent message.
type ReceiptInfo struct {
	CourierID   int64
	To          string
	ContactName string // "" when the recipient is not a named contact
	Body        string
	SentAt      int64
	DeliveryAt  int64 // 0 when no delivery receipt arrived
}

// ReceiptsEnabled reports whether this client opted into sending
// receipts to the given address.
func (c *Client) ReceiptsEnabled(toOrName string) (bool, error) {
	addr, err := c.cfg.ResolveRecipient(toOrName)
	if err != nil {
		return false, err
	}
	return c.cfg.ReceiptsEnabledFor(addr), nil
}

// ReceiptsStatus returns receipt status for sent messages, newest
// first. filter is an optional contact name or address limiting the
// list. Receipts from any sender are recorded; the peer's opt-in is
// their private state and is never shown.
func (c *Client) ReceiptsStatus(filter string) ([]ReceiptInfo, error) {
	var filterAddr string
	if filter != "" {
		addr, err := c.cfg.ResolveRecipient(filter)
		if err != nil {
			return nil, err
		}
		filterAddr = addr
	}
	sent, err := readSentLog()
	if err != nil {
		return nil, err
	}
	rs, err := loadReceipts()
	if err != nil {
		return nil, err
	}
	out := make([]ReceiptInfo, 0, len(sent))
	for i := len(sent) - 1; i >= 0; i-- {
		e := sent[i]
		if filterAddr != "" && e.To != filterAddr {
			continue
		}
		info := ReceiptInfo{
			CourierID:   e.CourierID,
			To:          e.To,
			ContactName: c.cfg.contactNameForAddress(e.To),
			Body:        e.Body,
			SentAt:      e.SentAt,
		}
		if rec := rs.Received[receivedReceiptKey(e.To, e.CourierID)]; rec != nil {
			info.DeliveryAt = rec.DeliveryAt
		}
		out = append(out, info)
	}
	return out, nil
}
