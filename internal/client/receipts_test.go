// Opt-in delivery/read receipt tests (issue #52).
package client

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestParseReceiptDMPayload: only well-formed receipt payloads are
// intercepted; anything else falls through to ordinary delivery.
func TestParseReceiptDMPayload(t *testing.T) {
	mk := func(s string) []byte { return []byte(s) }
	if p, ok := parseReceiptDMPayload(mk(`{"cr":3,"t":"delivery","m":42,"at":1700000000}`)); !ok || p.Type != receiptDelivery || p.MsgID != 42 {
		t.Fatal("valid delivery receipt not recognized")
	}
	if p, ok := parseReceiptDMPayload(mk(`{"cr":3,"t":"read","m":7,"at":1700000001}`)); !ok || p.Type != receiptRead {
		t.Fatal("valid read receipt not recognized")
	}
	for _, bad := range []string{
		``,
		`not json`,
		`{"cr":2,"t":"delivery","m":1,"at":1}`,  // channel magic, not receipt
		`{"cr":1,"t":"delivery","m":1,"at":1}`,  // group magic, not receipt
		`{"cr":3,"t":"bogus","m":1,"at":1}`,     // unknown type
		`{"cr":3,"t":"delivery","at":1}`,        // missing msg id
		`{"cr":3,"t":"delivery","m":0,"at":1}`,  // zero msg id
		`{"cr":3,"t":"delivery","m":1}`,         // missing at
		`{"cr":3,"t":"delivery","m":-5,"at":1}`, // negative msg id
		`{"cr":3}`,                              // no type
		`{"t":"delivery","m":1,"at":1}`,         // no magic
		`{"hello":"world"}`,                     // chat JSON
	} {
		if _, ok := parseReceiptDMPayload(mk(bad)); ok {
			t.Fatalf("payload %q intercepted", bad)
		}
	}
}

// TestReceiptsDefaultOff: a fresh identity has receipts disabled for
// every address — read activity can never leak without an explicit
// opt-in.
func TestReceiptsDefaultOff(t *testing.T) {
	cfg := testConfig(t)
	if cfg.ReceiptsEnabledFor("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("receipts enabled by default")
	}
	if len(cfg.ReceiptContacts) != 0 {
		t.Fatalf("ReceiptContacts = %v, want empty", cfg.ReceiptContacts)
	}
}

// TestReceiptOptInSetClear exercises the explicit opt-in/opt-out and
// the contact-removal cleanup.
func TestReceiptOptInSetClear(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	bob := e.bCfg.Address
	if err := e.aCfg.AddContact("bob", bob); err != nil {
		t.Fatal(err)
	}
	if e.aCfg.ReceiptsEnabledFor(bob) {
		t.Fatal("receipts on before opt-in")
	}
	if err := e.aCfg.SetReceiptsOptIn(bob, true); err != nil {
		t.Fatal(err)
	}
	if !e.aCfg.ReceiptsEnabledFor(bob) {
		t.Fatal("receipts not enabled after opt-in")
	}
	// Reloaded config keeps the choice.
	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.ReceiptsEnabledFor(bob) {
		t.Fatal("opt-in not persisted")
	}
	if err := e.aCfg.SetReceiptsOptIn(bob, false); err != nil {
		t.Fatal(err)
	}
	if e.aCfg.ReceiptsEnabledFor(bob) {
		t.Fatal("receipts still on after opt-out")
	}
	// Re-enable, then remove the contact: the opt-in must go with it.
	if err := e.aCfg.SetReceiptsOptIn(bob, true); err != nil {
		t.Fatal(err)
	}
	if err := e.aCfg.RemoveContact("bob"); err != nil {
		t.Fatal(err)
	}
	if e.aCfg.ReceiptsEnabledFor(bob) {
		t.Fatal("receipt opt-in survived contact removal")
	}
}

// TestReceiptsNotSentWhenDisabled: with receipts off (the default), a
// delivered message produces no receipt traffic at all.
func TestReceiptsNotSentWhenDisabled(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	id, err := e.alice.Send(e.bCfg.Address, "no receipts please")
	if err != nil {
		t.Fatal(err)
	}
	if id <= 0 {
		t.Fatalf("send id = %d", id)
	}
	// Bob reads the message with receipts disabled (default).
	e.asBob()
	var bCursor int64
	msgs := e.syncPersonal(e.bob, e.bCfg, &bCursor)
	if len(msgs) != 1 {
		t.Fatalf("bob got %d messages, want 1", len(msgs))
	}
	// Bob's sent-receipt dedup table must be empty: nothing fired.
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Sent) != 0 {
		t.Fatalf("receipts fired while disabled: %v", rs.Sent)
	}
	// Alice sees nothing new: no receipt DMs arrived.
	e.asAlice()
	var aCursor int64
	aMsgs := e.syncPersonal(e.alice, e.aCfg, &aCursor)
	if len(aMsgs) != 0 {
		t.Fatalf("alice got %d messages, want 0 (no receipts)", len(aMsgs))
	}
}

// TestReceiptRoundTrip exercises the full issue #52 flow against a real
// relay: opt in both ways, send, inbox delivery fires a delivery
// receipt, surfacing fires a read receipt, the sender records both, and
// receipt DMs never surface as chat or enter the sent log.
func TestReceiptRoundTrip(t *testing.T) {
	e := newGroupTestEnv(t)

	// Mutual contacts + mutual opt-in.
	e.asAlice()
	if err := e.aCfg.AddContact("bob", e.bCfg.Address); err != nil {
		t.Fatal(err)
	}
	if err := e.aCfg.SetReceiptsOptIn(e.bCfg.Address, true); err != nil {
		t.Fatal(err)
	}
	e.asBob()
	if err := e.bCfg.AddContact("alice", e.aCfg.Address); err != nil {
		t.Fatal(err)
	}
	if err := e.bCfg.SetReceiptsOptIn(e.aCfg.Address, true); err != nil {
		t.Fatal(err)
	}

	// Alice sends bob a message.
	e.asAlice()
	id, err := e.alice.Send(e.bCfg.Address, "receipts round trip")
	if err != nil {
		t.Fatal(err)
	}

	// Bob's inbox delivers it: the delivery receipt fires automatically.
	e.asBob()
	var bCursor int64
	msgs := e.syncPersonal(e.bob, e.bCfg, &bCursor)
	if len(msgs) != 1 || msgs[0].Body != "receipts round trip" {
		t.Fatalf("bob got %d messages, want the chat message", len(msgs))
	}

	// Bob surfaces the message: the read receipt fires.
	e.bob.SendReadReceipts(msgs)

	// Alice's inbox consumes both receipt DMs silently.
	e.asAlice()
	var aCursor int64
	aMsgs := e.syncPersonal(e.alice, e.aCfg, &aCursor)
	if len(aMsgs) != 0 {
		t.Fatalf("alice got %d chat messages, want 0 (receipts are silent)", len(aMsgs))
	}

	// Both receipts recorded against the sent envelope.
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	rec := rs.Received[receivedReceiptKey(e.bCfg.Address, id)]
	if rec == nil {
		t.Fatal("no receipt record for the sent message")
	}
	if rec.DeliveryAt <= 0 {
		t.Fatal("delivery receipt not recorded")
	}
	if rec.ReadAt <= 0 {
		t.Fatal("read receipt not recorded")
	}
	if rec.ReadAt < rec.DeliveryAt {
		t.Fatal("read recorded before delivery")
	}

	// ReceiptsStatus surfaces them for the CLI.
	infos, err := e.alice.ReceiptsStatus("")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("ReceiptsStatus = %d entries, want 1", len(infos))
	}
	if infos[0].DeliveryAt != rec.DeliveryAt || infos[0].ReadAt != rec.ReadAt {
		t.Fatal("ReceiptsStatus does not reflect recorded receipts")
	}
	if infos[0].ContactName != "bob" {
		t.Fatalf("ContactName = %q, want bob", infos[0].ContactName)
	}

	// Receipt DMs never entered the sent log (machine traffic only).
	sent, err := readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent log has %d entries, want 1 (receipts excluded)", len(sent))
	}
	for _, en := range sent {
		if strings.Contains(en.Body, `"cr":3`) {
			t.Fatal("receipt payload leaked into the sent log")
		}
	}
}

// TestReceiptUnknownEnvelopeDropped: a receipt referencing an envelope
// this client never sent is dropped, never recorded.
func TestReceiptUnknownEnvelopeDropped(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	if _, err := e.alice.Send(e.bCfg.Address, "ping"); err != nil {
		t.Fatal(err)
	}
	e.alice.handleReceiptDM(e.bCfg.Address, receiptDMPayload{
		Magic: receiptDMMagic, Type: receiptDelivery, MsgID: 999999, At: time.Now().Unix(),
	})
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Received) != 0 {
		t.Fatalf("receipt for unknown envelope recorded: %v", rs.Received)
	}
}

// TestReceiptBadTimestampsDropped: receipts dated before the message was
// sent, or absurdly in the future, are dropped.
func TestReceiptBadTimestampsDropped(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	id, err := e.alice.Send(e.bCfg.Address, "ping")
	if err != nil {
		t.Fatal(err)
	}
	sent, err := readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	var sentAt int64
	for i := range sent {
		if sent[i].CourierID == id {
			sentAt = sent[i].SentAt
		}
	}
	if sentAt == 0 {
		t.Fatal("sent entry not found")
	}
	e.alice.handleReceiptDM(e.bCfg.Address, receiptDMPayload{
		Magic: receiptDMMagic, Type: receiptDelivery, MsgID: id, At: sentAt - 100,
	})
	e.alice.handleReceiptDM(e.bCfg.Address, receiptDMPayload{
		Magic: receiptDMMagic, Type: receiptDelivery, MsgID: id, At: time.Now().Unix() + 3600,
	})
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Received) != 0 {
		t.Fatalf("receipt with bad timestamp recorded: %v", rs.Received)
	}
}

// TestReceiptReplayIdempotent: replays of the same receipt do not move
// the recorded timestamps.
func TestReceiptReplayIdempotent(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	id, err := e.alice.Send(e.bCfg.Address, "ping")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Unix()
	p := receiptDMPayload{Magic: receiptDMMagic, Type: receiptDelivery, MsgID: id, At: at}
	e.alice.handleReceiptDM(e.bCfg.Address, p)
	// A "later" replay of the same receipt type must not overwrite.
	e.alice.handleReceiptDM(e.bCfg.Address, receiptDMPayload{
		Magic: receiptDMMagic, Type: receiptDelivery, MsgID: id, At: at + 500,
	})
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	rec := rs.Received[receivedReceiptKey(e.bCfg.Address, id)]
	if rec == nil || rec.DeliveryAt != at {
		t.Fatalf("replay moved the receipt timestamp: %+v", rec)
	}
}

// TestReceiptSentDedup: each (peer, envelope, type) receipt fires at
// most once, even if delivery/surfacing is re-attempted.
func TestReceiptSentDedup(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	if err := e.aCfg.SetReceiptsOptIn(e.bCfg.Address, true); err != nil {
		t.Fatal(err)
	}
	// Send twice directly: the second send must be a no-op.
	if err := e.alice.sendReceipt(e.bCfg.Address, 123, receiptRead); err != nil {
		t.Fatal(err)
	}
	if err := e.alice.sendReceipt(e.bCfg.Address, 123, receiptRead); err != nil {
		t.Fatal(err)
	}
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Sent) != 1 {
		t.Fatalf("Sent = %d entries, want 1", len(rs.Sent))
	}
}

// TestPruneReceiptStore: both tables stay bounded.
func TestPruneReceiptStore(t *testing.T) {
	e := newGroupTestEnv(t)
	e.asAlice()
	if err := updateReceipts(func(rs *receiptStore) error {
		for i := 0; i < maxReceiptRecords+100; i++ {
			rs.Received[receivedReceiptKey("ed25519:x", int64(i))] = &receiptRecord{DeliveryAt: int64(1000 + i)}
		}
		for i := 0; i < maxSentReceipts+100; i++ {
			rs.Sent[sentReceiptKey("ed25519:x", int64(i), receiptDelivery)] = int64(1000 + i)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rs, err := loadReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Received) != maxReceiptRecords {
		t.Fatalf("Received = %d, want %d", len(rs.Received), maxReceiptRecords)
	}
	if len(rs.Sent) != maxSentReceipts {
		t.Fatalf("Sent = %d, want %d", len(rs.Sent), maxSentReceipts)
	}
	// Newest entries survive pruning.
	if rs.Received[receivedReceiptKey("ed25519:x", int64(maxReceiptRecords+99))] == nil {
		t.Fatal("newest received record pruned")
	}
}

// TestReceiptPayloadRoundTrip: marshal -> parse is the identity.
func TestReceiptPayloadRoundTrip(t *testing.T) {
	p := receiptDMPayload{Magic: receiptDMMagic, Type: receiptRead, MsgID: 99, At: 1700000000}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back, ok := parseReceiptDMPayload(raw)
	if !ok {
		t.Fatal("marshaled payload not recognized")
	}
	if back != p {
		t.Fatalf("round trip = %+v, want %+v", back, p)
	}
}
