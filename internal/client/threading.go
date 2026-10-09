// Reply threading (issue #51): in-conversation reply references.
//
// A reply carries the relay envelope ID of its parent inside the
// E2E-encrypted DM plaintext — no relay changes, no new endpoints.
// The v2 message payload extends the v1 attachment payload:
//
//	{"v":2,"body":"<text>","reply_to":42,"quote":"<parent snippet>","attachments":[...]}
//
// reply_to/quote/attachments are all optional. v1 keeps its exact
// legacy semantics (attachments only), and attachment-only sends still
// emit v1 byte-for-byte so old clients render them unchanged. Anything
// that is not a recognized payload version falls back to legacy raw
// text: old clients display a v2 reply's JSON as chat text (harmless,
// the established precedent for introduction DMs), and new clients never choke on foreign payloads.
package client

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/vhl"
)

// replyPayloadVersion is the DM plaintext payload version carrying
// reply threading metadata.
const replyPayloadVersion = 2

// replyPayload is the v2 wire form of a chat message: body text plus
// optional reply threading metadata, optional attachments, and an
// optional disappearing-message expiry (issue #53). The optional Bridge
// field (issue #61) carries bridge attribution for messages relayed
// from ChatGPT web; it is additive and ignored by pre-bridge clients,
// which render the banner-in-body per existing v2 handling.
type replyPayload struct {
	Version     int                           `json:"v"`
	Body        string                        `json:"body"`
	ReplyTo     int64                         `json:"reply_to,omitempty"`
	Quote       string                        `json:"quote,omitempty"`
	Attachments []envelope.AttachmentManifest `json:"attachments,omitempty"`
	ExpiresAt   int64                         `json:"expires_at,omitempty"`
	Bridge      *bridge.BridgeMeta            `json:"bridge,omitempty"`
	// issue #142: VHL tier tag + inline attestation, inside the E2E
	// ciphertext so the tag is sender-authenticated.
	VHLTier int              `json:"vhl_tier,omitempty"`
	VHL     *vhl.Attestation `json:"vhl,omitempty"`
}

// replyInfo is the threading metadata parsed out of a received message:
// the parent relay envelope id (0 when the message is not a reply) and
// the sender-provided parent snippet ("" when unknown).
type replyInfo struct {
	To    int64
	Quote string
}

// maxReplyQuoteLen bounds the parent snippet stored in a reply payload
// and in the local reply cache: long enough to quote meaningfully,
// short enough that a malicious or buggy peer cannot stuff megabytes
// of quote into a message.
const maxReplyQuoteLen = 500

// truncateQuote trims a parent snippet to a single line of at most
// maxReplyQuoteLen bytes (cut on a rune boundary, never mid-rune),
// collapsing internal whitespace. Quotes are display hints, not
// content: lossy is fine, unbounded is not.
func truncateQuote(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxReplyQuoteLen {
		return s
	}
	// Cut on a rune boundary.
	for len(s) > maxReplyQuoteLen {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// encodeMessageBody builds the DM plaintext: legacy raw text for plain
// messages, the v1 attachment/expiry payload when attachments or a TTL
// ride along, or the v2 reply payload (issue #51) when threading
// metadata is present. Attachment-only sends keep the exact legacy v1
// wire so old clients render them unchanged; TTL-only sends use the
// v1+expires_at form from #53.
func encodeMessageBody(body string, manifests []envelope.AttachmentManifest, replyTo int64, quote string, expiresAt int64) ([]byte, error) {
	switch {
	case replyTo > 0:
		return encodeReplyPayload(body, replyTo, quote, manifests, expiresAt)
	case len(manifests) > 0 || expiresAt != 0:
		return json.Marshal(messagePayload{Version: 1, Body: body, Attachments: manifests, ExpiresAt: expiresAt})
	default:
		return []byte(body), nil
	}
}

// encodeReplyPayload builds the v2 plaintext for a reply: body plus the
// parent envelope id and the best-effort parent snippet. Attachments and
// a TTL expiry may ride along; callers that have attachments or an
// expiry but no reply keep emitting the legacy v1 payload (see
// encodeMessageBody).
func encodeReplyPayload(body string, replyTo int64, quote string, manifests []envelope.AttachmentManifest, expiresAt int64) ([]byte, error) {
	return json.Marshal(replyPayload{
		Version:     replyPayloadVersion,
		Body:        body,
		ReplyTo:     replyTo,
		Quote:       truncateQuote(quote),
		Attachments: manifests,
		ExpiresAt:   expiresAt,
	})
}

// parseReplyPayload decodes a v2 reply payload. ok=false when the
// plaintext is not a well-formed v2 payload (wrong version, missing
// body); the caller then falls back to raw-text rendering. A present
// but non-positive reply_to is normalized to "not a reply" rather than
// failing the message.
func parseReplyPayload(plain []byte) (p replyPayload, ok bool) {
	if err := json.Unmarshal(plain, &p); err != nil {
		return p, false
	}
	if p.Version != replyPayloadVersion {
		return p, false
	}
	if p.ReplyTo < 0 {
		p.ReplyTo = 0
	}
	p.Quote = truncateQuote(p.Quote)
	return p, true
}

// replyCacheEntry is one locally remembered inbound message, kept so a
// reply's parent can be quoted without a relay round-trip.
type replyCacheEntry struct {
	CourierID int64  `json:"courier_id"`
	From      string `json:"from"`
	Snippet   string `json:"snippet"`
	SentAt    int64  `json:"sent_at"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// maxReplyCache is the cap on the local reply cache; older entries are
// dropped, mirroring maxSentLog.
const maxReplyCache = 1000

func replyCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "thread_cache.jsonl"), nil
}

// readReplyCache returns cached entries, oldest first. A missing or
// corrupt file yields no entries, never an error: the cache is a
// best-effort accelerator.
func readReplyCache() []replyCacheEntry { return readReplyCacheAt(time.Now().Unix()) }

// Old records without expiry metadata cannot be retroactively classified.
// Even when locking or physical pruning fails, expired plaintext is never returned.
func readReplyCacheAt(now int64) []replyCacheEntry {
	p, err := replyCachePath()
	if err != nil {
		return nil
	}
	var out []replyCacheEntry
	entered := false
	_ = withConfigLock(func() error {
		entered = true
		var expired bool
		out, expired = readReplyCacheLocked(p, now)
		if expired {
			return replaceReplyCacheLocked(p, out)
		}
		return nil
	})
	if !entered {
		out, _ = readReplyCacheLocked(p, now)
	}
	return out
}

func readReplyCacheLocked(p string, now int64) ([]replyCacheEntry, bool) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var out []replyCacheEntry
	expired := false
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var e replyCacheEntry
		if json.Unmarshal(line, &e) != nil || e.CourierID <= 0 {
			continue
		}
		if stateExpired(now, e.ExpiresAt) {
			expired = true
			continue
		}
		out = append(out, e)
	}
	return out, expired
}

// Caller holds the config lock. Same-directory replacement never exposes a
// partially written cache and newly created files are private from creation.
func replaceReplyCacheLocked(p string, entries []replyCacheEntry) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".thread-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

// writeReplyCache merges under the same cross-process lock as pruning.
// Empty input still performs expiry maintenance. Cache failures never fail delivery.
func writeReplyCache(entries []replyCacheEntry) { writeReplyCacheAt(entries, time.Now().Unix()) }

func writeReplyCacheAt(entries []replyCacheEntry, now int64) {
	p, err := replyCachePath()
	if err != nil {
		return
	}
	_ = withConfigLock(func() error {
		existing, expired := readReplyCacheLocked(p, now)
		if len(entries) == 0 && !expired {
			return nil
		}
		merged := make(map[int64]replyCacheEntry)
		var order []int64
		for _, batch := range [][]replyCacheEntry{existing, entries} {
			for _, e := range batch {
				if e.CourierID <= 0 || stateExpired(now, e.ExpiresAt) {
					continue
				}
				if _, ok := merged[e.CourierID]; !ok {
					order = append(order, e.CourierID)
				}
				merged[e.CourierID] = e
			}
		}
		if len(order) > maxReplyCache {
			order = order[len(order)-maxReplyCache:]
		}
		out := make([]replyCacheEntry, 0, len(order))
		for _, id := range order {
			out = append(out, merged[id])
		}
		return replaceReplyCacheLocked(p, out)
	})
}

// LookupReplyParent resolves the best-effort parent snippet for a reply
// target: the local sent log first (my own outbound messages), then the
// reply cache (inbound messages seen on this machine). ok=false when
// the parent is unknown locally — the reply is still sent, referencing
// the id; the recipient may resolve it from their own state.
func LookupReplyParent(replyTo int64) (quote string, ok bool) {
	return lookupReplyParentAt(replyTo, time.Now().Unix())
}

func lookupReplyParentAt(replyTo, now int64) (quote string, ok bool) {
	if replyTo <= 0 {
		return "", false
	}
	if sent, err := readSentLog(); err == nil {
		for i := len(sent) - 1; i >= 0; i-- {
			if sent[i].CourierID == replyTo && sent[i].Body != "" {
				return truncateQuote(sent[i].Body), true
			}
		}
	}
	for _, e := range readReplyCacheAt(now) {
		if e.CourierID == replyTo && e.Snippet != "" {
			return e.Snippet, true
		}
	}
	return "", false
}
