// Long-poll inbox subscriptions (issue #42): GET /v1/inbox/subscribe.
//
// Wake-on-message used to require an external script polling
// `courier inbox` every minute. This endpoint lets a client hold one
// signed request open and learn about a new envelope within a second
// or two of its arrival, with no polling loop and no missed-message
// risk: every response carries the messages after the caller's cursor,
// and reconnects resume from the last cursor the client persisted.
//
// Protocol:
//
//	GET /v1/inbox/subscribe?to=<addr>&cursor=<id>&ts=<unix>&sig=<b64url>
//
// The signature covers (address, cursor, ts) under a dedicated domain
// (envelope.SubscribeRequest), reusing the signed-inbox-request auth
// pattern: only the address owner can subscribe to their own inbox,
// and the freshness window is the same 300 seconds.
//
// Behavior:
//   - If envelopes are already pending after cursor, the response is
//     immediate: {"messages": [...], "timeout": false}.
//   - Otherwise the request is held until a new envelope for the
//     address is stored, or SubscribeTimeout fires, whichever comes
//     first. A timeout returns {"messages": [], "timeout": true}.
//   - "messages" has exactly the GET /v1/inbox shape, so clients reuse
//     the same parsing.
//
// Concurrency: one buffered signal channel per held subscription,
// keyed by recipient address. handleSend signals the waiters after a
// DM envelope is stored. The waiter registers before checking for
// pending messages, so a save racing the check cannot be missed: the
// signal is buffered and the waiter re-lists from its cursor.
package relay

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// SubscribeTimeout is the server-side deadline for a held subscription.
// It must stay comfortably below NAT/proxy idle timeouts and below the
// client's own HTTP timeout, so a wedged middlebox can never silently
// stall a waiter: the client simply re-subscribes after the deadline.
var SubscribeTimeout = 55 * time.Second

// maxSubscribersPerIdentity caps concurrently held subscriptions per
// recipient address. One daemon holds one; the cap only bites a buggy
// or hostile client opening subscriptions in a loop.
const maxSubscribersPerIdentity = 4

// inboxMsgJSON is one envelope in an inbox or subscribe response.
type inboxMsgJSON struct {
	ID          int64    `json:"id"`
	From        string   `json:"from"`
	Eph         string   `json:"eph"`
	Nonce       string   `json:"nonce"`
	Ct          string   `json:"ct"`
	SentAt      int64    `json:"sent_at"`
	ReceivedAt  int64    `json:"received_at"`
	Sig         string   `json:"sig"`
	SenderFlags []string `json:"sender_flags"`
}

// buildInboxPage renders stored envelopes into the /v1/inbox response
// shape, shared by the polling inbox and the long-poll subscribe
// endpoint so the two can never drift apart.
func (s *Server) buildInboxPage(envs []store.Envelope) []inboxMsgJSON {
	// Sender reputation flags (metadata-only, advisory): computed once
	// per distinct sender across the page. "rate_limited" means the
	// sender's send bucket is currently exhausted (actively bursting);
	// "reported" means the sender is currently over the distinct-reporter
	// throttle threshold. Recipients use these as machine-readable
	// reasons when triaging message requests. They are relay-asserted,
	// not signed — advisory signal, not authentication.
	senderFlags := make(map[string][]string)
	for _, e := range envs {
		if _, ok := senderFlags[e.From]; ok {
			continue
		}
		var flags []string
		if s.limiter.Exhausted("send:" + e.From) {
			flags = append(flags, "rate_limited")
		}
		if n, err := s.store.DistinctReporterCount(e.From, int64(s.cfg.SpamReportWindow.Seconds())); err == nil && n >= s.cfg.SpamReportThreshold {
			flags = append(flags, "reported")
		}
		senderFlags[e.From] = flags
	}
	out := make([]inboxMsgJSON, 0, len(envs))
	var size int
	for _, e := range envs {
		// Bound the page by encoded bytes (v0.6.11 F8): the base64url
		// fields plus JSON overhead per message. Always return at
		// least one message; pagination continues via after=lastID.
		size += len(e.From) + len(e.Eph) + len(e.Nonce) + len(e.Ct) + len(e.Sig) + 128
		if size > MaxInboxPageBytes && len(out) > 0 {
			break
		}
		out = append(out, inboxMsgJSON{
			ID: e.ID, From: e.From, Eph: e.Eph, Nonce: e.Nonce,
			Ct: e.Ct, SentAt: e.SentAt, ReceivedAt: e.ReceivedAt, Sig: e.Sig,
			SenderFlags: senderFlags[e.From],
		})
	}
	return out
}

// subscriber is one held /v1/inbox/subscribe request. ch is buffered
// (capacity 1) so a signal sent before the handler reaches select is
// not lost.
type subscriber struct {
	ch chan struct{}
}

// addSubscriber registers a waiter for to, enforcing the per-identity
// cap. The caller must call removeSubscriber when the request ends.
func (s *Server) addSubscriber(to string, sub *subscriber) bool {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	set := s.subs[to]
	if len(set) >= maxSubscribersPerIdentity {
		return false
	}
	if set == nil {
		set = make(map[*subscriber]struct{})
		s.subs[to] = set
	}
	set[sub] = struct{}{}
	return true
}

func (s *Server) removeSubscriber(to string, sub *subscriber) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	if set := s.subs[to]; set != nil {
		delete(set, sub)
		if len(set) == 0 {
			delete(s.subs, to)
		}
	}
}

// notifySubscribers wakes every held subscription for to. It is called
// after a DM envelope is durably stored; the woken handlers re-list
// from their own cursors, so a duplicate signal is harmless.
func (s *Server) notifySubscribers(to string) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for sub := range s.subs[to] {
		select {
		case sub.ch <- struct{}{}:
		default:
			// Already signaled; the handler will re-list anyway.
		}
	}
}

// handleSubscribe serves GET /v1/inbox/subscribe: a long-poll inbox
// subscription for DM envelopes addressed to the caller's identity.
// Group inboxes keep their own polling path; this endpoint is DM-only.
func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	to := q.Get("to")
	if strings.HasPrefix(to, envelope.GroupIDPrefix) {
		writeErr(w, http.StatusBadRequest, "group subscriptions are not supported; poll the group inbox")
		return
	}
	toEd, err := parseAddress(to)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to" query param: %v`, err))
		return
	}
	var cursor int64
	if c := q.Get("cursor"); c != "" {
		if _, err := fmt.Sscanf(c, "%d", &cursor); err != nil || cursor < 0 {
			writeErr(w, http.StatusBadRequest, `"cursor" must be a non-negative message id`)
			return
		}
	}

	// Signed subscription request, mirroring the inbox-request auth
	// (v0.6.11 F10): the signature binds the address, the resume
	// cursor, and a timestamp, and verifies against the "to" address
	// key — so only the address owner can hold a subscription on
	// their inbox, and a captured request cannot be replayed past
	// the freshness window.
	var ts int64
	if _, err := fmt.Sscanf(q.Get("ts"), "%d", &ts); err != nil || q.Get("ts") == "" {
		writeErr(w, http.StatusBadRequest, `"ts" must be a unix timestamp`)
		return
	}
	if now := time.Now().Unix(); ts < now-maxSignedRequestAge || ts > now+maxSignedRequestAge {
		writeErr(w, http.StatusBadRequest, `"ts" is outside the freshness window`)
		return
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	if err != nil || len(sigRaw) != 64 {
		writeErr(w, http.StatusUnauthorized, `"sig" must be a base64url Ed25519 signature`)
		return
	}
	if !crypto.Verify(toEd[:], envelope.SubscribeRequest(toEd[:], cursor, ts), sigRaw) {
		writeErr(w, http.StatusUnauthorized, "subscription request signature verification failed")
		return
	}

	// Register before checking for pending messages: a send racing
	// this check signals the buffered channel, so nothing is missed.
	sub := &subscriber{ch: make(chan struct{}, 1)}
	if !s.addSubscriber(to, sub) {
		writeErr(w, http.StatusTooManyRequests, "too many concurrent subscriptions for this address")
		return
	}
	defer s.removeSubscriber(to, sub)

	// Fast path: messages already pending at the cursor return
	// immediately, which is also what makes reconnects gap-free.
	if envs, err := s.store.List(to, cursor, MaxInboxLimit); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	} else if len(envs) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"messages": s.buildInboxPage(envs),
			"timeout":  false,
		})
		return
	}

	timer := time.NewTimer(SubscribeTimeout)
	defer timer.Stop()
	select {
	case <-sub.ch:
		envs, err := s.store.List(to, cursor, MaxInboxLimit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"messages": s.buildInboxPage(envs),
			"timeout":  false,
		})
	case <-timer.C:
		writeJSON(w, http.StatusOK, map[string]any{
			"messages": []inboxMsgJSON{},
			"timeout":  true,
		})
	case <-r.Context().Done():
		// Client went away; the deferred removeSubscriber cleans up.
		return
	}
}
