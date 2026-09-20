// Group messaging endpoints (issue #32).
//
// The relay tracks group membership through signed membership-control
// messages (POST /v1/groups/control) and enforces two rules end to end:
// only current members can post to a group (POST /v1/send with a group
// recipient) and only current members can read a group's envelopes and
// control feed (GET /v1/inbox with a group recipient and a signed
// membership authorization). The relay never sees plaintext: group
// message bodies are sealed under per-member symmetric sender keys held
// only by clients.
package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// handleGroupSend stores one group message envelope. The sender must be a
// current member of the group and must sign the group canonical bytes
// (which cover the group ID, sender-key epoch, and ciphertext) with their
// Ed25519 identity key.
func (s *Server) handleGroupSend(w http.ResponseWriter, req sendRequest) {
	groupID := req.To
	if _, err := envelope.ParseGroupID(groupID); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to": %v`, err))
		return
	}
	if req.Kind != "" && req.Kind != "group" {
		writeErr(w, http.StatusBadRequest, `"kind" must be "group" for group messages`)
		return
	}
	from, err := parseAddress(req.From)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"from": %v`, err))
		return
	}

	member, err := s.store.IsGroupMember(groupID, req.From)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !member {
		writeErr(w, http.StatusForbidden, "sender is not a current group member")
		return
	}

	eph, err := base64.RawURLEncoding.DecodeString(req.Eph)
	if err != nil || len(eph) != crypto.PubKeyLen {
		writeErr(w, http.StatusBadRequest, `"eph" must be base64url 32 random bytes`)
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != crypto.NonceLen {
		writeErr(w, http.StatusBadRequest, `"nonce" must be base64url 24-byte nonce`)
		return
	}
	ct, err := base64.RawURLEncoding.DecodeString(req.Ct)
	if err != nil {
		writeErr(w, http.StatusBadRequest, `"ct" must be base64url ciphertext`)
		return
	}
	if len(ct) == 0 || len(ct) > MaxCiphertextBytes {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("ciphertext must be 1..%d bytes", MaxCiphertextBytes))
		return
	}
	if req.SentAt <= 0 {
		writeErr(w, http.StatusBadRequest, `"sent_at" must be a positive unix timestamp`)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Sig)
	if err != nil || len(sig) != 64 {
		writeErr(w, http.StatusBadRequest, `"sig" must be a base64url Ed25519 signature`)
		return
	}

	// Verify the sender's signature over the group canonical bytes.
	canon := envelope.GroupCanonical(groupID, from[:], req.KeyEpoch, eph, nonce, req.SentAt, ct)
	if !crypto.Verify(from[:], canon, sig) {
		writeErr(w, http.StatusBadRequest, "signature verification failed")
		return
	}

	id, stored, err := s.store.Save(&store.Envelope{
		To: req.To, From: req.From, Eph: req.Eph,
		Nonce: req.Nonce, Ct: req.Ct, SentAt: req.SentAt, Sig: req.Sig,
		Kind: "group", KeyEpoch: req.KeyEpoch,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	// A replayed envelope is acknowledged with its original id rather
	// than stored twice (v0.6.11 F3).
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "duplicate": !stored})
}

// groupMessageJSON is one group envelope in a group inbox response.
// KeyEpoch tells the reader which sender key sealed the body.
type groupMessageJSON struct {
	ID         int64  `json:"id"`
	From       string `json:"from"`
	Eph        string `json:"eph"`
	Nonce      string `json:"nonce"`
	Ct         string `json:"ct"`
	KeyEpoch   int64  `json:"key_epoch"`
	SentAt     int64  `json:"sent_at"`
	ReceivedAt int64  `json:"received_at"`
	Sig        string `json:"sig"`
}

// groupControlJSON is one membership-control message in a group inbox
// response.
type groupControlJSON struct {
	Action string `json:"action"`
	Target string `json:"target"`
	Admin  string `json:"admin"`
	Epoch  int64  `json:"epoch"`
	Sig    string `json:"sig"`
}

// handleGroupInbox serves a group's envelopes plus its membership-control
// feed. The request must be signed by a current member (proving membership
// authorization); removed members get 403 and can no longer read the
// group's ciphertext.
func (s *Server) handleGroupInbox(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	groupID := q.Get("to")
	if _, err := envelope.ParseGroupID(groupID); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"to" query param: %v`, err))
		return
	}
	memberAddr := q.Get("member")
	memberEd, err := parseAddress(memberAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"member" query param: %v`, err))
		return
	}

	// Same cursor/limit/timestamp rules as personal inbox reads.
	var after int64
	if a := q.Get("after"); a != "" {
		if _, err := fmt.Sscanf(a, "%d", &after); err != nil || after < 0 {
			writeErr(w, http.StatusBadRequest, `"after" must be a non-negative message id`)
			return
		}
	}
	limit := 50
	if l := q.Get("limit"); l != "" {
		if _, err := fmt.Sscanf(l, "%d", &limit); err != nil {
			writeErr(w, http.StatusBadRequest, `"limit" must be an integer`)
			return
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > MaxInboxLimit {
		limit = MaxInboxLimit
	}
	var ts int64
	if t := q.Get("ts"); t == "" {
		writeErr(w, http.StatusBadRequest, `"ts" query param is required`)
		return
	} else if _, err := fmt.Sscanf(t, "%d", &ts); err != nil {
		writeErr(w, http.StatusBadRequest, `"ts" must be a unix timestamp`)
		return
	}
	if now := time.Now().Unix(); ts < now-maxInboxRequestAge || ts > now+maxInboxRequestAge {
		writeErr(w, http.StatusBadRequest, `"ts" is outside the freshness window`)
		return
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	if err != nil || len(sigRaw) != 64 {
		writeErr(w, http.StatusUnauthorized, `"sig" must be a base64url Ed25519 signature`)
		return
	}
	canon := envelope.GroupInboxRequest(groupID, memberEd[:], after, int64(limit), ts)
	if !crypto.Verify(memberEd[:], canon, sigRaw) {
		writeErr(w, http.StatusUnauthorized, "inbox request signature verification failed")
		return
	}

	member, err := s.store.IsGroupMember(groupID, memberAddr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !member {
		writeErr(w, http.StatusForbidden, "not a current group member")
		return
	}

	envs, err := s.store.List(groupID, after, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	controls, err := s.store.GroupControls(groupID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}

	msgs := make([]groupMessageJSON, 0, len(envs))
	for _, e := range envs {
		msgs = append(msgs, groupMessageJSON{
			ID: e.ID, From: e.From, Eph: e.Eph, Nonce: e.Nonce, Ct: e.Ct,
			KeyEpoch: e.KeyEpoch,
			SentAt:   e.SentAt, ReceivedAt: e.ReceivedAt, Sig: e.Sig,
		})
	}
	ctls := make([]groupControlJSON, 0, len(controls))
	for _, c := range controls {
		ctls = append(ctls, groupControlJSON{
			Action: c.Action, Target: c.Target, Admin: c.Admin,
			Epoch: c.Epoch, Sig: c.Sig,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"group":    groupID,
		"messages": msgs,
		"controls": ctls,
	})
}

// groupControlRequest is the wire format for POST /v1/groups/control.
// Name is only used for create.
type groupControlRequest struct {
	Group  string `json:"group"`
	Name   string `json:"name,omitempty"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Admin  string `json:"admin"`
	Epoch  int64  `json:"epoch"`
	Sig    string `json:"sig"`
}

// handleGroupControl accepts a signed membership-control message (create,
// add, remove, transfer-admin), verifies the admin's signature, and
// applies it to the group's roster. Responds with the group's current
// max envelope id so a newly added member can start reading from the
// right cursor.
func (s *Server) handleGroupControl(w http.ResponseWriter, r *http.Request) {
	var req groupControlRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := envelope.ParseGroupID(req.Group); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"group": %v`, err))
		return
	}
	switch req.Action {
	case envelope.GroupControlCreate,
		envelope.GroupControlAdd,
		envelope.GroupControlRemove,
		envelope.GroupControlTransferAdmin:
	default:
		writeErr(w, http.StatusBadRequest, `"action" must be create, add, remove, or transfer-admin`)
		return
	}
	admin, err := parseAddress(req.Admin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"admin": %v`, err))
		return
	}
	target := ""
	if req.Action == envelope.GroupControlCreate {
		if req.Target != "" {
			writeErr(w, http.StatusBadRequest, `"target" must be empty for create`)
			return
		}
		if len(req.Name) > 200 {
			writeErr(w, http.StatusBadRequest, `"name" must be at most 200 characters`)
			return
		}
	} else {
		if _, err := parseAddress(req.Target); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf(`"target": %v`, err))
			return
		}
		target = req.Target
	}
	if req.Epoch <= 0 {
		writeErr(w, http.StatusBadRequest, `"epoch" must be positive`)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Sig)
	if err != nil || len(sig) != 64 {
		writeErr(w, http.StatusBadRequest, `"sig" must be a base64url Ed25519 signature`)
		return
	}

	// Verify the control signature. For create the creator signs and
	// becomes the initial admin; for the rest the current admin must sign.
	canon := envelope.GroupControl(req.Group, req.Action, target, req.Admin, req.Epoch)
	if !crypto.Verify(admin[:], canon, sig) {
		writeErr(w, http.StatusBadRequest, "control signature verification failed")
		return
	}

	if err := s.store.ApplyGroupControl(req.Group, req.Name, req.Action, target, req.Admin, req.Epoch, req.Sig); err != nil {
		// ApplyGroupControl enforces the membership rules (admin-only,
		// strict epoch order, member existence), so its failures are
		// request problems.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	maxID, err := s.store.GroupMaxEnvelopeID(req.Group)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "epoch": req.Epoch, "max_id": maxID})
}
