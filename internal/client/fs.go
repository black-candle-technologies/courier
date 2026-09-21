// Forward-secrecy sessions (issue #50, v0.11.0).
//
// Double-Ratchet-style per-conversation forward secrecy for 1:1 DMs,
// plus stored-state erasure of old keys. The full design (negotiation,
// handshake, ratchet, erasure, migration story) is in
// docs/forward-secrecy.md — read it before changing this file.
//
// Transport recap: FS lives *inside* the existing DM envelope. The outer
// envelope (crypto_box to the recipient's long-term key + Ed25519
// signature) is byte-identical to legacy DMs, so the relay needs no
// changes and the inbox trial-decryption path is untouched. The inner
// plaintext is either legacy (raw body / messagePayload JSON) or an FS
// frame (this file). Handshake frames are protocol DMs: sealed legacy,
// consumed silently, never in the sent log or dashboard (the existing
// sendProtocolDM pattern).
//
// Local state lives in ~/.courier/fs.json (0600, atomic writes under the
// cross-process config lock, same discipline as state.json). It holds
// ONLY current keys: root key, current send/recv chain keys, current
// ratchet keypair, peer ratchet pub, bounded skipped keys. Superseded
// keys are overwritten on every advance; message keys exist only in
// memory for one encrypt/decrypt and are zeroed after.
package client

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"golang.org/x/crypto/nacl/secretbox"
)

var b64fs = base64.RawURLEncoding

// ---- wire frames ----

// fsMagic marks direct messages that belong to the forward-secrecy
// layer. group=1/"cg", channel=2/"cc", state=1/"cs" are taken.
const fsMagic = 3

// fsPayloadVersion is the current FS frame format version.
const fsPayloadVersion = 1

// FS frame types.
const (
	fsTypeMsg    = "fs-msg"
	fsTypeInit   = "fs-init"
	fsTypeAccept = "fs-accept"
)

// FSCapability is the directory capability token advertising FS support.
// v0.11.0+ clients auto-include it on directory register/update.
const FSCapability = "fs"

// fsPayload is the inner-plaintext JSON for FS frames. Handshake frames
// (init/accept) carry key material sealed under the recipient's
// long-term key; message frames carry a secretbox sealed under the
// per-message key.
type fsPayload struct {
	Magic   int    `json:"cf"`
	Type    string `json:"t"`
	Version int    `json:"v"`
	SID     string `json:"sid,omitempty"`     // base64url 16-byte session id
	InitID  string `json:"init_id,omitempty"` // base64url 16-byte handshake id
	RK0     string `json:"rk0,omitempty"`     // base64url 32B (init only)
	EphPub  string `json:"eph_pub,omitempty"` // base64url 32B ephemeral (init/accept)
	RPub    string `json:"r_pub,omitempty"`   // base64url 32B ratchet pub (init/accept)
	RPK     string `json:"rpk,omitempty"`     // base64url 32B sender ratchet pub (msg)
	N       int64  `json:"n,omitempty"`       // send counter (msg)
	PN      int64  `json:"pn,omitempty"`      // previous sending-chain length (msg)
	Nonce   string `json:"nonce,omitempty"`   // base64url 24B (msg)
	CT      string `json:"ct,omitempty"`      // base64url secretbox (msg)
}

// parseFSPayload returns the FS frame if plain is one, false otherwise.
// Only well-formed frames with a recognized type are intercepted;
// anything else falls through as an ordinary message — never silently
// swallowed.
func parseFSPayload(plain []byte) (fsPayload, bool) {
	var p fsPayload
	if json.Unmarshal(plain, &p) != nil {
		return p, false
	}
	if p.Magic != fsMagic || p.Version != fsPayloadVersion {
		return p, false
	}
	switch p.Type {
	case fsTypeMsg, fsTypeInit, fsTypeAccept:
		return p, true
	}
	return p, false
}

// fs frame validation errors (internal sentinels; the inbox counts them
// as ordinary decrypt failures).
var (
	errFSNoSession   = errors.New("fs: no session")
	errFSBadFrame    = errors.New("fs: malformed frame")
	errFSReplay      = errors.New("fs: replay or duplicate")
	errFSDecrypt     = errors.New("fs: message decryption failed")
	errFSGapTooLarge = errors.New("fs: message gap exceeds skipped-key window")
	errFSIgnored     = errors.New("fs: handshake ignored")
	errFSProcessed   = errors.New("fs: handshake already processed")
	// errFSRequired is returned by fsPrepareSend when the per-contact
	// require_fs policy (issue #110) is set and no FS session is
	// established: the send fails closed instead of silently falling
	// back to legacy encryption.
	errFSRequired = errors.New("fs: forward secrecy is required for this peer but no session is established (the handshake may be suppressed; run `courier fs start <peer>` or `courier fs on <peer>` to retry it)")
)

// ---- tunables ----

const (
	// maxFSSkippedKeys bounds the out-of-order message-key window.
	maxFSSkippedKeys = 100
	// fsRotateAfterMessages / fsRotateAfterSeconds trigger a sender-side
	// ratchet rotation, prompting the peer's next DH step.
	fsRotateAfterMessages = 25
	fsRotateAfterSeconds  = 24 * 3600
	// fsInitRefreshSeconds: a pending (unaccepted) init is refreshed on
	// the next send after this long.
	fsInitRefreshSeconds = 300
	// fsInitCooldownSeconds: at most one init per peer per this long
	// (self-heal ping-pong guard).
	fsInitCooldownSeconds = 60
	// fsCapCacheTTL: directory capability positive-result cache TTL.
	fsCapCacheTTL = 24 * 3600
	// fsNegCapCacheTTL: negative directory-capability results are cached
	// briefly so ordinary legacy sends don't hit the directory on every
	// message. (The design doc's "never cache negatives" is relaxed
	// here: a 10-minute window, after which a newly-registered peer is
	// discovered.)
	fsNegCapCacheTTL = 600
	// maxFSProcessedInits bounds remembered handshake ids (replay guard).
	maxFSProcessedInits = 50
	// fsDowngradeWarnCooldownSeconds: minimum interval between
	// downgrade warnings surfaced for the same peer (issue #110). The
	// persistent marker (visible in `courier fs status`) is set on the
	// first detection and cleared on recovery; the user-facing warning
	// is rate-limited so an actively-suppressed peer doesn't spam every
	// send.
	fsDowngradeWarnCooldownSeconds = 3600
)

// peer FS modes.
const (
	fsModeAuto = "auto" // default: use FS when the peer is known-capable
	fsModeOn   = "on"   // user override: peer is FS-capable, initiate
	fsModeOff  = "off"  // user override: never use FS with this peer
)

// ---- local state ----

// fsSession is one peer's ratchet session. Pending (handshake in flight)
// sessions carry only handshake secrets; established sessions carry only
// current keys. Superseded keys are never retained.
type fsSession struct {
	Peer        string `json:"peer"`
	SID         string `json:"sid"` // base64url 16B session id
	Initiator   bool   `json:"initiator"`
	Established bool   `json:"established"`
	InitID      string `json:"init_id,omitempty"` // pending only
	// Pending-handshake secrets (erased at establishment).
	RK0       string `json:"rk0,omitempty"`      // base64url 32B
	EphPriv   string `json:"eph_priv,omitempty"` // base64url 32B
	CreatedAt int64  `json:"created_at"`
	// Established-session keys (all base64url 32B; current only).
	RootKey        string `json:"root_key,omitempty"`
	SendChain      string `json:"send_chain,omitempty"`
	RecvChain      string `json:"recv_chain,omitempty"`
	SendN          int64  `json:"send_n"`
	RecvN          int64  `json:"recv_n"`
	SendChainLen   int64  `json:"send_chain_len"`  // msgs on current send chain
	SendPrevCount  int64  `json:"send_prev_count"` // pn: msgs on previous send chain
	RatchetPriv    string `json:"ratchet_priv,omitempty"`
	RatchetPub     string `json:"ratchet_pub,omitempty"`
	PeerRatchetPub string `json:"peer_ratchet_pub,omitempty"`
	// PrevRatchetPub is the peer ratchet key of the replaced receiving
	// chain, kept for one generation so late in-flight messages from
	// the old chain can still be decrypted from skipped keys.
	PrevRatchetPub string `json:"prev_ratchet_pub,omitempty"`
	// Skipped message keys for out-of-order delivery: "<peer-rpk-b64>:<n>" -> key.
	Skipped map[string]string `json:"skipped,omitempty"`
	// Rotation bookkeeping.
	SentSinceRotate int64 `json:"sent_since_rotate"`
	LastRotateAt    int64 `json:"last_rotate_at"`
	RekeyFlag       bool  `json:"rekey_flag,omitempty"`
	MsgsSent        int64 `json:"msgs_sent"`
	MsgsRecvd       int64 `json:"msgs_recvd"`
}

// fsCapEntry is a cached positive capability result.
type fsCapEntry struct {
	Capable bool  `json:"capable"`
	At      int64 `json:"at"`
}

// fsFile is ~/.courier/fs.json.
type fsFile struct {
	Sessions       map[string]*fsSession `json:"sessions"`
	PeerModes      map[string]string     `json:"peer_modes,omitempty"`
	CapCache       map[string]fsCapEntry `json:"cap_cache,omitempty"`
	NegCapCache    map[string]int64      `json:"neg_cap_cache,omitempty"`
	ProcessedInits []string              `json:"processed_inits,omitempty"`
	LastInitAt     map[string]int64      `json:"last_init_at,omitempty"`
	// RequireFS (issue #110) is the per-contact fail-closed policy:
	// when set for an address, sends to it refuse to fall back to
	// legacy encryption unless an FS session is established. Default
	// (absent) is fail-open, matching pre-#110 behavior.
	RequireFS map[string]bool `json:"require_fs,omitempty"`
	// FSPins (issue #110) pins observed FS capability: address ->
	// unix timestamp of first proof the peer speaks FS (completed
	// handshake or valid inbound FS frame). Pins are permanent: once
	// a peer has proven FS support, a later absence of capability
	// evidence is treated as a possible downgrade, not as proof the
	// peer is legacy-only. Pins also keep handshake pressure on
	// (fsShouldInit) when the relay suppresses directory availability.
	FSPins map[string]int64 `json:"fs_pins,omitempty"`
	// Downgrade (issue #110): address -> unix timestamp when a
	// pinned peer was first observed falling back to legacy with no
	// current positive capability evidence. Cleared when the peer
	// shows positive capability again or a session re-establishes.
	Downgrade map[string]int64 `json:"downgrade_since,omitempty"`
	// DowngradeWarnedAt rate-limits the user-facing warning per peer.
	DowngradeWarnedAt map[string]int64 `json:"downgrade_warned_at,omitempty"`
}

func fsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "fs.json"), nil
}

func (ff *fsFile) session(peer string) *fsSession {
	if ff.Sessions == nil {
		ff.Sessions = map[string]*fsSession{}
	}
	return ff.Sessions[peer]
}

func newFSFile() *fsFile {
	return &fsFile{
		Sessions:          map[string]*fsSession{},
		PeerModes:         map[string]string{},
		CapCache:          map[string]fsCapEntry{},
		NegCapCache:       map[string]int64{},
		LastInitAt:        map[string]int64{},
		RequireFS:         map[string]bool{},
		FSPins:            map[string]int64{},
		Downgrade:         map[string]int64{},
		DowngradeWarnedAt: map[string]int64{},
	}
}

func loadFSLocked() (*fsFile, error) {
	p, err := fsFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return newFSFile(), nil
		}
		return nil, err
	}
	ff := newFSFile()
	if err := json.Unmarshal(data, &ff); err != nil {
		return nil, fmt.Errorf("fs.json: %w", err)
	}
	// Normalize nil maps so update closures can assign directly.
	if ff.Sessions == nil {
		ff.Sessions = map[string]*fsSession{}
	}
	if ff.PeerModes == nil {
		ff.PeerModes = map[string]string{}
	}
	if ff.CapCache == nil {
		ff.CapCache = map[string]fsCapEntry{}
	}
	if ff.NegCapCache == nil {
		ff.NegCapCache = map[string]int64{}
	}
	if ff.LastInitAt == nil {
		ff.LastInitAt = map[string]int64{}
	}
	if ff.RequireFS == nil {
		ff.RequireFS = map[string]bool{}
	}
	if ff.FSPins == nil {
		ff.FSPins = map[string]int64{}
	}
	if ff.Downgrade == nil {
		ff.Downgrade = map[string]int64{}
	}
	if ff.DowngradeWarnedAt == nil {
		ff.DowngradeWarnedAt = map[string]int64{}
	}
	return ff, nil
}

func saveFSLocked(ff *fsFile) error {
	p, err := fsFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "fs-*.tmp")
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

// updateFS performs an atomic read-modify-write of fs.json under the
// cross-process config lock (same discipline as updateState).
func updateFS(fn func(*fsFile) error) error {
	return withConfigLock(func() error {
		ff, err := loadFSLocked()
		if err != nil {
			return err
		}
		if err := fn(ff); err != nil {
			return err
		}
		return saveFSLocked(ff)
	})
}

func loadFS() (*fsFile, error) {
	var ff *fsFile
	if err := withConfigLock(func() error {
		var err error
		ff, err = loadFSLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return ff, nil
}

// removeFSState deletes ~/.courier/fs.json (best-effort). Used by
// `backup restore`: a restored identity is a new device and must not
// inherit the old device's sessions (issue #50 §6b).
func removeFSState() error {
	p, err := fsFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ---- helpers ----

func fsRand32() ([32]byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return b, fmt.Errorf("fs rand: %w", err)
	}
	return b, nil
}

func fsRand16() ([16]byte, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return b, fmt.Errorf("fs rand: %w", err)
	}
	return b, nil
}

func fsGenX25519() (pub, priv [32]byte, err error) {
	return crypto.GenerateX25519Keypair()
}

func fsDecode32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := b64fs.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, errFSBadFrame
	}
	copy(out[:], raw)
	crypto.Zero(raw)
	return out, nil
}

func fsDecode16(s string) ([16]byte, error) {
	var out [16]byte
	raw, err := b64fs.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return out, errFSBadFrame
	}
	copy(out[:], raw)
	crypto.Zero(raw)
	return out, nil
}

// withFSCap returns caps with the FS capability token added (no dupes).
// Called on directory register/update so v0.11.0+ clients advertise.
func withFSCap(caps []string) []string {
	for _, c := range caps {
		if c == FSCapability {
			return caps
		}
	}
	return append(caps, FSCapability)
}

// fsInitDue reports whether an init may be sent to peer (cooldown guard).
func fsInitDue(ff *fsFile, peer string, cooldown int64) bool {
	last := ff.LastInitAt[peer]
	return time.Now().Unix()-last >= cooldown
}

// fsPinCapabilityLocked records first-observed FS capability for peer
// (issue #110). Pins are permanent: once a peer has proven FS support —
// a completed handshake or a valid inbound FS frame — later absence of
// capability evidence is treated as a possible downgrade, never as
// proof the peer is legacy-only. First-observed-wins: re-pinning never
// moves the timestamp.
func fsPinCapabilityLocked(ff *fsFile, peer string, now int64) {
	if ff.FSPins == nil {
		ff.FSPins = map[string]int64{}
	}
	if _, ok := ff.FSPins[peer]; !ok {
		ff.FSPins[peer] = now
	}
}

// ---- send path ----

// fsSendOutput carries one message's derived keys from the session
// advance to the seal step. The caller must seal promptly and erase both
// keys immediately after (fsSealMessage does this).
type fsSendOutput struct {
	MsgKey  [32]byte
	WrapKey [32]byte // attachment data-key wrap key, derived from MsgKey
	SID     string
	RPK     string // base64url sender ratchet pub for the header
	N       int64
	PN      int64
}

// erase zeroes the derived keys. Call on any path where the keys were
// derived but the message was not sealed (fsSealMessage erases them on
// the success path).
func (o *fsSendOutput) erase() {
	crypto.Zero(o.MsgKey[:])
	crypto.Zero(o.WrapKey[:])
}

// fsAdvanceSendLocked advances the session's sending chain and derives
// the message key. When a rotation trigger fires (explicit rekey, message
// count, or age), it first performs a sender-side DH step: a fresh
// ratchet keypair is minted and mixed with the peer's current ratchet
// key into a new root and sending chain. The receiver performs the
// complementary step on seeing the new RPK and derives the same chain.
// The old chain key is overwritten; the caller must erase the returned
// message key after sealing.
func fsAdvanceSendLocked(sess *fsSession) (*fsSendOutput, error) {
	now := time.Now().Unix()
	if sess.RekeyFlag || sess.SentSinceRotate >= fsRotateAfterMessages ||
		now-sess.LastRotateAt >= fsRotateAfterSeconds {
		peerRPK, err := fsDecode32(sess.PeerRatchetPub)
		if err != nil {
			return nil, err
		}
		pub, priv, err := fsGenX25519()
		if err != nil {
			return nil, err
		}
		dh, err := crypto.FSX25519(priv, peerRPK)
		if err != nil {
			crypto.Zero(priv[:])
			return nil, err
		}
		root, err := fsDecode32(sess.RootKey)
		if err != nil {
			crypto.Zero(priv[:])
			crypto.Zero(dh[:])
			return nil, err
		}
		newRoot, newSendChain := crypto.FSRootStep(root, dh)
		crypto.Zero(root[:])
		crypto.Zero(dh[:])
		oldSC, _ := fsDecode32(sess.SendChain)
		crypto.Zero(oldSC[:])
		sess.RootKey = b64fs.EncodeToString(newRoot[:])
		crypto.Zero(newRoot[:])
		sess.SendChain = b64fs.EncodeToString(newSendChain[:])
		crypto.Zero(newSendChain[:])
		sess.RatchetPriv = b64fs.EncodeToString(priv[:])
		crypto.Zero(priv[:])
		sess.RatchetPub = b64fs.EncodeToString(pub[:])
		sess.SendPrevCount = sess.SendChainLen
		sess.SendChainLen = 0
		sess.SendN = 0
		sess.SentSinceRotate = 0
		sess.LastRotateAt = now
		sess.RekeyFlag = false
	}
	chain, err := fsDecode32(sess.SendChain)
	if err != nil {
		return nil, err
	}
	newChain, msgKey := crypto.FSChainStep(chain)
	crypto.Zero(chain[:])
	out := &fsSendOutput{
		SID: sess.SID,
		RPK: sess.RatchetPub,
		N:   sess.SendN,
		PN:  sess.SendPrevCount,
	}
	copy(out.MsgKey[:], msgKey[:])
	crypto.Zero(msgKey[:])
	out.WrapKey = crypto.FSAttachWrapKey(out.MsgKey)
	sess.SendChain = b64fs.EncodeToString(newChain[:])
	crypto.Zero(newChain[:])
	sess.SendN++
	sess.SendChainLen++
	sess.SentSinceRotate++
	sess.MsgsSent++
	return out, nil
}

// fsSealMessage secretbox-seals plain under the message key and wraps it
// in an fs-msg frame. It erases the message and wrap keys.
func fsSealMessage(out *fsSendOutput, plain []byte) ([]byte, error) {
	var nonce [crypto.NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		crypto.Zero(out.MsgKey[:])
		crypto.Zero(out.WrapKey[:])
		return nil, fmt.Errorf("fs nonce: %w", err)
	}
	ct := secretbox.Seal(nil, plain, &nonce, &out.MsgKey)
	p := fsPayload{
		Magic: fsMagic, Type: fsTypeMsg, Version: fsPayloadVersion,
		SID: out.SID, RPK: out.RPK, N: out.N, PN: out.PN,
		Nonce: b64fs.EncodeToString(nonce[:]),
		CT:    b64fs.EncodeToString(ct),
	}
	raw, err := json.Marshal(p)
	crypto.Zero(out.MsgKey[:])
	crypto.Zero(out.WrapKey[:])
	crypto.Zero(ct)
	if err != nil {
		return nil, fmt.Errorf("fs encode: %w", err)
	}
	return raw, nil
}

// fsPrepareSend returns the FS seal parameters for one message to
// address, or nil to send via legacy seal. When the peer is known
// FS-capable but no session exists, it opportunistically sends an
// fs-init (best-effort protocol DM) and the message still goes legacy —
// the session upgrades from the next message (docs/forward-secrecy.md
// §4.5).
//
// Issue #110: when the per-contact require_fs policy is set for
// address, there is no silent legacy fallback — fsPrepareSend returns
// errFSRequired unless an FS session is established, and the send fails
// closed. On the legacy-fallback path it also runs downgrade detection
// for pinned peers (fsAssessDowngrade).
func (c *Client) fsPrepareSend(address string) (*fsSendOutput, error) {
	if address == c.cfg.Address {
		return nil, nil
	}
	var out *fsSendOutput
	err := updateFS(func(ff *fsFile) error {
		if ff.PeerModes[address] == fsModeOff && !ff.RequireFS[address] {
			return nil
		}
		sess := ff.session(address)
		if sess != nil && sess.Established {
			o, err := fsAdvanceSendLocked(sess)
			if err != nil {
				return err
			}
			out = o
			return nil
		}
		// No usable session. Fail closed when the peer requires FS —
		// never silently fall back to legacy (issue #110). Note this
		// deliberately wins over mode "off": "off" + "require" is a
		// contradictory configuration, and refusing to send is the
		// only safe reading of it.
		if ff.RequireFS[address] {
			return errFSRequired
		}
		return nil
	})
	if err != nil || out != nil {
		return out, err
	}
	// Legacy-fallback path: downgrade detection for pinned peers, then
	// the usual opportunistic handshake.
	c.fsAssessDowngrade(address)
	if c.fsShouldInit(address) {
		var due bool
		_ = updateFS(func(ff *fsFile) error {
			if fsInitDue(ff, address, fsInitCooldownSeconds) {
				if ff.LastInitAt == nil {
					ff.LastInitAt = map[string]int64{}
				}
				ff.LastInitAt[address] = time.Now().Unix()
				due = true
			}
			return nil
		})
		if due {
			// Best-effort: a failed init just means this message (and
			// later ones, until the next due init) go legacy.
			_ = c.sendFSInit(address)
		}
	}
	return nil, nil
}

// fsAssessDowngrade implements issue #110's downgrade detection. It
// runs on the legacy-fallback path (no established session, sends not
// fail-closed): a peer whose FS capability was previously observed
// (pinned) but for which no *current* positive capability evidence
// exists is downgrade-suspected — the relay may be suppressing
// directory availability or handshake traffic. It records a persistent
// marker (surfaced by `courier fs status`) and queues a rate-limited
// user-facing warning (consumed via FSConsumeWarning, printed by the
// send path).
//
// A handshake already in flight suppresses the warning: a slow
// round-trip is not a downgrade. Explicit `fs off` peers are exempt —
// the user chose legacy.
func (c *Client) fsAssessDowngrade(address string) {
	now := time.Now().Unix()
	ff, err := loadFS()
	if err != nil {
		return
	}
	if ff.PeerModes[address] == fsModeOff {
		return
	}
	if _, pinned := ff.FSPins[address]; !pinned {
		return
	}
	// Current positive evidence, excluding the pin itself: the point
	// is the peer "suddenly only offers legacy".
	positive := ff.PeerModes[address] == fsModeOn
	if !positive {
		if e, ok := ff.CapCache[address]; ok && e.Capable &&
			now-e.At < fsCapCacheTTL {
			positive = true
		}
	}
	if !positive {
		if at, ok := ff.NegCapCache[address]; ok && now-at < fsNegCapCacheTTL {
			// Fresh negative result: don't hit the directory again.
		} else if c.fsDirectoryCapable(address) {
			positive = true
			_ = updateFS(func(ff *fsFile) error {
				if ff.CapCache == nil {
					ff.CapCache = map[string]fsCapEntry{}
				}
				ff.CapCache[address] = fsCapEntry{Capable: true, At: now}
				delete(ff.NegCapCache, address)
				return nil
			})
		} else {
			_ = updateFS(func(ff *fsFile) error {
				if ff.NegCapCache == nil {
					ff.NegCapCache = map[string]int64{}
				}
				ff.NegCapCache[address] = now
				return nil
			})
		}
	}
	if !positive {
		if now-ff.LastInitAt[address] < fsInitRefreshSeconds {
			return
		}
		var warnDue bool
		_ = updateFS(func(ff *fsFile) error {
			if ff.Downgrade == nil {
				ff.Downgrade = map[string]int64{}
			}
			if _, ok := ff.Downgrade[address]; !ok {
				ff.Downgrade[address] = now
			}
			if ff.DowngradeWarnedAt == nil {
				ff.DowngradeWarnedAt = map[string]int64{}
			}
			if now-ff.DowngradeWarnedAt[address] >= fsDowngradeWarnCooldownSeconds {
				ff.DowngradeWarnedAt[address] = now
				warnDue = true
			}
			return nil
		})
		if warnDue {
			peer := shortPeer(address)
			c.noteFSWarning(address, fmt.Sprintf(
				"DOWNGRADE WARNING: %s previously negotiated forward secrecy but is currently reachable only via legacy encryption — the relay may be suppressing FS directory or handshake traffic. Run `courier fs start %s` to retry the handshake, or `courier fs require %s` to refuse legacy sends.",
				peer, peer, peer))
		}
		return
	}
	// Positive evidence again: clear any downgrade marker.
	_ = updateFS(func(ff *fsFile) error {
		delete(ff.Downgrade, address)
		return nil
	})
}

// fsShouldInit reports whether to send an fs-init to address: the peer
// is believed FS-capable and no live handshake is in flight (a pending
// init older than fsInitRefreshSeconds is refreshed).
func (c *Client) fsShouldInit(address string) bool {
	ff, err := loadFS()
	if err != nil {
		return false
	}
	if ff.PeerModes[address] == fsModeOff {
		return false
	}
	if sess := ff.session(address); sess != nil {
		if sess.Established {
			return false
		}
		if time.Now().Unix()-sess.CreatedAt <= fsInitRefreshSeconds {
			return false
		}
	}
	if ff.PeerModes[address] == fsModeOn {
		return true
	}
	// Issue #110: a pinned peer has proven FS support before. The pin
	// is permanent capability knowledge, so handshake pressure
	// continues even when the relay suppresses directory availability.
	if _, pinned := ff.FSPins[address]; pinned {
		return true
	}
	now := time.Now().Unix()
	if e, ok := ff.CapCache[address]; ok && e.Capable &&
		now-e.At < fsCapCacheTTL {
		return true
	}
	if at, ok := ff.NegCapCache[address]; ok && now-at < fsNegCapCacheTTL {
		return false
	}
	// Directory reverse lookup (network, outside the config lock).
	// Positive results are cached for a day; negatives briefly.
	if c.fsDirectoryCapable(address) {
		_ = updateFS(func(ff *fsFile) error {
			if ff.CapCache == nil {
				ff.CapCache = map[string]fsCapEntry{}
			}
			ff.CapCache[address] = fsCapEntry{Capable: true, At: now}
			delete(ff.NegCapCache, address)
			return nil
		})
		return true
	}
	_ = updateFS(func(ff *fsFile) error {
		if ff.NegCapCache == nil {
			ff.NegCapCache = map[string]int64{}
		}
		ff.NegCapCache[address] = now
		return nil
	})
	return false
}

// fsDirectoryCapable checks the peer's directory profiles for the `fs`
// capability token.
func (c *Client) fsDirectoryCapable(address string) bool {
	profiles, err := c.DirectoryReverse(address)
	if err != nil {
		return false
	}
	for _, p := range profiles {
		for _, cp := range p.Capabilities {
			if cp == FSCapability {
				return true
			}
		}
	}
	return false
}

// ---- handshake ----

// sendFSInit starts (or refreshes) an FS handshake with address: a
// protocol DM sealed with the legacy seal, never in the sent log.
func (c *Client) sendFSInit(address string) error {
	if address == c.cfg.Address {
		return errors.New("fs: cannot handshake with self")
	}
	rk0, err := fsRand32()
	if err != nil {
		return err
	}
	ephPub, ephPriv, err := fsGenX25519()
	if err != nil {
		return err
	}
	rPub, rPriv, err := fsGenX25519()
	if err != nil {
		return err
	}
	initID, err := fsRand16()
	if err != nil {
		return err
	}
	sid, err := fsRand16()
	if err != nil {
		return err
	}
	p := fsPayload{
		Magic: fsMagic, Type: fsTypeInit, Version: fsPayloadVersion,
		SID:    b64fs.EncodeToString(sid[:]),
		InitID: b64fs.EncodeToString(initID[:]),
		RK0:    b64fs.EncodeToString(rk0[:]),
		EphPub: b64fs.EncodeToString(ephPub[:]),
		RPub:   b64fs.EncodeToString(rPub[:]),
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("fs encode init: %w", err)
	}
	now := time.Now().Unix()
	err = updateFS(func(ff *fsFile) error {
		ff.Sessions[address] = &fsSession{
			Peer: address, SID: p.SID, Initiator: true, Established: false,
			InitID: p.InitID, RK0: p.RK0, EphPriv: b64fs.EncodeToString(ephPriv[:]),
			RatchetPriv: b64fs.EncodeToString(rPriv[:]),
			RatchetPub:  b64fs.EncodeToString(rPub[:]),
			CreatedAt:   now, LastRotateAt: now,
			Skipped: map[string]string{},
		}
		return nil
	})
	crypto.Zero(rk0[:])
	crypto.Zero(ephPriv[:])
	crypto.Zero(rPriv[:])
	if err != nil {
		return err
	}
	_, err = c.sendSealed(address, raw, "", 0, "", false, 0)
	return err
}

// handleFSHandshake dispatches an inbound FS handshake frame. It is
// called from the inbox loop; handshake frames are consumed silently.
func (c *Client) handleFSHandshake(from string, p fsPayload) {
	if from == c.cfg.Address {
		return
	}
	switch p.Type {
	case fsTypeInit:
		c.handleFSInit(from, p)
	case fsTypeAccept:
		c.handleFSAccept(from, p)
	}
}

// handleFSInit processes an fs-init: validates it, resolves
// init-vs-init races by address tie-break (docs/forward-secrecy.md
// §4.4), derives the session, and answers with fs-accept.
func (c *Client) handleFSInit(from string, p fsPayload) {
	rk0, err := fsDecode32(p.RK0)
	if err != nil {
		return
	}
	defer crypto.Zero(rk0[:])
	var ephPub, rPub [32]byte
	if ephPub, err = fsDecode32(p.EphPub); err != nil {
		return
	}
	if rPub, err = fsDecode32(p.RPub); err != nil {
		return
	}
	if _, err = fsDecode16(p.SID); err != nil {
		return
	}
	if _, err = fsDecode16(p.InitID); err != nil {
		return
	}
	var accept []byte
	err = updateFS(func(ff *fsFile) error {
		for _, id := range ff.ProcessedInits {
			if id == p.InitID {
				return errFSProcessed
			}
		}
		if sess := ff.session(from); sess != nil && !sess.Established {
			// Simultaneous inits: the smaller address initiates;
			// the larger adopts. Deterministic on both sides.
			if from > c.cfg.Address {
				return errFSIgnored
			}
		}
		// Adopt: nil, pending-out loser, or established (peer rekey).
		// Any prior session is replaced — its keys are erased.
		ephPub2, ephPriv, err := fsGenX25519()
		if err != nil {
			return err
		}
		rPub2, rPriv, err := fsGenX25519()
		if err != nil {
			crypto.Zero(ephPriv[:])
			return err
		}
		dh1, err := crypto.FSX25519(ephPriv, ephPub)
		if err != nil {
			crypto.Zero(ephPriv[:])
			crypto.Zero(rPriv[:])
			return err
		}
		dh2, err := crypto.FSX25519(rPriv, rPub)
		if err != nil {
			crypto.Zero(ephPriv[:])
			crypto.Zero(rPriv[:])
			crypto.Zero(dh1[:])
			return err
		}
		crypto.Zero(ephPriv[:])
		root0 := crypto.FSHandshakeRoot(rk0, dh1, dh2, p.SID)
		crypto.Zero(dh1[:])
		crypto.Zero(dh2[:])
		now := time.Now().Unix()
		sendChain0 := crypto.FSInitChain(root0, false)
		recvChain0 := crypto.FSInitChain(root0, true)
		ff.Sessions[from] = &fsSession{
			Peer: from, SID: p.SID, Initiator: false, Established: true,
			CreatedAt: now, LastRotateAt: now,
			RootKey:        b64fs.EncodeToString(root0[:]),
			SendChain:      b64fs.EncodeToString(sendChain0[:]),
			RecvChain:      b64fs.EncodeToString(recvChain0[:]),
			RatchetPriv:    b64fs.EncodeToString(rPriv[:]),
			RatchetPub:     b64fs.EncodeToString(rPub2[:]),
			PeerRatchetPub: p.RPub,
			Skipped:        map[string]string{},
		}
		crypto.Zero(root0[:])
		crypto.Zero(rPriv[:])
		ff.ProcessedInits = append(ff.ProcessedInits, p.InitID)
		if len(ff.ProcessedInits) > maxFSProcessedInits {
			ff.ProcessedInits = ff.ProcessedInits[len(ff.ProcessedInits)-maxFSProcessedInits:]
		}
		if ff.CapCache == nil {
			ff.CapCache = map[string]fsCapEntry{}
		}
		ff.CapCache[from] = fsCapEntry{Capable: true, At: now}
		// Issue #110: adopting their init is proof the peer speaks FS —
		// pin the capability, and clear any downgrade marker: the peer
		// is demonstrably back on FS.
		fsPinCapabilityLocked(ff, from, now)
		delete(ff.Downgrade, from)
		acc := fsPayload{
			Magic: fsMagic, Type: fsTypeAccept, Version: fsPayloadVersion,
			SID: p.SID, InitID: p.InitID,
			EphPub: b64fs.EncodeToString(ephPub2[:]),
			RPub:   b64fs.EncodeToString(rPub2[:]),
		}
		accept, err = json.Marshal(acc)
		return err
	})
	if err != nil || accept == nil {
		return
	}
	// Best-effort accept: if it fails to send, the initiator refreshes
	// its init within fsInitRefreshSeconds and we adopt again.
	_, _ = c.sendSealed(from, accept, "", 0, "", false, 0)
}

// handleFSAccept processes an fs-accept for our pending init and
// establishes the session.
func (c *Client) handleFSAccept(from string, p fsPayload) {
	var ephPub, rPub [32]byte
	var err error
	if ephPub, err = fsDecode32(p.EphPub); err != nil {
		return
	}
	if rPub, err = fsDecode32(p.RPub); err != nil {
		return
	}
	_ = updateFS(func(ff *fsFile) error {
		sess := ff.session(from)
		if sess == nil || sess.Established || sess.InitID != p.InitID || sess.SID != p.SID {
			return errFSIgnored
		}
		rk0, err := fsDecode32(sess.RK0)
		if err != nil {
			return err
		}
		defer crypto.Zero(rk0[:])
		ephPriv, err := fsDecode32(sess.EphPriv)
		if err != nil {
			return err
		}
		defer crypto.Zero(ephPriv[:])
		rPriv, err := fsDecode32(sess.RatchetPriv)
		if err != nil {
			return err
		}
		defer crypto.Zero(rPriv[:])
		dh1, err := crypto.FSX25519(ephPriv, ephPub)
		if err != nil {
			return err
		}
		defer crypto.Zero(dh1[:])
		dh2, err := crypto.FSX25519(rPriv, rPub)
		if err != nil {
			return err
		}
		defer crypto.Zero(dh2[:])
		root0 := crypto.FSHandshakeRoot(rk0, dh1, dh2, p.SID)
		defer crypto.Zero(root0[:])
		now := time.Now().Unix()
		sess.Established = true
		sess.RootKey = b64fs.EncodeToString(root0[:])
		sendChain0 := crypto.FSInitChain(root0, true)
		recvChain0 := crypto.FSInitChain(root0, false)
		sess.SendChain = b64fs.EncodeToString(sendChain0[:])
		sess.RecvChain = b64fs.EncodeToString(recvChain0[:])
		sess.PeerRatchetPub = p.RPub
		sess.RK0 = ""
		sess.EphPriv = ""
		// Rotate the handshake ratchet key on the first send, so the
		// DH ping-pong starts immediately (design §4.3d).
		sess.RekeyFlag = true
		sess.LastRotateAt = now
		ff.ProcessedInits = append(ff.ProcessedInits, p.InitID)
		if len(ff.ProcessedInits) > maxFSProcessedInits {
			ff.ProcessedInits = ff.ProcessedInits[len(ff.ProcessedInits)-maxFSProcessedInits:]
		}
		if ff.CapCache == nil {
			ff.CapCache = map[string]fsCapEntry{}
		}
		ff.CapCache[from] = fsCapEntry{Capable: true, At: now}
		// Issue #110: a completed handshake pins the peer's FS
		// capability and clears any downgrade marker.
		fsPinCapabilityLocked(ff, from, now)
		delete(ff.Downgrade, from)
		return nil
	})
}

// ---- receive path ----

// fsSkippedEntryKey keys a skipped message key by the sender ratchet
// key of its chain plus the message counter, so keys from different
// chain generations never collide.
func fsSkippedEntryKey(rpkB64 string, n int64) string {
	return rpkB64 + ":" + strconv.FormatInt(n, 10)
}

// fsSkippedCounter parses the counter suffix of a skipped-entry key.
func fsSkippedCounter(k string) (int64, bool) {
	i := len(k) - 1
	for i >= 0 && k[i] != ':' {
		i--
	}
	if i < 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(k[i+1:], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// fsDHStepLocked performs one DH ratchet step on a new peer ratchet key:
// derives skipped keys for the old receiving chain (bounded), mixes the
// DH into a new root, mints a fresh ratchet keypair, and derives the new
// sending chain. Old root, chains, ratchet private key, and skipped
// keys older than the replaced chain are erased.
func fsDHStepLocked(sess *fsSession, peerRPK [32]byte, pn int64) error {
	now := time.Now().Unix()
	oldRPKB64 := sess.PeerRatchetPub // the chain being replaced
	// Drop skipped keys for chains older than the one being replaced;
	// its late messages (if any) can still be decrypted from the keys
	// derived below.
	for k := range sess.Skipped {
		if !strings.HasPrefix(k, oldRPKB64+":") {
			delete(sess.Skipped, k)
		}
	}
	// Skipped keys for the chain being replaced: the sender sent pn
	// messages on its previous chain; derive the ones we missed.
	if pn > sess.RecvN {
		gap := pn - sess.RecvN
		if gap > maxFSSkippedKeys {
			gap = maxFSSkippedKeys
		}
		chain, err := fsDecode32(sess.RecvChain)
		if err != nil {
			return err
		}
		if sess.Skipped == nil {
			sess.Skipped = map[string]string{}
		}
		for i := int64(0); i < gap; i++ {
			var mk [32]byte
			chain, mk = crypto.FSChainStep(chain)
			sess.Skipped[fsSkippedEntryKey(oldRPKB64, sess.RecvN+i)] = b64fs.EncodeToString(mk[:])
			crypto.Zero(mk[:])
		}
		crypto.Zero(chain[:])
	}
	ratchetPriv, err := fsDecode32(sess.RatchetPriv)
	if err != nil {
		return err
	}
	dh1, err := crypto.FSX25519(ratchetPriv, peerRPK)
	crypto.Zero(ratchetPriv[:])
	if err != nil {
		return err
	}
	root, err := fsDecode32(sess.RootKey)
	if err != nil {
		crypto.Zero(dh1[:])
		return err
	}
	newRoot, recvChain := crypto.FSRootStep(root, dh1)
	crypto.Zero(root[:])
	crypto.Zero(dh1[:])
	oldSC, _ := fsDecode32(sess.SendChain)
	crypto.Zero(oldSC[:])
	oldRC, _ := fsDecode32(sess.RecvChain)
	crypto.Zero(oldRC[:])
	newPub, newPriv, err := fsGenX25519()
	if err != nil {
		crypto.Zero(newRoot[:])
		crypto.Zero(recvChain[:])
		return err
	}
	dh2, err := crypto.FSX25519(newPriv, peerRPK)
	if err != nil {
		crypto.Zero(newRoot[:])
		crypto.Zero(recvChain[:])
		crypto.Zero(newPriv[:])
		return err
	}
	newRoot2, sendChain := crypto.FSRootStep(newRoot, dh2)
	crypto.Zero(newRoot[:])
	crypto.Zero(dh2[:])
	sess.RootKey = b64fs.EncodeToString(newRoot2[:])
	crypto.Zero(newRoot2[:])
	sess.RecvChain = b64fs.EncodeToString(recvChain[:])
	crypto.Zero(recvChain[:])
	sess.SendChain = b64fs.EncodeToString(sendChain[:])
	crypto.Zero(sendChain[:])
	// Encode the new ratchet private key BEFORE zeroing it.
	sess.RatchetPriv = b64fs.EncodeToString(newPriv[:])
	crypto.Zero(newPriv[:])
	sess.RatchetPub = b64fs.EncodeToString(newPub[:])
	sess.PrevRatchetPub = oldRPKB64
	sess.PeerRatchetPub = b64fs.EncodeToString(peerRPK[:])
	sess.SendPrevCount = sess.SendChainLen
	sess.SendChainLen = 0
	sess.SendN = 0
	sess.RecvN = 0
	sess.LastRotateAt = now
	sess.SentSinceRotate = 0
	return nil
}

// fsTrimSkipped drops skipped keys beyond the bound, oldest counters first.
func fsTrimSkipped(sess *fsSession) {
	for len(sess.Skipped) > maxFSSkippedKeys {
		var oldest string
		var oldestN int64 = -1
		for k := range sess.Skipped {
			n, ok := fsSkippedCounter(k)
			if !ok {
				delete(sess.Skipped, k)
				continue
			}
			if oldestN < 0 || n < oldestN {
				oldest, oldestN = k, n
			}
		}
		if oldestN < 0 {
			break
		}
		delete(sess.Skipped, oldest)
	}
}

// fsDecryptCurrentChain decrypts an fs-msg on the session's current
// receiving chain (rpk already verified to match PeerRatchetPub).
// Handles in-order, replay-from-skipped, and gap (out-of-order) cases.
// The derived message key is written to msgKey; the caller zeroes it.
func fsDecryptCurrentChain(sess *fsSession, p fsPayload, rpk [32]byte, msgKey *[32]byte) error {
	rpkB64 := sess.PeerRatchetPub
	switch {
	case p.N < sess.RecvN:
		ks, ok := sess.Skipped[fsSkippedEntryKey(rpkB64, p.N)]
		if !ok {
			return errFSReplay
		}
		k, err := fsDecode32(ks)
		if err != nil {
			return err
		}
		copy(msgKey[:], k[:])
		crypto.Zero(k[:])
		delete(sess.Skipped, fsSkippedEntryKey(rpkB64, p.N))
	case p.N == sess.RecvN:
		chain, err := fsDecode32(sess.RecvChain)
		if err != nil {
			return err
		}
		nc, mk := crypto.FSChainStep(chain)
		crypto.Zero(chain[:])
		sess.RecvChain = b64fs.EncodeToString(nc[:])
		crypto.Zero(nc[:])
		copy(msgKey[:], mk[:])
		crypto.Zero(mk[:])
		sess.RecvN++
	default: // p.N > sess.RecvN: derive skipped keys for the gap
		if p.N-sess.RecvN > maxFSSkippedKeys {
			return errFSGapTooLarge
		}
		chain, err := fsDecode32(sess.RecvChain)
		if err != nil {
			return err
		}
		if sess.Skipped == nil {
			sess.Skipped = map[string]string{}
		}
		for i := sess.RecvN; i < p.N; i++ {
			var mk [32]byte
			chain, mk = crypto.FSChainStep(chain)
			sess.Skipped[fsSkippedEntryKey(rpkB64, i)] = b64fs.EncodeToString(mk[:])
			crypto.Zero(mk[:])
		}
		fsTrimSkipped(sess)
		nc, mk := crypto.FSChainStep(chain)
		crypto.Zero(chain[:])
		sess.RecvChain = b64fs.EncodeToString(nc[:])
		crypto.Zero(nc[:])
		copy(msgKey[:], mk[:])
		crypto.Zero(mk[:])
		sess.RecvN = p.N + 1
	}
	return nil
}

// fsDecryptMessage decrypts one fs-msg frame: DH-ratchets on a new peer
// key, derives (or reuses a skipped) message key, and opens the
// secretbox. It returns the inner plaintext and the attachment wrap key;
// the caller must zero the wrap key after the manifests are processed.
// On an unknown session id it triggers a self-healing re-init
// (rate-limited) and reports errFSNoSession.
func (c *Client) fsDecryptMessage(from string, p fsPayload) (plain []byte, wrapKey *[32]byte, err error) {
	var wk [32]byte
	var healInit bool
	err = updateFS(func(ff *fsFile) error {
		sess := ff.session(from)
		if sess == nil || !sess.Established || sess.SID != p.SID {
			// The peer has a session we don't (we wiped, restored, or
			// never completed). A well-formed fs frame proves they
			// speak FS: record it and re-initiate, rate-limited.
			if ff.CapCache == nil {
				ff.CapCache = map[string]fsCapEntry{}
			}
			ff.CapCache[from] = fsCapEntry{Capable: true, At: time.Now().Unix()}
			// Issue #110: inbound FS proof also pins the capability.
			fsPinCapabilityLocked(ff, from, time.Now().Unix())
			if fsInitDue(ff, from, fsInitCooldownSeconds) {
				if ff.LastInitAt == nil {
					ff.LastInitAt = map[string]int64{}
				}
				ff.LastInitAt[from] = time.Now().Unix()
				healInit = true
			}
			return errFSNoSession
		}
		if p.N < 0 {
			return errFSBadFrame
		}
		rpk, err := fsDecode32(p.RPK)
		if err != nil {
			return err
		}
		peerRPK, err := fsDecode32(sess.PeerRatchetPub)
		if err != nil {
			return err
		}
		var msgKey [32]byte
		defer crypto.Zero(msgKey[:])
		switch {
		case subtle.ConstantTimeCompare(rpk[:], peerRPK[:]) == 1:
			if err := fsDecryptCurrentChain(sess, p, rpk, &msgKey); err != nil {
				return err
			}
		case sess.PrevRatchetPub != "" && subtle.ConstantTimeCompare(
			[]byte(p.RPK), []byte(sess.PrevRatchetPub)) == 1:
			// Late in-flight message from the replaced chain: only
			// skipped keys can decrypt it.
			ks, ok := sess.Skipped[fsSkippedEntryKey(sess.PrevRatchetPub, p.N)]
			if !ok {
				return errFSReplay
			}
			k, err := fsDecode32(ks)
			if err != nil {
				return err
			}
			copy(msgKey[:], k[:])
			crypto.Zero(k[:])
			delete(sess.Skipped, fsSkippedEntryKey(sess.PrevRatchetPub, p.N))
		default:
			// Genuinely new peer ratchet key: DH-ratchet, then
			// decrypt on the new chain.
			if err := fsDHStepLocked(sess, rpk, p.PN); err != nil {
				return err
			}
			if err := fsDecryptCurrentChain(sess, p, rpk, &msgKey); err != nil {
				return err
			}
		}
		nonceRaw, err := b64fs.DecodeString(p.Nonce)
		if err != nil || len(nonceRaw) != crypto.NonceLen {
			return errFSBadFrame
		}
		var nonce [crypto.NonceLen]byte
		copy(nonce[:], nonceRaw)
		ct, err := b64fs.DecodeString(p.CT)
		if err != nil || len(ct) == 0 {
			return errFSBadFrame
		}
		pt, ok := secretbox.Open(nil, ct, &nonce, &msgKey)
		crypto.Zero(ct)
		if !ok {
			return errFSDecrypt
		}
		plain = pt
		wk = crypto.FSAttachWrapKey(msgKey)
		sess.MsgsRecvd++
		return nil
	})
	if healInit {
		_ = c.sendFSInit(from)
	}
	if err != nil {
		return nil, nil, err
	}
	return plain, &wk, nil
}

// ---- user-facing session management ----

// FSSessionInfo is a human-readable session summary for `courier fs status`.
type FSSessionInfo struct {
	Peer           string
	Established    bool
	Initiator      bool
	Mode           string
	MsgsSent       int64
	MsgsRecvd      int64
	LastRotateAt   int64
	SinceHandshake int64
	// Issue #110: fail-closed policy, capability pin, downgrade state.
	RequireFS          bool
	Pinned             bool
	DowngradeSuspected bool
	DowngradeSince     int64
}

// FSStatus lists FS sessions (one peer, or all).
func (c *Client) FSStatus(peer string) ([]FSSessionInfo, error) {
	var address string
	if peer != "" {
		a, err := c.cfg.ResolveRecipient(peer)
		if err != nil {
			return nil, err
		}
		address = a
	}
	ff, err := loadFS()
	if err != nil {
		return nil, err
	}
	var out []FSSessionInfo
	for addr, sess := range ff.Sessions {
		if address != "" && addr != address {
			continue
		}
		mode := ff.PeerModes[addr]
		if mode == "" {
			mode = fsModeAuto
		}
		_, pinned := ff.FSPins[addr]
		downgradeSince, downgrade := ff.Downgrade[addr]
		out = append(out, FSSessionInfo{
			Peer: addr, Established: sess.Established,
			Initiator: sess.Initiator, Mode: mode,
			MsgsSent: sess.MsgsSent, MsgsRecvd: sess.MsgsRecvd,
			LastRotateAt: sess.LastRotateAt, SinceHandshake: sess.CreatedAt,
			RequireFS: ff.RequireFS[addr], Pinned: pinned,
			DowngradeSuspected: downgrade, DowngradeSince: downgradeSince,
		})
	}
	return out, nil
}

// FSStart initiates an FS handshake now. It needs known capability
// (directory, handshake memory, or `fs on`); otherwise it errors rather
// than spamming a possibly-legacy peer with handshake frames.
func (c *Client) FSStart(peer string) error {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return err
	}
	if address == c.cfg.Address {
		return errors.New("cannot FS-handshake with self")
	}
	ff, err := loadFS()
	if err != nil {
		return err
	}
	known := ff.PeerModes[address] == fsModeOn || ff.session(address) != nil
	if !known {
		if e, ok := ff.CapCache[address]; ok && e.Capable &&
			time.Now().Unix()-e.At < fsCapCacheTTL {
			known = true
		}
	}
	if !known && c.fsDirectoryCapable(address) {
		known = true
		_ = updateFS(func(ff *fsFile) error {
			if ff.CapCache == nil {
				ff.CapCache = map[string]fsCapEntry{}
			}
			ff.CapCache[address] = fsCapEntry{Capable: true, At: time.Now().Unix()}
			return nil
		})
	}
	if !known {
		return fmt.Errorf("no FS capability known for %s (not in directory, no prior handshake); use `courier fs on %s` to mark them capable and initiate", shortPeer(address), peer)
	}
	return c.sendFSInit(address)
}

// FSSetPeerMode sets the per-peer FS mode ("on"/"off"/"auto"). "on"
// marks the peer capable and initiates a handshake; "off" erases any
// session and disables FS for the peer.
func (c *Client) FSSetPeerMode(peer, mode string) error {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return err
	}
	switch mode {
	case fsModeOn, fsModeOff, fsModeAuto:
	default:
		return fmt.Errorf("bad fs mode %q", mode)
	}
	err = updateFS(func(ff *fsFile) error {
		if mode == fsModeOff {
			// Erasure: disabling FS drops the session's keys now.
			delete(ff.Sessions, address)
			// Explicit user action, not a downgrade: clear markers.
			// (The capability pin is a historical fact and is kept.)
			delete(ff.Downgrade, address)
			delete(ff.DowngradeWarnedAt, address)
		}
		if ff.PeerModes == nil {
			ff.PeerModes = map[string]string{}
		}
		if mode == fsModeAuto {
			delete(ff.PeerModes, address)
		} else {
			ff.PeerModes[address] = mode
		}
		return nil
	})
	if err != nil {
		return err
	}
	if mode == fsModeOn {
		return c.sendFSInit(address)
	}
	return nil
}

// FSSetRequireFS sets (or clears) the per-contact fail-closed policy
// (issue #110): when set, sends to peer fail closed with errFSRequired
// unless an FS session is established — they never silently fall back
// to legacy encryption. The default is fail-open (policy absent),
// matching pre-#110 behavior. Setting the policy does not initiate a
// handshake; use `courier fs on <peer>` or `courier fs start <peer>`
// to establish a session first, otherwise sends will fail until one
// exists.
func (c *Client) FSSetRequireFS(peer string, require bool) error {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return err
	}
	return updateFS(func(ff *fsFile) error {
		if ff.RequireFS == nil {
			ff.RequireFS = map[string]bool{}
		}
		if require {
			ff.RequireFS[address] = true
		} else {
			delete(ff.RequireFS, address)
		}
		return nil
	})
}

// FSRequireForPeer reports whether the fail-closed require_fs policy
// (issue #110) is set for peer.
func (c *Client) FSRequireForPeer(peer string) (bool, error) {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return false, err
	}
	ff, err := loadFS()
	if err != nil {
		return false, err
	}
	return ff.RequireFS[address], nil
}

// FSPinnedAt returns the unix timestamp when FS capability was first
// observed for the peer's address (issue #110), or 0 if never pinned.
func (c *Client) FSPinnedAt(peer string) (int64, error) {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return 0, err
	}
	ff, err := loadFS()
	if err != nil {
		return 0, err
	}
	return ff.FSPins[address], nil
}

// FSRekey forces a DH rotation on the next send to peer.
func (c *Client) FSRekey(peer string) error {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return err
	}
	return updateFS(func(ff *fsFile) error {
		sess := ff.session(address)
		if sess == nil || !sess.Established {
			return fmt.Errorf("no established FS session with %s", shortPeer(address))
		}
		sess.RekeyFlag = true
		return nil
	})
}

// FSForget erases the FS session with peer and disables FS for them (so
// a peer that keeps sending FS doesn't silently re-establish).
func (c *Client) FSForget(peer string) error {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return err
	}
	return updateFS(func(ff *fsFile) error {
		delete(ff.Sessions, address)
		if ff.PeerModes == nil {
			ff.PeerModes = map[string]string{}
		}
		ff.PeerModes[address] = fsModeOff
		// Explicit user action, not a downgrade: clear markers.
		delete(ff.Downgrade, address)
		delete(ff.DowngradeWarnedAt, address)
		return nil
	})
}
