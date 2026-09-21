# Forward secrecy: per-conversation Double-Ratchet sessions (issue #50)

**Status:** design for v0.11.0. Implementation follows this document.
**Scope:** per-conversation (1:1 DM) forward secrecy for the wire protocol,
plus stored-state erasure of old keys in client state, client backups, and
relay-retained envelopes.

## 1. Background: what Courier guarantees today

Every DM is sealed with NaCl `crypto_box` to the recipient's X25519 key
using a **fresh ephemeral sender key per message** (see `internal/crypto`,
PROTOCOL.md "Encryption"). Stated honestly:

- Sender-side FS: yes — a compromised *sender* key cannot decrypt past
  messages (the ephemeral is gone).
- Recipient-side FS: **no** — the recipient's encryption key is long-lived.
  Anyone who captures ciphertext and later steals the recipient's X25519
  private key can read everything ever sealed to it. `courier rotate`
  (v0.5.0) bounds the window by retiring keys, but between rotations there
  is no forward secrecy, and the seed-derived key is re-derivable forever
  from the identity seed (see §6).

Issue #50 closes the recipient-side gap with a Double-Ratchet-style
per-conversation session, and erases old keys everywhere they are stored.

## 2. Goals and non-goals

**Goals**

1. After a session's DH ratchet advances, a compromise of either endpoint
   (device state *or* long-term keys) cannot decrypt messages sent before
   the advance. Per-message keys are erased immediately after use.
2. Old session keys are deleted from **client state** (`~/.courier/fs.json`),
   never enter **client backups** (`#47` payloads), and are unrecoverable
   from **relay-retained envelopes** (cryptographically, not by deletion —
   see §6).
3. **Migration story first** (the v0.6.11 lesson): no breaking wire change.
   Mixed-version pairs keep working; when the peer can't do FS, the client
   silently falls back to today's legacy encryption. No flag day, no
   coordination call with the other operator required.

**Non-goals (v1)**

- Group messages, channels, and shared-state events keep their existing
  crypto. FS sessions cover 1:1 DMs only (chat text + attachments).
  Protocol DMs (group/channel/state/handshake traffic) stay legacy-sealed:
  they are machine state where delivery reliability matters more, and the
  inbox pipeline decrypts FS before dispatching, so this is a one-line
  change per call site later if wanted.
- Metadata protection: the relay still sees from/to/timing/sizes, exactly
  as with legacy DMs.
- Post-compromise security beyond what the DH ratchet gives; deniability;
  multi-device session sync (sessions are per-device, see §7).

## 3. Negotiation: how two clients agree on the ratchet

The contact-discovery design (issue #39, `docs/contact-discovery-proposal.md`)
gives us **free-form capability tokens** on directory profiles (≤8 tokens,
≤32 chars each, matched opportunistically, no registry). FS negotiation uses
them — no new relay endpoint, no new signed object.

- **Capability token:** `fs`. A v0.11.0+ client includes `fs` in its
  directory profile capabilities on `directory register` and
  `directory update` (auto-added by the client; the token is inert for
  older clients, which ignore unknown tokens).
- **Positive capability knowledge** — the client initiates an FS handshake
  only when it *knows* the peer supports FS, from any of:
  1. **Directory:** reverse lookup of the peer's address returns a profile
     listing `fs` (works for public/unlisted handles; private handles are
     excluded from reverse lookup by design — see limitation below).
     Positive results are cached in `fs.json` for 24h (same TTL discipline
     as the handle cache); negative results are cached for 10 minutes so
     ordinary legacy sends don't hit the directory on every message (a
     newly-registered peer is discovered on the next send after that).
  2. **Handshake memory:** a previous successful handshake with the address
     is recorded locally — no re-probing, ever.
  3. **Explicit user intent:** `courier fs on <peer>` marks the peer capable
     and initiates; `courier fs start <peer>` initiates when capability is
     already known.
  4. **Inbound proof:** receiving a valid `fs-init` proves the peer speaks
     FS; the client records it and answers.
- **Fallback:** no positive knowledge → today's legacy seal, byte for byte.
  The client **never sends handshake probes to unknown peers**: an `fs-init`
  is a protocol DM, and a legacy client would display its JSON as a chat
  message. Probing strangers would spam them with garbage — the exact
  failure mode the v0.6.11 policy exists to prevent.
- **Opt-out:** `courier fs off <peer>` disables FS for a peer (legacy only).
  `courier fs forget <peer>` erases the session and sets the peer to off
  (so a peer that keeps sending FS doesn't silently re-establish).
- **Fail-closed opt-in (issue #110):** `courier fs require <peer>` sets a
  per-contact policy under which sends **refuse** to fall back to legacy:
  without an established FS session the send fails with an error instead
  of going out legacy-sealed. `courier fs require <peer> off` lifts it.
  The default stays fail-open (see §9).

**Limitation, stated plainly:** peers with private handles (or no handle)
cannot advertise `fs` through the directory. For those peers, FS starts
with `courier fs on <peer>` (one explicit user action), after which
handshake memory keeps it working.

## 4. Session protocol

### 4.1 Transport: FS lives *inside* the existing envelope

The outer envelope (`POST /v1/send`: to/from/eph/nonce/ct/sent_at/sig) is
**byte-identical to legacy DMs**. The relay cannot distinguish an FS message
from a legacy one, needs no changes, and the inbox trial-decryption path
(try each retained X25519 private key) is untouched. FS is purely a
plaintext-layer protocol: the inner plaintext is either legacy (raw body or
`messagePayload` JSON) or an FS frame:

```json
{"cf":1, "t":"fs-msg", "v":1, "sid":"<base64url 16B>",
 "rpk":"<base64url 32B sender ratchet pub>",
 "n":<send counter>, "pn":<prev chain length>,
 "nonce":"<base64url 24B>", "ct":"<base64url secretbox>"}
```

`cf:1` is the FS magic (group=1/`cg`, channel=2/`cc`, state=1/`cs` already
taken). The inner `ct` is XSalsa20-Poly1305 (`secretbox`) under the
per-message key; it seals the chat body or the `messagePayload` JSON
(body + attachment manifests).

Handshake frames ride as **protocol DMs** (logSent=false, consumed silently
by the inbox layer like group/channel/state traffic, never in the sent log
or dashboard):

```json
{"cf":1, "t":"fs-init", "v":1, "sid":"...", "init_id":"<base64url 16B>",
 "rk0":"<base64url 32B>", "eph_pub":"<base64url 32B>", "r_pub":"<base64url 32B>"}

{"cf":1, "t":"fs-accept", "v":1, "sid":"...", "init_id":"<base64url 16B>",
 "eph_pub":"<base64url 32B>", "r_pub":"<base64url 32B>"}
```

Both are sealed with the legacy `crypto.Seal` to the peer's current
recipient key and signed with the sender's Ed25519 key — the same
authentication as every DM.

### 4.2 Handshake (X3DH-shaped, no prekeys needed)

The initiator (Alice) generates: `rk0` (32 random bytes), an ephemeral
X25519 keypair `ephA`, and a ratchet keypair `rA`. She sends `fs-init`.
The responder (Bob) generates `ephB` and ratchet keypair `rB`, and sends
`fs-accept`. Both compute:

```
dh1   = X25519(ephA_priv, ephB_pub) = X25519(ephB_priv, ephA_pub)
dh2   = X25519(rA_priv,  rB_pub)    = X25519(rB_priv,  rA_pub)
root0 = HKDF-SHA256(ikm = rk0 || dh1 || dh2,
                    salt = "courier-fs-handshake-v1" || sid)            → 32 B
chainI2R = HMAC-SHA256(root0, "courier-fs-chain-v1:initiator-to-responder")
chainR2I = HMAC-SHA256(root0, "courier-fs-chain-v1:responder-to-initiator")
```

- Initiator: sendChain=chainI2R, recvChain=chainR2I, ratchet=(rA_priv,rA_pub),
  peerRatchet=rB_pub.
- Responder: sendChain=chainR2I, recvChain=chainI2R, ratchet=(rB_priv,rB_pub),
  peerRatchet=rA_pub.
- `ephA_priv` / `ephB_priv` are erased immediately after `root0` is derived.

**Why this is forward-secret from message one:** `root0` mixes two
*ephemeral-ephemeral* DH outputs. An attacker holding only long-term keys
(even both parties') and the full relay transcript recovers `rk0` from the
init envelope but cannot compute `dh1` or `dh2` — the ephemeral privates
never leave the devices and are erased after use. The handshake envelopes
retained by the relay are therefore content-safe against long-term-key
compromise by construction (§6).

### 4.3 Double ratchet

Standard Signal-shaped, per conversation:

- **Symmetric chain step** (every message):
  `chain' = HMAC-SHA256(chain, 0x01)`, `msgKey = HMAC-SHA256(chain, 0x02)`.
  `msgKey` is erased immediately after encrypt/decrypt. The old chain key
  is overwritten in `fs.json` (old bytes zeroed first).
- **DH ratchet step** (on receiving a message whose `rpk` differs from the
  stored peer ratchet key):
  ```
  (root', recvChain') = HKDF-SHA256(salt=root,  ikm=DH(ratchetPriv, rpk_new), info="courier-fs-root-v1") → 64 B
  generate fresh ratchet keypair r_new (erase old ratchetPriv)
  (root'', sendChain') = HKDF-SHA256(salt=root', ikm=DH(r_new_priv, rpk_new), info="courier-fs-root-v1")
  ```
  The old root and both old chain keys are erased. This is the step that
  heals a compromise: everything before it becomes unreadable.
- **Rotation triggers** (so DH steps actually happen, not just symmetric
  steps): (a) receiver-side DH step mints a fresh keypair for the next
  send, as above; (b) a sender rotates its ratchet keypair after 25 sent
  messages or 24h since the last rotation, advertising the new `rpk`;
  (c) `courier fs rekey <peer>` forces rotation on the next send;
  (d) the initiator rotates on its first send after receiving `fs-accept`,
  so the handshake's ratchet key is promptly replaced and the DH ping-pong
  starts immediately.
- **Out-of-order / gaps:** the header's `n`/`pn` let the receiver derive
  skipped message keys for the previous chain (bounded: 100 keys; erased on
  use, or dropped when the bound is exceeded, oldest first). Skipped keys
  from older chains are erased on each DH step — a message delayed past
  two DH steps is undecryptable, by design (erasure wins over extreme
  delay; the 30-day relay retention makes multi-DH-step delays pathological
  anyway).

### 4.4 Conflict resolution (simultaneous / repeated inits)

State per peer: `none | pending-out(init_id) | established`.

- Receiving `fs-init` while `pending-out` or `established`: **address
  tie-break** — if the peer's address is lexicographically smaller than
  ours, adopt their init (become responder, send `fs-accept`, replace any
  session); otherwise ignore it (our init wins; they will accept ours).
  Both sides apply the same rule, so simultaneous inits converge on the
  smaller address as initiator.
- Receiving `fs-init` while `established` from a peer that lost state is
  always honored (adopt + accept): it is an explicit rekey signal. (The
  tie-break only arbitrates init-vs-init races.)
- Receiving `fs-accept` for our `pending-out` init_id → `established`.
  An accept for any other init_id is ignored.
- Receiving `fs-msg` with an unknown `sid` → the peer's session and ours
  diverged (e.g. they restored from backup, which wipes `fs.json`). Send a
  fresh `fs-init` (rate-limited: at most one per peer per 60s, to rule out
  ping-pong loops) and drop the message as undecryptable. Self-healing
  without user action.
- Replays of handshake envelopes are already suppressed by the per-consumer
  seen sets (v0.9.2); a *fresh* init (new `init_id`) is always processed.

### 4.5 Upgrade path: opportunistic, first message may be legacy

`courier send` to a capable peer with no session: the client sends
`fs-init` (protocol DM) **and** delivers the message via legacy seal in the
same call. When `fs-accept` arrives, the session establishes and all later
messages use FS. `courier fs start <peer>` pre-establishes a session so a
sensitive conversation is FS from message one. This is honest about the
trade-off: no send ever blocks on a handshake round-trip, at the cost that
message #1 to a newly discovered FS peer has legacy-grade protection.

## 5. What the ratchet does NOT change

- **Outer envelope, relay, inbox fetch, dedup, spam filtering, dashboard
  push, sent log, attachments blob store**: all untouched. FS frames are
  decrypted to ordinary plaintext before the existing pipeline
  (group/channel/state/chat dispatch) runs.
- **Attachment data keys**: for FS sends, the per-file data key is wrapped
  under a wrap key derived from the FS message key
  (`wrapKey = HKDF(msgKey, "courier-fs-attach-v1")`, secretbox) instead of
  the recipient's long-term X25519 key. The `WrappedKey` wire shape is
  unchanged (`recipient` stays the address; `eph` carries 32 random bytes),
  so `envelope.ValidateManifest` still passes; the receive path chooses the
  unwrap method by transport (FS vs legacy). Attachment *contents* are
  therefore FS too — a long-term-key compromise does not reveal files sent
  over FS, only their relay-side metadata (blob id, size, timing).
- **Protocol DMs** (group/channel/state/fs-handshake) stay legacy-sealed.

## 6. Stored-state erasure

### (a) Client state — `~/.courier/fs.json` (0600, atomic writes, config lock)

Holds per peer: session id, role, root key, current send/recv chain keys
+ counters, current ratchet keypair, peer ratchet pub, bounded skipped keys
(≤100), capability mode/cache, handshake state. **Nothing else.**

- On every symmetric step the superseded chain key is overwritten; on
  every DH step the old root, both old chain keys, and the old ratchet
  private key are overwritten. Overwritten byte slices are zeroed before
  release (best-effort memory hygiene; Go has no locked-memory primitive
  here, and the doc says so).
- Message keys exist only in memory during a single encrypt/decrypt call,
  then are zeroed. They are never written to disk.
- `courier fs forget <peer>` deletes the peer's session record (and sets
  the peer to FS-off so it doesn't silently re-establish).
- Replacing a session (rekey, conflicting init) erases the old record first.

### (b) Client backups — issue #47

- `fs.json` is **never included** in backup or sync payloads: those are
  built from `Config` only (`backupPayload`), and no session-key field is
  added. Regression-tested: a backup taken with live sessions contains no
  session key material.
- `backup restore` **wipes `~/.courier/fs.json`**. A restored identity is a
  new device: it re-handshakes with peers (they self-heal via §4.4). Keeping
  the old device's session keys on a new machine would defeat erasure and
  multi-device reasoning alike.
- `backup import-sync` merges only long-term `EncKeys`; session keys are
  not syncable by design — syncing them would plant long-lived copies of
  ephemeral keys in sync envelopes.
- **Honest limitation — the seed:** a backup contains the identity seed,
  and the seed re-derives the original X25519 keypair forever. Anyone
  holding an old backup can decrypt anything *ever sealed to the
  seed-derived key* — legacy DMs and handshake envelopes retained on the
  relay. FS **session content** is unaffected (session keys are random and
  never derive from the seed). After a restore from an old backup, run
  `courier rotate` so *future* messages go to a fresh key; the seed-derived
  key's permanent decrypt capability for *past* ciphertext is inherent to
  the v0.5.0 identity design and out of scope for #50. The CLI prints this
  reminder after `backup restore`.

### (c) Relay-retained envelopes

**No relay change.** Erasure here is cryptographic, not deletion-based —
deliberately, because deleting post-delivery breaks multi-device sync
(issue #47): device B must still be able to fetch what device A already
read, and the relay cannot know when "all devices" are done.

- FS message envelopes hold ciphertext under per-message keys that are
  erased on use. Once the clients have ratcheted past, the relay's copy is
  permanently unreadable — to anyone, including the relay operator and
  anyone who later compromises either endpoint's long-term keys. There is
  no key left anywhere that opens them.
- Handshake (`fs-init`/`fs-accept`) envelopes are sealed under long-term
  keys, but §4.2 shows their content (`rk0` + ephemeral pubs) is
  insufficient to recover the session without the erased ephemeral DH
  privates. A long-term-key-only compromise within the 30-day retention
  window reveals *that* a handshake happened (metadata), never the session.
- The relay's existing 30-day retention prune then deletes the envelopes
  anyway. No new endpoint, no redeploy, no per-device deletion protocol
  with its attendant races.

## 7. Multi-device

Sessions are **per-device** (like the v0.6.11 seen sets are per-consumer).
Two devices sharing an identity each handshake independently with a peer;
the peer keeps the latest session per address (a new `fs-init` from the
same address rekeys, §4.4). Consequence, documented: the peer's FS replies
are readable on whichever of your devices completed the latest handshake.
This matches the existing per-device reality of `fs.json`-style local
state, and the self-healing init keeps it working without user intervention.

## 8. CLI

```
courier fs status [<peer>]   show FS sessions (peer, established, messages sent, last DH rotation, mode)
courier fs start <peer>      initiate a handshake now (needs known capability or `fs on`)
courier fs on <peer>         mark peer FS-capable and initiate
courier fs off <peer>        disable FS for peer (legacy only from now on)
courier fs rekey <peer>      force a DH rotation on next send
courier fs forget <peer>     erase the session (implies off)
courier fs require <peer> [on|off]
                             fail-closed policy: refuse legacy fallback for
                             this peer unless an FS session is established
                             (default on; `off` lifts it back to fail-open)
```

Handshake traffic never touches `~/.courier/sent.jsonl` (logSent=false,
the existing `sendProtocolDM` pattern) — the dashboard shows only human
chat.

## 9. Security properties, honestly stated

- **Provided:** per-message FS within a session (message keys erased on
  use); DH-ratchet FS across rotations (old roots/chains/ratchet privates
  erased); long-term-key-only compromise never reveals session content
  (ephemeral-ephemeral DH in the handshake root); graceful fallback keeps
  mixed-version pairs working.
- **Not provided:** metadata protection; protection of messages sent on a
  device compromised *before* the next DH step (inherent — the live state
  decrypts live messages); readability of messages delayed past two DH
  steps (erasure wins); FS for group/channel/state protocol traffic (v1
  scope); anything sealed to the seed-derived key by a holder of an old
  backup (§6b limitation).
- **Downgrade resistance:** FS is opportunistic **by default**, not
  enforced — a network attacker who suppresses `fs-init`/`fs-accept`
  keeps the conversation on legacy encryption. This is the standard
  opportunistic-encryption trade-off (cf. STARTTLS): it raises the cost
  of passive collection without promising protection against an active
  attacker who controls delivery. `courier fs status` shows whether a
  conversation is actually under FS, so users can verify.
- **Downgrade detection (issue #110):** the client *pins* observed FS
  capability per contact (`fs.json`: address → first-observed timestamp,
  set on completed handshakes and valid inbound FS frames). A pinned
  peer keeps receiving handshake attempts even when the relay suppresses
  directory availability (the pin is permanent capability knowledge),
  and a pinned peer that is suddenly reachable only via legacy — no
  session, no current positive capability evidence, no handshake in
  flight — is flagged: a persistent `downgrade_since` marker (visible in
  `courier fs status` as `⚠ DOWNGRADE SUSPECTED`) plus a rate-limited
  warning on send. The marker clears when the peer shows positive
  capability again or a session re-establishes. Pins and policies are
  keyed by the peer's address (the cryptographic identity), never by
  contact name.
- **Fail-closed mode (issue #110):** `courier fs require <peer>` makes
  sends to that contact refuse legacy fallback — without an established
  FS session the send fails with an error. This closes the
  relay-suppressible downgrade for contacts that opt in. It does not
  probe unknown peers (`fs on`/`fs start` still bootstrap capability),
  and it deliberately wins over `fs off` if both are set (contradictory
  configuration fails closed, loudly).
- **The default question, still open:** the default remains **fail-open**,
  exactly as v0.11.0 shipped — mixed-version pairs keep working with no
  flag day. Whether `require_fs` should become the default in a future
  release is an explicit product decision, not taken here: fail-closed
  by default would refuse sends to every legacy/unknown peer until a
  handshake completes, which changes the delivery-reliability contract
  the migration story was built on.

## 10. Changes

- **New:** `internal/crypto/ratchet.go` (KDFs, DH helpers),
  `internal/client/fs.go` (sessions, handshake, send/recv integration,
  `fs.json` store), `cmd/courier/fs.go` (CLI), this doc.
- **Touched:** `internal/client/client.go` (send path FS branch, inbox FS
  dispatch, attachment unwrap selection, FS warning plumbing),
  `internal/client/attachments.go` (FS data-key wrap variant),
  `internal/client/directory.go` (auto-add `fs` capability on register/update),
  `internal/client/backup.go` (wipe `fs.json` on restore + rotate reminder),
  `internal/client/bridge.go` (downgrade-warning surfacing on bridged sends),
  `PROTOCOL.md`, `README.md`.
- **Issue #110 (fail-closed policy + downgrade detection):** new in
  `internal/client/fs.go` — `RequireFS`/`FSPins`/`Downgrade`/
  `DowngradeWarnedAt` in `fs.json` (additive; old files load unchanged),
  `errFSRequired`, `fsAssessDowngrade`, `fsPinCapabilityLocked`,
  `Client.FSSetRequireFS`/`FSRequireForPeer`/`FSPinnedAt`/
  `FSConsumeWarning`, extended `FSSessionInfo`; new in
  `cmd/courier/fs.go` — `courier fs require <peer> [on|off]` and the
  `require-fs` / `capability: pinned` / `DOWNGRADE SUSPECTED` status lines.
  Default behavior is unchanged (fail-open).
- **Relay / dashboard: no changes.** No new endpoints, no migration, no
  redeploy. The wire is unchanged; negotiation reuses the directory's
  existing capability tokens.
