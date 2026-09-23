# Courier Protocol Specification — v1

This document specifies the Courier wire protocol: message envelopes,
encryption, signatures, the relay API, and the client behaviors that make
the system work. It is written for implementers of interoperable
clients and relays, and for reviewers who need a precise statement of
what the protocol guarantees and what it does not.

**Scope.** This spec describes the protocol as implemented at
`origin/main` of `black-candle-technologies/courier`, including the
merged bridge phase 1 (issue #61). In-flight work on feature branches
(see Appendix B) is not part of the spec yet.

**Reading order.** §1–§4 give the model. §5–§8 define the cryptographic
core. §9 is the relay API reference. §10–§14 cover messaging machinery
every endpoint relies on. §15–§24 specify optional protocol layers that
ride inside ordinary envelopes. §25 covers the bridge boundary, §26 the
dashboard, §27–§28 the security properties stated honestly, §29
versioning. Appendix A is the canonical signature-domain registry;
Appendix B lists pending changes.

## 1. Overview

Courier is store-and-forward, end-to-end encrypted messaging between
agents. There is exactly one trusted-by-design network component, the
**relay**: it stores opaque ciphertext envelopes and serves them to the
addressed recipient. It never holds decryption keys and cannot read
message contents. It does see **metadata** — who exchanges envelopes,
when, approximate sizes, IP-level connection facts, directory activity,
and blob identifiers. See §27–§28 for the precise, honest statement.

Communication is pairwise by default (direct messages, "DMs"). Optional
layers add group messaging (§16), OOB-code private channels (§17),
contact discovery (§18), shared agent state (§20), delivery receipts
(§21), reply threading (§22), disappearing messages (§23), and a
ChatGPT-web ingest bridge that is explicitly **not** end-to-end
encrypted (§25). A human-facing web dashboard (§26) shows decrypted
messages pushed by the agent that owns the keys; the dashboard itself
never decrypts.

All relay interactions are HTTPS with certificate pinning (§4). Every
protocol statement an endpoint makes to the relay is signed with the
sender's Ed25519 identity key under a domain-separated canonical form
(§7). Replay is handled by a content hash with a per-consumer seen set
(§10), not by timestamp windows.

## 2. Terminology

- **Agent / endpoint.** A program holding a Courier identity. Agents are
  the only parties that ever hold private keys.
- **Identity.** An Ed25519 keypair derived from a 32-byte seed
  (§5). The public key is both the signing key and the address.
- **Address.** `ed25519:<base64url>` — the 32-byte Ed25519 public key
  with a type prefix (§5.2). Addresses name recipients; they are not
  secret.
- **Relay.** The central store-and-forward server. It validates
  envelopes, verifies signatures, stores ciphertext, and serves it to
  the addressed recipient. One relay serves a deployment; this spec
  assumes a single relay per deployment.
- **Envelope.** The signed unit of transmission (§8). The relay stores
  and forwards envelopes; only endpoints can open them.
- **Plaintext.** What the envelope's ciphertext decrypts to. May be raw
  chat text or a versioned JSON payload (§13).
- **Protocol DM.** A machine-readable DM consumed silently by the
  client's protocol layers (group key distribution, channel handshake,
  shared-state events, FS handshake, receipts, introductions). Protocol
  DMs are ordinary envelopes; they never surface as chat and (except
  receipts' and handshake traffic's documented behavior) are never
  shown to the user. Legacy clients render their JSON as chat text
  (harmless degradation, §29).
- **Consumer.** One of the client's independent inbox readers. The
  implementation has three: the interactive inbox poller, the dashboard
  pusher, and the state-sync reader. Each keeps its own seen set and
  cursor (§10.2).
- **Bridge identity.** The Courier identity held by the ChatGPT-web
  bridge gateway (§25). Messages it sends are real envelopes signed by
  the gateway — they are end-to-end encrypted from the gateway to the
  recipient, but the gateway saw the plaintext before sealing it.

## 3. Notation and conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**,
and **OPTIONAL** in this document are to be interpreted as described in
RFC 2119.

Additional notation:

- `base64url(x)` — base64url encoding **without padding**
  (`base64.RawURLEncoding`), used for every binary field on the wire.
- `be64(n)` — the unsigned 64-bit big-endian encoding of `n`.
- `A || B` — byte-string concatenation.
- `0x00` — a single zero byte, used as a field separator in canonical
  forms.
- `SHA256(x)`, `HMAC-SHA256(k, x)`, `HKDF-SHA256(...)` — as in
  `internal/crypto/ratchet.go`.
- Unix time is seconds since the epoch, as a signed 64-bit integer.
- All JSON field names are exactly as shown; clients MUST ignore
  unknown JSON fields in relay responses and in decrypted payloads
  (§29).
- A "domain string" names the signature context, e.g.
  `"courier-envelope-sig-v1"`. In the implementation the domain is
  stored with a trailing `0x00` already appended
  (`internal/envelope/envelope.go`); the canonical forms below show the
  domain **including** that trailing separator byte as `D\x00` for
  clarity.

## 4. Transport

Courier uses **HTTPS only** for all relay and dashboard traffic. There
is no plaintext HTTP endpoint.

### 4.1 Certificate pinning

Relays use **self-signed certificates** (bare IP deployments cannot get
public CA certificates). Trust is established by certificate pinning
(`internal/tlscert/tlscert.go`, `internal/client/client.go`):

- At `courier init`, the client fetches the relay's certificate and
  pins its SHA-256 fingerprint (stored in `~/.courier/config.json` as
  `relay_fingerprint`). The fingerprint is printed at `init` (and by
  the relay at startup) so it can be compared against the operator's
  published value.
- Every connection verifies the presented certificate against the pin;
  any other certificate is rejected, defeating network-level
  impersonation. A missing pin is a hard error: the client refuses to
  connect and tells the user to `--repin` after verifying the
  fingerprint out of band.
- The client honors `HTTPS_PROXY`/`HTTP_PROXY` (CONNECT tunnels); the
  pin still applies end to end.

The relay generates a self-signed certificate on first start if none
is configured (`tlscert.Ensure`), defaulting to `<dbdir>/tls.crt` /
`<dbdir>/tls.key` (`cmd/courier-relay/main.go`).

### 4.2 What TLS does and does not hide

TLS with pinning protects **metadata from network observers** — who
exchanges envelopes, when, and how much — from anyone on the path who
is not the relay. Message contents are already protected by
end-to-end encryption. **The relay itself still sees metadata**
(§27.1).

## 5. Identities, addresses, and key management

### 5.1 The identity

Each agent holds one **32-byte seed**, the master secret
(`internal/crypto/crypto.go`):

- From the seed the agent derives an **Ed25519 keypair**: the
  long-term identity. It never changes for the life of the seed.
- The **initial X25519 encryption keypair** is, since v0.6.11, an
  **independent random keypair** generated at `courier init`
  (F13) — *not* derived from the seed, so that seed holders cannot
  regenerate it. Its signed announcement is published to the relay at
  init (`courier publish-key` republishes it).
- Identities created **before** v0.6.11 have a seed-derived epoch-0
  encryption key (`XPriv = clamp(SHA512(seed)[0:32])`, libsodium-style,
  `internal/crypto/crypto.go` `IdentityFromSeed`). Anyone holding such
  an identity's seed can regenerate its epoch-0 encryption key. Those
  identities MUST run `courier rotate` to move to an independent
  random key; until then, seed compromise also compromises epoch-0
  message confidentiality (§9.5).

The seed is stored at `~/.courier/config.json`, mode 0600, and in
encrypted identity backups (§5.4). There is no registration, no
username, no password at the protocol layer.

**Correction to earlier documentation:** earlier versions of this
document said "the seed never leaves the agent's machine." That was
wrong. The seed is included in encrypted identity backups by design
(`internal/client/backup.go` `CreateBackup`) — that is how
`backup restore` rebuilds an identity. What remains true: the seed is
never sent to the relay, never appears in any protocol message, and
is never logged.

### 5.2 Addresses

An address is the ASCII string:

```
ed25519:<base64url of the 32-byte Ed25519 public key>
```

The `ed25519:` prefix is part of the address
(`crypto.AddressPrefix`). It makes the key type explicit and makes
legacy v0.1.0 bare-X25519 addresses fail loudly instead of encrypting
to a dead key. Parsers MUST require the prefix
(`crypto.ParseAddress`); v0.1.0 addresses are invalid.

Anyone can compute the **address-derived** X25519 public key from an
address via the Edwards-to-Montgomery birational map
`u = (1+y)/(1-y)` (`crypto.Ed25519PubToX25519`, rejecting
non-canonical encodings). Senders use it only when no signed key
announcement exists for the recipient (§9.5).

### 5.3 Encryption keys and rotation

The recipient encryption key is rotatable **without changing the
address** (`Client.RotateKey`, `internal/client/client.go`):

- `courier rotate` generates a fresh random X25519 keypair, publishes
  a signed announcement to the relay's key directory (§9.5), and
  keeps up to 4 retired private keys for decrypting in-flight messages
  (`Config.encryptionPrivKeys`).
- Senders seal to the announced key when one exists, else to the
  address-derived key. Recipients trial-decrypt across retained keys
  (§12.2).
- Rotation bounds the recipient-side forward-secrecy window for
  legacy-sealed DMs (§15.1). Rotate regularly, and immediately on
  suspected compromise.

### 5.4 Backups

`courier backup` encrypts the identity (seed, address, encryption
keys) for restore on a new machine (`internal/client/backup.go`).
Session keys are **never** included: `fs.json` is excluded from backup
payloads and `backup restore` **wipes** `~/.courier/fs.json`, because
a restored identity is a new device and must re-handshake (§15.7).

**Honest limitation:** a backup contains the seed, and the seed
re-derives the original X25519 keypair forever (pre-rotation
identities especially). Anyone holding an old backup can decrypt
anything ever sealed to the seed-derived key — legacy DMs and FS
handshake envelopes retained on the relay. FS **session content** is
unaffected (session keys are random and never derive from the seed).
After restoring from an old backup, run `courier rotate` so future
messages go to a fresh key; the CLI prints this reminder.

## 6. Cryptographic primitives

All in `internal/crypto` (Go standard library plus
`golang.org/x/crypto`):

| Primitive | Construction | Use |
|---|---|---|
| Signatures | Ed25519 | Every envelope and every relay request |
| Key exchange | X25519 | `crypto_box` key agreement |
| Message encryption | NaCl `crypto_box` (X25519 + XSalsa20-Poly1305) | DM envelopes |
| Symmetric encryption | NaCl `secretbox` (XSalsa20-Poly1305) | Group bodies, attachment chunks, FS inner ciphertext |
| Key derivation | HKDF-SHA256, HMAC-SHA256 | FS ratchet (`internal/crypto/ratchet.go`) |
| Hashing | SHA-256 (dedup, key directory, safety numbers use SHA-512) | Content addressing, fingerprints |
| Randomness | `crypto/rand` | Ephemeral keys, nonces, seeds, blob ids, group ids |

- For every DM the sender generates a **fresh ephemeral X25519
  keypair** and seals the plaintext to the recipient's X25519 key
  (`crypto.Seal`). The nonce is 24 fresh random bytes.
- Ciphertext is Poly1305-authenticated; decryption failure is a hard
  error, never a partial read.

### 6.1 Crypto suites and versioning (issue #138)

Every cryptographic operation names the **suite** it runs under — a
versioned bundle of algorithms with a stable string id:

| Suite id | Kind | Algorithms |
|---|---|---|
| `ed25519-x25519-naclbox-v1` | message suite | Ed25519 signatures, X25519 key agreement, NaCl `crypto_box` (XSalsa20-Poly1305) |
| `x25519-hkdf-sha256-v1` | FS suite | X25519 DH, HKDF-SHA256 KDF, Signal-shaped chains, NaCl `secretbox` message keys |

A suite is "known" **if and only if** a descriptor with real
implementations is registered (`crypto.Descriptor`,
`crypto.FSDescriptor`). A bare suite name — on the wire, in a
config, anywhere — never selects behavior by itself: unknown names
are a loud refusal, never a silent fallback to v1. Every DH, KDF,
seal/open, and signature verification dispatches through the
resolved suite's descriptor (or an exhaustive switch over the
registry), so a future suite is an **additive registration**, not a
cross-cutting rewrite.

**Default-to-v1 compatibility.** The `suite` wire field is
`omitempty` everywhere it appears (DM envelope §8, key announcement
§9.5, group envelope §16.2, FS accept §15.3): absent means v1, so
pre-#138 peers interoperate without changes. Senders that know the
field MUST always emit it.

**Address/suite agreement.** Wherever a wire suite label meets
addresses (key-directory lookups, DM receive), the label and **every
address involved** must agree: `crypto.AgreeSuite` defaults an
absent label to v1 and requires the label to equal the suite parsed
from each address. A mismatch — or a label naming a suite the peer
does not implement — is a loud refusal to encrypt/decrypt, never a
best-effort attempt under the wrong algorithms.

Adding a suite is a deliberate, reviewed protocol change (§29):
register the descriptor, put it on the offer list, document the id
in the table above, and keep the v1 default intact so old clients
keep working.

## 7. Signed canonical forms

Every signature in Courier is Ed25519 over a **domain-separated
canonical byte string**. The domain binds the signature to one
protocol purpose: a signature for one purpose can never validate as
another. All multi-byte integers are `be64`; fixed-length fields are
raw bytes; variable-length fields are separated by `0x00`, and the
variable-length ciphertext is always last so encodings are
unambiguous. The full registry is in Appendix A; the definitions live
in `internal/envelope/envelope.go`.

The DM envelope canonical form (v0.2.0+):

```
"courier-envelope-sig-v1" || 0x00 ||
    to(32) || from(32) || eph(32) || nonce(24) || be64(sent_at) || ct
```

where `to`/`from` are the raw 32-byte Ed25519 keys (not the address
strings). The relay verifies this signature on every `POST /v1/send`
and rejects forgeries; the recipient re-verifies before decrypting
(§12.2). The `from` field is therefore **authenticated**: a message
that verifies came from the holder of that address's private key.

## 8. The message envelope (DM wire format)

`POST /v1/send`, JSON body (`internal/relay/server.go`
`sendRequest`):

```json
{
  "to":      "ed25519:<base64url Ed25519 public key>",
  "from":    "ed25519:<base64url Ed25519 public key>",
  "eph":     "<base64url: ephemeral X25519 public key>",
  "nonce":   "<base64url: 24-byte nonce>",
  "ct":      "<base64url: crypto_box ciphertext>",
  "sent_at": 1758316234,
  "sig":     "<base64url: Ed25519 signature>",
  "kind":    "dm",
  "key_epoch": 3,
  "suite":   "ed25519-x25519-naclbox-v1"
}
```

- `suite` (issue #138) names the message crypto suite (§6.1).
  Senders MUST emit it; absent means
  `ed25519-x25519-naclbox-v1` (pre-#138 envelopes). The relay
  validates that a present `suite` is a known suite id and rejects
  unknown ones with `400` — it never executes v1 validation for a
  future suite's name. Recipients require agreement between the
  envelope's suite label and the sender/recipient address suites
  (§6.1); a mismatch is a hard decrypt refusal.
- `kind` is `""` (or `"dm"`) for direct messages and `"group"` for
  group messages (§16). The relay rejects unknown kinds with `400`.
  Clients MUST skip envelopes whose kind is neither `""` nor `"dm"`
  in personal inboxes, advancing the cursor past them (§29.2).
- `key_epoch` is used only for group messages.
- The relay validates shapes and sizes (ciphertext 1..256 KiB,
  `MaxCiphertextBytes`), verifies the signature, and responds
  `201 {"id": <relay envelope id>, "duplicate": false}`. A replayed
  envelope (§10) is acknowledged with its original id and
  `"duplicate": true` instead of a second row.

The request body is capped at `MaxCiphertextBytes + 8192` bytes
before JSON parsing.

## 9. Relay API reference

Base path is `/v1/`; breaking wire changes bump the version (§29).
All timestamps are unix seconds. All `sig` parameters are
`base64url` Ed25519 signatures. Signed requests MUST use a `ts`
within **300 seconds** of relay time (past or future); the relay
rejects stale or far-future requests — a captured signed request
cannot be replayed indefinitely.

Errors are JSON: `{"error": "<message>"}` with HTTP status codes:

| Code | Meaning |
|---|---|
| 400 | Malformed request, bad signature, stale timestamp, unknown kind |
| 401 | Missing or invalid authorization signature |
| 403 | Authenticated but not permitted (not a group member, not the report recipient, reserved handle) |
| 404 | Unknown blob, key, handle |
| 409 | Conflict: stale epoch, handle taken, tombstoned |
| 410 | Handle tombstoned by operator takedown (with public reason) |
| 429 | Rate-limited, throttled, or subscription cap |
| 201 | Created |

The reference implementation is `internal/relay/server.go` (routes),
backed by `internal/store/store.go` (SQLite).

### 9.1 Common authorization pattern

Inbox reads, subscriptions, blob downloads, and directory queries all
follow the v0.6.11 F10 pattern: the **requester signs the request**
over a domain-separated canonical form (§7) binding the resource,
cursor/limit where relevant, and a timestamp. The relay verifies the
signature **against the key named in the request** (the `to` address,
the blob's stored recipient, the querier). Authorization is therefore
self-contained: the relay needs no session table, and only the address
owner can read their ciphertext and metadata.

### 9.2 POST /v1/send

Stores one envelope (§8). Order of checks: shape validation →
signature verification → per-sender token bucket → reporter-based
throttle (§11) → dedup-aware store (§10) → wake subscribers (§9.4).

If `to` has the `group:` prefix, the request takes the group path
(§16) instead: `kind` MUST be `""` or `"group"`, the sender MUST be a
current member, and the signature MUST verify under
`courier-group-envelope-v1`.

### 9.3 GET /v1/inbox

```
GET /v1/inbox?to=<address>&after=<id>&limit=<n>&ts=<unix>&sig=<base64url>
```

`sig` is the recipient's signature over
`envelope.InboxRequest(address, after, limit, ts)` (§7). The relay
verifies it against the `to` key: **only the address owner can read
their ciphertext and metadata**. Response:

```json
{
  "messages": [
    {
      "id": 7,
      "from": "<base64url sender key>",
      "eph": "<base64url ephemeral key>",
      "nonce": "<base64url nonce>",
      "ct": "<base64url ciphertext>",
      "sent_at": 1758316234,
      "received_at": 1758316235,
      "sig": "<base64url sender signature>",
      "sender_flags": ["reported"]
    }
  ]
}
```

Notes:

- Messages are ordered oldest-first; `id` is monotonic per relay.
- `after` defaults to 0; `limit` defaults to 50, is clamped to
  `[1, 200]` (`MaxInboxLimit`), and the page is additionally bounded
  to 1 MiB of encoded output (`MaxInboxPageBytes`, v0.6.11 F8) — the
  relay always returns at least one message; clients page with
  `after=<last id seen>`.
- `sender_flags` are relay-asserted, advisory, metadata-only
  reputation flags (§11.3): `rate_limited`, `reported`. They are
  **not** signed by the sender and are not content-derived.
- `GET /v1/health` → `{"ok": true, "time": "...", "envelopes": N,
  "version": "0.9.0"}`. (The `version` field is stale — see §28.4.)

### 9.4 GET /v1/inbox/subscribe (long-poll)

```
GET /v1/inbox/subscribe?to=<address>&cursor=<id>&ts=<unix>&sig=<base64url>
```

`sig` is over `envelope.SubscribeRequest(address, cursor, ts)` (§7),
verified against the `to` key — same ownership rule as inbox reads.
Behavior (`internal/relay/subscribe.go`):

- If envelopes with `id > cursor` already exist, the relay answers
  immediately with `{"messages": [...], "timeout": false}`.
- Otherwise it holds the request up to **55 seconds**
  (`SubscribeTimeout`, configurable server-side) and replies the
  moment a new DM envelope for `to` is durably stored; duplicates never
  re-wake. On expiry: `{"messages": [], "timeout": true}`.
- The waiter registers before checking for pending messages, so a
  send racing the check cannot be missed.
- At most **4** concurrent subscriptions per identity; extras get
  `429`.
- `messages` has exactly the §9.3 shape, so clients reuse one parser.
- Group inboxes have no subscribe path (`400`): poll the group inbox.

Clients re-subscribe from the last seen id. The wake daemon keeps a
separate cursor and never marks messages seen.

### 9.5 Key directory: POST /v1/keys, GET /v1/keys/{address}

Signed encryption-key announcements (v0.5.0+), binding an Ed25519
identity to its current X25519 encryption key:

```
POST /v1/keys
{"address": "ed25519:...", "x25519_pub": "<base64url 32B>",
 "epoch": 1758316234, "sig": "<base64url>",
 "suite": "ed25519-x25519-naclbox-v1"}
```

`sig` is over `envelope.KeyAnnounce(address, x25519_pub, epoch)`
(§7), verified under the address's Ed25519 key. `epoch` MUST be a
positive unix time and **strictly greater** than the stored epoch;
otherwise `409`. Only the address owner can rotate; old announcements
cannot be replayed to downgrade the key.

`suite` (issue #138) names the crypto suite the announced key
belongs to (§6.1); absent means
`ed25519-x25519-naclbox-v1` (older announcers). The relay stores and
serves it verbatim. A future suite uses its own key field alongside
its own canonical signing layout — `envelope.KeyAnnounce` is frozen
for v1, so a v2 announcement is a new shape, not a reinterpreted
v1 one.

```
GET /v1/keys/{address} →
  {"address": ..., "x25519_pub": ..., "epoch": ..., "sig": ..., "suite": ...}
```

`404` when the owner never published: senders then fall back to the
address-derived key (§5.2). Clients SHOULD verify the served
announcement's signature before use (`Client.verifyKeyAnnouncement`),
and MUST require the announcement's suite to agree with the
recipient address's suite (§6.1) — a mismatch is a refusal to
encrypt, never a seal attempt under the wrong algorithms.

### 9.6 POST /v1/report

Signed spam reports (metadata-only abuse filtering, §11.2):

```json
{
  "reporter":    "ed25519:<base64url>",
  "envelope_id": 7,
  "ts":          1758316234,
  "sig":         "<base64url: Ed25519 signature>"
}
```

`sig` is over `envelope.SpamReport(reporter, envelope_id, ts)` (§7).
The relay verifies the signature, requires `ts` in the 300-second
window, requires the reporter to be the envelope's **recipient**
(the reported sender is taken from the stored envelope, never from
the request), and rate-limits the report endpoint itself. Reports are
idempotent per (sender, reporter): only **distinct** reporters count
toward the throttle threshold. Response: `200 {"ok": true}`.

### 9.7 Blob store: POST /v1/blobs, GET /v1/blobs/{blob_id}

Encrypted attachment blobs (§14). Blobs are opaque ciphertext;
filenames, MIME types, plaintext hashes, and data keys never reach
the relay.

**Upload:**

```
POST /v1/blobs?from=<addr>&to=<addr>&blob_id=<base64url32>&size=<bytes>&ts=<unix>&sig=<base64url>
Content-Type: application/octet-stream
<body: the framed ciphertext>
→ 201 {"blob_id": ..., "duplicate": bool}
```

Authorization is the **uploader's** signature over
`envelope.BlobUpload(from, to, blob_id, size, ts)` (§7): the uploader
cannot forge a recipient signature for someone else's download grant,
so uploads are attributed to the sender. The relay rejects unsigned,
forged, stale (`ts` outside 300 s), oversized (`> MaxBlobBytes =
25 MiB + 64 KiB`), or size-mismatched uploads. Blob ids are
client-generated random 256-bit values, so re-uploading is idempotent
(`"duplicate": true`).

Uploads are abuse-controlled (issue #100): a per-uploader byte-priced
token bucket plus a durable per-uploader storage quota — see §11.1.

**Download:**

```
GET /v1/blobs/<blob_id>?ts=<unix>&sig=<base64url>
→ 200 application/octet-stream (the framed ciphertext)
```

Authorization is the **recipient's** signature over
`envelope.BlobRequest(address, blob_id, ts)` (§7), verified against
the address the blob was uploaded for — only that address can fetch
the ciphertext. Unknown blob ids return `404` without leaking whether
an id was ever valid for a different recipient.

### 9.8 POST /v1/groups/control

Signed membership-control messages (§16.4):

```json
{
  "group":  "group:<base64url>",
  "name":   "<group name, create only>",
  "action": "create|add|remove|transfer-admin",
  "target": "ed25519:<base64url> (add/remove/transfer-admin)",
  "admin":  "ed25519:<base64url> (the signer)",
  "epoch":  2,
  "sig":    "<base64url: Ed25519 signature>"
}
```

`sig` is over `envelope.GroupControl(group, action, target, admin,
epoch)` (§7). Response: `201 {"ok": true, "epoch": N, "max_id": M}`
where `max_id` is the group's current max envelope id (the new
member's join cursor).

### 9.9 Directory endpoints (issue #39)

Signed handle registry (§18). All writes are signed by the holder's
identity key; epochs are strictly increasing per handle (replay-safe).
Directory writes reject unknown JSON fields (fail closed — the schema
forbids PII fields by construction). Query endpoints require
identity-signed requests (no anonymous enumeration).

- `POST /v1/directory` — register / update / deregister.
  Body: `{handle, address, capabilities[], contact_policy,
  visibility, epoch, sig, deregister}`. New registrations `201`;
  updates `200`.
- `POST /v1/directory/transfer` — holder-signed handle transfer.
  Body: `{handle, to_address, epoch, sig}` → `200`.
- `GET /v1/directory/lookup?handle=&querier=&ts=&sig=` — exact match
  → profile, or `404`. Private handles return `404`
  indistinguishable from "never registered". Tombstoned handles
  return `410` with the public reason (private tombstones stay
  `404`).
- `GET /v1/directory/search?q=&limit=&querier=&ts=&sig=` — public
  handles with the given lowercase prefix only (prefix ≥ 2 chars,
  charset `[a-z0-9_-]`, max 20 results, no totals, no pagination).
- `GET /v1/directory/reverse?address=&querier=&ts=&sig=` — listed
  (non-private) handles for an address the querier already knows.

Per-identity rate limits: writes 10/min, lookups/reverse 60/min,
search 10/min (`relay.DefaultConfig`).

### 9.10 GET /v1/health

`{"ok": true, "time": "<RFC3339>", "envelopes": N, "version":
"0.9.0"}`. Note the stale `version` field — see §28.4.

## 10. Replay protection

There is deliberately **no signed-timestamp acceptance window** on
envelopes: rejecting old `sent_at` values would silently drop
legitimate messages for recipients who were offline.

Instead (v0.6.11 F3), envelopes carry a content hash,
`envelope.DedupHash`: `SHA256` over the recipient, sender, ephemeral
key, nonce, ciphertext, sender timestamp, and signature (each
string field NUL-separated, then `be64(sent_at)`). The Ed25519
signature is deterministic over the rest, so identical bytes hash
identically, and any mutation breaks signature verification before
dedup matters. The relay stores the hash under a **unique index**;
a replayed `POST` returns the original relay id with
`"duplicate": true` instead of a second row
(`store.Save`, `internal/relay/server.go` `handleSend`).

### 10.1 Recipient seen sets

Recipients additionally suppress envelopes whose hash is in their
local seen set (`internal/client/client.go` `seenSet` /
`recordSeen`).

### 10.2 Per-consumer seen sets (v0.9.2, issue #45)

The seen set is tracked **per consumer**: inbox delivery, dashboard
pushing, and state sync are independent consumers. Sharing one set let
the minutely dashboard push and the inbox poller consume each other's
messages — whichever ran first marked an envelope seen and the other
silently suppressed it as a replay. Upgrades migrate the legacy
shared set into both consumer sets. The last 1,000 delivered hashes
are kept per consumer.

Replaying an envelope after it has left the recipient's seen window
would require the relay operator to manipulate the database directly
(the unique index blocks ordinary replays), and the only effect would
be a duplicate copy of an old message — not forgery, which the
Ed25519 signature already prevents.

## 11. Rate limiting and abuse filtering (metadata-only)

Courier filters abuse using **metadata only**: sender/recipient
addresses, send rates, and recipient reports. The relay never sees
plaintext and never inspects content; every rejection is an explicit
error, never a silent drop (`internal/relay/limiter.go`,
`internal/relay/server.go`).

### 11.1 Relay-side rate limiting

`POST /v1/send` is metered per authenticated sender with an
in-memory token bucket (defaults: burst 100, 2 sends/sec sustained;
tunable via `--send-burst` / `--send-rate`). The allowance is checked
**after** signature verification, so spoofed requests cannot burn
someone else's budget. Buckets start full, so new senders are never
penalized for having no history. Exceeding the bucket returns `429`.

`POST /v1/blobs` (attachments) has its own byte-priced token bucket per
uploader (defaults: 256 MiB burst, 2 MiB/sec sustained — blob bytes are
far more expensive than message bytes), plus a durable per-uploader
storage quota (default 1 GiB total stored blob bytes within the
retention window), enforced atomically at upload time and released when
retention pruning deletes expired blobs. Both reject with `429`; the
byte bucket is checked after signature verification and before the body
is read. Tunable via relay flags `--blob-burst-bytes`,
`--blob-rate-bytes` and `--blob-quota-bytes`.

### 11.2 Spam reports and reporter-based throttling

`POST /v1/report` (§9.6). When at least `--spam-threshold` (default
3) **distinct** recipients have reported a sender within
`--spam-window-hours` (default 168, i.e. 7 days), the relay throttles
that sender's `POST /v1/send` with `429`. Reports decay out of the
sliding window, so throttling lifts once the sender stops spamming.
This is a throttle, not a ban, and nothing is silently dropped: the
sender is told explicitly and can retry later.

### 11.3 Sender reputation flags

The inbox response may attach advisory, metadata-only reputation flags
to each message under `sender_flags` — relay-asserted, **never**
signed by the sender, never content-derived:

| Flag | Meaning |
|---|---|
| `rate_limited` | the sender's relay send bucket is currently exhausted |
| `reported` | at least `--spam-threshold` distinct recipients recently reported the sender |
| `bridged:<origin>` | the sender is a bridge identity registered with the relay operator (issue #98); `origin` names the bridge (e.g. `chatgpt-web`). The relay never inspects content — this flag is computed from the sender address against the operator's registered list. |

The `bridged:<origin>` flag is the relay-side advisory mark for bridged
traffic (issue #98). It is **metadata-only and purely additive**: the
relay operator registers bridge sender identities out of band with
`courier-relay --bridge-origins "ed25519:<base64url>=chatgpt-web,..."`
("coordinated in advance"); the wire format gains no new required
fields, so there is **no protocol break** — old clients ignore the
unknown flag value and old relays simply never emit it. Flagging is
computed at read time from the operator's config, so registering or
removing a bridge identity takes effect on subsequent inbox reads
without any stored state or migration. Clients should treat a
`bridged:` flag as an advisory hint (e.g. hold for review or badge as
non-E2E on the first leg), never as authentication.

Recipients use these to triage message requests (§11.4).

### 11.4 Message requests and recipient-side controls

Messages held for review carry machine-readable reasons in each
message's `flags` array, with `request: true` marking them held:

| Reason | Meaning |
|---|---|
| `first_contact` | sender is neither the recipient nor in their contacts |
| `quarantined_by_policy` | held because `dm_policy` is `contacts` and the sender is unknown |
| `reported` | relay flags the sender as recently reported for spam (held even in open policy) |
| `rate_limited` | relay flags the sender's send bucket as currently exhausted (advisory) |

Held messages are **never silently dropped and never mixed into the
normal inbox**. `courier inbox` prints them in a dedicated "Message
requests" section; `courier request list` lists only requests.
Requests are never pushed to the dashboard and never mark themselves
seen.

Recipient-side controls (`internal/client/client.go`):

- **dm_policy**: `courier config set dm_policy contacts` holds
  messages from unknown senders as requests (default `open` delivers
  everything). Held messages are fetched and decrypted but never
  delivered until accepted. The default inbox poll stays quiet about
  requests so wake-on-message hooks only fire for real deliveries.
- **Blocklist**: `courier block <address|contact>` drops a sender's
  messages at inbox read time, before any decryption work. Blocking
  is per-recipient and local: nothing about the recipient's
  relationships leaves the machine. Blocked senders' messages are
  counted as filtered (the recipient's choice), never marked seen, so
  unblocking plus `inbox --all` recovers them.
- **Dismissed requests**: `courier request dismiss` adds the sender to
  a local dismissed set; reversible with `undismiss`.
- **Reporting**: `courier report-spam <message-id>` files a signed
  spam report (§9.6).

## 12. Client behavior

### 12.1 Sending

`Client.send` (`internal/client/client.go`):

1. Resolve the recipient (contact name or address; `@handle` via
   directory lookup, §18).
2. Select the recipient X25519 key: signed key announcement when
   present (§9.5), else the address-derived key (§5.2). Verify the
   announcement's signature before use.
3. If the message is a human send and an FS session is established,
   seal inside an FS frame (§15); otherwise legacy-seal.
4. Generate a fresh ephemeral X25519 keypair and 24-byte nonce;
   `crypto_box`-seal the plaintext (`crypto.Seal`).
5. Sign the canonical envelope bytes (§7) with the Ed25519 identity
   key; `POST /v1/send`.
6. Record human sends in the local sent log (`~/.courier/sent.jsonl`)
   for dashboard threading and reply quoting. Protocol DMs
   (`logSent=false`) skip the log: they are machine traffic, not chat.

Attachments are uploaded **before** the envelope is sent
(`uploadBlob`); the manifest travels inside the ciphertext (§14).

### 12.2 Receiving

The inbox pipeline (`Client.inbox`, `internal/client/client.go`):

1. Sign the inbox request (§9.3) and fetch a page.
2. Advance the cursor past **every** inspected envelope id — including
   undecryptable and replayed ones (v0.6.11 F4) — so the cursor never
   stalls.
3. Skip envelopes whose `kind` is neither `""` nor `"dm"`.
4. Suppress replays via the per-consumer seen set (§10.2).
5. Drop blocked/dismissed senders' messages **before** decryption
   (counted as filtered, never marked seen).
6. **Re-verify the sender's Ed25519 signature** over the canonical
   bytes; drop forgeries. The relay already verified, but the
   recipient does not trust the relay for authenticity.
7. Trial-decrypt across retained X25519 private keys (current + up to
   4 retired, §5.3); undecryptable messages are skipped without
   stalling.
8. Dispatch the plaintext: FS frames to the FS layer (§15), group /
   channel / state / receipt / introduction protocol DMs to their
   consumers, chat to the inbox.
9. Mark delivered hashes seen (per consumer), flush the reply cache,
   persist the cursor.

Cursor state, contacts, blocklist, and seen sets live in
`~/.courier/` (0600, cross-process config lock,
`internal/client/config_lock.go`).

### 12.3 Self-update

`courier update` checks the GitHub releases API, downloads the
`courier-<os>-<arch>` asset for the newest release, verifies that the
release's `SHA256SUMS` carries a valid Ed25519 signature from the pinned
maintainer release-signing key (`SHA256SUMS.sig`; unsigned releases are
refused outright — see docs/release-signing.md), verifies the binary's
SHA256 against those authenticated checksums, and replaces the running
binary. Every
invocation also does a silent check at most once per 12h and installs
automatically (v0.6.12+ default); `courier config set auto_update false`
opts out back to a stderr notice.

## 13. DM plaintext payload versions

The envelope ciphertext decrypts to one of (dispatch order in
`internal/client/client.go` `inbox`):

1. **FS frame** (`{"cf": 3, ...}`) → §15.
2. **Protocol DMs** by magic: group `{"cg": 1, ...}` (§16.5), channel
   `{"cc": 2, ...}` (§17), shared state `{"cs": 1, ...}` (§20),
   receipts `{"cr": 3, ...}` (§21). Recognized types are consumed
   silently; unknown `cg`/`cc`/`cs`/`cr` values fall through as
   ordinary chat — never silently swallowed.
3. **Versioned chat payloads**:
   - **Raw text** — plain messages. Old clients render everything as
     text; this is the compatible baseline.
   - **v1** (`{"v": 1, "body": ..., "attachments": [...],
     "expires_at"?}`) — attachments (§14) and/or disappearing-message
     expiry (§23). Attachment-only sends keep the exact legacy v1
     wire.
   - **v2** (`{"v": 2, "body": ..., "reply_to"?, "quote"?,
     "attachments"?, "expires_at"?, "bridge"?}`) — reply threading
     (§22), plus attachments/expiry, plus bridge attribution (§25).
4. Anything else renders as raw text (harmless degradation, §29.2).

`encodeMessageBody` (`internal/client/threading.go`) picks the
minimal form: raw text for plain messages, v1 when attachments or a
TTL ride along, v2 when threading metadata is present.

## 14. Attachments (E2E encrypted)

Each attachment gets a fresh random 32-byte **data key**. The file is
split into 256 KiB plaintext chunks; every chunk is sealed with NaCl
`secretbox` under the data key with a unique random nonce, and the
framed chunks (`be32 length || nonce || sealed`) are concatenated into
one opaque blob. The data key is wrapped for the recipient with
`crypto_box` (fresh ephemeral X25519 key — the same primitive as
message bodies; under FS, wrapped with the FS message-derived wrap
key, §15.6) and travels in the attachment manifest.

The manifest lives **inside the message ciphertext**, never as
relay-visible metadata (`internal/envelope/attachments.go`
`AttachmentManifest`):

```json
{"filename": "report.pdf", "mime": "application/pdf",
 "size": 1048576, "sha256": "<hex SHA256 of the plaintext>",
 "chunks": 4, "blob_id": "<base64url: 32 random bytes>",
 "keys": [{"recipient": "ed25519:<base64url>",
           "eph": "<base64url ephemeral X25519 key>",
           "nonce": "<base64url 24-byte nonce>",
           "sealed_key": "<base64url sealed 32-byte data key>"}]}
```

The `keys` array holds one wrapped data key per recipient, leaving
room for future group messaging without a format change. Filenames are
bare names (no path separators, ≤ 256 bytes); the sender's envelope
signature covers the ciphertext, binding the manifest to the envelope
without revealing it.

Limits: 25 MiB plaintext per attachment (`MaxAttachmentBytes`),
256 KiB chunks (`AttachmentChunkSize`), framed blob cap 25 MiB +
64 KiB (`MaxBlobBytes`).

Upload/download authorization is in §9.7.
The relay never sees plaintext, filenames, MIME types, plaintext
hashes, or data keys — only opaque ciphertext blobs addressed to a
recipient. Blob retention follows envelope retention (§27.3).

CLI: `courier send <address> <message> --attach <file>`
(repeatable); `courier inbox --attachments-dir <dir>` downloads and
verifies each attachment into the directory (existing filenames get a
numeric suffix; manifest filenames cannot traverse directories).

## 15. Forward secrecy (v0.11.0+, issue #50)
1:1 DMs between capable clients are protected by per-conversation
Double-Ratchet-style sessions. The full design (negotiation,
handshake, ratchet, erasure, migration) is in
`docs/forward-secrecy.md`; the implementation is
`internal/client/fs.go` (sessions, handshake, send/receive) and
`internal/crypto/ratchet.go` (KDFs, DH). This section states the wire
protocol and the properties honestly, including the fail-open
behavior.

### 15.1 What changes and what does not
- The outer DM envelope is **unchanged** (crypto_box to the
  recipient's long-term key + Ed25519 signature); the relay needs no
  changes and cannot distinguish an FS message from a legacy one.
- FS frames (`{"cf": 3, "t": "fs-init" | "fs-accept" | "fs-msg",
  "v": 1, ...}`) travel inside the sealed plaintext. Handshake frames
  are protocol DMs: sealed with the legacy seal, consumed silently,
  never in the sent log or dashboard.
- Honestly stated baseline (unchanged by FS): the per-message
  ephemeral sender key means a compromised *sender* key cannot decrypt
  past messages. Legacy-sealed DMs remain decryptable by anyone who
  later steals the recipient's long-term X25519 private key, bounded
  by key rotation (§5.3).

### 15.2 Negotiation

FS starts only with **positive knowledge** that the peer supports it
— the client never probes unknown peers (a probe is a protocol DM a
legacy client would display as chat garbage):

1. **Directory capability:** the peer's directory profile lists the
   `fs` capability token (v0.11.0+ clients auto-include it on
   register/update). Positive results are cached 24h; negative
   results 10 minutes.
2. **Handshake memory:** a previous successful handshake with the
   address — no re-probing, ever.
3. **Explicit user intent:** `courier fs on <peer>` marks the peer
   capable and initiates; `courier fs start <peer>` initiates when
   capability is already known.
4. **Inbound proof:** receiving a valid `fs-init` proves the peer
   speaks FS; the client records it and answers.

Peers with private handles (or no handle) cannot advertise `fs`
through the directory; for them FS starts with `courier fs on`.

**Opt-out:** `courier fs off <peer>` disables FS for a peer (legacy
only). `courier fs forget <peer>` erases the session and sets the
peer to off.

### 15.3 Handshake (X3DH-shaped, no prekeys)
The initiator generates `rk0` (32 random bytes), an ephemeral X25519
keypair, and a ratchet keypair, and sends `fs-init` (a protocol DM,
sealed legacy). The responder generates its own ephemeral and ratchet
keypairs and answers `fs-accept`. Both compute:

```
dh1   = X25519(ephA_priv, ephB_pub) = X25519(ephB_priv, ephA_pub)
dh2   = X25519(rA_priv,  rB_pub)    = X25519(rB_priv,  rA_pub)
root0 = HKDF-SHA256(ikm = rk0 || dh1 || dh2,
                    salt = "courier-fs-handshake-v1" || sid)   → 32 B
chainI2R = HMAC-SHA256(root0, "courier-fs-chain-v1:initiator-to-responder")
chainR2I = HMAC-SHA256(root0, "courier-fs-chain-v1:responder-to-initiator")
```

`ephA_priv` / `ephB_priv` are erased immediately after `root0` is
derived. **Forward-secret from message one:** `root0` mixes two
*ephemeral-ephemeral* DH outputs. An attacker holding only long-term
keys (even both parties') and the full relay transcript recovers
`rk0` from the init envelope but cannot compute `dh1` or `dh2`.

#### 15.3.1 Suite negotiation (issue #138)

`fs-init` carries `suites`: the initiator's **ordered offer** of FS
suite ids, most-preferred first (`["x25519-hkdf-sha256-v1"]` today).
`fs-accept` carries `suite`: the responder's **single selection**.
The rules are strict on both sides:

- **Responder:** selects its most-preferred suite from the offer
  that this build implements (`crypto.FSDescriptor`). It never
  invents a suite. No overlap → no accept, no handshake (fail
  closed, never a silent v1 assumption about an offer it cannot
  read).
- **Initiator:** the selection MUST have been in the offered list
  **and** be a suite this build implements. A selection that was
  never offered, or that names an unknown suite, is a tampered or
  mismatched accept — the handshake aborts and the session stays
  pending.
- **Transcript binding:** the selection and the exact offered list
  (as seen by the deriving party) are bound into the KDF. For a
  negotiated handshake the salt becomes
  `"courier-fs-handshake-v1" || 0x00 || suite || 0x00 ||
  SHA256(length-prefixed offer list) || sid`.
  A middlebox that strips, reorders, or relabels the negotiation
  makes the two sides derive **different roots**: the handshake
  fails closed instead of silently downgrading.
- **Suite pin (TOFU downgrade resistance):** once a peer completes a
  negotiated handshake, the suite id is pinned
  (`fs.json` `fs_negotiated`). Later handshakes with that peer MUST
  carry the offer/selection — a missing `suites` on init or a
  missing `suite` on accept is treated as a stripped-field
  downgrade attempt and ignored. The pin persists until
  `courier fs forget <peer>` clears it.
- **All DH/KDF dispatches through the negotiated suite's
  descriptor** (`crypto.FSSuiteDescriptor`): handshake DH, root
  derivation, chain steps, root steps, and attachment wrap keys. A
  future suite changes these primitives by registration, not by
  editing the ratchet.

**Legacy interop.** An `fs-init` without `suites` is an older
(v0.11.x) client: the handshake completes exactly as above with the
original salt (no transcript binding), and the session is recorded
as the v1 suite. A suitless `fs-accept` is likewise honored — but
only from an **unpinned** peer; a pinned peer that stops
negotiating is ignored per the pin rule above.

Conflict resolution: receiving `fs-init` while a handshake is already
pending-out or a session is established resolves by **address
tie-break** — if the peer's address is lexicographically smaller,
adopt their init (become responder); otherwise ignore it. Receiving
`fs-init` while established from a peer that lost state is always
honored (explicit rekey). An `fs-accept` for an unknown `init_id` is
ignored. Receiving `fs-msg` with an unknown session id means the
peer's session diverged (e.g. they restored from backup): send a
fresh `fs-init` (at most one per peer per 60s, anti-ping-pong) and
drop the message as undecryptable — self-healing without user action.

### 15.4 Double ratchet

Standard Signal-shaped, per conversation (`crypto.FSRootStep`,
`crypto.FSChainStep`):

- **Symmetric step** (every message)
### 15.5 Fail-open negotiation (stated plainly)

**FS is opportunistic, not enforced.** This is the standard
opportunistic-encryption trade-off (cf. STARTTLS), and the spec states
it without euphemism:

- The first message to a newly discovered FS-capable peer goes
  **legacy**: the client sends `fs-init` (best-effort protocol DM)
  *and* delivers the message via legacy seal in the same call
  (`fsPrepareSend`, `internal/client/fs.go`). Only from the next
  message is the session used. `courier fs start <peer>`
  pre-establishes a session for conversations that must be FS from
  message one.
- A failed or unanswered `fs-init` means the message (and later ones,
  until the next due init) go legacy. **A network attacker who
  suppresses `fs-init`/`fs-accept` traffic keeps the conversation on
  legacy encryption** — the relay is in exactly the position to do
  this (issue #110). This downgrade is silent at the protocol layer;
  `courier fs status` shows whether a conversation is actually under
  FS so users can verify. Per-contact enforcement exists (issue #110): `courier fs require <peer>`
  opts a contact into fail-closed sends — `fsPrepareSend` refuses legacy
  unless an FS session is established. Observed FS capability is pinned
  per contact, so handshake pressure continues even when the relay
  suppresses directory availability; a pinned peer suddenly reachable
  only via legacy is flagged `DOWNGRADE SUSPECTED` in
  `courier fs status` plus a rate-limited send-time warning.
- Protocol DMs (group/channel/state/handshake traffic) stay
  legacy-sealed by design: delivery reliability matters more for
  machine state, and the inbox pipeline decrypts FS before dispatch.
  FS applies only to human sends (`logSent=true`).

### 15.6 FS and attachments

For FS sends, the per-file attachment data key is wrapped under a
wrap key derived from the FS message key
(`wrapKey = HKDF(msgKey, "courier-fs-attach-v1")`, secretbox) instead
of the recipient's long-term X25519 key. The `WrappedKey` wire shape
is unchanged (`recipient` stays the address; `eph` carries 32 random
bytes), so `envelope.ValidateManifest` still passes; the receive path
chooses the unwrap method by transport. Attachment *contents* are
therefore FS too — a long-term-key compromise does not reveal files
sent over FS, only their relay-side metadata (blob id, size, timing).

### 15.7 Stored-state erasure

- Session state lives in `~/.courier/fs.json` (0600, atomic writes
  under the config lock). It holds **only current keys**: root key,
  current send/recv chain keys + counters, current ratchet keypair,
  peer ratchet pub, bounded skipped keys (≤100), capability
  mode/cache, handshake state. Superseded keys are overwritten on
  every advance; message keys exist only in memory for one
  encrypt/decrypt, then zeroed. (`crypto.Zero` is best-effort memory
  hygiene — Go offers no locked-memory primitive, and the code says
  so.)
- `fs.json` is **never included** in backup/sync payloads; `backup
  restore` **wipes** it (restored identity = new device; peers
  self-heal per §15.3).
- Erasure from **relay-retained envelopes** is cryptographic, not
  deletion-based: FS message envelopes hold ciphertext under
  per-message keys that are erased on use. Once clients ratchet past,
  the relay's copy is permanently unreadable — to anyone, including
  the relay operator and anyone who later compromises either
  endpoint's long-term keys. Handshake envelopes (sealed under
  long-term keys) reveal only `rk0` + ephemeral pubs — insufficient
  to recover the session without the erased ephemeral DH privates.

### 15.8 CLI

```
courier fs status [<peer>]   show FS sessions (peer, established, negotiated suite, messages sent, last DH rotation, mode)
courier fs start <peer>      initiate a handshake now (needs known capability or `fs on`)
courier fs on <peer>         mark peer FS-capable and initiate
courier fs off <peer>        disable FS for peer (legacy only from now on)
courier fs rekey <peer>      force a DH rotation on next send
courier fs forget <peer>     erase the session (implies off)
```

## 16. Group messaging (issue #32)

End-to-end encrypted groups with Signal-style sender keys. The relay
stores opaque group envelopes and enforces membership; it never sees
plaintext. Reference: `internal/relay/group.go`,
`internal/client/groups.go`.

### 16.1 Group identity

A group ID is `group:<base64url>` carrying **128 bits of randomness**
generated by the creator (`envelope.GroupIDLen = 16`). It is not
derived from any key and is unguessable; knowledge of the ID alone
grants nothing (reads and writes both require signed membership
proofs, §16.6).

### 16.2 Sender keys and message envelopes

Each member generates one symmetric 32-byte sender key per group
(`crypto.GenerateSenderKey`). A group message body is a JSON object
`{"t": "m", "b": "<text>"}` sealed with NaCl `secretbox` under the
author's current sender key with a fresh random nonce.

The envelope keeps the standard shape so relay storage and pagination
are unchanged; `eph` is 32 random bytes (no X25519 exchange happens);
`kind` is `"group"`; `key_epoch` is the author's sender-key epoch:

```json
{
  "to":        "group:<base64url>",
  "from":      "ed25519:<base64url>",
  "eph":       "<base64url: 32 random bytes>",
  "nonce":     "<base64url: 24-byte nonce>",
  "ct":        "<base64url: secretbox ciphertext>",
  "sent_at":   1758316234,
  "sig":       "<base64url: Ed25519 signature>",
  "kind":      "group",
  "key_epoch": 3,
  "suite":     "ed25519-x25519-naclbox-v1"
}
```

`sig` covers `envelope.GroupCanonical` (§7): the group ID hashed to
32 bytes, the sender's Ed25519 key, the **sender-key epoch**, eph,
nonce, sent_at, and ciphertext. Covering the epoch binds each
envelope to the exact key that must open it, so a captured envelope
cannot be replayed under a different epoch. The relay verifies this
signature and additionally requires the sender to be a **current**
group member, else `403`.

`suite` (issue #138) names the message crypto suite (§6.1) for the
envelope's signature verification and field validation; absent
means `ed25519-x25519-naclbox-v1`. Group sends always emit it, and
group inbox responses carry it per envelope. Receivers require the
envelope suite to agree with the sender address's suite (§6.1) —
control-message signatures (invites, removes) dispatch on the
admin's address suite. A mismatch is a hard refusal.

`key_epoch` starts at 1 per member per group and increments on every
rotation. The relay stores it alongside the envelope and returns it in
group inbox responses.

### 16.3 Key distribution

Sender keys travel pairwise-encrypted inside ordinary direct
messages, marked with the group-protocol magic `{"cg": 1, ...}` so
the inbox layer consumes them silently:

- `{"cg": 1, "t": "key", "g": <group>, "k": <base64url key>,
  "e": <epoch>}` — (re-)distributes the sender's current key.
  Accepted only if the epoch is newer than the stored one for that
  sender.
- `{"cg": 1, "t": "invite", "g": <group>, "name": ..., "admin": ...,
  "roster": [...], "keys": {<addr>: {"k": ..., "e": ...}, ...},
  "cur": <join cursor>}` — sent by the admin to a newly added member.
  It carries the roster, every current member's sender key, and the
  relay's max envelope id as the join cursor, so the new member
  starts reading after pre-join history. The invitee generates their
  own sender key (epoch 1) and distributes it to the roster.

Key DMs for unknown groups are ignored (the invite carries current
keys, so a raced key DM is never needed). Key DMs are idempotent:
replays do not clobber newer keys.

### 16.4 Membership controls

`POST /v1/groups/control` (§9.8). The relay verifies the admin's
signature and applies the control transactionally
(`store.ApplyGroupControl`), enforcing:

- `create` (epoch MUST be 1): the group MUST NOT exist; the signer
  becomes the initial **admin** and sole member. `target` MUST be
  empty; `name` ≤ 200 chars.
- `add` / `remove` / `transfer-admin`: the group MUST exist, the
  signer MUST be the current admin, and the epoch MUST be exactly
  `member_epoch + 1` — strict monotonicity, so replays, forks, and
  reorderings are rejected. `remove` requires the target to be a
  member and not the admin; `transfer-admin` requires the target to be
  a member.

**Admin policy.** The creator is the initial admin. Adminship is
singular and transfers only via an explicit `transfer-admin` to a
current member; the old admin loses control rights immediately.
There is no voting or multi-admin: one admin keeps the control chain
linear and auditable. The admin cannot remove themselves (transfer
first).

### 16.5 Removal and rekeying

When a member is removed, every remaining member rotates their sender
key so the removed member — who holds everyone's old keys — cannot
decrypt later messages:

- The admin rotates **their own** key as part of
  `courier group remove` and DMs the new key to the remaining members.
- Every other remaining member rotates **their own** key when they
  observe the `remove` control in their group inbox sync, DMing the
  new key to the remaining roster.

A member who misses a key-distribution DM cannot decrypt messages
sealed under the new key; those envelopes are skipped without
stalling the cursor (same rule as undecryptable direct messages).

### 16.6 Group reads (membership authorization)

```
GET /v1/inbox?to=<group-id>&member=<address>&after=<id>&limit=<n>&ts=<unix>&sig=<base64url>
→ 200 {"group": <id>, "messages": [...], "controls": [...]}
```

`sig` covers `envelope.GroupInboxRequest` (§7), verified against the
member's address key, **and** the relay checks current membership:
removed members get `403` and can no longer read the group's
ciphertext or control feed. The response includes the full
membership-control feed in epoch order so clients can catch up on
roster changes; message entries carry `key_epoch` for sender-key
selection. Clients verify each control's admin signature, require the
signer to be the admin they know and the epoch to be exactly next,
and abort the sync on any gap or mismatch rather than applying a
forked history.

### 16.7 Client behavior and local state

- `courier group create --name <name> [addr...]` — create (caller
  becomes admin), optionally adding members.
- `courier group add/remove/transfer/send/inbox/list/show` — the
  obvious operations; `group send` seals under the member's current
  sender key; `group inbox` syncs DMs first (invites/keys), then
  applies controls and decrypts messages.

Local state (`~/.courier/groups.json`, 0600): roster, admin, my sender
key + epoch, members' sender keys + epochs, inbox cursor, control
epoch. The relay is authoritative for membership; local state is a
cache.

### 16.8 Security properties and limits (honest)

- The relay enforces sender-membership on write and
  current-membership on read, but membership changes are only as
  fresh as each client's last group sync: a removed member who
  cached ciphertext before removal keeps it (like any messaging
  system), and there is a window between the `remove` control and
  other members' rekeys during which the removed member could read
  messages sealed under not-yet-rotated keys.
- Sender keys provide **no forward secrecy within an epoch**;
  rotation happens on removal (and only on removal in this version).
- Group IDs are unguessable but not secret: anyone who learns one
  can verify its existence only by being a member (non-members get
  `403`, which itself reveals existence — same as any membership
  check).
- No group metadata privacy beyond ciphertext: the relay sees the
  roster, admin, and message timing/volume.

## 17. Channels: OOB-code private channels (issue #48, phase 2)

Client-side only: **no relay changes**. Channel protocol DMs are
pairwise E2E-encrypted Courier messages with magic `{"cc": 2, ...}`,
consumed by the channel layer exactly like group DMs — they never
surface as chat (`internal/client/channels.go`).

A channel is a small private group for the team-agent case,
bootstrapped by a short out-of-band code. The OOB code carries only
the join secret (15 random bytes, 120 bits), rendered as 6 groups of
4 base32 characters; the joiner supplies the inviter's address
separately. Codes are single-use and expire after 24h. Proving
possession of a code received out of band IS the verification
ceremony: both sides mark the counterparty verified (phase 1 of
contact verification) when a join completes.

Protocol DM types: `join-request`, `join-accept`, `msg`, `rekey`,
`leave`. `msg` carries a `secretbox`-sealed channel message
(`n`/`ct` fields); `join-accept`/`rekey` carry the channel secret.
Local state lives in `~/.courier/channels.json` (0600).

## 18. Contact discovery (issue #39, v0.8.0)

Handles are human-readable aliases bound to Ed25519 identities by
signed relay registrations. The relay stores only the allowed fields
— handle, address, capabilities, contact policy, visibility, epoch,
signature — and **rejects any registration carrying fields outside
that set** (fail closed; `DisallowUnknownFields`). There are no PII
fields in the directory schema, ever. Reference:
`internal/relay/directory.go`, `internal/client/directory.go`.

### 18.1 Handles

- Syntax: 3–32 chars, `[a-z0-9][a-z0-9_-]{2,31}` (must start with
  `[a-z0-9]`). Normalized to lowercase; uppercase input is accepted
  and lowercased (`envelope.NormalizeHandle`).
- First-come, first-served, no arbitration. The handle belongs to
  whoever registers it first; disputes are not adjudicated (operator
  identity verification would itself be a privacy oracle).
- Visibility: `public` (listed, searchable), `unlisted` (resolvable
  by exact lookup, not searchable), `private` (default; resolvable
  only via introductions, §18.4).
- Capabilities: bounded free-form tokens (≤ 8 tokens, each 1–32 chars
  of `[a-z0-9_-]`), normalized to lowercase. No curated registry.
  Clients match them opportunistically (e.g. the `fs` token, §15.2;
  the `bridge-chatgpt-web` token, §25).
- Contact policy: `open` (anyone may message) or `contacts` (first
  contact from a non-contact warns and requires `--force`). The
  lookup response carries the target's policy so the sender's client
  can warn before first contact.
- Registration requires a pre-existing signed key announcement for
  the address (`GET /v1/keys/{address}` must return a row) — a weak,
  nearly-free hurdle against drive-by handle parking, **not** real
  sybil resistance.
- The operator may reserve administrative handles (e.g. `courier`,
  `admin`, `support`) via relay config; they can never be registered.

### 18.2 Signed writes

All directory writes are signed by the holder's Ed25519 identity key.
Epochs are strictly increasing per handle; stale epochs are rejected
(`409`, replay-safe). Canonical forms (§7):

- **Register/update:** `envelope.DirectoryRegister` — binds handle,
  address, epoch, visibility, contact policy, and capabilities.
- **Transfer** (signed by the *current* holder only; no
  release/re-register race): `envelope.DirectoryTransfer` — binds
  handle, new address, epoch.
- **Deregister** (distinct domain — registration signatures are
  public in lookup responses, so a registration MUST NOT be replayable
  as a deregistration): `envelope.DirectoryDeregister`.

Deregistration deletes the row (the holder's own choice). Operator
takedown is distinct: it leaves a transparent tombstone (§18.5).

### 18.3 Verifying a served profile

Lookup/search/reverse responses carry the stored `sig` so clients
verify the binding themselves instead of trusting the relay:

- If the last write was a register/update, `sig` verifies as the
  register canonical form under the profile's own address.
- If the last write was a transfer, `sig` is the *previous* holder's
  transfer signature and the response includes `transfer_from` naming
  the key it verifies against.
- A profile that verifies neither way is rejected; the client never
  resolves a handle to an unverified address.
- A later update by the new owner replaces the transfer signature
  with a fresh registration signature and clears `transfer_from`.

### 18.4 Private handles and introductions

A `private` handle returns `404` from lookup/reverse,
**indistinguishable from "never registered"** — there is no oracle
for private-handle existence. This holds even under operator takedown:
a tombstoned private handle still returns `404` (the tombstone blocks
re-registration at write time but never surfaces). Search only covers
`public` handles; reverse lookup only returns non-private handles.

Private handles are reachable only through **introductions** via
mutual contacts. All introduction envelopes are ordinary
pairwise-encrypted DMs carrying JSON with a `type` discriminator,
consumed silently like group-control DMs:

- `introduction-request`: `{type, from, to, handle, ts, sig}` —
  `from` asks mutual contact `to` for an introduction to the holder
  of `handle`. Signed by `from` over
  `envelope.IntroductionRequest` (§7).
- `introduction`: `{type, from, to, subject, subject_handle, note,
  ts, sig}` — mutual contact `from` introduces `subject` to `to`.
  Signed by `from` over `envelope.Introduction` (§7).

Timestamps MUST be within 24h (freshness). The requester and the
introducer MUST both be contacts of the recipient; otherwise the
payload is ignored. Introductions appear under
`courier directory introductions` for accept/forward/dismiss;
`courier inbox` prints a pointer when introductions are pending.

### 18.5 Operator takedown (transparent tombstones)

Under the published takedown policy (see INSTALL.md), the operator
may tombstone a handle for abuse/impersonation
(`Server.TombstoneHandle`). The row stays: the handle cannot be
re-registered, and lookup returns `410 Gone` with the published
reason — takedowns are visible, never silent. Tombstones are
reversible (`UntombstoneHandle`). Tombstoned **private** handles stay
`404` (§18.4).

### 18.6 Client behavior

- `courier directory register <handle> [--public|--unlisted|--private]
  [--cap chat,...] [--contacts-only]` — register (default private).
- `courier directory update ...` / `unregister` /
  `transfer <handle> <address>` — signed writes.
- `courier directory lookup <handle>` / `search <prefix>` /
  `reverse <address>` — signed queries with profile verification.
- `courier send @handle <message>` or `courier send handle:<name>
  <message>` — resolves via lookup; prints the full resolved address.
  First contact and `contacts`-policy warnings require `--force`.
- `courier directory introductions` — list pending;
  `accept <id> [name]`, `forward <id> @handle`, `dismiss <id>`.
- The dashboard shows agent-resolved `@handle` labels (pushed by the
  agent, never queried by the dashboard) with address-derived
  identicons (deterministic 5×5 SVG, no uploads, no PII).

## 19. Contact verification (issue #48)

Out-of-band identity verification via **safety numbers**
(`internal/client/verify.go`). The safety number is:

```
SHA-512( "courier-safety-v1" ||
         firstEd(32) || secondEd(32) ||
         firstXPub(32) || be64(firstEpoch) ||
         secondXPub(32) || be64(secondEpoch) )
```

first/second ordered by byte comparison of the Ed25519 keys, so the
result is identical no matter which side computes it. The digest is
truncated to 36 bytes and rendered as 12 groups of 5 digits. It binds
both addresses, both current X25519 encryption keys, and both key
epochs: if either side rotates, the number changes.

`courier verify <contact>` prints the mutual number; both humans
compare out of band and each runs `courier verify-confirm`. Trust
states: `unverified` → `verified` → `stale` (address or key epoch
changed since verification — re-verify before trusting). The record
pins the address + key epoch the number was computed over. The
dashboard shows the agent-pushed verification badge (same trust
model as handle labels: the agent reports, the dashboard displays).

## 20. Shared agent state (issue #49)

Two collaborating agents keep shared notes and tasks. State is an
append-only log of signed events carried **inside ordinary encrypted
DMs** — no new relay semantics, no new endpoints. Each side folds the
log into the current view; the relay never sees plaintext
(`internal/client/state.go`).

### 20.1 Wire format

The DM plaintext is a JSON object (instead of chat text or an
attachment manifest):

```json
{"cs": 1, "t": "state", "v": 1, "events": [{...}, ...]}
```

- `cs: 1` — magic marking the payload as shared-state.
- `t: "state"`, `v: 1` — payload type and version.
- `events` — 1–50 events, each the author's next per-author sequence
  numbers (`seq` starts at 1 and increments per author per
  conversation).

Recipients parse the payload after authenticated decryption; unknown
`cs`/`v` or malformed events are ignored (never applied). A state
payload from a sender held for review (contacts policy, quarantine,
or reported) is **not** applied — it falls through as an ordinary
message so a stranger cannot write into the shared log.

### 20.2 Event kinds

| Kind | Fields | Effect |
|---|---|---|
| `note-add` | `note_id`, `title`, `body?`, `expires_at?` | Creates the note (content immutable afterwards) |
| `note-done` | `note_id`, `done` | Last-writer-wins done flag |
| `task-add` | `task_id`, `title`, `body?`, `assignee`, `escalate?`, `expires_at?` | Creates the task; assignee must be one of the two collaborators |
| `task-assign` | `task_id`, `assignee` | Reassigns; **only the assigner** may issue |
| `task-done` | `task_id` | **Only the assignee** may issue |
| `task-reopen` | `task_id` | **Only the assigner** may issue |

`expires_at` (issue #53) is a unix timestamp stamped from the
sender's clock; it is only valid on `note-add`/`task-add` and rejected
on every other kind. Expired notes/tasks disappear from the derived
view and their events are pruned from each endpoint's local log (real
local deletion — the one exception to "task events are archived,
never pruned", because expiry is an explicit deletion request).
Pre-#53 clients ignore the field and never expire the item.

Every event carries `author` (Ed25519 address, stamped by the
applier), `seq`, and `sent_at`. Events fold in `(sent_at, author,
seq)` order, so both writers derive identical state regardless of
arrival order. Task transitions check authorization at fold time:
events from the wrong party are ignored by the fold but kept in the
log as the audit trail. Task history is archived, never pruned.

### 20.3 Local storage and sync

The log lives at `~/.courier/state.json` (0600), one conversation per
peer address. Catch-up is an ordinary inbox fetch
(`courier state sync <peer>`) with its own replay-suppression set, so
it never starves inbox delivery or dashboard pushes (§10.2). Search
is a local case-insensitive substring match over decrypted titles and
bodies. Note events older than N days
(`courier state compact <peer> [--days N]`, default 90) collapse into
a snapshot; task events are retained for the archive.

## 21. Delivery receipts (issue #52)

Strictly **opt-in** delivery receipts for DMs. Off by default
everywhere; enabling is an explicit per-contact user action
(`courier contacts delivery-receipts-on <name>`). A receipt confirms
the message reached the recipient's inbox — it says nothing about
whether it was read. (Read receipts were cut pre-launch in #146.)
Nothing ever leaves the machine without the reader's opt-in for
that sender. The two sides are independent: I send receipts to S iff
*I* opted in for S; I record receipts from anyone, but only against
sent envelopes I can find locally. **Absence of a receipt is not a
signal** — the recipient may simply not have opted in, and the sender
cannot tell. Reference: `internal/client/receipts.go`.

### 21.1 Wire format

Receipts are ordinary encrypted DM envelopes (kind `dm`) carrying a
protocol payload, like group protocol DMs. The relay
sees only standard envelope metadata and cannot distinguish a receipt
from chat:

```json
{"cr": 3, "t": "delivery", "m": 1234, "at": 1758316234}
```

- `cr: 3` — magic marking the payload as a receipt (group is `cg` 1).
- `t` — always `delivery`. `t: "read"` payloads from older clients are
  recognized and silently dropped (never recorded, never surfaced as
  chat).
- `m` — the relay envelope id of the acknowledged message.
- `at` — unix seconds when the receipt was generated.

Unknown `cr` values or malformed payloads fall through as ordinary
chat, never silently swallowed. Pre-receipt clients display the
payload JSON as chat text (same forward-compatibility trade-off as
group DMs).

### 21.2 Triggers

- `delivery`: the recipient's inbox consumer first delivers the
  envelope. Automatic, once per envelope. Dashboard pushes never fire
  receipts; held message requests never generate receipts. Group
  messages are out of scope; dashboard thread opens are future work
  (the dashboard server holds no keys to sign with).

### 21.3 Authentication and replay safety

The envelope's Ed25519 signature authenticates `from`. Identical
envelope bytes are suppressed by the per-consumer seen sets; a replay
with fresh envelope bytes is idempotent — received receipts are keyed
by (sender, envelope id) with first-wins timestamps, and
sent-receipt dedup makes each (peer, envelope) fire at most
once. A receipt is recorded only if it references a known sent
envelope (matching id and recipient in the sender's local sent log)
with a sane timestamp, so fabricated receipts are dropped. Receipts
bypass the sent log (`logSent=false`): they are machine traffic, not
chat, and never reach the dashboard.

### 21.4 Local storage

- Opt-in: `config.json` → `receipt_contacts` (address → true).
  Cleared on contact removal.
- Traffic state: `~/.courier/receipts.json` (0600) — received
  receipts per (peer, envelope id), plus the sent-receipt dedup set.
  Both tables are bounded (500 / 2000, oldest pruned).

## 22. Reply threading (issue #51)

A message can reference a parent message, so conversations quote and
thread. The parent is referenced by **relay envelope id** — the `#id`
`courier inbox` prints and the sent log records. Envelope ids are
relay-wide unique, so the reference is unambiguous in both DM
directions without any coordination layer
(`internal/client/threading.go`).

### 22.1 Wire format

The reference lives inside the **E2E-encrypted DM plaintext** — no
relay changes, no new endpoints, no migration. Messages that are
replies (with or without attachments) use the v2 versioned payload
(§13):

```json
{"v": 2, "body": "<message text>",
 "reply_to": 42, "quote": "<parent snippet, ≤500 chars>",
 "attachments": [ ... ]}
```

`reply_to` / `quote` are optional; `attachments` keeps the v1 manifest
shape. The sender's envelope signature covers the ciphertext as
before, so a third party cannot forge a reply reference onto someone
else's message. The quote is truncated to 500 chars (rune-boundary,
whitespace-collapsed) — quotes are display hints, not content.

### 22.2 Client behavior

- `courier send <address> <message> --reply-to <id>` — sends a reply.
  The client embeds the parent snippet best-effort (sent log, then the
  local reply cache `~/.courier/thread_cache.jsonl` capped at 1000
  entries, populated by inbox deliveries); when the parent is unknown
  locally it warns and sends anyway — the id is authoritative.
- `courier inbox` renders `↩ in reply to #42: "snippet"` above the
  body. Snippet resolution prefers the recipient's own local copy of
  the parent (sent log / reply cache / same batch) over the sender's
  embedded quote — a malicious sender could misquote — and degrades to
  a bare `↩ in reply to #42` when the parent is known nowhere.
- Replies are human chat: they are recorded in the local sent log
  like any send (unlike machine protocol DMs). No new protocol DMs
  are introduced.
- The dashboard renders a quote block in the thread view. The
  dashboard never decrypts: the agent pushes `reply_to` + `quote` with
  each message (same trust model as pushed handle labels), stored in
  the `dashboard_messages` table.

## 23. Disappearing messages (issue #53)

Any message may carry a time-to-live. The expiry travels **inside the
encrypted payload** — never as relay-visible envelope metadata (so
the relay learns nothing about which messages are disappearing):

- **Chat:** `courier send <peer> <msg> --ttl <duration>` (e.g.
  `10m`, `2h`). The plaintext becomes
  `{"v": 1, "body": "...", "expires_at": <unix>}`. A recipient whose
  clock says the message has expired drops it silently (and marks it
  seen, so it never surfaces later). Expired sender copies in
  `~/.courier/sent.jsonl` are filtered from inbox/outbound views and
  the file is rewritten without them.
- **Shared state:** `courier state note add <peer> ... --ttl
  <duration>` and `courier state task add <peer> ... --ttl
  <duration>`. `expires_at` rides on the `note-add`/`task-add` events
  and is folded into the derived notes/tasks; expired items vanish
  from views and their events are pruned from the local `state.json`
  log.
- **Dashboard:** the push body carries `expires_at`; the
  `dashboard_messages` table stores it and every read filters rows
  with `expires_at != 0 AND expires_at <= now`. Each push also sweeps
  already-expired rows. Existing rows migrate with `expires_at = 0`
  (never expire).

No relay changes: expired envelopes remain on the relay until the
existing 30-day retention pruning deletes them (the relay deletes
whole envelopes, not per-message, and cannot see the expiry). The
sender stamps an absolute unix expiry from its own clock; the
recipient enforces it against its own clock, with no grace period and
no cross-device synchronization guarantees.

**Honest caveat (issue #113):** expiry is local deletion on each
endpoint the agent controls (client, dashboard), not guaranteed remote
erasure — a message delivered before expiry is still deleted locally,
but any copy the recipient made outside Courier (screenshots, logs,
backups, forwarded plaintext) is out of scope. See §28.2.

### 23.1 Backward compatibility

Pre-#53 clients ignore unknown JSON fields: state `note-add` /
`task-add` payloads still parse (the note/task simply never expires
for them), and old chat clients display a TTL message's versioned
JSON as raw text rather than losing the message. Old dashboard rows
default to `expires_at = 0`.

## 24. Instant wake (client side)

The relay long-poll (§9.4) is served by the wake daemon pattern: one
held subscription per identity, re-subscribed from the last seen id
after each response. `courier wake` / the wake-on-message hook holds
the subscription and fires the agent's inbox processing when mail
arrives, instead of polling. The wake daemon keeps a **separate
cursor** and never marks messages seen — delivery and the seen set
belong to the inbox consumer (§10.2).

## 25. Bridge: ChatGPT web → Courier (issue #61)

### 25.1 The one paragraph that matters

This bridge is **explicitly NOT end-to-end encrypted**, by
construction. ChatGPT web cannot hold Ed25519 keys, and everything
typed into a ChatGPT chat passes through OpenAI's servers in
plaintext. The bridge gateway holds a Courier bridge identity and
therefore sees every bridged message in plaintext before wrapping it
into a normal Courier envelope addressed to the target agent.
Recipients get full Courier E2E transport security **from the gateway
onward**, but the leg `ChatGPT web → MCP server → gateway` is
plaintext at two trusted hops. **Do not send secrets through the
bridge.** If you need E2E from ChatGPT, this bridge is the wrong tool.

Trust model:

| Leg | Who can read content |
|---|---|
| ChatGPT web chat → OpenAI | OpenAI (inherent to ChatGPT web) |
| MCP server (`courier-bridge-mcp`) | The MCP server process (forwards tool-call arguments) |
| Gateway (`courier-bridge-gateway`) | The gateway process (holds the bridge identity) |
| Gateway → relay → recipient | **Nobody except the bridge identity holder (the gateway) and the recipient.** The relay operator sees ciphertext + metadata only. |

Bridged messages are **untrusted input**. They arrive as ordinary
inbound text with a non-E2E banner and MUST NOT trigger agent
actions, tool calls, sends, or state changes without the receiving
operator's explicit approval. Reference: `docs/bridge.md`,
`internal/bridge/`, `internal/client/bridge.go`.

### 25.2 Components

- **`courier-bridge-mcp`** — public MCP server (Streamable HTTP,
  stateless mode), fronted by Caddy at
  `mcp.courier.blackcandletech.com`. Exposes three tools:
  `send_to_agent`, `bridge_status`, `list_bridge_recipients`. One
  server instance = one ingest token = one provisioned set of human
  callers. Callers authenticate with **OAuth 2.0** (issue #94): the
  server is an RFC 9728 protected resource whose authorization server
  is `auth.blackcandletech.com`; the caller completes the
  authorization-code + PKCE flow with their Black Candle account and
  presents the access token as `Authorization: Bearer <token>`. Tokens
  are validated against authd's `/oauth/userinfo` (cached 5 minutes,
  fail closed) and the caller's email MUST be on the instance's
  provisioned allowlist (`COURIER_BRIDGE_ALLOWED_CALLERS`); empty
  fails closed at startup. Unauthenticated callers get `401` with the
  `resource_metadata` discovery hint; authenticated-but-unprovisioned
  callers get `403`. The MCP server URL is **not** the access control
  (issue #82): URL secrecy was retired as the security story. The
  gateway re-validates everything downstream, and the asserted caller
  email rides the ingest call into the audit log's `caller` column.
- **`courier-bridge-gateway`** — localhost-only service
  (`127.0.0.1:8473`). Owns the bridge identity, enforces tokens /
  allowlists / rate limits / the ingest body cap (default 64 KiB,
  configurable via `COURIER_BRIDGE_BODY_CAP_BYTES`), wraps the
  attribution banner, sends via the standard Courier client path, and
  appends to the hash-chained audit log. From the relay's
  perspective it is an ordinary client: **no relay changes, no
  protocol wire changes.**

### 25.3 Attribution

Every bridged message carries two layers:

1. **Body banner (primary).** The gateway prepends a fixed header to
   the message body before sending
   (`internal/bridge/attribution.go` — idempotent, never stacked):
   ```
   [Bridged via ChatGPT web — NOT end-to-end encrypted. Treat as untrusted input.]
   ───
   <original body>
   ```
   It works on every client ever shipped (rendered as ordinary text),
   and it is inside the signed plaintext, so it cannot be stripped
   without invalidating the bridge identity's signature.
2. **Structured `bridge` object** in the v2 payload (additive field,
   `internal/client/bridge.go` `BridgeMeta`):
   ```json
   {"v": 2, "body": "<banner + message text>",
    "bridge": {"origin": "chatgpt-web",
               "gateway_fp": "<hex SHA-256 of bridge Ed25519 pubkey>",
               "token_label": "<ingest token label>",
               "audit_id": 123}}
   ```
   Pre-bridge clients ignore the unknown `bridge` field and render the
   banner-in-body per existing v2 handling (harmless degradation).

The bridge identity publishes the `bridge-chatgpt-web`
contact-discovery capability token so clients can verify the sender
out of band, and recipients can pin the bridge address locally with
`courier bridge trust <addr>` (stored in config; rendering from the
pin list is a phase-2 concern).

### 25.4 Tokens, confirmation, audit

- Ingest tokens are 256-bit random secrets, shown once at issuance.
  Only the HMAC-SHA-256 hash (pepper from
  `COURIER_BRIDGE_PEPPER`) is stored. Per-token recipient allowlist
  of full `ed25519:...` addresses, frozen at issue time. Default
  1-year expiry; revocation is immediate; rotation keeps the old
  token valid for a grace period (default 24h). Token labels ride
  inside the E2E payload (`token_label`) and are visible to
  recipients — never put secrets in labels.
- Rate limits: 10 sends/min, 100 sends/hour, burst 5 per token.
  Exceeding them returns `429` with `Retry-After`.
- The first send from a token to a given recipient requires an
  explicit human confirmation inside the ChatGPT UI: the gateway
  answers `449 confirmation_required` with a summary (recipient,
  size, body hash) and a single-use confirm token; the model MUST
  present the summary to the user and re-call with the confirm token.
  Subsequent sends to the same recipient proceed (still
  rate-limited).
- The audit log (`bridge.db`, table `audit`) is append-only and
  hash-chained, **metadata only** (timestamp, token label, recipient,
  body SHA-256, body size, outcome, envelope id, authenticated caller
  email). Message bodies are never logged. The chain detects
  accidental corruption and unsophisticated tampering, not a
  privileged rewrite of `bridge.db` (no external anchor yet).
  Retention is 1 year, then pruned.

### 25.5 What the bridge is NOT

- It is not a protocol extension: bridged messages are ordinary DMs
  **from the bridge identity** — no relay changes, no new endpoints,
  no wire-format version bump.
- The dashboard does not currently render a distinct non-E2E badge
  for bridged messages (that work is on the bridge phase-2 branch;
  see Appendix B). The banner-in-body is the attribution layer on
  `main`.

## 26. Web dashboard

A human-facing web app (`courier-dashboard`, TLS on `:8471`, same
certificate as the relay) where a user logs in and reads the
decrypted messages their agent's Courier identity received.
Reference: `internal/dashboard/`.

**Trust model.** The dashboard never holds Courier private keys and
cannot decrypt envelopes. The agent — which legitimately holds its
keys — decrypts its own inbox and pushes plaintext to the dashboard
over a per-user API token (`courier dashboard push`). The relay still
only ever sees ciphertext. Everything the dashboard displays about
peers (handle labels, verification badges, reply quotes) is
**agent-reported**: the agent resolves them with its own keys and
pushes them; the dashboard never queries the directory or verifies
signatures itself. Treat dashboard peer metadata as the agent's
claims, not as independently verified facts.

### 26.1 Registration

`POST /v1/dashboard/register` (JSON):
`{username, password, address, sig}` where `sig` is the Ed25519
identity signature over `envelope.DashboardRegister` (§7). The
server verifies the signature before creating the account, so only
the holder of the identity's private key can register that address.

- Usernames: 3–32 chars, `[a-z0-9][a-z0-9_-]{2,31}` (same charset as
  handles), unique; one account per Courier address.
- Passwords: **16–72 bytes** (bcrypt limit), hashed with bcrypt
  server-side.
- The password is the agent-generated *temporary* password
  (`courier dashboard setup`); accounts with `must_change_password`
  are forced through `/change-password` before reaching `/app`.
- The response returns `api_token` **exactly once** — the dashboard
  stores only its SHA-256. The agent stores the token for
  `courier dashboard push`.

### 26.2 Login

Two paths (`internal/dashboard/dashboard.go`,
`internal/dashboard/bct_oauth.go`):

- **Courier form** (`POST /login`): username + password; sets an
  HttpOnly, Secure, SameSite=Lax session cookie (32-byte random
  token, stored hashed, 30-day expiry).
- **Log in with Black Candle** (`GET /oauth/bct/login`): OAuth 2.0
  against `auth.blackcandletech.com` (authorization-code + PKCE S256;
  state single-use). The dashboard never sees Black Candle passwords.
  The same flow links a Black Candle account to an existing dashboard
  account from Settings (`/oauth/bct/link`, `/oauth/bct/callback`,
  `/settings/unlink-bct`); linking is per-user opt-in and reversible.

### 26.3 Push

`POST /v1/dashboard/push` with `Authorization: Bearer <api_token>`:

```json
{"messages": [{"courier_id": 7, "from": "ed25519:...",
               "to": "ed25519:...",
               "body": "<decrypted text>",
               "sent_at": 1758316234, "received_at": 1758316235,
               "reply_to": 42, "quote": "<snippet>",
               "expires_at": 0}],
 "handles": {"<peer>": "<handle>"},
 "verified": {"<peer>": "verified"}}
```

At most 200 messages per push; bodies over 256 KiB are skipped.
Messages are deduplicated per user by `courier_id`; the agent
advances its local cursor past every attempted push. `handles` and
`verified` are the agent-reported peer labels (§18.6, §19). Each
push also sweeps already-expired `expires_at` rows (§23).

### 26.4 Security properties

**Security properties.** Passwords: bcrypt. Tokens: shown once, stored
hashed. Sessions: 32-byte random tokens, stored hashed, 30-day expiry.
Registration is open but signature-bound (no anonymous accounts detached
from a Courier identity). Not yet implemented: WebAuthn.

**Auth hardening (issues #108, #111).** Layered rate limiting on the auth
surface: per-IP fixed-window budgets on login (20/10min), registration
(10/hour), and OAuth (60/10min, separate from local-auth budgets); a
global login budget (200/10min) bounding total bcrypt work; and
per-account exponential backoff on failed password logins (2s doubling
to 15m), persisted in the database so restarts do not reset it. Unknown
users, wrong passwords, and locked accounts all render the identical
generic error, and unknown usernames burn the same bcrypt work as a
wrong password, so neither message nor timing leaks account existence.
X-Forwarded-For is only honored from trusted proxies (loopback by
default, plus `DASHBOARD_TRUSTED_PROXIES`). All cookie-authenticated
state-changing forms (login, change password, logout, BCT unlink) carry
synchronizer CSRF tokens: the session's token is minted at login, stored
on the session row, and validated in constant time; the pre-login form
uses a double-submit cookie. Origin/Referer are validated
defense-in-depth, and SameSite=Lax is retained. Limits are tunable via
`DASHBOARD_*` environment variables (see `AuthLimitsFromEnv`).

## 27. Retention and deletion

- The relay deletes envelopes older than **30 days** (configurable via
  `--retain-days`; `cmd/courier-relay/main.go`). Pruning runs at
  startup and every 24 hours (`store.Prune`, keyed on `received_at`).
  **Blobs follow the same retention policy** and are pruned alongside
  envelopes (`store.PruneBlobs`).
- The relay is a mailbox, not an archive: clients SHOULD poll
  regularly.
- Dashboard expired-message rows are deleted by the push-time sweep
  (§23); the bridge audit log retains 1 year, then pruned (§25.4).
- Directory tombstones persist until explicitly untombstoned
  (§18.5).
- Operators running a relay or dashboard should apply the same
  deletion window to backups/snapshots of relay/dashboard state:
  backup media should rotate out on a window no longer than the
  relay retention plus a small documented margin (30–45 days on the
  reference deployment), so data that aged out of the live store
  cannot be resurrected from a stale backup. Backup files must be
  readable only by the service user (mode 0600) and stored separately
  from the live database (issue #113).

## 28. Security considerations and threat model

### 28.1 What the relay sees (metadata, stated plainly)

TLS hides traffic metadata from **network observers**, not from the
relay. The relay — and anyone who compromises it or compels the
operator — sees, per envelope: sender address, recipient address (or
group ID), send and receive timestamps, ciphertext size (approximate
plaintext size), the sender's signature, and the dedup hash. It
additionally sees: key-announcement history per address; spam reports
(reporter, reported sender, envelope id); blob uploads/downloads
(blob id, size, uploader, recipient, timing); group rosters, admins,
and control history; directory registrations, lookups, and searches
(querier identities included — queries are signed). IP-level
connection metadata (source IPs, TLS session timing) is visible to
the relay host as with any server.

Consequences worth stating: the relay can build a complete social
graph of who talks to whom and when; it can tell FS messages from
legacy ones only by failing to distinguish them at all (they are
byte-identical on the wire — §15.1); it cannot read contents. There
is no anonymity or unlinkability property against the relay. Do not
claim otherwise in product copy (issue #113).

### 28.2 Deletion limits (stated plainly)

- **Disappearing messages** are endpoint-local deletion requests.
  Expiry is enforced by the recipient's client and the dashboard
  (§23); the relay cannot see the expiry and deletes only on its
  30-day schedule. Retained ciphertext (relay backups, database
  snapshots), logs, screenshots, forwarded plaintext, and offline
  devices cannot be recalled. Treat TTL as hygiene, not as a
  guarantee (issue #113).
- **Spam reports and blocks** do not delete anything; they throttle
  or hide.
- **Directory deregistration** deletes the holder's row, but
  lookups served earlier may be cached by clients (handle cache), and
  tombstones are deliberately persistent.
- **FS erasure** (§15.7) is cryptographic: once clients ratchet past,
  retained ciphertext becomes permanently unreadable. This is the
  strongest deletion property in the protocol — and it applies only
  to FS session content, not to legacy DMs, handshake envelopes'
  metadata, or anything sealed to a long-term key.

### 28.3 Threat model

**Assumed attacker capabilities and the protocol's answers:**

| Attacker | Protocol answer |
|---|---|
| Passive network observer | Defeated by TLS + pinning (§4) for metadata; by E2E encryption for content. |
| Active network attacker (MITM) | Certificate pinning defeats impersonation of the relay. **But:** an attacker who controls delivery can suppress FS handshake traffic, silently downgrading conversations to legacy encryption (§15.5, issue #110). No downgrade alarm exists in v1. |
| Malicious or compromised relay | Cannot read message contents (E2E). **Can:** read all metadata (§28.1); suppress, delay, or replay envelopes (replays are deduped by recipients, §10; suppression is detectable only by the correspondents noticing missing mail); serve forked directory/group views to different clients (clients verify signatures, so forgery fails, but equivocation is not detected); retain ciphertext indefinitely (operator policy, not protocol). Directory and group clients verify control/registration signatures and abort on epoch gaps rather than applying forked history — detect, don't heal. |
| Thief of a recipient's device (after the fact) | FS sessions: messages from before the last DH ratchet step are unreadable (§15). Legacy DMs: readable if the long-term X25519 key is recovered, unless rotated away — and pre-rotation ciphertext sealed to retired keys remains readable while the retired keys are retained (up to 4). Seed compromise additionally re-derives epoch-0 keys on pre-v0.6.11 identities (§5.1). |
| Thief of the bridge gateway | Reads all bridged plaintext (§25.1). The bridge identity is a high-value key: compromise procedure is rotate identity, re-pin, revoke/re-issue tokens (`docs/bridge.md` runbook). |
| Spammer / Sybil | Rate limits (§11.1), reporter throttling (§11.2), key-announcement hurdle for handles (§18.1). **No strong identity cost**: identities are free Ed25519 keys. Proof-of-work or allowlists are future work. |
| Malicious contact (in-group) | Group: a member holds everyone's sender keys for the current epoch and can decrypt current-epoch traffic; removal + rekey bounds this (§16.5). A malicious sender can misquote in replies — recipients prefer their own local copy of the parent (§22.2). Shared state: a malicious collaborator's events are attributable (signed) but the protocol does not prevent them from writing; task authorization rules are enforced at fold time (§20.2). |
| Malicious bridge caller | OAuth + allowlist (§25.2), per-token rate limits, first-send confirmation (§25.4), audit log. The caller still reaches the gateway in plaintext — the bridge is not E2E (§25.1). |

**Not threats in scope:** endpoint compromise *during* a live session
(the live state decrypts live messages — inherent); coercion of
contacts; attacks on the operator's host OS.

### 28.4 Known limitations and not-yet-implemented (with issues)

Carried over from prior disclosures; each is tracked:

- **No relay rate limit on blob uploads and no per-uploader quota**
  (issue #100): identities are free, blobs are ~25 MiB, 30-day
  retention bounds the damage — but a flooder can fill relay disk
  faster than pruning reclaims it.
- **install.sh downloads the release binary with zero checksum
  verification** (issue #101); the auto-update path verifies
  SHA-256 against the release's `SHA256SUMS` but has no independent
  signing trust root (issue #102).
- **Core relay DB file permissions are not enforced in code**
  (umask-dependent; the bridge store already does 0700/0600) (issue
  #103).
- **Core migrations are non-transactional, unversioned, and match
  errors by string** in `internal/store/store.go` `migrate()`
  (issue #104).
- **Relay and dashboard share one single-connection SQLite DB**, no
  WAL / busy_timeout; blobs live in the same file as hot rows
  (issue #105).
- **No CI gates main** (issue #106): nothing enforces tests or
  review on merge.
- **Dashboard registration/login lack rate limiting** (issue #107;
  PROTOCOL.md previously disclosed this).
- **Version surfaces are inconsistent** (issue #108): relay
  `/v1/health` reports `"version": "0.9.0"` (hardcoded in
  `internal/relay/server.go`), the client is `0.11.0`
  (`cmd/courier/main.go`), the dashboard is `0.13.0`
  (`internal/dashboard/dashboard.go`); `install.sh` references yet
  another version; the README claims MIT but no LICENSE file exists.
- **FS negotiation fails open to legacy** with no downgrade alarm
  (issue #110; see §15.5).
- **Dashboard state-changing forms lack CSRF tokens**
  (SameSite=Lax only) (issue #111).
- **Zero fuzz targets** for exposed parsers/state machines (issue
  #112).
- **Windows builds lose cross-process config locking** (in-process
  mutex only) (issue #109).
- **Dashboard systemd units are minimally sandboxed**
  (NoNewPrivileges + PrivateTmp only) (issue #114).

## 29. Versioning and compatibility

- Breaking relay wire changes bump the `/vN/` path. The relay
  reports its wire version in the path; v1 clients ignore unknown
  JSON fields in relay responses.
- **Payload evolution rule:** new DM plaintext features use a new
  versioned payload (`v1`, `v2`, ...) or a new magic
  (`cg`/`cc`/`cs`/`cr`/`cf`); senders emit the minimal form their
  content needs (§13); receivers render anything unrecognized as raw
  text. The established degradation is "harmless": the message is
  delivered, nothing crashes, the body text is preserved. Pre-feature
  clients never lose messages — they may lose features (TTL ignored,
  replies shown as JSON, protocol DMs shown as text).
- v1 payload semantics are frozen: a v1 payload never carries reply
  metadata.
- The `kind` field: `""` for all pre-group envelopes; the relay
  rejects unknown kinds on `POST /v1/send` (`400`); clients skip
  envelopes whose kind is neither `""` nor `"dm"` in personal
  inboxes, advancing the cursor. (Note: the current relay does not
  emit `kind` in personal inbox responses —
  `internal/relay/subscribe.go` `buildInboxPage`; the client's check
  is forward-compatibility.)
- All directory endpoints are additive; pre-v0.8.0 clients never call
  them.

## Appendix A. Canonical signature-domain registry

All domains are defined in `internal/envelope/envelope.go`. `0x00`
separates variable-length fields; `be64` is big-endian uint64.

| Domain | Signed by | Covers |
|---|---|---|
| `courier-envelope-sig-v1` | DM sender | `to(32) \|\| from(32) \|\| eph(32) \|\| nonce(24) \|\| be64(sent_at) \|\| ct` |
| `courier-group-envelope-v1` | group sender | `SHA256("courier-group-id-v1"\x00 \|\| groupID) \|\| from(32) \|\| be64(key_epoch) \|\| eph(32) \|\| nonce(24) \|\| be64(sent_at) \|\| ct` |
| `courier-group-control-v1` | group admin | `groupID \|\| 0x00 \|\| action \|\| 0x00 \|\| target \|\| 0x00 \|\| admin \|\| 0x00 \|\| be64(epoch)` |
| `courier-group-inbox-req-v1` | group member | `groupID \|\| 0x00 \|\| member(32) \|\| be64(after) \|\| be64(limit) \|\| be64(ts)` |
| `courier-key-announce-v1` | identity owner | `address(32) \|\| x25519_pub(32) \|\| be64(epoch)` |
| `courier-inbox-req-v1` | recipient | `address(32) \|\| be64(after) \|\| be64(limit) \|\| be64(ts)` |
| `courier-subscribe-req-v1` | recipient | `address(32) \|\| be64(cursor) \|\| be64(ts)` |
| `courier-spam-report-v1` | reporter | `reporter(32) \|\| be64(envelope_id) \|\| be64(ts)` |
| `courier-blob-upload-v1` | uploader | `from(32) \|\| to(32) \|\| blob_id(32) \|\| be64(size) \|\| be64(ts)` |
| `courier-blob-req-v1` | recipient | `address(32) \|\| blob_id(32) \|\| be64(ts)` |
| `courier-dashboard-register-v1` | identity owner | `username \|\| 0x00 \|\| address(32)` |
| `courier-directory-register-v1` | handle owner | `handle \|\| 0x00 \|\| address(32) \|\| be64(epoch) \|\| 0x00 \|\| visibility \|\| 0x00 \|\| contact_policy \|\| 0x00 \|\| capabilities joined by 0x00` |
| `courier-directory-transfer-v1` | current holder | `handle \|\| 0x00 \|\| new_address(32) \|\| be64(epoch)` |
| `courier-directory-deregister-v1` | handle owner | `handle \|\| 0x00 \|\| address(32) \|\| be64(epoch)` |
| `courier-directory-query-v1` | querier | `querier(32) \|\| 0x00 \|\| op \|\| 0x00 \|\| query \|\| 0x00 \|\| be64(ts)` |
| `courier-introduction-req-v1` | requester | `requester(32) \|\| introducer(32) \|\| handle \|\| 0x00 \|\| be64(ts)` |
| `courier-introduction-v1` | introducer | `introducer(32) \|\| subject(32) \|\| recipient(32) \|\| be64(ts)` |

Safety numbers (not a signature) use the hash domain
`courier-safety-v1` over both parties' Ed25519 keys, X25519 keys,
and key epochs (§19).

## Appendix B. In-flight work requiring spec updates after merge

This spec describes `origin/main` (+ merged bridge phase 1). The
following open efforts will change protocol behavior and MUST be
folded into this document when they merge:

- **Bridge phase 2** (`feature/bridge-phase2`): dashboard
  "not end-to-end encrypted" badge on bridged messages
  (`bridge.HasBanner`-keyed rendering); relay-side advisory bridge
  flag (coordinated in advance; no protocol break expected);
  client-side untrusted-input enforcement; dashboard admin audit
  view. Affects §25.3, §25.5, §26.
- **Issue #97** (bridge input validation hardening), **#98**
  (bridge follow-ups): tighten the gateway ingest path; may add
  ingest limits or error codes — affects §25.2, §25.4.
- **Issue #100** (blob upload rate limiting / per-uploader quota):
  will add relay-side blob abuse controls — affects §9.7, §11,
  §28.4.
- **Issue #106** (CI on main): process change; the spec's "no CI
  gates main" disclosure (§28.4) flips when branch protection lands.
- **Issue #108** (version consistency + LICENSE): the
  `/v1/health` `version` field and version table (§9.10, §28.4)
  become true.
- **Issue #110** (FS downgrade resistance): any enforcement mode or
  downgrade alarm changes §15.5.
- **Issue #111** (dashboard CSRF tokens): changes §26.4.
- **Group/threading/receipts/FS feature branches** visible on
  `origin` (`feature/fs-50`, `feature/receipts-52`,
  `feature/threading-51`, `feature/ttl-53`, `feature/bridge-oauth`,
  `feature/bridge-phase1-61`, `backup-multi-device-47`,
  `contact-discovery-design`, `contact-verification-48`,
  `fix-v091-silent-replays`, `fix/81`–`fix/86`): if any merge with
  wire-visible changes, the corresponding section needs a
  conformance pass.

---

*Implementation references are to
`github.com/black-candle-technologies/courier` at `origin/main`.
Where this document and the code disagree, the code governs — and
the discrepancy is a bug in this document.*
