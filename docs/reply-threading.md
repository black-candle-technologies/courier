# Reply threading (issue #51)

In-conversation reply references: a message can quote/thread off a parent
message. Design for milestone v0.11.0.

## The questions

### 1. How is the parent referenced?

By **relay envelope ID** — the same `#id` that `courier inbox` prints and
that the local sent log records as `courier_id`.

- It is the identifier the user already sees (`[#42] from ...`), so
  `courier send <addr> <msg> --reply-to 42` needs no new vocabulary.
- Relay envelope IDs are relay-wide unique (single autoincrement
  namespace across all envelopes), so the reference is unambiguous in
  both DM directions: Alice's sent log records the same ID that Bob's
  inbox shows for the same envelope.
- Rejected alternative: per-conversation sequence numbers. Two
  independent senders would race on who assigns the next number; it
  needs a coordination layer (and a conflict story) for something the
  relay ID already gives us for free.

### 2. How is the reference encoded on the wire?

Inside the **E2E-encrypted DM plaintext** — no relay changes, no new
endpoints, no migration path. The relay stays opaque: it sees an
ordinary envelope whose ciphertext happens to carry structured JSON,
exactly like attachment manifests (v0.7.0) and shared-state events
(#49, v0.10.0) before it.

The DM plaintext gains a v2 versioned payload:

```json
{"v": 2, "body": "<message text>",
 "reply_to": 42, "quote": "<parent snippet, ≤500 chars>",
 "attachments": [ ... ] }
```

- `reply_to` / `quote` are optional (`omitempty`).
- v1 (`{"v":1,"body","attachments"}`, attachments required) keeps its
  exact legacy semantics, and **attachment-only sends still emit v1
  byte-for-byte** — old clients render them exactly as before.
- Plain-text messages without a reply reference keep the legacy
  raw-text plaintext (unchanged).

**Backward compatibility:** pre-v0.11.0 `parseMessagePayload` treats
anything that isn't v1-with-attachments as raw text, so a v2 reply
renders on old clients as the JSON blob — the message is delivered,
nothing crashes, and the body text is preserved inside the JSON. This
is the codebase's established "harmless" degradation (introduction
DMs, shared-state events: "old clients display their JSON as chat
text"). Go's `json.Unmarshal` also ignores the unknown `reply_to` /
`quote` fields on v1 payloads, so mixed-version traffic never chokes.

**Why not the shared-state (#49) substrate?** The issue suggests
considering it. Threading metadata is immutable, sender-stamped,
per-message data — not foldable multi-writer state. It must render
with zero coordination and without a state log, and a payload field
preserves the relay-opaque, zero-new-endpoint property that made
state events shippable. Merging it into shared state would add log
machinery, event kinds, and fold rules for something that is, at its
core, one optional integer per message. Standalone is the right call.

**Why not an envelope-level (relay-visible) field?** It would leak
conversation structure to the relay as metadata, require a relay DB
migration and a `/v1/send` schema change, and force old relays to
reject (or mis-handle) new clients. The ciphertext already carries
richer structure; keep it there.

### 3. How does `courier inbox` render a reply?

```
[#101] from ed25519:... at 2026-09-20 18:44:01Z
↩ in reply to #42: "want to sync at 3?"
yes, 3 works
```

- The quote snippet resolves in this order:
  1. **Locally-resolved parent** (most trustworthy): the sender's own
     sent log, or the local reply cache (see below). This beats the
     embedded quote because it is *this recipient's* copy of the
     parent bytes, not the sender's assertion about them.
  2. **Embedded `quote`** from the payload — the sender's snippet,
     which makes the common case work even when the recipient has no
     local copy (different device, fresh machine, aged-out logs).
  3. **Bare reference** `↩ in reply to #42` when the parent cannot be
     resolved anywhere. Never fails, never blocks delivery.
- Held message requests render the same way.

**Reply cache** (`~/.courier/thread_cache.jsonl`, 0600, capped at
1000 entries): every successfully decrypted+verified DM delivery
records `{courier_id, from, snippet (≤500 chars), sent_at}`. It is a
best-effort local accelerator, written on the inbox path (all
consumers: inbox poller, dashboard pusher, review). It makes
"see [#42], reply to it" work for inbound parents without a relay
round-trip.

**Send-time behavior** (`courier send --reply-to 42`): the client
resolves the parent snippet from the sent log, then the reply cache,
and embeds it as `quote`. If the parent isn't found locally, it warns
on stderr and sends anyway — the ID is authoritative, and the
recipient may resolve it from their own state.

**Security note:** `quote` is sender-asserted — a malicious sender
could misquote the parent. The parent ID is always shown so the
recipient can verify against their own copy, and locally-resolved
snippets take precedence over the embedded one. Reply metadata rides
inside the signed ciphertext, so a third party cannot forge a reply
reference onto someone else's message.

### 4. How does the dashboard render threads?

The dashboard server never decrypts (it holds no identity keys), so
the **agent pushes** `reply_to` + `quote` alongside each message body
— the same trust model as pushed handle labels (#39) and verification
badges (#48): the agent reports, the dashboard displays.

- Push API: `reply_to` / `quote` fields on each pushed message
  (validated: `reply_to >= 0`, quote length-bounded).
- Store: `dashboard_messages` gains `reply_to INTEGER DEFAULT 0` and
  `quote TEXT DEFAULT ''` via the existing `addColumn` migration
  pattern. Old rows render without a quote block.
- Thread view renders a `<blockquote>` above the message bubble:

  > ↩ in reply to #42
  > "want to sync at 3?"

  (HTML-escaped by `html/template` as usual.) The thread-list preview
  stays body-only so quotes don't noise up the conversation list.

### 5. Scope and follow-ups

- **DMs only for v0.11.0.** Group messages use a separate plaintext
  format (`{"t":"m","b":...}`); the extension path is adding
  `"r"`/`"q"` keys there plus `courier group send --reply-to`.
- **No targeted parent fetch yet.** If the parent is unresolvable
  locally, the UI shows the bare ID. A future `courier inbox --show
  <id>` (signed targeted fetch via `after=id-1&limit=1`, no cursor or
  seen-set side effects) would close that gap.
- Replies are human chat: they **are** recorded in the local sent log
  (`~/.courier/sent.jsonl`) like any send. No new machine-protocol
  DMs are introduced, so the `sendProtocolDM` / `logSent=false` rule
  is unaffected.
- Version const: not bumped in this PR (release cuts bump it).
