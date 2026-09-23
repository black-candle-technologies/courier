# Disappearing messages / TTL (issue #53)

## Decision

Expiry is implemented **once, client-side, in the ciphertext** — on two
surfaces:

1. **Shared-state substrate (the primary primitive, issue #49):** an
   `expires_at` timestamp on `note-add` / `task-add` state events. A note
   with an expiry is the natural agent primitive (scratch context,
   one-time secrets, "remember this for 10 minutes").
2. **Plain chat DMs:** an `expires_at` timestamp on the versioned message
   payload (`courier send --ttl`). "Disappearing messages" without chat
   coverage would be a surprising gap, and the dashboard is the human
   reading surface where disappearance must be visible.

There is deliberately **no new envelope kind, no new relay endpoint, and
no relay change**. Both forms ride inside ordinary encrypted DMs, so the
relay never learns which messages expire (metadata protection is
preserved) and old clients degrade gracefully instead of choking.

## Where expiry lives

- **State events:** `StateEvent.expires_at` (unix seconds, `omitempty`).
  Valid only on `note-add` and `task-add`; rejected on other event kinds.
  Folded into `StateNote.expires_at` / `StateTask.expires_at` so snapshots
  and derived views carry it.
- **Chat DMs:** `messagePayload.expires_at` (unix seconds, `omitempty`).
  `--ttl` wraps the body as `{"v":1,"body":...,"expires_at":...}`.
  Messages without TTL keep the legacy raw-text plaintext byte-for-byte.
- **Dashboard push:** `pushMessage.expires_at`; the dashboard stores it
  per message row (`dashboard_messages.expires_at`, 0 = never expires).
- **Sent log:** `SentEntry.expires_at` so the sender's own copies expire.

The sender stamps an **absolute** timestamp (`send_time + ttl`) from its
own clock. The envelope's `sent_at` is not used as the anchor: the
absolute value is simpler to evaluate on every read path and survives
relay delays identically on both ends.

## Who enforces deletion (both endpoints, independently)

Expiry is enforced on **read/sync paths**, never by a delete RPC:

- **State:** expired items are excluded from the derived view
  (`viewOf`, used by `state list/show/search`). Their events are pruned
  from the local log — real local deletion — in `applyStateEvents`
  (covers inbox, dashboard-push, and state-sync consumers plus the
  sender's own local apply), in `StateSync`, and on the `StateConversation`
  read funnel (covers `list`/`show`/`search` when no new events arrive).
- **Chat, recipient:** a message already expired at fetch time is consumed
  silently — dropped, never delivered to inbox, dashboard, or requests.
  A message still alive is delivered with its `expires_at` attached.
- **Chat, sender:** expired entries are pruned from `~/.courier/sent.jsonl`
  on read; already-expired entries are never pushed to the dashboard.
- **Dashboard server:** expired rows are filtered from threads, thread
  views, and search, and deleted by a sweep on every push.

No coordination between the endpoints is needed: each side deletes its
own copies on its own schedule. A peer that never fetches keeps its
(unread) envelopes until relay retention removes them — see below.

## What "deletion" means

| Store | Meaning of expiry |
|---|---|
| `~/.courier/state.json` | Expired notes'/tasks' events are pruned from the conversation log; expired snapshot entries dropped. Gone from `state list/show/search`. |
| `~/.courier/sent.jsonl` | Expired entries pruned on read. |
| Dashboard DB (`dashboard_messages`) | Expired rows filtered from every read and deleted by the push-time sweep. |
| Relay envelopes | **Not** deleted per-message. TTL is an *endpoint* guarantee, not a relay guarantee. Envelopes age out under the relay's existing retention policy (daily prune of envelopes older than `--retain-days`). |

This is the honest limit of the feature, and it matches the product's
threat model: the relay is a dumb mailbox that already retains
ciphertext for a bounded window. Endpoint deletion covers the realistic
"disappearing" use cases (shared scratch state, secrets that should not
linger in logs or the dashboard UI).

## Clock skew

The sender's clock defines the absolute `expires_at`; the recipient
evaluates it against its own clock. A few minutes of skew shifts
effective expiry by the skew — acceptable for a best-effort
ephemerality feature (same posture as Signal-style disappearing
messages). No NTP enforcement, no grace window: `now >= expires_at`
means expired. Senders that need tighter semantics should pad the TTL.

## Backward compatibility

- **State events:** `expires_at` is `omitempty`. Pre-#53 clients unmarshal
  the event fine (unknown JSON fields are ignored) and simply never
  expire the note — graceful degradation, no choke.
- **Chat DMs:** pre-#53 `parseMessagePayload` returns the JSON wrapper as
  raw body text when there are no attachments, so the message is
  **preserved and readable** (rendered as JSON) but the TTL is not
  enforced. This mirrors the documented pre-v0.10.0 behavior for state
  payloads ("display the payload JSON as chat text (harmless)"). Any
  in-ciphertext scheme has this property; a relay envelope field would
  have been cleaner for old clients but requires a relay deploy, and a
  new envelope `kind` would make old clients *silently drop* the message,
  which is worse than showing it.
- **Dashboard:** `expires_at` is `omitempty` on push; old rows default to
  0 (never expire). The column is added by the standard `migrate()`
  `ALTER TABLE` path, so existing dashboard DBs upgrade in place.
- **Sent log:** old entries without the field parse as never-expiring.

## CLI

- `courier send <addr> <msg> --ttl 10m` (Go duration syntax: `30s`,
  `10m`, `2h`, …; must be positive)
- `courier state note add <peer> --title <t> [--body <b>] --ttl 10m`
- `courier state task add <peer> --title <t> ... --ttl 1h`

`courier inbox` annotates live messages with their expiry; `courier
state show` reports it for notes/tasks.

## Non-goals / future work

- Per-message relay deletion (would need a signed delete endpoint +
  relay deploy; the retention window already bounds relay storage).
- Read-receipt-triggered expiry ("disappear after read") was a
  considered non-goal and is now moot: read receipts were cut
  pre-launch (#146); only delivery receipts remain.
- Expiry on group/channel control traffic (out of scope; group messages
  could adopt `messagePayload.expires_at` later since they share the
  plaintext format path).
