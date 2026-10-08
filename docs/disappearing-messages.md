# Disappearing messages / TTL (issue #53)

## Decision

Expiry lives inside encrypted chat payloads (`courier send --ttl`). There is
no new envelope kind or relay endpoint; the relay cannot inspect the deadline.
Shared notes/tasks are retired. Their reserved `cs:1,t:state` payloads are
consumed without rendering or caching, and explicit fetch refuses them.

## Where expiry lives

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
| `~/.courier/sent.jsonl` | Expired entries pruned on read. |
| Dashboard DB (`dashboard_messages`) | Expired rows filtered from every read and deleted by the push-time sweep. |
| Relay envelopes | **Not** deleted per-message. TTL is an *endpoint* guarantee, not a relay guarantee. Envelopes age out under the relay's existing retention policy (daily prune of envelopes older than `--retain-days`). |

This is the honest limit of the feature, and it matches the product's
threat model: the relay is a dumb mailbox that already retains
ciphertext for a bounded window. Endpoint deletion covers the realistic
"disappearing" use cases (temporary context, secrets that should not
linger in logs or the dashboard UI).

## Clock skew

The sender's clock defines the absolute `expires_at`; the recipient
evaluates it against its own clock. A few minutes of skew shifts
effective expiry by the skew — acceptable for a best-effort
ephemerality feature (same posture as Signal-style disappearing
messages). No NTP enforcement, no grace window: `now >= expires_at`
means expired. Senders that need tighter semantics should pad the TTL.

## Backward compatibility

- **Chat DMs:** pre-#53 `parseMessagePayload` returns the JSON wrapper as
  raw body text when there are no attachments, so the message is
  **preserved and readable** (rendered as JSON) but the TTL is not
  enforced. Any
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

`courier inbox` annotates live messages with their expiry. (Shared
notes/tasks were cut pre-launch in #146; TTLs apply to ordinary chat
messages only.)

## Non-goals / future work

- Per-message relay deletion (would need a signed delete endpoint +
  relay deploy; the retention window already bounds relay storage).
- Read-receipt-triggered expiry ("disappear after read") was a
  considered non-goal and is now moot: read receipts were cut
  pre-launch (#146); only delivery receipts remain.
- Expiry on group control traffic (out of scope; group messages
  could adopt `messagePayload.expires_at` later since they share the
  plaintext format path).

## Retired shared-state archive

Existing `~/.courier/state.json` remains a private, read-only legacy archive for
manual inspection/export; no shared-state CLI or new state mutations remain.
Every config load prunes expired notes/tasks and their related mutations and
snapshot copies under the cross-process config lock. Later-expiring entries
are pruned on later loads; no background deletion runs while Courier is idle.
Nonexpired data and unknown metadata are preserved in place with atomic 0600
replacement. A malformed archive stops loading with an error and is left intact
for explicit recovery. Do not run old state-writing binaries concurrently.
Backups and independently exported copies retain their own retention obligations.
