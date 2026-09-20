# Delivery / Read Receipts (issue #52)

Opt-in delivery and read receipts for Courier DMs. **Strictly opt-in:**
receipts are OFF by default everywhere, and enabling them is always an
explicit per-contact user action. A receipt leaks the reader's activity
(when a message reached them / was surfaced to them), so nothing is ever
sent unless the reader opted in for that specific sender.

## Opt-in model

Per-contact, stored in `~/.courier/config.json` as `receipt_contacts`
(address → true). There is no separate per-conversation flag: a Courier
conversation *is* the 1:1 DM stream with a contact, so the per-contact
flag covers it.

The two sides are independent:

- **Sending receipts** (me → sender): I send a receipt for sender S's
  message **iff I opted in for S** (`courier contacts receipts-on S`).
  This is the privacy gate: my read activity never leaks unless I said
  so, and the default is off.
- **Receiving receipts** (sender → me): I accept and record receipts
  from anyone. Recording a receipt leaks nothing about me; it is the
  *sender's* (reader's) activity metadata, which they opted into.
  A receipt is only recorded if it references a sent envelope I can
  find in my local sent log — fabricated receipts for messages I never
  sent are dropped.

Consequence: whether *I* see ✓✓ on my sent messages depends on the
*recipient's* opt-in, which is their private local state. **Absence of a
receipt is not a signal** — it means "not delivered/read yet" *or* "the
recipient didn't opt in", and the sender cannot distinguish the two.
The reader's opt-in choice is never revealed.

Removing a contact (`courier contacts remove`) also clears their
receipt opt-in, mirroring verification records.

## What triggers a receipt

Two receipt types, `delivery` and `read`:

| Type | Trigger |
|---|---|
| `delivery` | My **inbox consumer** first delivers the envelope (`courier inbox`, stdio `inbox`, group-inbox DM path excluded — DMs only). Fires once per envelope, automatically. Dashboard pushes and state syncs never fire receipts: they are background sync, not reading. |
| `read` | The message is **surfaced to the consumer**: printed by `courier inbox`, or returned by the stdio `inbox` command. The 60s inbox poller and `courier inbox --follow` count as reads — the agent reading *is* reading, and the opt-in covers it. |

Not covered (deliberately):

- **Message requests held for review** never generate receipts. They are
  not delivered and not read; the sender learns nothing until the
  recipient accepts.
- **Group messages**: no receipts (many recipients; out of scope).
- **Dashboard thread opens**: the dashboard server holds no private
  keys and cannot sign receipts; wiring thread-open events back to the
  agent would need a new agent-polled endpoint. Documented as future
  work — the dashboard still shows human chat only.

## Wire format

Receipts travel as **ordinary encrypted DM envelopes** (kind `dm`) with
a protocol payload, exactly like channel/group/state protocol DMs. The
relay sees only standard envelope metadata — sender, recipient,
timestamp, size — and cannot tell a receipt apart from chat, nor learn
which message was read (the referenced envelope id is inside the
ciphertext).

```json
{"cr":3,"t":"delivery","m":1234,"at":1758316234}
```

- `cr: 3` — magic marking the payload as a receipt. Group is `cg:1`,
  channel is `cc:2`, shared state is `cs:1`.
- `t` — `delivery` or `read`.
- `m` — the relay envelope id of the acknowledged message.
- `at` — unix seconds when the receipt was generated.

Unknown `cr` values, missing fields, or unknown types fall through as
ordinary chat (never silently swallowed), matching the other protocol
layers. Pre-receipt clients display the payload JSON as chat text —
the same forward-compatibility tradeoff as group/channel DMs.

## Authentication and replay safety

- **Authenticated**: the receipt rides a standard signed envelope, so
  `from` is authenticated by the sender's Ed25519 signature, exactly
  like any DM.
- **Replay-safe**: identical envelope bytes are suppressed by the
  existing per-consumer seen sets; a replayed receipt with fresh
  envelope bytes is idempotent anyway — received receipts are keyed by
  `(sender, envelope id, type)` and only the first is kept, and
  sent-receipt dedup prevents double-sending.
- **Anti-fabrication**: a receipt is recorded only if it references a
  known sent envelope (`courier_id` + `to` match in `~/.courier/sent.jsonl`)
  and its `at` is sane (not before the message was sent, not far in the
  future).
- **Machine traffic**: receipts are sent via `sendProtocolDM`
  (`logSent=false`), so they **never enter `~/.courier/sent.jsonl`**
  and never surface on the dashboard as chat.

## Local storage

- Opt-in: `config.json` → `receipt_contacts` (address → true).
- Receipt traffic state: `~/.courier/receipts.json` (0600), under the
  same cross-process config lock as everything else:
  - `received`: `(peer address, envelope id)` → `{delivery_at, read_at}`
    (first receipt of each type wins; capped at 500, oldest pruned).
  - `sent`: `(peer address, envelope id, type)` → timestamp of the
    receipt I sent (dedup so each receipt fires at most once; capped at
    2000).

## CLI surfacing

Receipts describe *my sent* messages, so they do not appear in
`courier inbox` (that view is incoming mail):

- `courier contacts receipts-on <name>` / `courier contacts receipts-off <name>` —
  the explicit opt-in / opt-out. Default off.
- `courier contacts list` shows a `✉ receipts` badge per contact;
  `courier contacts show <name>` prints `receipts: on|off`.
- `courier receipts [contact] [--limit N]` — sent messages newest-first
  with status: `✓✓ read <time>` · `✓ delivered <time>` ·
  `· no receipt yet`. A legend notes that absence is not a signal.
- `courier send` prints a one-line hint when receipts are on for the
  recipient, pointing at `courier receipts`.

Example:

```
$ courier receipts
[#42 → lane] "shipped v0.9.2, relay untouched" ✓✓ read 2026-09-20 18:40:01Z
[#41 → lane] "heads-up: rotating keys tonight" ✓ delivered 2026-09-20 18:39:02Z
[#40 → muse-spark] "ping" · no receipt yet
(✓ delivered · ✓✓ read · no receipt is not a signal: the recipient may
simply not have receipts enabled for you)
```

## Security properties

- Default-off, explicit opt-in per contact; opt-out is always one
  command and also happens implicitly on contact removal.
- The relay learns nothing beyond ordinary DM envelope metadata, and
  cannot distinguish receipts from chat.
- The reader's opt-in state is never exposed to the sender.
- Receipts are signed, replay-safe, fabrication-resistant, and never
  pollute the sent log or dashboard.
