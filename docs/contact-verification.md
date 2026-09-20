# Contact verification + OOB-code private channels (issue #48)

One workstream, two phases. The OOB ceremony *is* the verification
bootstrap: entering a code received out of band both verifies the
counterparty and joins the private channel.

## Phase 1 — Contact verification UX

### Safety number

Both parties must compute the *same* number independently, Signal-style:

```
safety = digits(SHA512("courier-safety-v1" ||
    min(addrA, addrB) || max(addrA, addrB) ||
    xA || epochA || xB || epochB))
```

- `addrA`/`addrB`: raw 32-byte Ed25519 public keys, sorted lexicographically.
- `(xA, epochA)`: the X25519 encryption key + epoch belonging to the
  party whose address sorted first; `(xB, epochB)` the other.
- Each side knows its own key locally and fetches the other's from the
  relay key directory (`GET /v1/keys/<address>`, signature-verified,
  rollback-rejecting — the same trust as `recipientKey`). A contact that
  never published a key contributes the address-derived key with epoch 0,
  which is deterministic, so both sides still agree.
- Rendered as 60 decimal digits in 12 groups of 5 (30 hash bytes, 20 bits
  per group). Short enough to read over a call, long enough to matter.

### Verification records

`Config.ContactVerifications`: contact name →

```
{ verified_at, safety_number, key_epoch, address }
```

`address` and `key_epoch` are the values the safety number was computed
over. Trust is re-evaluated live:

- **verified** — record exists, contact address unchanged, contact's
  current key epoch == recorded epoch.
- **stale** — address changed or the contact rotated encryption keys
  since verification (re-verify; the safety number is different now).
- **unverified** — no record.

Key fetches are best-effort: if the relay is unreachable, the stored
state is reported with a note instead of failing.

### CLI

- `courier contacts verify <name> [--yes]` — fetch keys, print the safety
  number, prompt for OOB confirmation (`--yes` asserts it non-interactively).
- `courier contacts unverify <name>` — clear the record (e.g. suspected
  compromise).
- `courier contacts list` — trust column: `✓ verified`, `• unverified`,
  `⚠ key changed — re-verify`.
- `courier contacts show <name>` — address, status, verified-at, safety number.
- Any verification change resets the dashboard label refresh timer so the
  next minutely push carries the new state promptly.

### Dashboard trust indicators

Mirrors the peer-handle labels (issue #39): the agent pushes a
`verified` map (peer → `verified`|`stale`) with its daily peer-label
refresh; the dashboard stores it in `dashboard_peer_verified` (7-day TTL)
and renders a badge in the thread list and thread view — `✓` green for
verified, `⚠` amber for stale. No badge for unverified/unknown (no nagging).

## Phase 2 — OOB-code private channels

A channel is a small private group for the team-agent case, bootstrapped
by a short out-of-band code. Client-side only: no relay changes. Channel
protocol DMs are pairwise E2E-encrypted Courier messages with a magic
marker (`cc:2`), consumed by the channel layer exactly like group DMs
(issue #32) — never surfaced as chat.

### OOB code

15 random bytes (120 bits), base32 upper-case, no padding, rendered as 6
groups of 4 (`ABCD-EFGH-IJKL-MNOP-QRST-UVWX`). The code carries only the
*join secret*; the joiner supplies the inviter's address/contact
separately. Codes are single-use and expire after 24h.

### Protocol

1. `channel create <name>` — local channel: id `ch_<base32(16B)>`,
   256-bit secret, roster=[self], admin=self.
2. `channel invite <channel>` — mint a join secret, store the pending
   invite, print the OOB code. The operator conveys it out of band.
3. `channel join <inviter> <code>` — send a `join-request` DM
   `{secret}` to the inviter, then poll inbox up to 60s for the accept.
   - Inviter's handler: invite must exist, be unused and unexpired; the
     joiner is added to the roster, the invite is burned, and a
     `join-accept` DM goes back carrying `{channel id, name, secret,
     epoch, roster, admin}`. If the joiner is a named contact they are
     marked verified — code possession *is* the OOB ceremony.
   - Joiner's handler: accept must come from the inviter, roster must
     contain both parties; the channel is stored and the inviter is
     marked verified (same ceremony, other direction).
4. `channel send <channel> <msg>` — body sealed with secretbox under the
   channel secret, DM'd to every roster member except self. Sent and
   received messages are kept in the local channel log (cap 500).
5. `channel inbox <channel>` — print the channel log.
6. `channel remove <channel> <addr>` (admin) — drop the member, rotate
   the channel secret (epoch+1), distribute via `rekey` DMs.
7. `channel leave <channel>` — drop self, notify admin with `leave`.

### Security properties

- Join secret: 120-bit, single-use, 24h expiry. Channel secret: 256-bit,
  rotated on member removal (removed members cannot read later messages).
- Every channel DM is pairwise-encrypted and Ed25519-authenticated by the
  existing Courier envelope layer; the relay sees only ciphertext.
- Trust root is the OOB code: whoever holds it can join (TOFU). Admin
  rotation is out of scope — a compromised admin re-creates the channel.
- Malformed channel payloads fall through as ordinary messages, never
  silently swallowed (same rule as introductions, issue #39).

### State

`~/.courier/channels.json` (0600): channels, pending invites (keyed by
join secret), pending outbound joins (inviter → timestamp, for accept
correlation).
