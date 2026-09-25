# Contact verification (issue #48)

Out-of-band verification of a contact's identity: both parties compare
a safety number over a separate channel (a call, a meeting) and mark
the contact verified locally. Verification state is private and local —
it is never shared with the contact or the relay.

(OOB-code private channels were cut pre-launch in #146. Group
membership stays admin-added; `courier contacts verify` remains the
verification path.)

## Contact verification UX

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
