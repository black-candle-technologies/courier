# Team addressing and multi-host plan

**Status:** Revised design and implementation reference, updated 2026-10-09. Packet A context isolation and Packet B team wire implementation are in separate review PRs; this PR contains planning documents and a CI Go 1.26.9 pin, with no team runtime implementation. Remaining recommendations are subject to the named owner decisions and downstream integration gates. Riley retains the merge gate; neither this document nor an independent design review authorizes a merge.

**Context:** Courier needs to link agents belonging to different people, including Riley’s Muse and Picasso and Lane’s Muse. Rig’s `user@team` addressing and named-host configuration are inspiration only; Courier is decoupled from rig and uses its own protocols. A Courier host means a relay endpoint, not an SSH machine.

**Non-negotiable:** Courier remains end-to-end encrypted. The directory may learn names, addresses and membership, but never message plaintext.

This revision supersedes the incompatible addressing and incomplete trust assumptions in the [initial proposal](https://github.com/black-candle-technologies/courier/blob/ec99b39f80c2f288c9374d49af1e7aeb0b4c10b6/docs/team-addressing-plan.md). It preserves the multi-owner, multi-host goal. See [implementation work packets](team-addressing-implementation-plan.md) for dependencies, file ownership, acceptance gates and prepared agent handoffs. Packets A and B have been dispatched under separate authorization; their implementation and review status do not establish readiness of downstream packets.

Keep teams as signed address books, preserve Courier’s existing sender-key groups, and add multi-host support only after isolating local state by relay and principal. Use explicit team fanout rather than changing the meaning of `@handle`. Retain SuiteV1 throughout this work.

This resolves the compatibility and trust gaps in [PR 162](https://github.com/black-candle-technologies/courier/pull/162). The design below combines the implemented Packet B wire contract with proposed downstream behavior; it does not establish a complete implemented feature or permission to merge. PR 162 remains unmerged; its historical first revision is linked above.

## Independent design review

Independent review found the revised proposal suitable for owner review after corrections to expired-history catch-up, private invitation bootstrap, historical membership disclosure, member leaving, VHL scope, transfer proofs and expiry during long fanouts. That outcome does not approve implementation or merge. The acceptance tests, remaining owner decisions and downstream integration below remain release gates; the approved choices are recorded separately below.

## Direct assignments to existing peers

**Accepted requirement, 2026-10-09:** agents must be able to assign work to other existing agents in their team/crew, without requiring child-agent creation. The [peer-task handoff extension](peer-task-handoff-plan.md) defines proposed assignment, recipient acceptance/decline, local fenced claims, status/results, cancellation, expiry and replay-safe recovery over existing E2E DMs. Team membership grants no execution authority; recipient runtime policy remains independent of sender per-recipient VHL.

Historical shared tasks are being retired by [PR 150](https://github.com/black-candle-technologies/courier/pull/150). The new extension uses a separate namespace and does not resurrect shared notes/state or retired discriminators. Packet B's active team wire contract remains unchanged; later H/I packets add task wire types and context-bound handoff integration. Independent review approved the extension as design-only after corrections, not as implementation readiness. Exact support proof, measured limits/replay horizon, runtime interface and proposed single-ledger topology remain engineering gates.

## Decisions in brief

- Preserve `@handle` and `handle:name` as single-contact directory lookup. Add `courier send --team crew "message"` for deliberate fanout. Support `muse@crew` only through an explicitly pinned local team alias.
- A team is an address book. A group is the existing encrypted conversation with its own membership, admin and sender-key lifecycle. Neither silently changes the other.
- Make a selected context immutable for a command: relay security binding, principal, key store and state store. Every cursor, replay set, trust record and sidecar must use that context.
- Pin a team’s genesis identity through a verified invitation or an independently checked fingerprint. A valid signature from a directory-supplied owner does not establish that this is the intended owner.
- Use canonical, domain-separated, chained roster snapshots with durable version and hash checkpoints, signed expiration and explicit key transitions.
- Default teams to private, invitation-only membership and owner-only roster mutation. Team membership confers no contact trust, VHL status or harness authority.

## What the code already does

The original proposal describes `@team` broadcast and future group E2E. Both need correction against the current base, commit `454843d411f3c0db7f00f8dcbf0b6ad05d2f354d`.

1. [ResolveHandleTarget](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/directory.go#L485-L508) already interprets `@handle` and `handle:name` as directory lookup for one address. Reinterpreting the former as broadcast could disclose a formerly direct message to a team.
2. [Group messaging](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/groups.go#L1-L13) already uses per-sender symmetric keys distributed through pairwise-encrypted DMs. It has signed, ordered membership controls and removal-triggered sender-key rotation. The [group CLI](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/cmd/courier/group.go) already exposes create, add, remove, transfer, send and inbox.
3. [Config](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/client.go#L69-L163) combines identity keys, relay pins, cursors, contact verifications, key epochs and per-consumer replay sets. Groups, FS sessions, VHL, state, receipts, sent messages and reply caches also use fixed paths under `~/.courier`. Selecting another config filename alone does not isolate these resources.
4. [SuiteV1](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/crypto/suite.go#L25-L52) is Ed25519, X25519 and NaCl box. The suite registry is an extension point, not evidence that RSA or mixed-suite sending is implemented. Preserve omitted-suite compatibility on existing DM, key-announcement and group wire formats; new team schemas can reject unsupported explicit suites without breaking those old formats.
5. The existing [send path](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/client.go#L1134-L1168) binds VHL attestations to the resolved recipient and exact message requirements. A team label cannot replace that binding.

## Alternatives and why this design wins

**Reuse groups for every team.** This minimizes conceptual nouns and reuses working group encryption. It also couples directory naming to a conversation’s membership, admin and key distribution. Someone could want an organization address book without joining every conversation. Keep groups and teams separate, with explicit one-time import as a later convenience.

**Make every team message a group message.** Efficient for large, persistent conversations, but it changes reply semantics and requires group membership and key distribution before delivery. Use `group send` when that is the intent; team fanout is a set of direct messages.

**Overload `@name`, choosing contacts before teams.** Even precedence rules leave behavior dependent on directory availability or name creation. An explicit fanout selector removes that ambiguity. Do not fall back from failed contact lookup to team lookup, or vice versa.

**Global first-claim team names.** Familiar and short, but creates squatting, impersonation, recreation and multi-relay ambiguity. Prefer cryptographic team identity plus local aliases. Public friendly names can be added later as untrusted discovery hints.

**Trust the relay to choose the owner.** Simple, but roster signatures then protect only against accidental corruption after the relay has selected its own signing key. Pin the genesis root independently and treat the relay as a distributor that can withhold data.

**Implement RSA alongside addressing.** This multiplies protocol combinations and migration risks. Keep addresses suite-tagged and fail closed on unsupported suites; design and review mixed-suite migration separately.

## Addressing and CLI

Preserve existing raw-address and contact behavior. Keep `@alice` and `handle:alice` single-recipient. Add `muse@crew`, where `crew` must be a local alias pinned to one immutable team identity within the selected context. Unknown aliases are errors, not opportunities for automatic public-name discovery.

Supported contact names already exclude `@`, so ordinary contacts do not collide with `muse@crew`. Defensively detect manually edited or legacy-invalid config entries with that exact name and refuse ambiguous positional sends. An explicit `--contact` or `--team-member crew muse` selector can resolve that exceptional case without silently changing its target.

Proposed commands, with global selectors before the subcommand:

```text
courier --host work --identity muse team import <invitation> --as crew
courier --host work team resolve muse@crew
courier --host work send muse@crew "hello"
courier --host work send --team crew "hello everyone"
courier --host work send --team crew --dry-run "hello everyone"
courier --host work team create crew
courier --host work team invite crew muse ed25519:<public-key>
courier --host work team accept <invitation-id>
courier --host work team remove crew muse
courier --host work team show crew
courier --host work team transfer crew ed25519:<new-owner>
```

These are proposed interfaces. `team show` and dry-run display the full context, owner fingerprint, team ID, version/hash, expiry, member count and resolved addresses. JSON output carries the same information for harnesses. Team aliases never redirect to a replacement team without an explicit trust reset.

Phase one uses a single selected relay for both directory resolution and delivery. Cross-relay forwarding and federation are separate work; an address on a roster does not imply that another relay knows its encryption key or receives its inbox. Preflight must verify routability and key availability on the selected relay.

## Teams and existing groups

Team fanout creates separate DMs and separate replies. It does not create a shared thread, expose the full recipient list inside every DM, change a group roster, distribute group keys or rotate them. The sender retains a local operation record tying deliveries to the roster snapshot. A sender’s team ownership does not confer administration of any group.

Retain the existing group protocol unchanged in this feature. A later `group create --from-team` can take an explicitly reviewed snapshot and record its provenance. It must not install ongoing synchronization. Later team removals would still require explicit group removals and the existing group key lifecycle. Team removal cannot recall past DMs, erase a recipient’s copies or invalidate keys that recipient already received through an unrelated group.

## Identity and state isolation

Introduce three explicit objects instead of passing a mutable global config:

- `IdentityStore`: a stable principal address, signing seed, encryption-key history and identity-wide key-rotation lock. Config aliases and filenames are not principal IDs.
- `RelayBinding`: an immutable local relay ID, normalized HTTPS endpoint, approved certificate pin and pin-change history. Bind signed team objects to the normalized relay origin in phase one; endpoint migration requires an explicit migration design, not editing the host name.
- `Context`: `(relay binding ID, principal address)` plus a context-scoped state root. Two aliases for the same binding/principal resolve to the same context; a different principal or relay gets different state.

A host entry refers to a relay binding and a default named identity. Selection resolves once before opening stores or making network calls. Reject a missing identity, ambiguous selection, unexpected endpoint change or pin mismatch. Never retry another host or principal automatically.

Scope inbox, dashboard, wake and shared-state cursors independently by context and consumer. Scope replay sets, contacts and verification records, receipt opt-ins, block/request decisions, directory epochs and caches, invitations, team trust checkpoints, group keys and membership, FS/channel sessions, VHL state, shared state, sent logs, receipt tracking, attachments and reply caches to the context. Scope daemon PID files and locks too. Audit every path helper rather than limiting the migration to the obvious config fields.

Keep signing seeds and encryption-key rotation history in the identity store. For the first release, bind each principal to one relay security binding and reject concurrent reuse on a second relay; hosts can still select distinct named local identities. This reduces cross-relay replay, peer trust and encryption-key publication ambiguities while context isolation is introduced. Moving an existing principal to another relay requires a separately designed migration, not changing a TOML path. If later reuse is allowed, rotation must be identity-wide with publication tracked per relay, peer key-epoch floor semantics must be settled, and protocol replay/authority binding must be reviewed across relays. Retain old decryption keys under the existing retention rules. Never silently copy contact or VHL trust into a new context.

Each store receives a `Context` or a context-bound interface, never a process-global current-host variable. Use cross-process locks, atomic replace and fsync for security checkpoints and transaction journals. Capture the context in daemon startup; changing a CLI default does not switch a running daemon. Make backup, restore and import-sync context-aware too. Preserve the existing restore policy that resets FS/VHL and starts contacts and cursors fresh. Imported team checkpoints establish historical lower bounds only; a restored or new device must revalidate a pinned root and a fresh complete head chain before sending. Never restore consumed consent, VHL authority or an old ratchet as though it were live. Treat a restored backup’s potentially stale trust checkpoints as a recovery event, not as proof that an old roster is current.

## Team identity and signed wire format

Use a cryptographic ID independent of a friendly slug. For every new production team creation, the downstream creation path must generate a fresh 256-bit nonce with a CSPRNG (`crypto/rand` in Go), fail closed if generation fails, and encode those 32 bytes as canonical unpadded base64url `genesis_nonce` (strict decoding and exact encode/decode round-trip). It must not accept a user-chosen, fixed, derived or reused creation nonce: reusing the same nonce with the same genesis owner and relay collides with the permanent team ID and any tombstone. Deterministic supplied nonces are only fixture or pure derivation/verification inputs, not a production creation option. Packet B’s pure `NewTeamRoot` constructor continues to accept an explicit encoded nonce and derive identifiers without generating randomness; verifiers recompute identifiers from the received nonce and check its encoding, but cannot prove that its creator used fresh entropy. `genesis_owner` must be a SuiteV1 address that exactly round-trips through the SuiteV1 formatter. Let `C` be the UTF-8 bytes of RFC 8785 canonical JSON containing **precisely** the three string fields `genesis_nonce`, `genesis_owner` and `relay_origin`, in that canonical key order. Use Packet B's restricted grammar: printable ASCII strings, objects, arrays and null; no JSON numbers, booleans, controls or non-ASCII strings. For this commitment, the values are the three validated strings, without extra fields.

```text
team_id      = "sha256:" + lowercase_hex(SHA256(ASCII("courier.team.id.v1")      || 0x00 || C))
genesis_root = "sha256:" + lowercase_hex(SHA256(ASCII("courier.team.genesis.v1") || 0x00 || C))
```

`relay_origin` must already satisfy Packet B's canonical HTTPS grammar: lowercase ASCII DNS labels (1–63 characters, letters/digits/hyphens, no leading/trailing hyphen or empty label), or accepted canonical IP spelling; bracketed IPv6 must equal Go's canonical IP spelling. The origin is at most 269 bytes and has no userinfo, path (including `/`), query or fragment. An optional port is a canonical decimal integer from 1–65535 excluding 443, without leading zeroes; empty/default ports are rejected. The entire input must exactly equal the reconstructed `https://host[:port]`. Reject noncanonical signed field values; never normalize them before validating a root or signature. Packet A's endpoint normalizer can accept origins that B rejects. Downstream C/D must enforce B's grammar and compare the signed origin to their captured binding, failing visibly for an incompatible binding; no silent migration or trust reset is permitted.

This encoding is implemented in [Packet B NewTeamRoot and origin validation](https://github.com/black-candle-technologies/courier/blob/a9af611aa478eb103a66300b133e98c098665abe/internal/envelope/team.go#L169-L238). The pinned [wire contract](https://github.com/black-candle-technologies/courier/blob/a9af611aa478eb103a66300b133e98c098665abe/docs/packet-b-team-wire.md), [golden fixture](https://github.com/black-candle-technologies/courier/blob/a9af611aa478eb103a66300b133e98c098665abe/internal/envelope/testdata/team/golden.json), [Go vector tests](https://github.com/black-candle-technologies/courier/blob/a9af611aa478eb103a66300b133e98c098665abe/internal/envelope/team_vectors_test.go) and [independent Node oracle](https://github.com/black-candle-technologies/courier/blob/a9af611aa478eb103a66300b133e98c098665abe/internal/envelope/testdata/team/vectors.mjs) define reproducible cross-language evidence. The creation commitment is member-free, avoiding a circular dependency with membership consent. Preserve the genesis owner namespace after ownership transfer. A slug is a signed display label; uniqueness applies within `(relay origin, genesis owner, slug)` while active. A deleted team leaves a permanent tombstone for its ID. Reusing a slug yields a new ID and never inherits client pins.

The following is a field-level schema, with placeholders rather than a valid signed fixture:

```json
{
  "schema": "courier.team.roster.v1",
  "suite": "ed25519-x25519-naclbox-v1",
  "relay_origin": "https://relay.example:8470",
  "team_id": "sha256:<digest>",
  "genesis_owner": "ed25519:<key>",
  "genesis_nonce": "<base64url-32-bytes>",
  "genesis_root": "sha256:<creation-commitment-digest>",
  "slug": "crew",
  "version": "3",
  "previous_hash": "sha256:<version-2-payload>",
  "owner": "ed25519:<current-key>",
  "owner_epoch": "1",
  "owner_transition_hash": null,
  "issued_at": "2026-10-08T22:00:00Z",
  "expires_at": "2026-10-09T22:00:00Z",
  "status": "active",
  "visibility": "private",
  "history_disclosure": "current_and_future_members",
  "removal_policy": "owner_dependent_with_local_blocking",
  "members": [
    {
      "handle": "muse",
      "address": "ed25519:<member-key>",
      "consent_hash": "sha256:<accepted-invitation>"
    }
  ],
  "signatures": [{"role": "owner", "address": "ed25519:<key>", "sig": "<base64url>"}]
}
```

Sign the exact UTF-8 canonical payload excluding `signatures`, prefixed by `courier.team.roster.v1\0`. Use RFC 8785 JSON Canonicalization Scheme with cross-language golden vectors; the restricted field grammar avoids Unicode and number-normalization ambiguity. Reject duplicate keys, all unknown fields in v1 (future extensions require a new schema or an explicitly signed extension contract), invalid UTF-8, noncanonical integers, inconsistent suite/address labels and oversized arrays or strings before verification. Decimal-string versions avoid JSON number precision differences; validate unsigned 64-bit range and increment without wrap. Producers sort members by canonical handle before signing. Verifiers reject unsorted members and duplicate handles or addresses; they never reorder a signed array to make it valid. Equivalent valid JSON whitespace and escaping converge to the same canonical bytes, but invalid field encodings (such as padded base64url, noncanonical addresses, counters or origins) are rejected rather than repaired. Use lower-case ASCII handles/slugs, length 1–32, with an explicit `[a-z0-9][a-z0-9_-]*` grammar; do not normalize lookalike Unicode into trusted names.

Hash the canonical payload, excluding signatures, with SHA256. The signature covers all routing, identity, privacy, membership and freshness fields. Genesis has version `1`, null previous hash and owner equal to genesis owner. Every later snapshot advances exactly one version, chaining to the last payload hash. Transport certificates are separate from roster signer identity; a legitimate certificate rotation never resets roster trust.

## Trust and roster acceptance state machine

**Unknown.** Fetching a signed roster permits inspection only. Import requires an independently checked genesis owner/team fingerprint, or an invitation authenticated from an already individually verified Courier contact. Display exactly who controls the roster. A human-readable owner label, relay TLS pin or signature under a key supplied by the same untrusted response is insufficient.

**Invitation verified.** Before admission, verify the invitation against an independently pinned genesis root and a compact owner-transition certificate chain that contains no member lists. This chain proves historical ownership continuity, not that the signer is the latest owner. This is provisional trust for accepting the disclosed invitation only; it does not permit resolution or sending. Admission publication must use compare-and-swap against the relay’s current head, and a stale former-owner invitation cannot activate an alias. The documented malicious-relay withholding limitation also applies during provisional acceptance. After the member accepts and the owner publishes admission, the relay permits historical roster reads. The client then verifies the full roster chain and fresh admitted head before activating its alias. This avoids requiring private roster access before the invitee is authorized to read it.

**Pinned.** Persist `(context, team_id, genesis root, current owner/epoch, highest version, payload hash, expiration, trust method)`. A successful import may use a verified checkpoint bundled with the invitation; verify the chain from genesis, including owner transitions, before committing it.

**Update.** Reject another origin or team ID, invalid signature, wrong owner epoch, expired/future-dated data, lower version, or a higher version with a missing chain link. A duplicate version with the same payload hash is an idempotent read. The same version with a different hash is an equivocation alarm: freeze team sending until an operator resolves it. Fetch missing intermediate snapshots with bounded pagination; do not accept a convenient unsigned “latest version” pointer as proof. Historical chain links may be expired: verify their signatures, structural rules, owner continuity and monotonic issued times, while applying present-time freshness to the terminal snapshot used for sending. Otherwise any new client would fail as soon as genesis expires.

**Commit.** Compare against the latest local checkpoint under a lock, then atomically persist the validated advancement before using newly resolved targets. Persistence failure stops sending. Concurrent updates use compare-and-swap on version and hash at both client and relay; a loser fetches and reviews the new roster rather than reapplying a stale mutation silently.

**Expired or suspect.** Allow cached inspection with a clear stale label; do not resolve it for a new send. An owner-signed renewal is another chained version. Lowering the local wall clock cannot restore freshness: retain a durable last-observed time floor, allow a small documented clock-skew tolerance, and stop on material clock rollback. Local storage rollback or a compromised clock remains a recovery/security limitation.

**Rotated.** Owner transfer is a next-version snapshot authorized by the previously pinned owner, co-signed by the new owner over the same transition payload, with owner epoch incremented. Publish a compact transition certificate alongside each transfer. Its signed payload contains a separate domain tag, relay origin, team ID, genesis root, previous certificate hash, old and new owners, new owner epoch, effective roster version and previous roster hash; both owners sign it. The transfer snapshot sets `owner_transition_hash` to its certificate hash; ordinary snapshots set it to null. Reject certificate-chain gaps, forks and reused epochs. Compare the certificate’s effective version, previous roster hash, previous certificate hash and new owner epoch exactly against the full roster transition before activation. Invitation recipients can validate ownership continuity without receiving member lists; the full roster chain must later confirm the certificate’s exact transition before team sending is enabled. The roster’s existing team ID and genesis root remain unchanged. Subsequent snapshots require the new owner. Lost or compromised owner keys cannot be recovered safely by a relay assertion; absent a separately designed recovery authority, create and explicitly re-pin a new team. A member’s signing-address change requires a fresh invitation/consent and invalidates address-bound contact verification; ordinary signed X25519 key rotation stays in the existing key-directory protocol.

**Deleted.** A signed tombstone advances the chain, clears active membership and permanently disables sends for that ID. Deletion is terminal: accept an authentic chained tombstone even after its original expiration, because expiration cannot revive a deleted team. Retain its checkpoint locally even if the alias is removed.

## Freshness and removal guarantees

Version monotonicity detects replay of something older than a client has seen. It cannot prove that a malicious relay has shown the newest roster, particularly on a new device. State this limitation explicitly.

The approved first-release freshness policy permits owner-signed snapshots valid for no more than 24 hours and forbids expired-roster sends. Downstream integration must also provide a fresh relay fetch before every new team send or retry operation. A relay that withholds an unexpired removal can still cause a sender to target the removed member until expiration. Removal is therefore not instantaneous revocation against a malicious relay. A compromised owner can sign harmful fresh rosters; signatures do not eliminate that risk.

Riley approved the 24-hour bound and its availability versus stale-membership tradeoff on 2026-10-09, as recorded in the pinned Packet B decision record below. Renewals require the owner or an explicitly provisioned signing service; installing a team must not silently authorize recurring roster signing. If stronger revocation is required, design an online owner freshness attestation or a transparency/witness service as a separate protocol. A nonce echoed by the relay alone does not solve malicious-relay withholding.

## Invitations and privacy

Use new, domain-separated invitation and acceptance payload types inside existing authenticated E2E DMs. Bind both to context origin, team ID, genesis root, current owner, invite ID, proposed handle, member address, visibility, expiry and a random nonce. The owner signs the invitation; the prospective member signs acceptance. Store consumed and cancelled invite IDs durably. An expired, reused, cross-team or different-address acceptance is rejected.

An invitation is pending metadata, not active membership. Only after acceptance does the owner publish a new roster referencing the consent record. Recheck the owner and target membership against the latest head before publishing; if ownership transferred, issue a new invitation rather than silently transferring consent. Cancellation prevents later admission. Removal is owner-authorized and takes effect in the next roster; a former member must consent again to rejoin. Provide `team leave-request` to send an authenticated removal request to the owner and mark the member’s local subscription inactive. If the owner is unavailable or refuses, v1 cannot independently revoke roster membership: the member can locally block team traffic and stop processing it, but their address can remain listed. State that limitation in the invitation. Do not claim an independent member-consent revocation check until a separately signed withdrawal protocol and its freshness rules exist.

Private teams are not searchable or publicly enumerable. The relay directory authenticates reads and permits only current members, the owner, and separately approved directory readers. A pending invite carries the information needed to consent; it does not grant the entire private roster. After admission, chain verification requires access to historical full snapshots, so all current members can read former membership and handle history. Bind an explicit `history_disclosure: current_and_future_members` policy into invitations, acceptances and the roster schema, and require consent to it before joining. Removal blocks later reads but cannot erase already cached history. If that disclosure is unacceptable, use a separately designed compact checkpoint/owner-transition proof format before shipping; do not imply private teams hide past membership from new members. Errors should not disclose whether inaccessible team IDs exist. Phase one should omit arbitrary external reader sharing if its approval flow is not implemented.

The relay necessarily learns roster names, addresses, owner and membership, and sees DM routing/timing. Private means access-controlled directory metadata, not membership secrecy from the relay. Visibility changes from private to public require explicit owner approval and renewed member consent for that exposure; the safer v1 default is to support private teams only. Do not turn roster members into trusted contacts, bypass existing spam/request handling, enable receipts or expose plaintext in telemetry.

## Safe fanout and retries

Treat fanout as a local transaction with non-atomic remote delivery:

1. Resolve one verified, unexpired snapshot and freeze its roster hash and unique `(handle, address, consent_hash)` target tuples. Exclude the sending principal by default and show that choice. Preflight every target’s route, SuiteV1 support, signed encryption-key announcement and required outgoing policy. Reject an empty set or unsupported flags before any delivery. V1 can support text only and reject attachments, reply IDs and TTL until their per-recipient semantics are implemented.
2. Preserve the current directory-send first-contact and contacts-policy warnings and `--force` confirmation requirements per expanded recipient, without interpreting `--force` as human/VHL approval. Preserve each peer’s FS-required mode; an unavailable required session blocks preflight rather than downgrading encryption. Apply authorization to the expanded recipients and content. A team selector is not standing authorization for future members. The execution plan exposes its roster hash and recipient set so a harness can bind any required human decision. Evaluate Tier 1 token scope separately for each recipient and mint a separate recipient-bound attestation. An existing unscoped token may remain eligible under the current VHL rules; a scoped token is eligible only for its counterparty. Do not reuse a recipient-bound Tier 2 approval across recipients. An unsupported VHL fanout fails before sending; never downgrade it to Tier 0.
3. Persist a send operation with a random operation ID, context, roster checkpoint, content hash and per-target states. Prepare each encrypted envelope once, durably recording the ciphertext and any associated FS advancement before submission. Reuse that exact envelope on retry, rather than advancing the ratchet and generating a second logical message. Implementation must audit the existing send/ratchet persistence boundaries before claiming crash-safe retries.
4. Record each target as prepared, submitted, acknowledged, uncertain, failed or cancelled. A timeout after submit is uncertain, not failed. Retransmit the same ciphertext using the existing relay envelope-deduplication behavior; audit its actual contract and retention before depending on it. Relay acceptance is not proof that the recipient read the message. If durable preparation/deduplication cannot be established, expose uncertain status and require explicit retry handling rather than promise exactly-once delivery.
5. Before resuming, fetch and validate the current roster. Never add newly joined members to an existing operation. Cancel unsent or uncertain-target retransmissions for addresses now removed, or whose handle/consent binding changed. A pending local leave request alone is not evidence of roster removal. A previously accepted envelope may already be delivered and cannot be recalled. If the roster is expired, unavailable or conflicted, pause outstanding sends. A trusted fresh roster does not make a malicious relay’s unseen removal knowable.
6. Return a per-recipient result and nonzero exit status for incomplete operations. Provide `team send-status <operation-id>` and explicit resume/cancel. A new operation is required to send to a newly expanded roster or changed content. Check snapshot expiration immediately before every network submission, including after human approval or a long pause. Re-fetch after approval and before each resumed batch; if the roster hash changes, re-evaluate the frozen target subset and any approval scope before proceeding. Expiration or a security-relevant change pauses the operation; an in-flight request already submitted cannot be recalled.

## Relay API and implementation boundaries

Add a versioned team directory API rather than overloading contact records or group control endpoints. Proposed resources are immutable snapshots by team ID/version, a current-head pointer, signed publication with expected version/hash, and authenticated private reads. The relay validates owner continuity, consent records and publication authorization, then commits snapshot, head and ACL changes in one storage transaction. Conflicting updates return a conflict response with the current checkpoint. Repeating an identical publication is idempotent.

Store tombstones and owner-transition history durably. Bound roster size, invitation rate, snapshot bytes and chain-fetch pages. Authentication must bind method, path, team ID and request freshness using the project’s reviewed request-authentication pattern; an authenticated team reader is not a roster writer. Logs contain operation IDs and redacted diagnostics, not plaintext message bodies or unnecessary complete rosters.

Suggested client boundaries are `ContextResolver`, `IdentityStore`, `ContextStore`, `TeamTrustStore`, `TeamDirectoryClient`, `RecipientResolver` and `FanoutOutbox`. Keep parsing free of network access; return a typed recipient intent, then perform context-bound resolution. The implementation should extend existing crypto and envelope canonicalization conventions with tested new types, not reuse another protocol’s signing bytes.

## Harness and human approval boundary

A team roster proves only that a particular trusted owner assigned a handle to an address under the accepted roster. It does not prove who is human, that the owner can direct another agent, that a member may run tools or that a message has human approval.

Lumen and other harnesses consume resolved provenance and recipient identities through the same API. Keep action permissions, contact-specific standing approvals, VHL attestations and signing capabilities separate from directory membership. Roster updates cannot grant the ability to sign as another member or mint a human attestation. Machine invitation handling must not mistake receipt for user consent. Roster content, names and incoming messages remain untrusted input to a harness’s policy evaluation.

## Migration and rollout

1. **Correct the proposal first.** Record the parser collision and existing group implementation. Approve the team/group split, pin model and freshness budget before coding.
2. **Introduce context plumbing.** Refactor every state path and lock behind an explicit context without changing legacy behavior. Test two principals on one relay, rejected principal reuse on a second relay, aliases of one context and concurrent processes.
3. **Migrate safely.** Stop or refuse migration while older daemons are active. Under the legacy cross-process lock, stage a copied default context, preserve keys, pins, contacts, cursors and all sidecars, verify checksums, write a durable migration manifest, and atomically switch the new client’s active manifest. Keep a rollback copy, but do not run old and new binaries as independent writers. Recovery resumes or discards an uncommitted staging directory; it never half-selects new identity state and old group/FS state. Once new ratchets or checkpoints advance, reverting to an old state copy is unsafe and requires an explicit recovery procedure.
4. **Add roster read and lifecycle support.** Ship import, inspection, verification, private invitations and owner publication behind a feature gate. Add `user@alias` direct resolution only after the collision and trust tests pass.
5. **Add text fanout.** Gate release on durable outbox semantics, per-recipient authorization and failure reporting. Keep dashboard team management, group synchronization, public teams, federation and new crypto suites out of the first release.

Legacy installs retain their principal and current relay pin; do not re-init, regenerate keys or copy a pin to a different endpoint. Preserve the existing default path through a compatibility adapter until explicit migration succeeds. Detect a migrated installation when an older supported binary starts and refuse unsafe mixed-version writes where technically possible; document that arbitrary historical binaries cannot be made migration-aware retroactively.

## Acceptance tests and release gates

- **Parser:** `@crew` always remains one directory lookup, even if a team called crew exists; failed lookup never broadcasts. Verify `handle:crew`, raw addresses, ordinary contacts, manually edited or legacy-invalid contacts containing `@`, malformed selectors and flags in documented positions.
- **Context isolation:** colliding relay message IDs do not hide messages; inbox/push/state replay sets remain independent; groups, FS, VHL and dashboard state never cross principals; alias renames do not reset trust; changed endpoints/pins fail closed; daemon and command concurrency cannot select different identities mid-operation.
- **Roster integrity:** altered member, owner, origin, expiry, visibility or suite fails; duplicate keys/handles/addresses, invalid field encodings and unsorted members fail; equivalent valid JSON whitespace or escaping produces identical canonical bytes; lower versions, gaps, equal-version forks, integer overflow and missing owner transitions fail; identical snapshots are idempotent.
- **Trust and recovery:** self-signed replacement owners cannot bootstrap trust; a new device must import a verified checkpoint; a reset cache cannot silently inherit trust; tombstone/slug recreation never rebinds an alias; old/new owner dual signatures and lost-key recovery paths are tested.
- **Freshness:** an unexpired frozen head demonstrates the documented stale-member window; expiration and clock rollback stop sends; missing chain pages and private-read revocation fail visibly; a relay nonce is not accepted as owner freshness.
- **Consent and privacy:** wrong invite nonce/team/handle/member/owner/visibility, replay, cancellation, expiry and transfer all block admission; pending invitees cannot fetch private rosters; removal updates ACLs atomically; unapproved visibility expansion fails.
- **Fanout:** crash before prepare, after ratchet advancement, before submit, after submit and before acknowledgement preserves safe recovery; duplicate relay submissions do not duplicate delivery under the verified contract; partial failure remains visible; resumed operations never add new members or resend to known removed members; attachments and unsupported VHL modes fail before the first send; expiration during approval or mid-batch blocks every later submission.
- **Group regression:** the existing create/add/remove/transfer/send/inbox tests and key-rotation tests still pass. A team update changes none of those memberships or keys.
- **Authority regression:** membership cannot auto-verify contacts, bypass request filters, enable receipts, mint VHL approval or authorize harness tool execution. Recipient-bound VHL behavior remains intact.

Require protocol golden vectors, adversarial relay fixtures, cross-process race tests and migration crash injection in addition to happy-path CLI tests. This proposal is not a claim that those tests have run or passed.

## Approved choices and remaining decisions

The original recommendations below were subsequently approved for implementation by Riley. The pinned [Packet B decision record](https://github.com/black-candle-technologies/courier/blob/a9af611aa478eb103a66300b133e98c098665abe/docs/packet-b-team-wire.md#decisions-and-dependency) records D1/D2/D4/D5 and the CLI portion of D6 at 2026-10-09 01:41 UTC, with D3 separately approved. These approvals do not authorize provisioning, actual disclosure, sending, deployment or merge; numeric budgets and downstream integration/release gates remain pending.

1. **D1 freshness — approved:** owner-signed roster lifetimes of at most 24 hours and no expired sends, accepting bounded stale-membership exposure and the renewal burden. Stronger revocation requires a separately reviewed online owner/witness design.
2. **D2 private-only first release — approved:** private invitation-only teams. Public discovery and nonmember directory readers require a separate metadata-disclosure and consent policy.
3. **D3 key reuse across relays — approved:** one relay security binding per principal for the first release. Cross-relay reuse requires a separate replay, trust and rotation design; arbitrary config paths must not bypass this restriction.
4. **D4 owner recovery — approved:** no automatic lost-owner recovery. A recovery key or threshold-owner model requires separate review; the relay cannot become an implicit recovery authority.
5. **D5 membership privacy and leaving — approved:** historical full-roster disclosure to current and future members, with owner-dependent removal and local blocking in v1. These limits must be visible in invitations.
6. **D6 CLI — approved; numeric policy pending:** explicit text-only `send --team`, preserving existing address semantics. Measured roster/operation limits, retention and other numeric budgets still require owner/reviewer approval, along with downstream integration and release checks.

RSA selection, autonomous harness authority and automatic group synchronization are separate proposals, not unresolved prerequisites for team addressing.

## Relationship to other work

- Rig remains inspiration only. Its single-owner factories and Courier’s multi-owner teams share no code or protocol.
- Lumen and a Courier Control Plane can expose the same harness-agnostic team service. Dashboard and team-management UI remain later work; neither front door grants authority beyond Courier’s explicit trust and approval rules.
- Shared notes/boards and the ChatGPT bridge remain separate concerns. The newly requested direct peer-task handoff is specified in [its own extension](peer-task-handoff-plan.md); it does not inherit team ownership as action authority.

## Source references

- [Original PR 162 proposal at ec99b39](https://github.com/black-candle-technologies/courier/blob/ec99b39f80c2f288c9374d49af1e7aeb0b4c10b6/docs/team-addressing-plan.md)
- [Current client config, send and key-directory logic](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/client.go)
- [Current directory resolution and introductions](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/directory.go)
- [Current sender-key groups](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/groups.go)
- [Current FS state](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/fs.go), [VHL state](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/vhl.go), [shared state](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/state.go), [receipts](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/receipts.go) and [reply cache](https://github.com/black-candle-technologies/courier/blob/454843d411f3c0db7f00f8dcbf0b6ad05d2f354d/internal/client/threading.go)
