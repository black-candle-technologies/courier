# Packet B: team wire contract (review candidate)

No runtime feature is enabled. No real keys, teams, rosters or messages were created. Independent cryptographic review, predecessor review, downstream integration, numeric release policy, merge and deployment are separate gates.

## Decisions and dependency

Riley approved D1/D2/D4/D5 and the CLI portion of D6 through the parent conversation on 2026-10-09 at 01:41 UTC: private invitation-only teams; owner-signed roster lifetimes at most 24 hours and no expired sends; no automatic lost-owner recovery; historical roster disclosure to current/future members; owner-dependent removal with local blocking; explicit text-only `send --team`. This records the chosen tradeoff of bounded stale-membership exposure, disclosure needed for full-history verification, and no implicit recovery authority. D3 (one security binding per principal) was separately approved. Approval covers implementation, not provisioning, actual disclosure, sending or deployment. Numeric budgets remain proposals requiring measured review.

Initial base: PR163 `packet-a/context-isolation`, commit `db0f83c68277cb45990193c2dd0e213e44655907`, tree `ad8f9a35d9a493d87ed95447a2293f16f229ac7d`. Planning reference: PR162 `26f89b23aeb1b077340cdd63296737d41e04b133`, `docs/team-addressing-plan.md` and `docs/team-addressing-implementation-plan.md`. No AGENTS.md exists in the assigned tree or workspace ancestors. Packet A configuration fixes are incorporated at the refreshed base below; B does not import client or edit its context/config/path code.

## Wire and canonicalization

The new `internal/envelope/team*.go` files are the complete implementation surface. Existing envelopes and SuiteV1 dispatch/defaults are unchanged. Every team object explicitly declares `ed25519-x25519-naclbox-v1`; omission and unknown suites fail. Signature verification uses the existing suite descriptor. There is no RSA or mixed-suite behavior.

All fields in the exported wire structs are required, including nullable hashes and signature arrays. Unknown, duplicate (including escaped-equivalent), missing, case-mismatched and null scalar fields fail. Counters are canonical unsigned decimal strings in the uint64 range. Times are exact UTC `YYYY-MM-DDTHH:MM:SSZ`, without fractions or offsets. Bytes use unpadded canonical base64url; hashes use `sha256:` followed by 64 lowercase hexadecimal digits. Names follow `[a-z0-9][a-z0-9_-]{0,31}`. Members must already be ordered by handle with unique handles and addresses; verifiers never silently reorder input. Addresses must round-trip through SuiteV1's formatter. Origin input must already be a normalized ASCII HTTPS origin, without path/query/fragment/userinfo/default port; ambiguous ports and noncanonical IPv6 are rejected. C/D must compare it with their captured binding origin, and fail visibly for unsupported origin spelling.

Dependency decision: no new library. `CanonicalTeamJSON` implements RFC 8785 **only on the restricted v1 grammar**: printable ASCII strings, null, arrays and objects. Numbers, booleans, controls and non-ASCII are rejected before hashing. Printable ASCII has identical UTF-16 and byte key order. Quotes/backslashes use JSON escapes; `/`, `<`, `>` and `&` remain literal. Equivalent valid input escaping/whitespace converges to the same canonical bytes. This is not a general JCS implementation. Maximum nesting eight and 32 object fields are schema restrictions. Review this restriction and the small encoder independently against [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html); broader strings/numbers require a new reviewed contract, not relaxed parsing.

Creation commitment `C = JCS({genesis_nonce, genesis_owner, relay_origin})` is member-free. `team_id = SHA256("courier.team.id.v1\0" || C)` and `genesis_root = SHA256("courier.team.genesis.v1\0" || C)`. Both have the hash encoding above. This defines the proposal's previously unspecified genesis root without a circular dependency between first-roster membership and consent. Callers provide 32 bytes of creation entropy; B derives identifiers but generates no entropy. Root fields remain identical throughout the chain and must be independently pinned by D.

For each signed object: payload is JCS of all wire fields except `signatures`; payload hash is SHA256(payload); signing bytes are `schema || NUL || payload`. The schema also sits inside the hashed payload. Domains are `courier.team.roster.v1`, `courier.team.invitation.v1`, `courier.team.acceptance.v1`, and `courier.team.owner-transition.v1`. A tombstone is a roster with `status=deleted` and `members=[]`, under the roster domain, never a separate unchained deletion assertion.

Ordinary rosters have exactly one `owner` signature. Transfers have `old_owner`, then `new_owner` signatures over the same complete roster payload, plus a separate certificate signed in that same role order. Certificate hash, previous certificate hash, previous roster hash, version, root, old/new owner and incremented owner epoch must match the actual transition. Ordinary snapshots set `owner_transition_hash=null`; the last certificate hash is carried by validation state. Genesis version/epoch are `1`; every roster increments version exactly once. Equal issued times are allowed; backwards or future issued times fail. Deletion is terminal and cannot transfer ownership.

Invitation and acceptance both bind the full creation root, owner and owner epoch, 32-byte invite ID and nonce, handle, member address, visibility, history disclosure, removal policy and invitation window. Acceptance additionally binds the invitation payload hash and its own acceptance time. The exact policy constants are `private`, `current_and_future_members`, and `owner_dependent_with_local_blocking`. The owner signs the invitation and member signs acceptance. A roster member's consent hash is the acceptance payload hash. Every genesis member, including an owner listed as a member, needs consent. Unchanged tuples retain consent; additions, rebinding and rejoining need unused consent. Full-history validation rejects repeat invite IDs, including rejoin with old consent.

## API for C/D

- `TeamRoot`, `TeamRoster`, `TeamMember`, `TeamSignature`, `TeamConsentBinding`, `TeamInvitation`, `TeamAcceptance`, `TeamOwnerTransition`, `TeamConsent` define wire values. `NewTeamRoot` derives public identifiers from explicit caller data.
- `ParseTeamRoster`, `ParseTeamInvitation`, `ParseTeamAcceptance`, `ParseTeamOwnerTransition` perform bounded strict parsing/structural validation, **not trust verification**. Never use a value returned with an error.
- `CanonicalTeamJSON`, `CanonicalTeamPayload`, `TeamPayloadHash`, `TeamSigningBytes` define bytes. `MakeTeamSignature` invokes an explicit caller-supplied signer and verifies its output; it does not authorize signing.
- `VerifyTeamOwnerProof` checks historical compact ownership continuity from a pinned root. Its owner/epoch are provisional, not proof of the latest owner or permission to send. It contains no member list.
- `VerifyTeamConsent` checks signed consent at an explicit admission timestamp against an explicit expected root/owner/epoch. C must independently check current-head CAS, cancellation, consumption and invitation authorization atomically before publication. Historical verification cannot prove that an invite was not cancelled before admission.
- `VerifyTeamChain` checks a complete genesis-to-terminal chain, its complete certificate list and exactly the consent records introduced in that history. A supplied `TeamCheckpoint` is a trusted historical lower bound: its exact version/hash/status must appear, preventing rollback/equal-version forks. Missing links and unused certificates/consents fail. No partial-chain or compacted-history optimization is claimed.
- `TeamChainResult` carries the terminal checkpoint, owner/epoch, last certificate hash and expiration. Authentic expired historical links are accepted; an active terminal head must be fresh. A valid terminal tombstone succeeds with `Deleted=true` even after expiry. `TeamCanSend` rejects that state and rechecks expiration; callers must use a freshly verified/persisted result, not construct one from relay metadata.
- Errors wrap `ErrTeamWire`, `ErrTeamLimit`, `ErrTeamSignature`, `ErrTeamBinding`, `ErrTeamChain`, `ErrTeamFreshness` or `ErrTeamDeleted`; callers use `errors.Is` and must treat every error as non-authorizing. Error text avoids exposing roster content.

C/D remain responsible for independently authenticated bootstrap, captured context comparison, durable checkpoints/time floors, clock rollback defense, current-head CAS, private ACLs, cancellation/consumption, transactional admission, persisted tombstones and fresh fetches. B has no IO or mutable trust state. A withheld unexpired removal remains possible for up to the approved validity window; a relay nonce cannot fix this. Recovery cannot clear a checkpoint or revive a deleted ID. A new team after lost ownership requires a fresh independently pinned root.

The user subsequently requested same-team peer task assignment. That protocol remains separate and unimplemented here. Reserve a distinct schema/domain rather than adding unknown fields to v1 rosters or treating consent/membership as execution or tool authority. Task authorization must not reuse invitation acceptance signatures.

## Proposed resource budgets and fixtures

`TeamLimits` is an explicit validated input to every parser/verifier; zero values fail. No release defaults are installed. Test/benchmark proposals are 256 members, 256 array entries, 512 bytes/string, 256 KiB/object, 1,024 total chain objects (each invitation and acceptance counts separately), 8 MiB total serialized chain data for stress tests and 24-hour invitation lifetime. The measured initial release proposal is tighter: 2 MiB total chain data, retaining the other numeric caps; it is not a default and still needs owner/reviewer approval. Roster lifetime is the approved hard 24-hour protocol bound; invitation lifetime is a caller budget capped at that bound for this candidate.

These budgets bound one validation attempt, not total team lifetime. Longer histories must fail visibly until a separately reviewed bounded catch-up/checkpoint design is available. Do not prune signed history, consumed consent or tombstones to make validation pass. Durable security metadata retention and any outbox retention are unresolved release policy; Packet B neither owns outbox storage nor claims an unmeasured retention maximum is safe. Benchmark evidence is recorded below before recommending release values.

`internal/envelope/testdata/team/golden.json` revision `packet-b-v1` contains synthetic invitation, acceptance, genesis, dual-signed certificate/transfer, renewal after expired history and terminal tombstone. Each entry includes wire JSON, canonical payload, signing bytes in hex, payload hash and signatures. `node internal/envelope/testdata/team/vectors.mjs` independently reconstructs and compares all seven using ECMAScript serialization and Node Ed25519. Only `--write` intentionally replaces the fixture. Go consumes the committed artifact and verifies the complete chain; no runtime JS dependency exists.

Tests include strict schema/encoding rejection, JCS equivalence, domain separation, immutable signature-free hashes, consent substitutions/rejoin, actual signed certificate mismatches, history expiry, active-head expiry, tombstone finality, checkpoint forks/rollback, transition gaps/epoch reuse, resource budgets and preserved omitted-suite compatibility. `FuzzTeamWire` tests parser/canonicalization round trips; `FuzzTeamChainBinding` re-signs mutated transfer shapes to reach chain invariants rather than stopping only at signature failures.

## Remaining gates

- Independent acceptance of refreshed Packet A and any further predecessor fixes. Incorporation at the verified base below is complete; independent predecessor review is not claimed.
- Independent review of schema/API, creation commitment, restricted canonicalizer, signatures, consent semantics and golden revision before C/D freeze dependencies.
- Numeric limits and security-state retention policy, with production-representative benchmarks and a design for long-lived history.
- Native platform/release evidence and downstream malicious-relay, atomic admission, persistence/crash and fanout tests. B's pure verifier tests do not establish those properties.
- The root authorized the separate CI trigger change in `3b97a68`: both push and pull-request branch filters now cover `main`, `consolidation/**` and `packet-*/**`. All existing jobs, permissions and gates are preserved. Actual remote run outcomes must be tied to the exact candidate head; local checks are not substitutes for remote CI.
- Root coordinates independent reviews and all merges; no deployment or release is authorized here.


## Refreshed base and measurements

GitHub PR metadata and Git commit API independently confirmed PR163 head `490c736bf8511042a55f60824a8de539d8af1ec5`, tree `8ec775ba321e2a2668859d9b30ff00bfe99a31eb`, branch `packet-a/context-isolation`. It contains the caller-config/locked-update fixes and the latest PR154 integration. B was replayed into a fresh `packet-b/team-wire-v1` worktree directly from that tip. The original unpublished `packet-b/team-wire` branch remains intact; no merge or force push was performed. The resulting diff contains only new envelope files/fixtures and this document.

Go 1.26.9, Darwin/arm64, Apple M5, `GOMAXPROCS=2`, `-benchtime=3x`, synthetic public fixtures. These are small local measurements (some with other bounded validation jobs running), not throughput guarantees or peak resident memory. `B/op` measures total allocations per verification.

| Fixture | Serialized bytes | Time/op | Allocated bytes/op |
| --- | ---: | ---: | ---: |
| 1 member, genesis plus consent | 1,169 roster bytes | 0.83 ms | 195,040 |
| 64 members, genesis plus consent | 11,942 roster bytes | 70.9 ms | 8,323,133 |
| 256 members, genesis plus consent | 44,774 roster bytes | 171.9 ms | 33,318,362 |
| 128 empty snapshots | 136,783 | 35.8 ms | 7,185,088 |
| 1,024 empty snapshots | 1,095,528 | 360.3 ms | 57,419,704 |
| 256 members, 32 snapshots, all consent (2 MiB proposal) | 2,027,826 | 525.7 ms | 93,167,866 |
| 256 members, 160 snapshots, all consent (8 MiB stress budget) | 7,767,919 | 2,152.7 ms | 340,084,602 |

Commands: `go test -run '^$' -bench '^BenchmarkTeam(Chain|History)$' -benchmem -benchtime=3x ./internal/envelope` and `go test -run '^$' -bench '^BenchmarkTeamCombinedBudget' -benchmem -benchtime=3x ./internal/envelope`. The 8 MiB stress result motivates the 2 MiB initial proposal. Even that costs material allocation and limits long-lived histories: release needs a reviewed catch-up/retention design or explicit fail-closed product limits, not silent deletion of security history. Member count, snapshot/chain budgets, invite lifetime/rate and downstream operation/outbox retention still require release sign-off; B does not invent rate or outbox policies.

Fixture SHA256: `23c9118bde7d7cefb4baafc46451e714aad548c42620fc95b10edf6608e1ed28`. Exported API and fixture acceptance must pin the eventual draft PR head, not a moving branch.


## Repaired Packet A integration and review delta

The parent supplied Packet A freeze `80bff09d5c9e1548db6f7be0e44920887c2e64d3`, tree `0770b0fecfaa024a9806e4623c56f03d8bad53bb`, containing predecessor `b1c9c7196c82af0a3cec7ad999fd2bcf0acdc797`. GitHub and local Git independently confirmed the freeze. Merge commit `79f7edcece0b81cd1e3848cf7c0952bb38049150`, tree `ce503821db60007c9e72dd4f9bc44fd76e1f0f9f`, has parents B `3b97a68` and A `80bff09`. It cleanly incorporates A's 13-file update without rewriting either history. No B protocol, API, tests, fixtures or CI implementation changed in that merge. Fresh local full/race tests, vet, staticcheck, module verification and independent Node vectors passed at the merge head.

The coordinator reported independent acceptance of the pure B protocol/API at `3b97a68`, with no confirmed defects after full/race tests, seven Node vectors and 383 additional checks. That is protocol review evidence, not acceptance of numeric release policy or later base changes. The subsequent B-specific delta is documentation only: correcting CI coverage and recording the measured history constraint below. Final delta review and exact-head remote CI remain gates coordinated by the root.

## Measured history limit and downstream proposal

Independent review measured the proposed **2 MiB total validation budget** with **256 unchanged members and all original consent**: **33 snapshots fit; snapshot 34 fails closed at 2,117,514 serialized bytes**, exceeding 2,097,152 bytes. Its 32-snapshot fixture reported approximately **211 ms** and **93.6 MB allocated per verification**. Timing is environment-dependent and does not supersede the separate local measurements above. There is no guaranteed 33-day lifetime: renewal frequency, membership churn and other object sizes change when the bound is reached. Neither the 2 MiB budget nor a retention/history strategy has release approval.

Downstream C/D proposal, subject to review:

- Paginate and bound raw retrieval, then enforce the existing total object/serialized-byte limits for verification. Pagination alone does not make an over-budget full history admissible. Preflight projected history growth and expose remaining capacity before publication; errors must clearly pause activation/sending instead of dropping old records.
- Until a longer-history protocol is reviewed, retain full history and security records and fail closed at the configured limit. A separately authorized new team requires a fresh root pin and fresh consent; it cannot silently inherit the old team's trust or erase its tombstone/checkpoint.
- Explore an explicitly reviewed incremental-verification API rooted only in a **durably saved, previously fully verified local checkpoint**, with authenticated continuity and persistent anti-rollback, owner-transition, membership/consent replay, deletion and clock-floor state. This is a design proposal, not an available B capability. A compact ownership proof, relay assertion, arbitrary checkpoint or restored unverified cache must not substitute for full membership history or establish a fresh head. New-device/bootstrap and recovery need their own reviewed authenticated evidence design before any checkpoint-based history compaction can ship.

Do not silently increase limits, prune consent/history/tombstones, accept partial chains, or convert a limit failure into trusted state. Current `VerifyTeamChain` still requires complete history within explicit budgets; this documentation introduces no alternate acceptance path.
