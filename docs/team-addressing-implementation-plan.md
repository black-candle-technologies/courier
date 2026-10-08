# Team addressing implementation work packets

**Status:** Prepared dispatch plan, 2026-10-08. No implementation agents have been dispatched by this plan. Documentation publication does not authorize runtime implementation, rollout or merge. Riley retains the merge gate.

Implement the [revised team addressing design](team-addressing-plan.md) in small independently reviewable changes. The verified source baseline is main `454843d411f3c0db7f00f8dcbf0b6ad05d2f354d`; PR 162 originally contains only the proposal at `ec99b39f80c2f288c9374d49af1e7aeb0b4c10b6`. Recheck both before any future dispatch and pin every worker to its actual assigned base. Do not assume these SHAs remain current.

## Dispatch gate and decision record

The next authorized action today is documentation only. A later explicit implementation authorization opens packet dispatch; it does not waive the following unresolved product/security decisions or Riley’s merge gate.

Record each decision with the responsible owner, approval date, chosen value, rationale and affected packet IDs before releasing the dependent implementation. Recommended values are design proposals, not already accepted policy:

| Decision | Recommended first release | Gates |
| --- | --- | --- |
| D1 freshness | Owner-signed snapshots valid at most 24 hours; no expired sends; explicit withholding limitation | B, C, D, E, F |
| D2 visibility | Private-only, no arbitrary nonmember readers | B, C, D, E |
| D3 principal reuse | One relay security binding per principal; distinct named identities per host remain supported | A, D, E |
| D4 owner recovery | No relay-mediated recovery; lost owner requires a new explicitly pinned team | B, C, D |
| D5 history and leaving | Members consent to historical roster disclosure to future members; leaving depends on owner removal, with local blocking available | B, C, D, E |
| D6 limits and CLI | Explicit `send --team`; bounded text-only fanout; exact supported flags, roster limits and outbox retention agreed before coding | B, C, E, F |

For D6, choose and record numeric maxima for roster members, snapshot bytes, chain pages, invitation lifetime/rate, outbox bytes and retention. Benchmark proposals before claiming limits are safe; a worker must not quietly invent permanent defaults. Retention must preserve uncertain-send recovery and consent/checkpoint security. Feature-disabled context refactoring may proceed only after separate implementation authorization and D3 selection; no team write/send path is exposed before its full gate is satisfied.

If owners reject D1 or D5, stop affected protocol work and revise the reviewed design before coding. Stronger freshness, privacy-preserving history proofs or independent withdrawal are protocol changes, not small implementation details.

## Ownership and integration rules

Use a dedicated branch or worktree per packet. An integrator owns sequencing and shared-file arbitration; an independent reviewer must not be the implementation author. A packet’s owner may edit only its listed surfaces unless the integrator explicitly transfers ownership. New file names below are proposed ownership boundaries, not claims that they already exist.

- Packet A owns all existing local state-path helpers, config loading/saving and host/identity/context wiring. No parallel packet changes those helpers while A is active.
- Packet B owns new wire types and canonicalization. Freeze its exported types and error contracts before C and D consume them.
- Packet C owns relay handlers and persistence. Existing `internal/store/store.go` and relay route registration have one designated writer.
- Packet D owns client roster trust, invitations and team lifecycle. It consumes context and protocol interfaces rather than reopening A/B files. After A completes, D receives a short exclusive ownership window for the inbound team-protocol DM dispatch hook in `internal/client/client.go`; D hands that file off before E starts. No other worker changes it during that window.
- Packet E owns CLI team resolution/fanout and the existing send pipeline integration. It is the single writer for `cmd/courier/main.go` and `internal/client/client.go` after A’s handoff.
- Packet F owns independent test additions and adversarial fixtures. It does not modify implementation to make its tests pass; defects return to their packet owner.
- Packet G owns integration and release documentation after the other packets. No independent worktree may publish directly to main or merge another worker’s branch.

Use small commits with one behavior or refactor each; pair the change with its tests. Keep feature flags disabled by default. An ordinary code revert can undo an unshipped refactor, but once persisted state/ratchets have advanced, restoring an old disk image is not a safe rollback. Every state-changing packet must supply an explicit forward-recovery procedure.

## Dependency graph

After implementation authorization and relevant decision closure:

1. A context isolation and B protocol types may run in parallel in disjoint files. F may independently write test plans/fixtures in its own test surfaces.
2. A completes its compatibility review and hands off context/store interfaces. B completes protocol review and publishes immutable golden vectors.
3. C relay/storage and D client trust can then proceed in parallel, using B’s wire contract and A’s context APIs. Agree an API fixture before either assumes endpoint behavior.
4. E starts once A, B, C and D’s reviewed commits are integrated into its base; do not implement a speculative send path against moving trust semantics.
5. F runs full adversarial and migration coverage against the integrated candidate. Defects return to their owners; rerun review after fixes.
6. G assembles release evidence and operator docs. Riley decides merge; release/rollout is a separate authorization.

The integrator resolves shared-file conflicts by transferring a file to one worker at a time, not by concurrent edits followed by guessed conflict resolution.

## Packet A Isolate client contexts

**Outcome:** A command resolves one immutable relay/principal context; every local state operation and daemon uses it, with unchanged default single-host behavior.

**Owned surfaces:** proposed `internal/client/context.go`, `hosts.go`, `context_store.go` and tests; context wiring in `internal/client/client.go`, config lock files, all existing path helpers (`groups.go`, `fs.go`, `vhl.go`, `state.go`, `receipts.go`, `threading.go`, channels/attachments/backup/wake as discovered), and minimal command construction plumbing. Coordinate Windows and Unix locks. Do not add team endpoints or alter cryptographic wire formats.

**Commit slices:** (A1) introduce context interfaces and legacy adapter without moving data; (A2) convert path/lock helpers and consumer state in small file-family slices; (A3) host/identity selection and one-relay-per-principal validation; (A4) journaled explicit migration and recovery.

**Acceptance:** existing single-host tests unchanged; two principals on one relay do not share cursors, replay sets, group keys, FS, VHL, contacts or logs; aliases of one binding/principal share the correct state; a second relay for the same principal is rejected; no pin copying; backup/restore/import-sync obey context and existing FS/VHL reset behavior; daemon identity is stable; multi-process races and migration interruption at each commit point are recoverable.

**Review gate:** independent full state-path inventory plus negative cross-context tests. Deliver exported interfaces and a migration matrix before C/D/E depend on them. Do not claim encryption or approval state can be safely rolled back from an old backup.

## Packet B Specify and validate team wire types

**Outcome:** strict, independently tested roster, invitation, acceptance, tombstone and owner-transition representations with canonical bytes.

**Owned surfaces:** proposed `internal/envelope/team.go`, `team_test.go`, team fuzz tests and golden fixture files. Reuse existing crypto dispatch via narrow interfaces; do not change SuiteV1 or existing omitted-suite defaults. Any unavoidable edit to shared envelope or crypto registry code requires integrator ownership transfer.

**Commit slices:** (B1) schema, strict parsing and RFC 8785 canonicalization; (B2) signatures/hash-chain and transition certificate validation; (B3) invitation/acceptance binding and fixtures; (B4) fuzz and cross-language golden vectors.

**Acceptance:** duplicate/unknown fields, invalid encodings, repeated handles/addresses, overflow, wrong domain/origin/team/signer/epoch, version/hash forks and certificate gaps fail. Historical expired links verify as history; active terminal heads require freshness; tombstones stay terminal. Transition certificate fields agree exactly with the roster transition. Consent binds visibility and historical-disclosure policy. Unknown suites fail on new team data while existing protocol defaults remain compatible.

**Review gate:** independent cryptographic protocol review of canonical bytes, hash definitions, domain separation and fixtures. Dependency choice for canonicalization must follow repository policy and be explicitly reviewed; no new crypto suite. Publish the exact API/fixture revision C and D will consume.

## Packet C Implement relay team storage and API

**Outcome:** owner-authorized compare-and-swap publication, immutable chain history and private access controls committed transactionally.

**Owned surfaces:** proposed `internal/relay/team.go`, relay team tests; proposed `internal/store/teams.go` and migrations/tests. The integrator grants this packet sole write ownership of existing route registration and `internal/store/store.go` during its window. Do not modify existing group authorization or contact-directory meaning.

**Commit slices:** (C1) additive storage schema and rollback-safe inactive tables; (C2) publication CAS and tombstones; (C3) authenticated private reads, admission and ACL changes; (C4) bounded rate/size controls and failure handling.

**Acceptance:** unauthorized readers cannot enumerate roster existence; pending invitees see no roster history; current members receive the history their consent covers; admission/removal and ACL changes are atomic; old owner cannot publish after transfer; an identical update is idempotent; concurrent updates yield one winner; signed consent cannot be replayed/cross-bound; tombstoned IDs never revive; limits fail without partial writes. Existing relay directory/group tests remain green.

**Review gate:** independent storage transaction, authentication, privacy and abuse review. Return endpoint fixture, migration/recovery notes and no-plaintext-log evidence. A nonce signed only by the relay must never be presented as owner freshness.

## Packet D Implement client team trust and lifecycle

**Outcome:** clients cannot resolve/send through a team until independent bootstrap, private admission, full chain verification and durable fresh checkpoints succeed.

**Owned surfaces:** proposed `internal/client/team_trust.go`, `team_directory.go`, `team_lifecycle.go`, their tests and context-bound team storage. Use A/B APIs; do not modify global config/path helpers or the general outgoing send pipeline. After A’s handoff, own the narrow inbound team-protocol DM dispatch hook in `internal/client/client.go` exclusively, then relinquish that file before E begins. Reuse the existing context-bound authenticated protocol-DM transport for invitations/acceptance, and own owner lifecycle signing and roster publication; these operations must not wait on or route through E’s future team-fanout path.

**Commit slices:** (D1) inspect-only unknown state and verified root import; (D2) provisional invitation validation using member-free owner proof, acceptance/admission, full-chain activation; (D3) renewal, transfer, removal, terminal deletion; (D4) checkpoint concurrency, restore and clock rollback handling.

**Acceptance:** directory-provided owner signatures alone never bootstrap trust; historical owner continuity does not imply latest-owner freshness; full chain activates only after admission and fresh head verification; persistence failure blocks use; version rollback/fork pauses; missing links are fetched within limits; expired heads cannot send; historical links/tombstones have correct expiry semantics; restored checkpoints are only historical lower bounds; alias removal/recreation cannot resurrect trust; owner-unavailable leaving is reported honestly.

**Review gate:** independent malicious-relay and crash-recovery review, including withheld fresh removals and the documented 24-hour limitation. Do not auto-create trusted contacts, enable receipts, bypass requests or grant VHL authority.

## Packet E Add CLI resolution and safe text fanout

**Outcome:** existing send syntax stays compatible; explicit team fanout produces audited, resumable per-recipient direct-message operations.

**Owned surfaces:** proposed `cmd/courier/team.go`, CLI/team parser tests, proposed `internal/client/team_fanout.go` and outbox tests. After A’s handoff, this packet alone owns send integration in `cmd/courier/main.go` and `internal/client/client.go`; coordinate narrow FS preparation API changes with the integrator.

**Commit slices:** (E1) typed pure parser and resolve/dry-run outputs; (E2) recipient expansion plus full-policy preflight; (E3) durable prepared ciphertext/outbox and exact-envelope retries; (E4) status/resume/cancel and partial failure reporting.

**Acceptance:** `@handle` and `handle:name` remain single-recipient, with no fallback broadcast; unsupported/malformed flags fail before sending; dry-run sends nothing. Preserve first-contact/contacts-policy `--force`, each peer’s FS-required setting and per-recipient VHL rules. First release is text-only and rejects attachments, replies, TTL and any unimplemented VHL fanout mode before the first delivery. Freeze `(handle,address,consent_hash)` targets; never add new members during resume or retransmit to known removed/rebound recipients. Verify expiry immediately before each submission and revalidate after human approval. Disk failure/crashes around ratchet advancement and submission do not silently create duplicate logical messages. Uncertain acceptance remains uncertain until established.

**Review gate:** independent end-to-end send/ratchet transaction and authorization review. Audit actual relay deduplication and retention; do not advertise exactly-once delivery without proof. Team sends never auto-create/synchronize a sender-key group.

## Packet F Challenge the integrated implementation

**Outcome:** independent evidence that the claimed compatibility, privacy and safety properties hold.

**Owned surfaces:** new integration tests/fixtures under repository-approved test locations, separate adversarial test files, and test reports. Do not change implementation or rewrite existing tests to weaken expectations. Agree exact new file names with the integrator before work starts.

**Commit slices:** (F1) baseline behavioral tests and malicious-relay fixtures; (F2) migration/process-race/crash matrix; (F3) full CLI and fanout scenarios; (F4) regression and fuzz evidence.

**Acceptance:** exercise every acceptance category in the design, including new-client bootstrap, expired history, equal-version equivocation, compact-proof forks, tombstone replay, historic membership disclosure, leave limitation, changed recipient approval scope, post-approval expiry, partial/uncertain delivery and context collisions. Run existing group, FS, VHL, contact, directory, backup and multi-platform tests without weakening them.

**Review gate:** report failures before fixes, map each invariant to tests, identify untested boundaries and independently rerun the final candidate. A design review does not substitute for test execution or security review of new code.

## Packet G Integrate and prepare release evidence

**Outcome:** one candidate with traceable dependencies, disabled-by-default feature behavior, operator recovery instructions and honest CI evidence.

**Owned surfaces:** integration branch, `docs/team-addressing-plan.md`, this dispatch plan, release/operator docs and only integrator-approved wiring. No feature work, broad refactors or unreviewed conflict resolutions.

**Commit slices:** reviewed packet integration in dependency order, documentation/CLI help updates, evidence manifest. Stop on unexplained baseline movement and rebase/review deliberately; never force push another owner’s branch.

**Acceptance:** exact candidate SHA with all relevant checks; end-to-end two-principal demonstration on a test relay without production secrets; documented pin/identity migration and clock/checkpoint recovery; bounded unsupported modes visible in help; no automatic rollout, merge or deployment.

**Review gate:** independent final diff review, owner sign-off on D1–D6, and Riley’s explicit merge decision. Production enabling and signing-service provisioning need separate authorization.

## Required check contract

Read current `AGENTS.md`, applicable scoped instructions, `go.mod` and `.github/workflows/ci.yml` at each worker’s assigned base. The inspected baseline CI uses Go 1.26.8 and runs formatting, module verification, vet, full tests, race tests, pinned staticcheck/govulncheck, fuzz smoke and Linux/macOS/Windows compile jobs. Reuse the current workflow’s versions and commands rather than copying stale values from this plan.

For implementation changes, run focused tests first and then the complete relevant aggregate gates, including `go test -count=1 -timeout=15m ./...` and `go test -race -count=1 -timeout=25m ./...` when unchanged in current CI. Include platform-lock coverage and dependency review if dependencies change. Never call focused checks a full pass. Report passed, failed, blocked and not-run checks separately with commands and exact commit SHA.

This documentation update does not execute those runtime checks. Its publication gate is reviewed docs-only diff, source verification, Markdown/link checks and remote read-back; any CI run triggered by publication must be reported separately.

## Copyable worker handoff

Use only after dispatch is explicitly authorized and the packet’s decisions/dependencies are satisfied:

> Implement packet [ID] from docs/team-addressing-implementation-plan.md at assigned base [SHA] on branch [branch]. Read the design and current repository instructions first. Own only [file surfaces]; coordinate shared files through the integrator. Preserve existing @handle/contact behavior, SuiteV1, group encryption, per-recipient authorization and state isolation. Make small reversible commits with tests; explain forward recovery for persisted state. Do not merge, deploy, change unrelated files or start another packet. Stop if a decision gate is unresolved, a dependency changed, or authorization is missing. Report useful results and blockers promptly. Return commit/diff references, exact commands and results, remaining risks and an independent-review-ready summary. Publication permissions must be stated explicitly in the assignment; absence of permission means keep work local.

## Prepared dispatch checklist

- [ ] Implementation authorization received, with publication scope for each worker
- [ ] Current main/PR heads and repository instructions rechecked
- [ ] D1–D6 owners and decisions recorded for dependent packets
- [ ] Integrator and independent reviewers assigned
- [ ] Exclusive file ownership and shared interfaces agreed
- [ ] Isolated branches/worktrees and base SHAs assigned
- [ ] Test fixtures, crash matrix and recovery expectations accepted
- [ ] Packet dependencies reviewed before each dispatch
- [ ] Riley’s merge gate retained; release remains separately gated
