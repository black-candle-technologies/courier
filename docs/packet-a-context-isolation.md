# Packet A: context isolation

Implementation in progress; this document does not claim acceptance or release approval.

## Owner decision

D3 was approved by Riley through the authenticated parent conversation on 2026-10-09: v1 requires one relay security binding per principal. Distinct identities may use multiple hosts. The explicit question described separate identities for each relay and the user answered “Yes” (message `Sentinel_8cfbcc9261e081918aec9191ae9a3a64`). This approves implementation, not real credential creation, user-data migration, deployment, or merging.

D1 freshness, D2 visibility, D4 owner recovery, D5 history/leave policy, and D6 limits/CLI remain unresolved proposals. No team protocol or send behavior is enabled by this packet.

## Initial compatibility slice

`Context` captures a state root once. `LegacyContext` preserves the existing default directory without moving data or creating files. A zero or failed context is an error. Later slices bind each store and command to the selected context; this first slice alone does not establish isolation.

Base initially verified at `1e71d18f96e049b127ca48c55a012af7eeb06aa2`, tree `05c7301ac58a294f660a1252872fa2fb4dbf94dd`. Integrator fixes are pending; final verification must use the refreshed stack tip supplied by the parent.

## Store and migration contract

All client path helpers now receive `Context`; legacy package functions are adapters. `Config` captures its context when loaded/saved or attached to a client. Named clients snapshot their config so later caller mutations cannot select another principal. `IdentityStore` is a context-bound view of identity keys, co-located in `config.json` during this compatibility phase. D3 makes its cross-process config lock identity-wide. Rotation reloads key history under that lock. This is logical separation without introducing a second key-file commit point.

`Hosts.Resolve(root, host, identity)` is pure and disabled unless the registry explicitly sets `enabled: true`. It validates HTTPS origins and supplied SHA256 pins, checks D3 across all identity aliases, and derives a directory from binding ID plus principal, never from aliases. Config loading rejects mismatched principal/seed, endpoint, or pin. Unknown selectors never fall back.

`Context.MigrateLegacy(target, MigrationOptions)` is explicitly invoked. The caller must confirm all old writers are stopped, including custom-PID wake, dashboard and bridge processes. It also checks the default wake lock and holds the legacy config lock. Arbitrary historical binaries cannot be made migration-aware retrospectively; do not restart them after migration.

The migration copies config, groups, FS (including required-FS policy), imported VHL, delivery receipts, sent log, reply cache, retired channel archive and retired shared-state archive. It does not copy live locks/PIDs or interrupted temporary files. Source files are retained. Source checksums and target binding are journaled and fsynced before copying; staged files are fsynced, renamed and checksummed before the active manifest is atomically replaced and its directory fsynced. The manifest is the sole commit point.

On interruption, invoke the same migration with the same selection after stopping writers again. An unchanged source resumes; changed source/binding or mismatched target checksums stops for investigation and preserves evidence. A committed migration is idempotent and never recopies stale ratchets. Supported legacy writers refuse the migrated store. Never restore the retained source copy after new state advances: recover forward in the selected context. Do not manually remove the active manifest to roll back.

Journaled migration is explicitly unavailable on Windows and platforms without verified cross-process locking/directory fsync. Named Windows stores and locks compile, but native lock execution and durable Windows migration remain release gates.

The subprocess crash fixture exits after journal creation, every sidecar copy, staging, verification and commit. These are disposable synthetic stores only; no real configuration has been migrated. Negative fixtures cover active default wake locks, missing quiescence confirmation and symlink staging. Separate subprocess tests exercise two contexts with concurrent writers.

## Command selection and handoff

Global `--host HOST [--identity IDENTITY]` selectors precede the command. They read the explicitly enabled public registry at the legacy root's `hosts.json`. No selector preserves the existing layout until a migration commits, then resolves the active manifest once. Each command object carries its context; no process-global current host or HOME mutation is introduced. Running daemons retain their captured config and root.

Explicit migration spelling: `courier --host HOST context migrate --confirm-legacy-writers-stopped`. This is an operator interface, not a request to run it against existing user data. Named `init`/repinning and automatic systemd installation fail visibly pending separate provisioning/service lifecycle work; they never fall through to the legacy identity or overwrite its unit. Named wake can run explicitly in the foreground. No team behavior is added.

Exports available for downstream review: `Context`, `LegacyContext`, `Context.ActiveContext`, `StateRoot`, `Principal`, `Binding`, `LoadConfig`, `ConfigExists`, `RestoreBackup`, `LookupReplyParent`, `DefaultWakePIDFile`, `IdentityStore`, `IdentityStore.Load`, `Hosts.Resolve`, `RelayBinding`, `NamedIdentity`, `Host`, `NormalizeRelayOrigin`, `MigrationOptions`, `Context.MigrateLegacy`; errors `ErrContextsDisabled`, `ErrContextMismatch`, `ErrLegacyMigrated`. Packet B may use normalized origin/value snapshots but must not treat these as team trust or owner authorization. Interfaces remain subject to independent review and refreshed-base integration.

State inventory: config includes contacts/verification pins, relay/dashboard pins, independent inbox/push replay sets and inbox/dashboard/sent/wake cursors, directory epochs/cache, request/block decisions and receipt opt-ins. Groups, FS/required-FS, imported VHL, delivery receipt records, sent logs and reply caches are context-bound. Attachment input/output paths are explicit user destinations; no implicit attachment sidecar exists. Backup preserves its existing fresh-contacts/cursors and FS/VHL-reset semantics. Imported sync keys target the captured identity. Retired channels retain warning/quarantine only; retired shared state retains archive TTL maintenance/quarantine only; read receipts remain retired. No channel/shared-state runtime is restored.

## Refreshed predecessor integration

The parent supplied and authenticated GitHub verification confirmed PR154 head `545c1034bd80748205f2aa114b2c086f305ca18f`, tree `c2b422fb62492f7d506ef89d2279e279395d5d99`. It is merged without rewriting Packet A commits. The FS conflict retains the predecessor's active-session preservation guard and routes both the guarded update and new `FSStart` read through the captured context. Single-warning behavior, resolved-handle confirmation, and lookup-failure handling remain intact. Current-head independent review and merge authorization remain with the parent.

D3 also survives removal/replacement of all host aliases: the installation root's `principal-bindings.json` durably records the principal-to-binding assignment (public metadata only). Named store operations take the installation config lock before their context lock. Provisioning validates the identity before recording its binding; subsequent conflicting binding/endpoint/pin claims fail. Migration checks and records the same ledger under the legacy installation lock, with a crash-injection boundary after its durable write. The ledger is never silently deleted or reset by alias changes, backup restore or migration recovery. Platforms without cross-process locks reject named store operations.

Incomplete migration also blocks direct named-host access to its target, including the interval after target-directory rename and before active-manifest commit. `ErrMigrationIncomplete` requires explicit recovery; selecting `--host` cannot bypass the sole commit point and create a second live ratchet store. Crash fixtures assert this at every pre-commit boundary. Windows binding-ledger replacement uses the OS write-through replacement primitive; native Windows execution remains unverified and full Windows directory migration remains disabled.

The second parent-authorized predecessor is `f9a965be056d61d9054282461ca3f9ce6dee16de`, tree `74fb8347dbb5cb4468f8b1cc1eee458630f40095`, superseding the earlier handoff. Its canonical protocol corrections and cached-only dashboard labels merged without conflict. Packet A retains those changes, including the zero-directory-network regression test. Final publication evidence must use this predecessor and the resulting Packet A head.
